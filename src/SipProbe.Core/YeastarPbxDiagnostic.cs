using System.Net.Http.Headers;
using System.Text.Json;

namespace InspireTel.SipProbe.Core;

public sealed record YeastarPbxCheckRequest
{
    public required string ApiBaseUrl { get; init; }
    public required string ClientId { get; init; }
    public required string ClientSecret { get; init; }
    public required string ExtensionNumber { get; init; }
    public string AuthenticationName { get; init; } = string.Empty;
    public int TimeoutSeconds { get; init; } = 15;
}

public sealed class YeastarPbxDiagnostic
{
    private static readonly string[] BlockedIpEndpoints =
    {
        "blockedip/list",
        "blockedip/search",
        "blocked_ip/list",
        "ip_defense/list"
    };

    private readonly List<DiagnosticLogEntry> _entries = new();
    private readonly object _entryLock = new();
    private readonly HttpMessageHandler? _handler;

    public YeastarPbxDiagnostic(HttpMessageHandler? handler = null) => _handler = handler;

    public event Action<DiagnosticLogEntry>? EntryAdded;

    public IReadOnlyList<DiagnosticLogEntry> Entries
    {
        get
        {
            lock (_entryLock)
                return _entries.ToArray();
        }
    }

    public async Task RunAsync(YeastarPbxCheckRequest request, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(request.ClientId) || string.IsNullOrWhiteSpace(request.ClientSecret))
            throw new ArgumentException("PBX API Client ID and Client Secret are required.");
        if (string.IsNullOrWhiteSpace(request.ExtensionNumber))
            throw new ArgumentException("SIP user / extension is required for the PBX status check.");

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(Math.Clamp(request.TimeoutSeconds, 5, 60)));

        using var http = _handler is null
            ? new HttpClient { Timeout = TimeSpan.FromSeconds(20) }
            : new HttpClient(_handler, disposeHandler: false);
        using var client = new YeastarOpenApiClient(request.ApiBaseUrl, http);
        {
            Log(DiagnosticLevel.Info, $"Checking Yeastar OpenAPI at {client.BaseUrl} for extension {request.ExtensionNumber.Trim()}.");
            Log(DiagnosticLevel.Detail, "API Client Secret is never written to the log.");

            string? publicIp = null;
            if (_handler is null)
            {
                publicIp = await TryGetPublicIpAsync(timeout.Token);
                if (publicIp is not null)
                    Log(DiagnosticLevel.Info, $"This laptop's public IP is {publicIp}.");
                else
                    Log(DiagnosticLevel.Detail, "Could not determine this laptop's public IP.");
            }

            string token;
            try
            {
                var tokenResponse = await client.GetTokenAsync(request.ClientId.Trim(), request.ClientSecret, timeout.Token);
                token = tokenResponse.GetProperty("access_token").GetString()
                        ?? throw new InvalidOperationException("get_token succeeded but returned no access_token.");
                Log(DiagnosticLevel.Success, "OpenAPI authentication succeeded.");
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                Log(DiagnosticLevel.Error, $"OpenAPI authentication failed: {ex.Message}");
                Log(DiagnosticLevel.Detail, "Enable API access under Settings → Integrations → API and use the Client ID / Secret. User-Agent must be OpenAPI.");
                return;
            }

            await TryLogSystemAsync(client, token, timeout.Token);

            JsonElement? extension = null;
            try
            {
                extension = await FindExtensionAsync(client, token, request.ExtensionNumber.Trim(), timeout.Token);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                Log(DiagnosticLevel.Error, $"extension/search failed: {ex.Message}");
            }

            if (extension is null)
            {
                Log(DiagnosticLevel.Error, $"Extension {request.ExtensionNumber.Trim()} was not found on this PBX.");
            }
            else
            {
                await LogExtensionAsync(client, token, extension.Value, request, timeout.Token);
            }

            await TryLogPhonesAsync(client, token, request.ExtensionNumber.Trim(), timeout.Token);
            await TryLogBlockedIpsAsync(client, token, publicIp, timeout.Token);
        }
    }

    private async Task TryLogSystemAsync(YeastarOpenApiClient client, string token, CancellationToken cancellationToken)
    {
        try
        {
            var info = await client.GetAsync("system/information", token, null, cancellationToken);
            if (info.TryGetProperty("data", out var data) || info.TryGetProperty("system_info", out data))
            {
                var name = ReadString(data, "name", "pbx_name", "hostname");
                var version = ReadString(data, "version", "firmware_version", "sys_version");
                Log(DiagnosticLevel.Success,
                    "PBX " + string.Join("; ", new[] { name, version }.Where(value => !string.IsNullOrWhiteSpace(value))));
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            Log(DiagnosticLevel.Detail, $"system/information skipped: {ex.Message}");
        }
    }

    private async Task<JsonElement?> FindExtensionAsync(
        YeastarOpenApiClient client,
        string token,
        string number,
        CancellationToken cancellationToken)
    {
        var result = await client.GetAsync(
            "extension/search",
            token,
            new Dictionary<string, string>
            {
                ["search_value"] = number,
                ["page"] = "1",
                ["page_size"] = "50"
            },
            cancellationToken);

        if (!result.TryGetProperty("data", out var data) || data.ValueKind != JsonValueKind.Array)
            return null;

        JsonElement? fallback = null;
        foreach (var item in data.EnumerateArray())
        {
            var candidate = ReadString(item, "number");
            if (string.Equals(candidate, number, StringComparison.Ordinal))
                return item.Clone();
            fallback ??= item.Clone();
        }

        return fallback;
    }

    private async Task LogExtensionAsync(
        YeastarOpenApiClient client,
        string token,
        JsonElement basic,
        YeastarPbxCheckRequest request,
        CancellationToken cancellationToken)
    {
        var number = ReadString(basic, "number") ?? request.ExtensionNumber.Trim();
        var name = ReadString(basic, "caller_id_name", "first_name") ?? string.Empty;
        Log(DiagnosticLevel.Success, $"Extension {number} exists{(string.IsNullOrWhiteSpace(name) ? "" : $" ({name})")}.");
        LogOnlineStatus(basic);

        if (!basic.TryGetProperty("id", out var idElement))
            return;

        var id = idElement.ValueKind == JsonValueKind.Number
            ? idElement.GetInt32().ToString()
            : idElement.ToString();

        try
        {
            var detail = await client.GetAsync(
                "extension/get",
                token,
                new Dictionary<string, string> { ["id"] = id },
                cancellationToken);
            var data = detail.TryGetProperty("data", out var inner) ? inner : detail;
            var transport = ReadString(data, "transport");
            var concurrent = ReadInt(data, "concurrent_registrations");
            var regName = ReadString(data, "reg_name");
            var ipRestriction = ReadInt(data, "enb_ip_restriction", "enable_ip_restriction");
            var userAgentAuth = ReadInt(data, "enb_ua_reg_auth", "enb_user_agent_reg");

            if (!string.IsNullOrWhiteSpace(transport))
                Log(DiagnosticLevel.Info, $"Extension transport on the PBX is {transport.ToUpperInvariant()}.");
            if (concurrent is not null)
                Log(DiagnosticLevel.Info, $"Concurrent IP-phone registrations allowed: {concurrent}.");
            if (!string.IsNullOrWhiteSpace(regName))
            {
                Log(DiagnosticLevel.Detail, $"PBX registration name is {regName}.");
                var probeAuth = string.IsNullOrWhiteSpace(request.AuthenticationName)
                    ? request.ExtensionNumber.Trim()
                    : request.AuthenticationName.Trim();
                if (!string.Equals(regName, probeAuth, StringComparison.Ordinal))
                {
                    Log(DiagnosticLevel.Warning,
                        $"Probe authentication name '{probeAuth}' does not match PBX registration name '{regName}'. A Yealink User Name vs Register Name mismatch will produce repeated 401.");
                }
            }

            if (ipRestriction == 1)
                Log(DiagnosticLevel.Warning, "Extension SIP registration IP restriction is enabled. An unexpected public IP will be rejected with 403.");
            if (userAgentAuth == 1)
                Log(DiagnosticLevel.Warning, "User-agent registration authorization is enabled. This probe's User-Agent may be rejected even when the handset is allowed.");
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            Log(DiagnosticLevel.Detail, $"extension/get skipped: {ex.Message}");
        }
    }

    private void LogOnlineStatus(JsonElement extension)
    {
        if (!extension.TryGetProperty("online_status", out var online))
        {
            Log(DiagnosticLevel.Warning, "Extension online status was not returned.");
            return;
        }

        LogEndpoint("SIP phone", online, "sip_phone");
        LogEndpoint("Linkus Desktop", online, "linkus_desktop");
        LogEndpoint("Linkus Mobile", online, "linkus_mobile");
        LogEndpoint("Linkus Web", online, "linkus_web");
    }

    private void LogEndpoint(string label, JsonElement online, string property)
    {
        if (!online.TryGetProperty(property, out var endpoint))
            return;

        var ips = new List<string>();
        if (endpoint.TryGetProperty("status_list", out var list) && list.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in list.EnumerateArray())
            {
                if (ReadInt(item, "status") == 1)
                {
                    var ip = ReadString(item, "ip");
                    ips.Add(string.IsNullOrWhiteSpace(ip) ? "online" : ip);
                }
            }
        }

        var status = ReadInt(endpoint, "status");
        if (ips.Count > 0)
            Log(DiagnosticLevel.Success, $"{label} registered from {string.Join(", ", ips)}.");
        else if (status == 1)
            Log(DiagnosticLevel.Success, $"{label} is online.");
        else
            Log(DiagnosticLevel.Warning, $"{label} is not registered.");
    }

    private async Task TryLogPhonesAsync(
        YeastarOpenApiClient client,
        string token,
        string extension,
        CancellationToken cancellationToken)
    {
        try
        {
            var result = await client.GetAsync(
                "phone/search",
                token,
                new Dictionary<string, string>
                {
                    ["search_value"] = extension,
                    ["page"] = "1",
                    ["page_size"] = "50"
                },
                cancellationToken);
            if (!result.TryGetProperty("data", out var data) || data.ValueKind != JsonValueKind.Array)
            {
                Log(DiagnosticLevel.Detail, "No auto-provisioned phones were returned for this search.");
                return;
            }

            var matched = false;
            foreach (var phone in data.EnumerateArray())
            {
                var assigned = ReadString(phone, "assigned_ext_num", "ext_number", "number");
                if (!string.IsNullOrWhiteSpace(assigned) &&
                    !string.Equals(assigned, extension, StringComparison.Ordinal))
                    continue;

                matched = true;
                var mac = ReadString(phone, "mac") ?? "unknown MAC";
                var model = ReadString(phone, "model") ?? "unknown model";
                var ip = ReadString(phone, "ip", "phone_ip");
                var firmware = ReadString(phone, "firmware", "fw_version");
                var template = ReadString(phone, "template_name", "template");
                Log(DiagnosticLevel.Info,
                    $"Auto-provisioned phone {model} {mac}" +
                    (string.IsNullOrWhiteSpace(template) ? "" : $"; template {template}") + ".");
                if (string.IsNullOrWhiteSpace(ip) && string.IsNullOrWhiteSpace(firmware))
                {
                    Log(DiagnosticLevel.Warning,
                        "The PBX has no reported IP or firmware for this phone, so it has not successfully registered or posted status. That matches a handset stuck on Registering.");
                }
                else
                {
                    if (!string.IsNullOrWhiteSpace(ip))
                        Log(DiagnosticLevel.Success, $"Phone last reported IP {ip}.");
                    if (!string.IsNullOrWhiteSpace(firmware))
                        Log(DiagnosticLevel.Detail, $"Phone firmware {firmware}.");
                }
            }

            if (!matched)
                Log(DiagnosticLevel.Warning, $"No auto-provisioned phone is assigned to extension {extension}.");
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            Log(DiagnosticLevel.Detail, $"phone/search skipped: {ex.Message}");
        }
    }

    private async Task TryLogBlockedIpsAsync(
        YeastarOpenApiClient client,
        string token,
        string? publicIp,
        CancellationToken cancellationToken)
    {
        foreach (var endpoint in BlockedIpEndpoints)
        {
            try
            {
                var result = await client.GetAsync(
                    endpoint,
                    token,
                    new Dictionary<string, string>
                    {
                        ["page"] = "1",
                        ["page_size"] = "200"
                    },
                    cancellationToken);

                var rows = ExtractArray(result);
                Log(DiagnosticLevel.Success, $"Blocked IP list is available via {endpoint} ({rows.Count} entries).");
                var hits = 0;
                foreach (var row in rows)
                {
                    var ip = ReadString(row, "ip", "source_ip", "src_ip", "ip_address", "source_ip_address", "host");
                    if (string.IsNullOrWhiteSpace(ip))
                        continue;
                    var reason = ReadString(row, "defense_type", "block_type", "protocol", "reason") ?? "blocked";
                    if (publicIp is not null && ip.StartsWith(publicIp, StringComparison.Ordinal))
                    {
                        hits++;
                        Log(DiagnosticLevel.Error,
                            $"This laptop's public IP {publicIp} is on the PBX blocked list ({reason}). Clear it under Security → Security Rules → Blocked IPs before testing again.");
                    }
                }

                if (hits == 0)
                {
                    Log(publicIp is null ? DiagnosticLevel.Info : DiagnosticLevel.Success,
                        publicIp is null
                            ? $"PBX reports {rows.Count} blocked IP entries; compare them with the customer public IP in the web UI."
                            : $"This laptop's public IP {publicIp} is not among the {rows.Count} blocked IP entries returned by the API.");
                }

                return;
            }
            catch (YeastarApiException ex) when (ex.IsMissingInterface)
            {
                Log(DiagnosticLevel.Detail, $"{endpoint} is not exposed by this PBX OpenAPI.");
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                Log(DiagnosticLevel.Detail, $"{endpoint} failed: {ex.Message}");
            }
        }

        Log(DiagnosticLevel.Warning,
            "This PBX OpenAPI does not expose Blocked IPs. Check Security → Security Rules → Blocked IPs in the web UI" +
            (publicIp is null ? "." : $" for {publicIp}."));
    }

    private static async Task<string?> TryGetPublicIpAsync(CancellationToken cancellationToken)
    {
        try
        {
            using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(5) };
            http.DefaultRequestHeaders.UserAgent.Add(new ProductInfoHeaderValue("InspireTel-SIP-Probe", "1.1"));
            var ip = (await http.GetStringAsync("https://api.ipify.org/", cancellationToken)).Trim();
            return ip.Length == 0 ? null : ip;
        }
        catch
        {
            return null;
        }
    }

    private static List<JsonElement> ExtractArray(JsonElement root)
    {
        foreach (var name in new[] { "data", "list", "blocked_ip", "blocked_ips" })
        {
            if (root.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.Array)
                return value.EnumerateArray().Select(item => item.Clone()).ToList();
        }

        return root.ValueKind == JsonValueKind.Array
            ? root.EnumerateArray().Select(item => item.Clone()).ToList()
            : new List<JsonElement>();
    }

    private static string? ReadString(JsonElement element, params string[] names)
    {
        foreach (var name in names)
        {
            if (element.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String)
            {
                var text = value.GetString();
                if (!string.IsNullOrWhiteSpace(text))
                    return text;
            }
        }

        return null;
    }

    private static int? ReadInt(JsonElement element, params string[] names)
    {
        foreach (var name in names)
        {
            if (!element.TryGetProperty(name, out var value))
                continue;
            if (value.ValueKind == JsonValueKind.Number && value.TryGetInt32(out var number))
                return number;
            if (value.ValueKind == JsonValueKind.String && int.TryParse(value.GetString(), out var parsed))
                return parsed;
        }

        return null;
    }

    private void Log(DiagnosticLevel level, string message)
    {
        var entry = new DiagnosticLogEntry(DateTimeOffset.Now, level, message);
        lock (_entryLock)
            _entries.Add(entry);
        EntryAdded?.Invoke(entry);
    }
}
