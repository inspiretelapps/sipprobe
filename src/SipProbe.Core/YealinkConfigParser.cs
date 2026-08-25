namespace InspireTel.SipProbe.Core;

public sealed record YealinkAccountSettings
{
    public string? Server { get; init; }
    public string? SipUser { get; init; }
    public string? AuthenticationName { get; init; }
    public string? Password { get; init; }
    public SipTransport? Transport { get; init; }
    public int? Port { get; init; }
    public int? ExpirySeconds { get; init; }
    public IReadOnlyList<string> NtpServers { get; init; } = Array.Empty<string>();
    public bool? OutboundProxyEnabled { get; init; }
    public string? OutboundProxyAddress { get; init; }
    public int? OutboundProxyPort { get; init; }

    public IReadOnlyList<string> LoadedFields
    {
        get
        {
            var loaded = new List<string>();
            if (!string.IsNullOrWhiteSpace(Server)) loaded.Add("server");
            if (!string.IsNullOrWhiteSpace(SipUser)) loaded.Add("SIP user");
            if (!string.IsNullOrWhiteSpace(AuthenticationName)) loaded.Add("authentication name");
            if (!string.IsNullOrWhiteSpace(Password)) loaded.Add("password (local memory only)");
            if (Transport is not null) loaded.Add("transport");
            if (Port is not null) loaded.Add("destination port");
            if (ExpirySeconds is not null) loaded.Add("registration expiry");
            if (NtpServers.Count > 0) loaded.Add("NTP servers");
            if (OutboundProxyEnabled is not null) loaded.Add("outbound proxy");
            return loaded;
        }
    }

    public IReadOnlyList<(DiagnosticLevel Level, string Message)> Warnings()
    {
        var warnings = new List<(DiagnosticLevel, string)>();
        if (OutboundProxyEnabled == true && string.IsNullOrWhiteSpace(OutboundProxyAddress))
        {
            warnings.Add((DiagnosticLevel.Warning,
                "Outbound proxy is enabled but the proxy address is empty. A Yealink can stay on Registering even when TLS to the SIP hostname works from this computer."));
        }
        else if (OutboundProxyEnabled == true)
        {
            warnings.Add((DiagnosticLevel.Info,
                $"Outbound proxy is enabled: {OutboundProxyAddress}" +
                (OutboundProxyPort is null ? "" : $":{OutboundProxyPort}")));
        }
        return warnings;
    }
}

public static class YealinkConfigParser
{
    public static YealinkAccountSettings Parse(IEnumerable<string> lines)
    {
        var values = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var rawLine in lines)
        {
            var line = rawLine.Trim();
            if (line.Length == 0 || line.StartsWith('#'))
                continue;
            var separator = line.IndexOf('=');
            if (separator <= 0)
                continue;
            values[line[..separator].Trim()] = line[(separator + 1)..].Trim();
        }

        string? Find(params string[] keys) =>
            keys.Select(key => values.TryGetValue(key, out var value) ? value : null)
                .Select(value => value?.Trim())
                .FirstOrDefault(value =>
                    !string.IsNullOrWhiteSpace(value) &&
                    !value.Equals("%NULL%", StringComparison.OrdinalIgnoreCase));

        var transport = Find("account.1.sip_server.1.transport_type") switch
        {
            "0" => SipTransport.Udp,
            "1" => SipTransport.Tcp,
            "2" => SipTransport.Tls,
            _ => (SipTransport?)null
        };

        int? port = null;
        if (int.TryParse(Find("account.1.sip_server.1.port"), out var parsedPort) && parsedPort is >= 1 and <= 65535)
            port = parsedPort;

        int? expiry = null;
        if (int.TryParse(Find("account.1.sip_server.1.expires"), out var parsedExpiry) &&
            parsedExpiry is >= 30 and <= 86400)
            expiry = parsedExpiry;

        var ntp = new[]
            {
                Find("local_time.ntp_server1", "local_time.ntp_server_1"),
                Find("local_time.ntp_server2", "local_time.ntp_server_2")
            }
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .Select(value => value!)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();

        bool? outboundEnabled = Find("account.1.outbound_proxy_enable") switch
        {
            "1" => true,
            "0" => false,
            _ => null
        };
        int? outboundPort = null;
        if (int.TryParse(Find("account.1.outbound_proxy.1.port"), out var parsedOutboundPort) &&
            parsedOutboundPort is >= 1 and <= 65535)
            outboundPort = parsedOutboundPort;

        return new YealinkAccountSettings
        {
            Server = Find("account.1.sip_server.1.address"),
            SipUser = Find("account.1.user_name"),
            AuthenticationName = Find("account.1.auth_name"),
            Password = Find("account.1.password"),
            Transport = transport,
            Port = port,
            ExpirySeconds = expiry,
            NtpServers = ntp,
            OutboundProxyEnabled = outboundEnabled,
            OutboundProxyAddress = Find("account.1.outbound_proxy.1.address"),
            OutboundProxyPort = outboundPort
        };
    }
}
