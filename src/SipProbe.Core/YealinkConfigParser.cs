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
            return loaded;
        }
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
                .FirstOrDefault(value => !string.IsNullOrWhiteSpace(value));

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

        return new YealinkAccountSettings
        {
            Server = Find("account.1.sip_server.1.address"),
            SipUser = Find("account.1.user_name"),
            AuthenticationName = Find("account.1.auth_name"),
            Password = Find("account.1.password"),
            Transport = transport,
            Port = port,
            ExpirySeconds = expiry,
            NtpServers = ntp
        };
    }
}
