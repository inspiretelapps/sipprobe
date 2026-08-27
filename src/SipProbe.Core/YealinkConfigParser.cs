using System.Net;

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
    public bool? AccountEnabled { get; init; }
    public bool? StaticDnsEnabled { get; init; }
    public string? PrimaryDns { get; init; }
    public string? SecondaryDns { get; init; }
    public bool? StaticIpEnabled { get; init; }
    public bool? StunEnabled { get; init; }
    public string? StunServer { get; init; }
    public int? KeepAliveMode { get; init; }
    public int? KeepAliveSeconds { get; init; }
    public bool? TrustCertificatesOnly { get; init; }
    public int? SipListenPort { get; init; }

    public bool KeepAliveEnabled => KeepAliveMode is > 0;

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
            if (StunEnabled is not null) loaded.Add("STUN");
            if (KeepAliveMode is not null) loaded.Add("SIP keep-alive");
            return loaded;
        }
    }

    /// <summary>
    /// True when the file contains something that will stop the handset registering
    /// on every transport, regardless of the network.
    /// </summary>
    public bool HasBlockingProblem => Audit().Any(finding => finding.Level == DiagnosticLevel.Error);

    public IReadOnlyList<(DiagnosticLevel Level, string Message)> Warnings() => Audit();

    public IReadOnlyList<(DiagnosticLevel Level, string Message)> Audit()
    {
        var findings = new List<(DiagnosticLevel, string)>();

        if (AccountEnabled == false)
        {
            findings.Add((DiagnosticLevel.Error,
                "Account 1 is disabled (account.1.enable = 0). The handset will never attempt to register."));
        }

        foreach (var missing in MissingCredentialFields())
        {
            findings.Add((DiagnosticLevel.Error,
                $"{missing} is missing from the configuration. The handset cannot register without it."));
        }

        if (OutboundProxyEnabled == true && string.IsNullOrWhiteSpace(OutboundProxyAddress))
        {
            findings.Add((DiagnosticLevel.Error,
                "Outbound proxy is enabled but the proxy address is empty. Every REGISTER is routed to a proxy that does not exist, " +
                "so UDP, TCP and TLS all fail while this laptop still registers fine. Set account.1.outbound_proxy_enable = 0, " +
                "or give account.1.outbound_proxy.1.address a real value."));
        }
        else if (OutboundProxyEnabled == true)
        {
            findings.Add((DiagnosticLevel.Info,
                $"Outbound proxy is enabled: {OutboundProxyAddress}" +
                (OutboundProxyPort is null ? "" : $":{OutboundProxyPort}") +
                ". This probe dials the SIP server directly, so it does not exercise that proxy."));
        }

        if (StaticDnsEnabled == true && string.IsNullOrWhiteSpace(PrimaryDns) && string.IsNullOrWhiteSpace(SecondaryDns))
        {
            findings.Add((DiagnosticLevel.Error,
                "Static DNS is enabled but no DNS server is set. The handset cannot resolve the PBX hostname, which fails every transport."));
        }
        else if (StaticIpEnabled == true && string.IsNullOrWhiteSpace(PrimaryDns))
        {
            findings.Add((DiagnosticLevel.Warning,
                "The handset uses a static IP but has no primary DNS server. Hostname lookups will fail unless the PBX is reached by IP."));
        }

        foreach (var dns in new[] { PrimaryDns, SecondaryDns })
        {
            if (!string.IsNullOrWhiteSpace(dns) && IPAddress.TryParse(dns, out var parsed) && IsUnusable(parsed))
            {
                findings.Add((DiagnosticLevel.Warning,
                    $"DNS server {dns} is not a usable address. The handset will not resolve the PBX hostname."));
            }
        }

        if (Transport is not null && Port is not null)
        {
            var expected = Transport == SipTransport.Tls ? 5061 : 5060;
            var other = Transport == SipTransport.Tls ? 5060 : 5061;
            if (Port == other)
            {
                findings.Add((DiagnosticLevel.Warning,
                    $"Transport is {Transport.ToString()!.ToUpperInvariant()} but the port is {Port}. " +
                    $"{Transport.ToString()!.ToUpperInvariant()} is normally {expected}; the handset will time out against the wrong listener."));
            }
        }

        if (Transport == SipTransport.Tls && !string.IsNullOrWhiteSpace(Server) && IPAddress.TryParse(Server, out _))
        {
            findings.Add((DiagnosticLevel.Warning,
                $"Transport is TLS but the server is the IP address {Server}. Certificate hostname validation will fail on the handset."));
        }

        if (Transport == SipTransport.Tls && TrustCertificatesOnly == true)
        {
            findings.Add((DiagnosticLevel.Warning,
                "Only trusted certificates are accepted (static.security.trust_certificates = 1). " +
                "Older Yealink firmware does not carry current Let's Encrypt roots, so TLS can fail on the handset while it succeeds here."));
        }

        if (StunEnabled == true && string.IsNullOrWhiteSpace(StunServer))
        {
            findings.Add((DiagnosticLevel.Warning,
                "STUN is enabled but no STUN server is set. The handset may stall while trying to discover its public address."));
        }

        if (KeepAliveEnabled)
        {
            findings.Add((DiagnosticLevel.Detail,
                "SIP keep-alive is enabled" +
                (KeepAliveSeconds is null ? "." : $" every {KeepAliveSeconds}s.") +
                " That helps plain NAT. It does not beat SIP ALG."));
        }

        if (ExpirySeconds is not null && ExpirySeconds < 60)
        {
            findings.Add((DiagnosticLevel.Warning,
                $"Registration expiry is {ExpirySeconds}s. Yeastar Cloud usually enforces a minimum of 600s and will reject shorter values with 423."));
        }

        if (SipListenPort is not null && SipListenPort != 5060)
        {
            findings.Add((DiagnosticLevel.Detail,
                $"The handset listens on SIP port {SipListenPort} rather than 5060."));
        }

        return findings;
    }

    private IEnumerable<string> MissingCredentialFields()
    {
        if (string.IsNullOrWhiteSpace(Server)) yield return "SIP server address";
        if (string.IsNullOrWhiteSpace(SipUser)) yield return "SIP user name";
        if (string.IsNullOrWhiteSpace(AuthenticationName)) yield return "Authentication name";
        if (string.IsNullOrWhiteSpace(Password)) yield return "Password";
    }

    private static bool IsUnusable(IPAddress address) =>
        IPAddress.IsLoopback(address) ||
        address.Equals(IPAddress.Any) ||
        address.Equals(IPAddress.Broadcast) ||
        address.GetAddressBytes() is [169, 254, ..];
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

        bool? Flag(params string[] keys) => Find(keys) switch
        {
            "1" => true,
            "0" => false,
            _ => null
        };

        int? Number(string key, int min, int max)
        {
            if (int.TryParse(Find(key), out var parsed) && parsed >= min && parsed <= max)
                return parsed;
            return null;
        }

        var transport = Find("account.1.sip_server.1.transport_type") switch
        {
            "0" => SipTransport.Udp,
            "1" => SipTransport.Tcp,
            "2" => SipTransport.Tls,
            _ => (SipTransport?)null
        };

        var ntp = new[]
            {
                Find("local_time.ntp_server1", "local_time.ntp_server_1"),
                Find("local_time.ntp_server2", "local_time.ntp_server_2")
            }
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .Select(value => value!)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();

        // internet_port.type: 0 = DHCP, 2 = static IPv4.
        var staticIp = Find("static.network.internet_port.type") switch
        {
            "2" => true,
            "0" => false,
            _ => (bool?)null
        };

        return new YealinkAccountSettings
        {
            Server = Find("account.1.sip_server.1.address"),
            SipUser = Find("account.1.user_name"),
            AuthenticationName = Find("account.1.auth_name"),
            Password = Find("account.1.password"),
            Transport = transport,
            Port = Number("account.1.sip_server.1.port", 1, 65535),
            ExpirySeconds = Number("account.1.sip_server.1.expires", 30, 86400),
            NtpServers = ntp,
            OutboundProxyEnabled = Flag("account.1.outbound_proxy_enable"),
            OutboundProxyAddress = Find("account.1.outbound_proxy.1.address"),
            OutboundProxyPort = Number("account.1.outbound_proxy.1.port", 1, 65535),
            AccountEnabled = Flag("account.1.enable"),
            StaticDnsEnabled = Flag("static.network.static_dns_enable"),
            PrimaryDns = Find("static.network.primary_dns"),
            SecondaryDns = Find("static.network.secondary_dns"),
            StaticIpEnabled = staticIp,
            StunEnabled = Flag("account.1.nat.nat_traversal"),
            StunServer = Find("account.1.nat.stun_server"),
            KeepAliveMode = Number("account.1.nat.udp_update_enable", 0, 3),
            KeepAliveSeconds = Number("account.1.nat.udp_update_time", 1, 3600),
            TrustCertificatesOnly = Flag("static.security.trust_certificates"),
            SipListenPort = Number("sip.listen_port", 1, 65535)
        };
    }
}
