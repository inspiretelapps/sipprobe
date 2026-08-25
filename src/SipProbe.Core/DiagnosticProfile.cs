namespace InspireTel.SipProbe.Core;

public enum SipTransport
{
    Udp,
    Tcp,
    Tls
}

public sealed record DiagnosticProfile
{
    public required string Server { get; init; }
    public int Port { get; init; } = 5060;
    public int UdpPort { get; init; } = 5060;
    public int TcpPort { get; init; } = 5060;
    public int TlsPort { get; init; } = 5061;
    public SipTransport Transport { get; init; } = SipTransport.Udp;
    public required string SipUser { get; init; }
    public string AuthenticationName { get; init; } = string.Empty;
    public string Password { get; init; } = string.Empty;
    public int LocalPort { get; init; }
    public int RegistrationExpirySeconds { get; init; } = 600;
    public int TimeoutSeconds { get; init; } = 7;
    public bool ForceTls12 { get; init; } = true;
    public bool IgnoreTlsCertificateErrors { get; init; }
    public bool Authenticate { get; init; } = true;
    public bool KeepRegistered { get; init; }
    public bool UnregisterOnly { get; init; }
    public string UserAgent { get; init; } = "InspireTel-SIP-Probe/1.3";
    public IReadOnlyList<string> NtpServers { get; init; } = Array.Empty<string>();

    public string EffectiveAuthenticationName =>
        string.IsNullOrWhiteSpace(AuthenticationName) ? SipUser.Trim() : AuthenticationName.Trim();

    public DiagnosticProfile Validate()
    {
        if (string.IsNullOrWhiteSpace(Server))
            throw new ArgumentException("PBX server is required.", nameof(Server));
        if (Port is < 1 or > 65535)
            throw new ArgumentOutOfRangeException(nameof(Port), "Port must be between 1 and 65535.");
        ValidatePort(UdpPort, nameof(UdpPort));
        ValidatePort(TcpPort, nameof(TcpPort));
        ValidatePort(TlsPort, nameof(TlsPort));
        if (string.IsNullOrWhiteSpace(SipUser))
            throw new ArgumentException("SIP user / extension is required.", nameof(SipUser));
        if (LocalPort is < 0 or > 65535)
            throw new ArgumentOutOfRangeException(nameof(LocalPort), "Local port must be 0 or between 1 and 65535.");
        if (UnregisterOnly)
        {
            if (RegistrationExpirySeconds is not 0)
                throw new ArgumentOutOfRangeException(nameof(RegistrationExpirySeconds), "Unregister must use expiry 0.");
        }
        else if (RegistrationExpirySeconds is < 30 or > 86400)
            throw new ArgumentOutOfRangeException(nameof(RegistrationExpirySeconds), "Expiry must be between 30 and 86400 seconds.");
        if (TimeoutSeconds is < 2 or > 60)
            throw new ArgumentOutOfRangeException(nameof(TimeoutSeconds), "Timeout must be between 2 and 60 seconds.");
        return this;
    }

    public IReadOnlyList<(SipTransport Transport, int Port)> MatrixTargets()
    {
        var items = new List<(SipTransport Transport, int Port)>
        {
            (SipTransport.Udp, UdpPort),
            (SipTransport.Tcp, TcpPort),
            (SipTransport.Tls, TlsPort)
        };
        var selected = (Transport, Port);
        if (!items.Contains(selected))
            items.Add(selected);
        return items;
    }

    private static void ValidatePort(int port, string name)
    {
        if (port is < 1 or > 65535)
            throw new ArgumentOutOfRangeException(name, "Port must be between 1 and 65535.");
    }
}

public enum DiagnosticLevel
{
    Info,
    Success,
    Warning,
    Error,
    Detail
}

public sealed record DiagnosticLogEntry(DateTimeOffset Timestamp, DiagnosticLevel Level, string Message)
{
    public override string ToString() => $"{Timestamp:HH:mm:ss.fff} [{Level.ToString().ToUpperInvariant(),-7}] {Message}";
}

public interface IHeldSipRegistration : IAsyncDisposable
{
    bool IsAlive { get; }
    Task UnregisterAsync(CancellationToken cancellationToken = default);
    event Action<DiagnosticLogEntry>? EntryAdded;
}

public sealed record DiagnosticResult(
    bool NetworkReachable,
    bool SipResponseReceived,
    bool Registered,
    int? FinalStatusCode,
    string Summary,
    IReadOnlyList<DiagnosticLogEntry> Entries,
    IHeldSipRegistration? Held = null);
