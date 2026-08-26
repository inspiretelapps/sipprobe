using System.Collections.Concurrent;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace InspireTel.SipProbe.Core;

/// <summary>
/// Where to forward the handset's SIP when relay mode is on. The laptop performs
/// the DNS lookup and the TLS handshake on the handset's behalf, so a working
/// relay proves the fault is in the handset's own path rather than its stack.
/// </summary>
public sealed record SipRelayTarget
{
    public required string Server { get; init; }
    public required int Port { get; init; }
    public required SipTransport Transport { get; init; }
    public bool ForceTls12 { get; init; } = true;
    public bool IgnoreCertificateErrors { get; init; }
}

public sealed record SipCaptureOptions
{
    public int Port { get; init; } = 5060;

    /// <summary>
    /// Answer a REGISTER with 401 so the handset resends with its Authorization
    /// header, then 200 OK. Ignored when <see cref="Relay"/> is set.
    /// </summary>
    public bool Challenge { get; init; } = true;

    public string Realm { get; init; } = "sipprobe";

    /// <summary>
    /// When set, forward the handset's SIP to the real PBX instead of answering locally.
    /// </summary>
    public SipRelayTarget? Relay { get; init; }
}

/// <summary>
/// Listens for SIP sent by a handset so you can see what it actually transmits.
/// Point the phone's SIP server or outbound proxy at this machine and watch.
/// </summary>
public sealed class SipCaptureListener : IAsyncDisposable
{
    private static readonly Regex DigestField = new(@"(\w+)\s*=\s*(""([^""]*)""|([^,\s]+))", RegexOptions.Compiled);
    private static readonly Regex ViaBranch = new(@"branch=(?<branch>[^;,\s]+)", RegexOptions.Compiled);

    private readonly List<DiagnosticLogEntry> _entries = new();
    private readonly object _entryLock = new();
    private readonly ConcurrentDictionary<string, int> _seen = new();
    private readonly ConcurrentDictionary<string, IPEndPoint> _pendingByBranch = new();
    private CancellationTokenSource? _cts;
    private UdpClient? _udp;
    private TcpListener? _tcp;
    private Task? _udpLoop;
    private Task? _tcpLoop;
    private Task? _upstreamLoop;
    private IUpstreamChannel? _upstream;
    private int _messageCount;

    public event Action<DiagnosticLogEntry>? EntryAdded;

    public bool IsRunning => _cts is { IsCancellationRequested: false };

    public int MessageCount => Volatile.Read(ref _messageCount);

    public IReadOnlyList<DiagnosticLogEntry> Entries
    {
        get
        {
            lock (_entryLock)
                return _entries.ToArray();
        }
    }

    public async Task StartAsync(SipCaptureOptions options, CancellationToken cancellationToken = default)
    {
        if (IsRunning)
            throw new InvalidOperationException("The capture listener is already running.");

        _cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        var token = _cts.Token;

        try
        {
            _udp = new UdpClient(AddressFamily.InterNetwork);
            _udp.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
            _udp.Client.Bind(new IPEndPoint(IPAddress.Any, options.Port));

            _tcp = new TcpListener(IPAddress.Any, options.Port);
            _tcp.Server.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
            _tcp.Start();
        }
        catch (SocketException ex)
        {
            Cleanup();
            throw new InvalidOperationException(
                $"Could not listen on port {options.Port}: {ex.SocketErrorCode}. " +
                "Another SIP application may already be using it, or the firewall is blocking it.", ex);
        }

        Log(DiagnosticLevel.Success, $"Listening for SIP on UDP and TCP port {options.Port}.");
        foreach (var address in LocalAddresses())
            Log(DiagnosticLevel.Info, $"Point the handset at {address}:{options.Port} (SIP server, or outbound proxy).");

        if (options.Relay is not null)
        {
            try
            {
                _upstream = await ConnectUpstreamAsync(options.Relay, token);
                Log(DiagnosticLevel.Success,
                    $"Relay is on: forwarding to {options.Relay.Server}:{options.Relay.Port} over {options.Relay.Transport.ToString().ToUpperInvariant()}.");
                Log(DiagnosticLevel.Detail,
                    "This laptop performs the DNS lookup and TLS handshake. If the handset now registers, its credentials and SIP stack are fine and the fault is in its own path.");
                Log(DiagnosticLevel.Warning,
                    "Relay is for diagnosis only. The PBX will see this laptop as the source, so calls are not expected to work through it.");
                _upstreamLoop = Task.Run(() => PumpUpstreamAsync(token), token);
            }
            catch (Exception ex)
            {
                Cleanup();
                throw new InvalidOperationException($"Could not open the relay to the PBX: {ex.Message}", ex);
            }
        }
        else
        {
            Log(DiagnosticLevel.Detail, options.Challenge
                ? "Challenge mode is on: this will answer 401 then 200 OK, so the phone reveals the authentication name it really uses."
                : "Challenge mode is off: messages are logged but never answered.");
        }

        Log(DiagnosticLevel.Warning,
            "This is a diagnostic listener, not a PBX. Set the handset back to the real PBX when you are done.");

        _udpLoop = Task.Run(() => RunUdpAsync(options, token), token);
        _tcpLoop = Task.Run(() => RunTcpAsync(options, token), token);
    }

    private async Task RunUdpAsync(SipCaptureOptions options, CancellationToken token)
    {
        while (!token.IsCancellationRequested)
        {
            UdpReceiveResult received;
            try
            {
                received = await _udp!.ReceiveAsync(token);
            }
            catch (OperationCanceledException)
            {
                return;
            }
            catch (Exception ex) when (ex is SocketException or ObjectDisposedException)
            {
                return;
            }

            var text = Encoding.UTF8.GetString(received.Buffer);
            var reply = await HandleMessageAsync(text, received.RemoteEndPoint, "UDP", options, token);
            if (reply is null)
                continue;

            try
            {
                var bytes = Encoding.UTF8.GetBytes(reply);
                await _udp!.SendAsync(bytes, bytes.Length, received.RemoteEndPoint);
            }
            catch (Exception ex) when (ex is SocketException or ObjectDisposedException)
            {
                Log(DiagnosticLevel.Warning, $"Could not answer {received.RemoteEndPoint}: {ex.Message}");
            }
        }
    }

    private async Task RunTcpAsync(SipCaptureOptions options, CancellationToken token)
    {
        while (!token.IsCancellationRequested)
        {
            TcpClient client;
            try
            {
                client = await _tcp!.AcceptTcpClientAsync(token);
            }
            catch (OperationCanceledException)
            {
                return;
            }
            catch (Exception ex) when (ex is SocketException or ObjectDisposedException or InvalidOperationException)
            {
                return;
            }

            _ = Task.Run(() => ServeTcpAsync(client, options, token), token);
        }
    }

    private async Task ServeTcpAsync(TcpClient client, SipCaptureOptions options, CancellationToken token)
    {
        using (client)
        {
            var remote = client.Client.RemoteEndPoint as IPEndPoint;
            Log(DiagnosticLevel.Info, $"TCP connection from {remote}.");
            try
            {
                using var stream = client.GetStream();
                var buffer = new byte[8192];
                var pending = new StringBuilder();

                while (!token.IsCancellationRequested)
                {
                    var read = await stream.ReadAsync(buffer, token);
                    if (read == 0)
                        break;

                    pending.Append(Encoding.UTF8.GetString(buffer, 0, read));
                    var content = pending.ToString();

                    int boundary;
                    while ((boundary = content.IndexOf("\r\n\r\n", StringComparison.Ordinal)) >= 0)
                    {
                        var message = content[..(boundary + 4)];
                        content = content[(boundary + 4)..];

                        var reply = await HandleMessageAsync(message, remote, "TCP", options, token);
                        if (reply is not null)
                        {
                            var bytes = Encoding.UTF8.GetBytes(reply);
                            await stream.WriteAsync(bytes, token);
                        }
                    }

                    pending.Clear();
                    pending.Append(content);
                }
            }
            catch (OperationCanceledException)
            {
                // shutting down
            }
            catch (Exception ex) when (ex is IOException or SocketException or ObjectDisposedException)
            {
                Log(DiagnosticLevel.Detail, $"TCP connection from {remote} ended: {ex.Message}");
            }
        }
    }

    private async Task<string?> HandleMessageAsync(
        string raw,
        IPEndPoint? remote,
        string transport,
        SipCaptureOptions options,
        CancellationToken token)
    {
        if (string.IsNullOrWhiteSpace(raw))
            return null;

        Interlocked.Increment(ref _messageCount);

        var lines = raw.Split(new[] { "\r\n" }, StringSplitOptions.None);
        var startLine = lines.FirstOrDefault()?.Trim() ?? string.Empty;
        if (startLine.Length == 0)
            return null;

        var headers = ParseHeaders(lines);
        var method = startLine.Split(' ').FirstOrDefault()?.ToUpperInvariant() ?? "?";

        // Collapse retransmissions: the same transaction resent looks identical
        // apart from timing, and a handset that gets no answer will resend for ever.
        var fingerprint = string.Join('|',
            headers.GetValueOrDefault("Call-ID", ""),
            headers.GetValueOrDefault("CSeq", ""),
            BranchOf(headers.GetValueOrDefault("Via", "")) ?? "",
            startLine);
        var repeat = _seen.AddOrUpdate(fingerprint, 1, (_, count) => count + 1);

        if (repeat == 1)
        {
            Log(DiagnosticLevel.Success, $"{transport} from {remote}: {startLine}");
            foreach (var name in new[] { "User-Agent", "From", "To", "Contact", "Expires", "Call-ID", "Via" })
            {
                if (headers.TryGetValue(name, out var value))
                    Log(DiagnosticLevel.Detail, $"  {name}: {value}");
            }

            if (headers.TryGetValue("User-Agent", out var agent))
                Log(DiagnosticLevel.Info, $"Handset identifies as: {agent}");
        }
        else if (repeat == 2 || repeat % 5 == 0)
        {
            Log(DiagnosticLevel.Warning,
                $"{transport} from {remote}: {method} retransmitted (x{repeat}). The handset is not getting an answer it accepts.");
        }

        var authHeader = headers.TryGetValue("Authorization", out var auth)
            ? auth
            : headers.TryGetValue("Proxy-Authorization", out var proxyAuth) ? proxyAuth : null;

        if (authHeader is not null && repeat == 1)
            LogCredentials(authHeader);

        if (!startLine.EndsWith("SIP/2.0", StringComparison.OrdinalIgnoreCase))
            return null;

        if (_upstream is not null)
        {
            await ForwardUpstreamAsync(raw, headers, remote, token);
            return null;
        }

        if (!options.Challenge)
            return null;

        if (method == "REGISTER" && authHeader is null)
        {
            Log(DiagnosticLevel.Info, "Answering 401 so the handset resends with credentials.");
            return BuildResponse(401, "Unauthorized", headers, remote, transport, options, challenge: true);
        }

        if (repeat == 1)
        {
            Log(DiagnosticLevel.Success,
                $"Answering 200 OK to {method}. The handset's SIP stack and network path to this machine work.");
        }

        return BuildResponse(200, "OK", headers, remote, transport, options, challenge: false);
    }

    private async Task ForwardUpstreamAsync(
        string raw,
        IReadOnlyDictionary<string, string> headers,
        IPEndPoint? remote,
        CancellationToken token)
    {
        if (_upstream is null || remote is null)
            return;

        var branch = "z9hG4bK-relay-" + RandomToken(8);
        _pendingByBranch[branch] = remote;

        var via = $"Via: SIP/2.0/{_upstream.TransportName} {_upstream.LocalAddress};branch={branch};rport\r\n";
        var forwarded = InsertAfterStartLine(raw, via);

        try
        {
            await _upstream.SendAsync(forwarded, token);
            Log(DiagnosticLevel.Detail, $"Relayed upstream with branch {branch}.");
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            Log(DiagnosticLevel.Error, $"Relay to the PBX failed: {ex.Message}");
        }
    }

    private async Task PumpUpstreamAsync(CancellationToken token)
    {
        while (!token.IsCancellationRequested && _upstream is not null)
        {
            string? message;
            try
            {
                message = await _upstream.ReceiveAsync(token);
            }
            catch (OperationCanceledException)
            {
                return;
            }
            catch (Exception ex)
            {
                Log(DiagnosticLevel.Error, $"Relay connection to the PBX ended: {ex.Message}");
                return;
            }

            if (message is null)
                return;

            var lines = message.Split(new[] { "\r\n" }, StringSplitOptions.None);
            var startLine = lines.FirstOrDefault()?.Trim() ?? string.Empty;
            var headers = ParseHeaders(lines);
            var branch = BranchOf(headers.GetValueOrDefault("Via", ""));

            Log(DiagnosticLevel.Success, $"PBX answered: {startLine}");

            if (branch is null || !_pendingByBranch.TryRemove(branch, out var phone))
            {
                Log(DiagnosticLevel.Detail, "The PBX response had no matching relay branch; not forwarded to the handset.");
                continue;
            }

            var stripped = RemoveTopVia(message);
            try
            {
                var bytes = Encoding.UTF8.GetBytes(stripped);
                await _udp!.SendAsync(bytes, bytes.Length, phone);
                Log(DiagnosticLevel.Detail, $"Relayed the PBX response back to {phone}.");
            }
            catch (Exception ex) when (ex is SocketException or ObjectDisposedException)
            {
                Log(DiagnosticLevel.Warning, $"Could not return the PBX response to {phone}: {ex.Message}");
            }
        }
    }

    private async Task<IUpstreamChannel> ConnectUpstreamAsync(SipRelayTarget relay, CancellationToken token)
    {
        var addresses = await Dns.GetHostAddressesAsync(relay.Server, token);
        var address = addresses.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork)
                      ?? addresses.FirstOrDefault()
                      ?? throw new InvalidOperationException($"Could not resolve {relay.Server}.");
        Log(DiagnosticLevel.Success, $"Relay resolved {relay.Server} to {address}.");

        if (relay.Transport == SipTransport.Udp)
        {
            var client = new UdpClient(AddressFamily.InterNetwork);
            client.Connect(new IPEndPoint(address, relay.Port));
            return new UdpUpstream(client);
        }

        var tcp = new TcpClient(AddressFamily.InterNetwork);
        await tcp.ConnectAsync(address, relay.Port, token);

        if (relay.Transport == SipTransport.Tcp)
            return new StreamUpstream(tcp, tcp.GetStream(), "TCP");

        var ssl = new SslStream(tcp.GetStream(), false, (_, _, _, errors) =>
            errors == SslPolicyErrors.None || relay.IgnoreCertificateErrors);
        await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
        {
            TargetHost = relay.Server,
            EnabledSslProtocols = relay.ForceTls12 ? SslProtocols.Tls12 : SslProtocols.None,
            CertificateRevocationCheckMode = System.Security.Cryptography.X509Certificates.X509RevocationMode.NoCheck
        }, token);
        Log(DiagnosticLevel.Success, $"Relay TLS handshake succeeded: {ssl.SslProtocol}.");
        return new StreamUpstream(tcp, ssl, "TLS");
    }

    private void LogCredentials(string header)
    {
        var fields = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (Match match in DigestField.Matches(header))
        {
            var key = match.Groups[1].Value;
            var value = match.Groups[3].Success ? match.Groups[3].Value : match.Groups[4].Value;
            fields[key] = value;
        }

        if (fields.TryGetValue("username", out var username))
        {
            Log(DiagnosticLevel.Success,
                $"The handset is authenticating as '{username}'. Compare this with the PBX registration name — a mismatch here is a permanent 401.");
        }

        foreach (var key in new[] { "realm", "algorithm", "qop", "uri" })
        {
            if (fields.TryGetValue(key, out var value))
                Log(DiagnosticLevel.Detail, $"  digest {key}={value}");
        }

        Log(DiagnosticLevel.Detail, "The digest response hash is never logged.");
    }

    private static string InsertAfterStartLine(string message, string headerLine)
    {
        var break1 = message.IndexOf("\r\n", StringComparison.Ordinal);
        return break1 < 0 ? message : message[..(break1 + 2)] + headerLine + message[(break1 + 2)..];
    }

    private static string RemoveTopVia(string message)
    {
        var lines = message.Split(new[] { "\r\n" }, StringSplitOptions.None).ToList();
        for (var i = 1; i < lines.Count; i++)
        {
            if (lines[i].Length == 0)
                break;
            if (lines[i].StartsWith("Via:", StringComparison.OrdinalIgnoreCase) ||
                lines[i].StartsWith("v:", StringComparison.OrdinalIgnoreCase))
            {
                lines.RemoveAt(i);
                break;
            }
        }

        return string.Join("\r\n", lines);
    }

    private static string? BranchOf(string via)
    {
        var match = ViaBranch.Match(via);
        return match.Success ? match.Groups["branch"].Value : null;
    }

    private static string BuildResponse(
        int status,
        string reason,
        IReadOnlyDictionary<string, string> headers,
        IPEndPoint? remote,
        string transport,
        SipCaptureOptions options,
        bool challenge)
    {
        var response = new StringBuilder();
        response.Append($"SIP/2.0 {status} {reason}\r\n");

        if (headers.TryGetValue("Via", out var via))
        {
            var rewritten = via;
            if (remote is not null)
            {
                if (!via.Contains(";received=", StringComparison.OrdinalIgnoreCase))
                    rewritten += $";received={remote.Address}";
                if (!via.Contains(";rport=", StringComparison.OrdinalIgnoreCase))
                    rewritten += $";rport={remote.Port}";
            }
            response.Append($"Via: {rewritten}\r\n");
        }

        if (headers.TryGetValue("From", out var from))
            response.Append($"From: {from}\r\n");
        if (headers.TryGetValue("To", out var to))
        {
            response.Append("To: ").Append(to);
            if (!to.Contains(";tag=", StringComparison.OrdinalIgnoreCase))
                response.Append(";tag=").Append(RandomToken(8));
            response.Append("\r\n");
        }
        if (headers.TryGetValue("Call-ID", out var callId))
            response.Append($"Call-ID: {callId}\r\n");
        if (headers.TryGetValue("CSeq", out var cseq))
            response.Append($"CSeq: {cseq}\r\n");

        if (challenge)
        {
            response.Append(
                $"WWW-Authenticate: Digest realm=\"{options.Realm}\", nonce=\"{RandomToken(16)}\", algorithm=MD5, qop=\"auth\"\r\n");
        }
        else if (headers.TryGetValue("Contact", out var contact))
        {
            response.Append($"Contact: {contact};expires=3600\r\n");
            response.Append("Expires: 3600\r\n");
        }

        response.Append($"Server: InspireTel SIP Probe capture ({transport})\r\n");
        response.Append("Content-Length: 0\r\n\r\n");
        return response.ToString();
    }

    private static Dictionary<string, string> ParseHeaders(IEnumerable<string> lines)
    {
        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var line in lines.Skip(1))
        {
            if (line.Length == 0)
                break;
            var separator = line.IndexOf(':');
            if (separator <= 0)
                continue;
            var name = line[..separator].Trim();
            var value = line[(separator + 1)..].Trim();
            if (!headers.ContainsKey(name))
                headers[name] = value;
        }

        return headers;
    }

    private static IEnumerable<string> LocalAddresses()
    {
        IPAddress[] addresses;
        try
        {
            addresses = Dns.GetHostAddresses(Dns.GetHostName());
        }
        catch (SocketException)
        {
            yield break;
        }

        foreach (var address in addresses)
        {
            if (address.AddressFamily == AddressFamily.InterNetwork && !IPAddress.IsLoopback(address))
                yield return address.ToString();
        }
    }

    private static string RandomToken(int bytes) =>
        Convert.ToHexString(RandomNumberGenerator.GetBytes(bytes)).ToLowerInvariant();

    private void Log(DiagnosticLevel level, string message)
    {
        var entry = new DiagnosticLogEntry(DateTimeOffset.Now, level, message);
        lock (_entryLock)
            _entries.Add(entry);
        EntryAdded?.Invoke(entry);
    }

    public async ValueTask DisposeAsync()
    {
        _cts?.Cancel();

        foreach (var loop in new[] { _udpLoop, _tcpLoop, _upstreamLoop })
        {
            if (loop is null)
                continue;
            try { await loop; }
            catch (OperationCanceledException) { }
            catch (Exception) { /* listener already torn down */ }
        }

        if (_upstream is not null)
        {
            await _upstream.DisposeAsync();
            _upstream = null;
        }

        Cleanup();
        Log(DiagnosticLevel.Info, $"Capture stopped after {MessageCount} SIP message(s).");
    }

    private void Cleanup()
    {
        try { _udp?.Dispose(); } catch { /* already closed */ }
        try { _tcp?.Stop(); } catch { /* already stopped */ }
        _udp = null;
        _tcp = null;
        _cts?.Dispose();
        _cts = null;
    }

    private interface IUpstreamChannel : IAsyncDisposable
    {
        string TransportName { get; }
        string LocalAddress { get; }
        Task SendAsync(string message, CancellationToken token);
        Task<string?> ReceiveAsync(CancellationToken token);
    }

    private sealed class UdpUpstream : IUpstreamChannel
    {
        private readonly UdpClient _client;

        public UdpUpstream(UdpClient client) => _client = client;

        public string TransportName => "UDP";

        public string LocalAddress => _client.Client.LocalEndPoint?.ToString() ?? "0.0.0.0";

        public async Task SendAsync(string message, CancellationToken token)
        {
            var bytes = Encoding.UTF8.GetBytes(message);
            await _client.SendAsync(bytes, token);
        }

        public async Task<string?> ReceiveAsync(CancellationToken token)
        {
            var result = await _client.ReceiveAsync(token);
            return Encoding.UTF8.GetString(result.Buffer);
        }

        public ValueTask DisposeAsync()
        {
            _client.Dispose();
            return ValueTask.CompletedTask;
        }
    }

    private sealed class StreamUpstream : IUpstreamChannel
    {
        private readonly TcpClient _client;
        private readonly Stream _stream;
        private readonly StringBuilder _pending = new();

        public StreamUpstream(TcpClient client, Stream stream, string transportName)
        {
            _client = client;
            _stream = stream;
            TransportName = transportName;
        }

        public string TransportName { get; }

        public string LocalAddress => _client.Client.LocalEndPoint?.ToString() ?? "0.0.0.0";

        public async Task SendAsync(string message, CancellationToken token)
        {
            var bytes = Encoding.UTF8.GetBytes(message);
            await _stream.WriteAsync(bytes, token);
            await _stream.FlushAsync(token);
        }

        public async Task<string?> ReceiveAsync(CancellationToken token)
        {
            var buffer = new byte[8192];
            while (true)
            {
                var content = _pending.ToString();
                var boundary = content.IndexOf("\r\n\r\n", StringComparison.Ordinal);
                if (boundary >= 0)
                {
                    var message = content[..(boundary + 4)];
                    _pending.Clear();
                    _pending.Append(content[(boundary + 4)..]);
                    return message;
                }

                var read = await _stream.ReadAsync(buffer, token);
                if (read == 0)
                    return null;
                _pending.Append(Encoding.UTF8.GetString(buffer, 0, read));
            }
        }

        public async ValueTask DisposeAsync()
        {
            try { await _stream.DisposeAsync(); } catch { /* already closed */ }
            _client.Dispose();
        }
    }
}
