using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace InspireTel.SipProbe.Core;

public sealed record SipCaptureOptions
{
    public int Port { get; init; } = 5060;

    /// <summary>
    /// Answer a REGISTER with 401 so the handset resends with its Authorization
    /// header, then 200 OK. This reveals the credentials the phone actually uses.
    /// </summary>
    public bool Challenge { get; init; } = true;

    public string Realm { get; init; } = "sipprobe";
}

/// <summary>
/// Listens for SIP sent by a handset so you can see what it actually transmits.
/// Point the phone's SIP server or outbound proxy at this machine and watch.
/// </summary>
public sealed class SipCaptureListener : IAsyncDisposable
{
    private static readonly Regex DigestField = new(@"(\w+)\s*=\s*(""([^""]*)""|([^,\s]+))", RegexOptions.Compiled);

    private readonly List<DiagnosticLogEntry> _entries = new();
    private readonly object _entryLock = new();
    private CancellationTokenSource? _cts;
    private UdpClient? _udp;
    private TcpListener? _tcp;
    private Task? _udpLoop;
    private Task? _tcpLoop;
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

    public Task StartAsync(SipCaptureOptions options, CancellationToken cancellationToken = default)
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
        Log(DiagnosticLevel.Detail, options.Challenge
            ? "Challenge mode is on: this will answer 401 then 200 OK, so the phone reveals the authentication name it really uses."
            : "Challenge mode is off: messages are logged but never answered.");
        Log(DiagnosticLevel.Warning,
            "This is a diagnostic listener, not a PBX. Set the handset back to the real PBX when you are done.");

        _udpLoop = Task.Run(() => RunUdpAsync(options, token), token);
        _tcpLoop = Task.Run(() => RunTcpAsync(options, token), token);
        return Task.CompletedTask;
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
            var reply = HandleMessage(text, received.RemoteEndPoint, "UDP", options);
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

                        var reply = HandleMessage(message, remote, "TCP", options);
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

    private string? HandleMessage(string raw, IPEndPoint? remote, string transport, SipCaptureOptions options)
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

        Log(DiagnosticLevel.Success, $"{transport} from {remote}: {startLine}");

        foreach (var name in new[] { "User-Agent", "From", "To", "Contact", "Expires", "Call-ID", "Via" })
        {
            if (headers.TryGetValue(name, out var value))
                Log(DiagnosticLevel.Detail, $"  {name}: {value}");
        }

        if (headers.TryGetValue("User-Agent", out var agent))
            Log(DiagnosticLevel.Info, $"Handset identifies as: {agent}");

        var authHeader = headers.TryGetValue("Authorization", out var auth)
            ? auth
            : headers.TryGetValue("Proxy-Authorization", out var proxyAuth) ? proxyAuth : null;

        if (authHeader is not null)
            LogCredentials(authHeader);

        if (!options.Challenge || !startLine.EndsWith("SIP/2.0", StringComparison.OrdinalIgnoreCase))
            return null;

        if (method is not ("REGISTER" or "OPTIONS" or "SUBSCRIBE"))
            return null;

        if (method == "REGISTER" && authHeader is null)
        {
            Log(DiagnosticLevel.Info, "Answering 401 so the handset resends with credentials.");
            return BuildResponse(401, "Unauthorized", headers, remote, transport, options, challenge: true);
        }

        Log(DiagnosticLevel.Success, $"Answering 200 OK to {method}. The handset's SIP stack and network path to this machine work.");
        return BuildResponse(200, "OK", headers, remote, transport, options, challenge: false);
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

        foreach (var loop in new[] { _udpLoop, _tcpLoop })
        {
            if (loop is null)
                continue;
            try { await loop; }
            catch (OperationCanceledException) { }
            catch (Exception) { /* listener already torn down */ }
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
}
