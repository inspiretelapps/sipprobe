using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace InspireTel.SipProbe.Core;

public sealed class SipDiagnosticEngine
{
    private readonly List<DiagnosticLogEntry> _entries = new();
    private readonly object _entryLock = new();

    public event Action<DiagnosticLogEntry>? EntryAdded;

    public IReadOnlyList<DiagnosticLogEntry> Entries
    {
        get
        {
            lock (_entryLock)
                return _entries.ToArray();
        }
    }

    public async Task<DiagnosticResult> RunAsync(DiagnosticProfile suppliedProfile, CancellationToken cancellationToken = default)
    {
        DiagnosticProfile profile;
        try
        {
            profile = suppliedProfile.Validate() with
            {
                Server = NormalizeServer(suppliedProfile.Server),
                SipUser = suppliedProfile.SipUser.Trim(),
                AuthenticationName = suppliedProfile.AuthenticationName.Trim()
            };
        }
        catch (Exception ex)
        {
            Log(DiagnosticLevel.Error, ex.Message);
            return Result(false, false, false, null, "Invalid configuration.");
        }

        Log(DiagnosticLevel.Info,
            $"Starting {profile.Transport.ToString().ToUpperInvariant()} SIP probe to {profile.Server}:{profile.Port}.");
        Log(DiagnosticLevel.Detail,
            $"SIP user={profile.SipUser}; authentication name={profile.EffectiveAuthenticationName}; local port={(profile.LocalPort == 0 ? "automatic" : profile.LocalPort)}; timeout={profile.TimeoutSeconds}s.");
        Log(DiagnosticLevel.Detail, "The password and digest response are never written to the log.");

        IPAddress[] addresses;
        try
        {
            using var dnsTimeout = CreateTimeout(cancellationToken, profile.TimeoutSeconds);
            addresses = await Dns.GetHostAddressesAsync(profile.Server, dnsTimeout.Token);
            if (addresses.Length == 0)
                throw new SocketException((int)SocketError.HostNotFound);

            Log(DiagnosticLevel.Success, "DNS resolved: " + string.Join(", ", addresses.Select(a => a.ToString())));
        }
        catch (Exception ex) when (ex is SocketException or OperationCanceledException)
        {
            Log(DiagnosticLevel.Error, $"DNS resolution failed: {FriendlyException(ex, cancellationToken)}");
            return Result(false, false, false, null, "DNS resolution failed.");
        }

        foreach (var finding in ClockCertificateCheck.AnalyzeNtpServers(profile.NtpServers))
            Log(finding.Level, finding.Message);

        await TryCompareHttpsDateAsync(profile, cancellationToken);

        var orderedAddresses = addresses
            .OrderBy(address => address.AddressFamily == AddressFamily.InterNetwork ? 0 : 1)
            .ToArray();

        Exception? lastConnectionError = null;
        foreach (var address in orderedAddresses)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Log(DiagnosticLevel.Info, $"Trying {address} ({address.AddressFamily})...");

            await using ISipChannel? channel = await TryOpenChannelAsync(profile, address, cancellationToken, ex => lastConnectionError = ex);
            if (channel is null)
                continue;

            var networkReachable = profile.Transport != SipTransport.Udp;
            try
            {
                var callId = $"{Guid.NewGuid():N}@sipprobe";
                var fromTag = Convert.ToHexString(RandomNumberGenerator.GetBytes(8)).ToLowerInvariant();
                var requestUri = $"sip:{profile.Server}";
                var firstRequest = BuildRegister(profile, channel.LocalEndPoint, requestUri, callId, fromTag, 1, null, null);

                Log(DiagnosticLevel.Info, "Sending initial REGISTER without credentials (a 401/407 challenge is expected).");
                await channel.SendAsync(firstRequest.Text, cancellationToken);

                SipResponse firstResponse;
                try
                {
                    firstResponse = await ReceiveFinalResponseAsync(channel, profile.TimeoutSeconds, cancellationToken);
                    networkReachable = true;
                }
                catch (Exception ex) when (ex is SocketException or IOException or OperationCanceledException or FormatException)
                {
                    Log(DiagnosticLevel.Error, $"No usable SIP response: {FriendlyException(ex, cancellationToken)}");
                    var transportHint = profile.Transport == SipTransport.Udp
                        ? "UDP was sent, but no reply returned. A firewall, SIP ALG, routing policy, or wrong port is likely."
                        : "The connection opened, but the PBX did not return a SIP response.";
                    Log(DiagnosticLevel.Warning, transportHint);
                    return Result(networkReachable, false, false, null, "No SIP response received.");
                }

                LogResponse(firstResponse, "Initial response");
                LogAlg(firstRequest, firstResponse, channel.LocalEndPoint);

                if (firstResponse.StatusCode == 200)
                {
                    Log(DiagnosticLevel.Success, "The PBX accepted registration without a digest challenge.");
                    await TryRemoveDiagnosticBindingAsync(
                        channel, profile, requestUri, callId, fromTag, 2, null, cancellationToken);
                    return Result(true, true, true, 200, "Registration test succeeded.");
                }

                if (firstResponse.StatusCode is not (401 or 407))
                {
                    ExplainStatus(firstResponse.StatusCode);
                    return Result(true, true, false, firstResponse.StatusCode,
                        $"PBX replied {firstResponse.StatusCode} {firstResponse.ReasonPhrase}.");
                }

                Log(DiagnosticLevel.Success,
                    "The SIP challenge proves that DNS, the selected transport, the destination port, and return traffic are working.");

                var challengeHeaderName = firstResponse.StatusCode == 407 ? "Proxy-Authenticate" : "WWW-Authenticate";
                var challengeValue = firstResponse.GetHeader(challengeHeaderName);
                if (string.IsNullOrWhiteSpace(challengeValue))
                {
                    Log(DiagnosticLevel.Error, $"The {firstResponse.StatusCode} response did not contain {challengeHeaderName}.");
                    return Result(true, true, false, firstResponse.StatusCode, "Authentication challenge was malformed.");
                }

                DigestChallenge challenge;
                try
                {
                    challenge = DigestChallenge.Parse(challengeValue, firstResponse.StatusCode == 407);
                    Log(DiagnosticLevel.Detail,
                        $"Digest realm={challenge.Realm}; algorithm={challenge.Algorithm}; qop={challenge.Qop ?? "not supplied"}.");
                }
                catch (Exception ex) when (ex is FormatException or NotSupportedException)
                {
                    Log(DiagnosticLevel.Error, ex.Message);
                    return Result(true, true, false, firstResponse.StatusCode, "Unsupported authentication challenge.");
                }

                if (!profile.Authenticate)
                {
                    Log(DiagnosticLevel.Success, "Reachability-only probe completed; authentication was intentionally skipped.");
                    return Result(true, true, false, firstResponse.StatusCode, "PBX reachable; authentication not attempted.");
                }

                if (string.IsNullOrEmpty(profile.Password))
                {
                    Log(DiagnosticLevel.Warning, "The PBX is reachable, but no password was supplied, so authenticated registration was skipped.");
                    return Result(true, true, false, firstResponse.StatusCode, "PBX reachable; password not supplied.");
                }

                var authorization = challenge.CreateAuthorization(
                    profile.EffectiveAuthenticationName,
                    profile.Password,
                    "REGISTER",
                    requestUri);
                var authorizationName = challenge.IsProxy ? "Proxy-Authorization" : "Authorization";
                var secondRequest = BuildRegister(
                    profile,
                    channel.LocalEndPoint,
                    requestUri,
                    callId,
                    fromTag,
                    2,
                    authorizationName,
                    authorization);

                Log(DiagnosticLevel.Info, "Sending authenticated REGISTER (digest value redacted).");
                await channel.SendAsync(secondRequest.Text, cancellationToken);
                var finalResponse = await ReceiveFinalResponseAsync(channel, profile.TimeoutSeconds, cancellationToken);
                LogResponse(finalResponse, "Authenticated response");

                if (finalResponse.StatusCode == 200)
                {
                    Log(DiagnosticLevel.Success,
                        "REGISTER succeeded. The PBX, credentials, network path, and selected transport all work from this laptop.");
                    await TryRemoveDiagnosticBindingAsync(
                        channel, profile, requestUri, callId, fromTag, 3, challenge, cancellationToken);
                    return Result(true, true, true, 200, "Registration test succeeded.");
                }

                ExplainStatus(finalResponse.StatusCode);
                return Result(true, true, false, finalResponse.StatusCode,
                    $"Registration rejected: {finalResponse.StatusCode} {finalResponse.ReasonPhrase}.");
            }
            catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
            {
                Log(DiagnosticLevel.Error, $"Operation timed out after {profile.TimeoutSeconds} seconds.");
                return Result(networkReachable, false, false, null, "Operation timed out.");
            }
            catch (AuthenticationException ex)
            {
                Log(DiagnosticLevel.Error, $"TLS authentication failed: {ex.Message}");
                return Result(false, false, false, null, "TLS handshake failed.");
            }
            catch (Exception ex) when (ex is SocketException or IOException or FormatException or NotSupportedException)
            {
                Log(DiagnosticLevel.Error, $"Probe failed: {ex.Message}");
                return Result(networkReachable, false, false, null, "Probe failed.");
            }
        }

        Log(DiagnosticLevel.Error,
            "Could not open the selected transport to any resolved address: " + (lastConnectionError?.Message ?? "unknown error"));
        return Result(false, false, false, null, "Connection failed.");
    }

    private async Task<ISipChannel?> TryOpenChannelAsync(
        DiagnosticProfile profile,
        IPAddress address,
        CancellationToken cancellationToken,
        Action<Exception> recordError)
    {
        try
        {
            using var timeout = CreateTimeout(cancellationToken, profile.TimeoutSeconds);
            ISipChannel channel = profile.Transport switch
            {
                SipTransport.Udp => await UdpSipChannel.OpenAsync(address, profile.Port, profile.LocalPort, timeout.Token),
                SipTransport.Tcp => await StreamSipChannel.OpenTcpAsync(address, profile.Port, profile.LocalPort, timeout.Token),
                SipTransport.Tls => await StreamSipChannel.OpenTlsAsync(
                    address,
                    profile.Port,
                    profile.LocalPort,
                    profile.Server,
                    profile.ForceTls12,
                    profile.IgnoreTlsCertificateErrors,
                    Log,
                    timeout.Token),
                _ => throw new ArgumentOutOfRangeException()
            };

            Log(DiagnosticLevel.Success,
                $"{profile.Transport.ToString().ToUpperInvariant()} channel opened from {channel.LocalEndPoint} to {address}:{profile.Port}.");
            return channel;
        }
        catch (Exception ex) when (ex is SocketException or IOException or AuthenticationException or OperationCanceledException)
        {
            recordError(ex);
            Log(DiagnosticLevel.Warning,
                $"Connection to {address}:{profile.Port} failed: {FriendlyException(ex, cancellationToken)}");
            return null;
        }
    }

    private static SipRegisterMessage BuildRegister(
        DiagnosticProfile profile,
        IPEndPoint local,
        string requestUri,
        string callId,
        string fromTag,
        int cseq,
        string? authorizationHeaderName,
        string? authorizationValue)
    {
        var transportToken = profile.Transport.ToString().ToUpperInvariant();
        var transportParameter = profile.Transport.ToString().ToLowerInvariant();
        var localHost = FormatHost(local.Address);
        var branch = "z9hG4bK-" + Convert.ToHexString(RandomNumberGenerator.GetBytes(10)).ToLowerInvariant();
        var serverHost = FormatHostForUri(profile.Server);
        var user = profile.SipUser;
        var viaValue = $"SIP/2.0/{transportToken} {localHost}:{local.Port};branch={branch};rport";
        var contactUri = $"sip:{user}@{localHost}:{local.Port};transport={transportParameter}";
        var builder = new StringBuilder();

        builder.Append("REGISTER ").Append(requestUri).Append(" SIP/2.0\r\n");
        builder.Append("Via: ").Append(viaValue).Append("\r\n");
        builder.Append("Max-Forwards: 70\r\n");
        builder.Append("From: <sip:").Append(user).Append('@').Append(serverHost).Append(">;tag=").Append(fromTag).Append("\r\n");
        builder.Append("To: <sip:").Append(user).Append('@').Append(serverHost).Append(">\r\n");
        builder.Append("Call-ID: ").Append(callId).Append("\r\n");
        builder.Append("CSeq: ").Append(cseq).Append(" REGISTER\r\n");
        builder.Append("Contact: <").Append(contactUri).Append(">\r\n");
        builder.Append("Expires: ").Append(profile.RegistrationExpirySeconds).Append("\r\n");
        builder.Append("Supported: path, outbound\r\n");
        builder.Append("User-Agent: ").Append(profile.UserAgent).Append("\r\n");
        if (!string.IsNullOrEmpty(authorizationHeaderName) && !string.IsNullOrEmpty(authorizationValue))
            builder.Append(authorizationHeaderName).Append(": ").Append(authorizationValue).Append("\r\n");
        builder.Append("Content-Length: 0\r\n\r\n");
        return new SipRegisterMessage(builder.ToString(), viaValue, contactUri, branch, localHost, local.Port);
    }

    private static async Task<SipResponse> ReceiveFinalResponseAsync(
        ISipChannel channel,
        int timeoutSeconds,
        CancellationToken cancellationToken)
    {
        for (var attempt = 0; attempt < 4; attempt++)
        {
            using var timeout = CreateTimeout(cancellationToken, timeoutSeconds);
            var raw = await channel.ReceiveAsync(timeout.Token);
            var response = SipResponse.Parse(raw);
            if (response.StatusCode >= 200)
                return response;
        }
        throw new FormatException("Only provisional SIP responses were received.");
    }

    private async Task TryRemoveDiagnosticBindingAsync(
        ISipChannel channel,
        DiagnosticProfile profile,
        string requestUri,
        string callId,
        string fromTag,
        int cseq,
        DigestChallenge? challenge,
        CancellationToken cancellationToken)
    {
        try
        {
            string? headerName = null;
            string? headerValue = null;
            if (challenge is not null)
            {
                headerName = challenge.IsProxy ? "Proxy-Authorization" : "Authorization";
                headerValue = challenge.CreateAuthorization(
                    profile.EffectiveAuthenticationName,
                    profile.Password,
                    "REGISTER",
                    requestUri,
                    "00000002");
            }

            var unregisterProfile = profile with { RegistrationExpirySeconds = 0 };
            var unregister = BuildRegister(
                unregisterProfile,
                channel.LocalEndPoint,
                requestUri,
                callId,
                fromTag,
                cseq,
                headerName,
                headerValue);
            Log(DiagnosticLevel.Info, "Removing the temporary diagnostic registration binding (Expires: 0).");
            await channel.SendAsync(unregister.Text, cancellationToken);
            var response = await ReceiveFinalResponseAsync(channel, profile.TimeoutSeconds, cancellationToken);
            if (response.StatusCode == 200)
                Log(DiagnosticLevel.Success, "Temporary diagnostic registration removed successfully.");
            else
                Log(DiagnosticLevel.Warning,
                    $"The registration test succeeded, but cleanup returned SIP {response.StatusCode} {response.ReasonPhrase}. The binding will expire automatically.");
        }
        catch (Exception ex) when (ex is SocketException or IOException or OperationCanceledException or FormatException)
        {
            Log(DiagnosticLevel.Warning,
                $"The registration test succeeded, but automatic cleanup failed: {FriendlyException(ex, cancellationToken)}. The binding will expire automatically.");
        }
    }

    private void LogResponse(SipResponse response, string label)
    {
        Log(response.StatusCode is >= 200 and < 300 ? DiagnosticLevel.Success : DiagnosticLevel.Info,
            $"{label}: SIP {response.StatusCode} {response.ReasonPhrase}.");
        foreach (var header in new[] { "Server", "User-Agent", "Warning", "Retry-After" })
        {
            var value = response.GetHeader(header);
            if (!string.IsNullOrWhiteSpace(value))
                Log(DiagnosticLevel.Detail, $"{header}: {value}");
        }
    }

    private void ExplainStatus(int code)
    {
        var explanation = code switch
        {
            401 => "Authentication was challenged again. Check the registration name/authentication name and password.",
            403 => "The PBX forbade registration. Check transport permission, registration security, blocked IPs, and credentials.",
            404 => "The PBX could not find the SIP identity. Check the extension/user and registration name.",
            408 => "The PBX reported a request timeout.",
            423 => "The expiry is below the PBX minimum. Use the Min-Expires value returned by the PBX.",
            429 => "Too many attempts were made. Stop testing and check whether the public IP was rate-limited.",
            500 => "The PBX encountered an internal error.",
            503 => "The SIP service is temporarily unavailable.",
            _ => "The PBX returned a SIP rejection; inspect the response and PBX logs for the exact policy reason."
        };
        Log(DiagnosticLevel.Warning, explanation);
    }

    private DiagnosticResult Result(
        bool networkReachable,
        bool sipResponseReceived,
        bool registered,
        int? finalStatusCode,
        string summary) =>
        new(networkReachable, sipResponseReceived, registered, finalStatusCode, summary, Entries);

    private void Log(DiagnosticLevel level, string message)
    {
        var entry = new DiagnosticLogEntry(DateTimeOffset.Now, level, message);
        lock (_entryLock)
            _entries.Add(entry);
        EntryAdded?.Invoke(entry);
    }

    private static CancellationTokenSource CreateTimeout(CancellationToken parent, int seconds)
    {
        var timeout = CancellationTokenSource.CreateLinkedTokenSource(parent);
        timeout.CancelAfter(TimeSpan.FromSeconds(seconds));
        return timeout;
    }

    private static string FriendlyException(Exception ex, CancellationToken parent) => ex switch
    {
        OperationCanceledException when !parent.IsCancellationRequested => "timed out",
        SocketException socket => $"{socket.SocketErrorCode} ({socket.Message})",
        _ => ex.Message
    };

    private static string NormalizeServer(string server)
    {
        var value = server.Trim();
        if (value.StartsWith("sip:", StringComparison.OrdinalIgnoreCase))
            value = value[4..];
        if (value.StartsWith("sips:", StringComparison.OrdinalIgnoreCase))
            value = value[5..];
        if (value.Contains('/') || value.Contains('@'))
            throw new ArgumentException("Enter only the PBX hostname or IP address, without a URL path or user name.");

        if (value.StartsWith('[') && value.EndsWith(']'))
            value = value[1..^1];
        return value.TrimEnd('.');
    }

    private void LogAlg(SipRegisterMessage sent, SipResponse response, IPEndPoint local)
    {
        var analysis = SipAlgDetector.Analyze(sent, response, local);
        foreach (var finding in analysis.Findings)
            Log(finding.Level, finding.Message);
    }

    private async Task TryCompareHttpsDateAsync(DiagnosticProfile profile, CancellationToken cancellationToken)
    {
        if (IPAddress.TryParse(profile.Server, out _))
            return;

        try
        {
            using var timeout = CreateTimeout(cancellationToken, Math.Min(profile.TimeoutSeconds, 5));
            using var handler = new HttpClientHandler
            {
                ServerCertificateCustomValidationCallback = (_, _, _, _) => true
            };
            using var http = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(5) };
            using var request = new HttpRequestMessage(HttpMethod.Head, $"https://{profile.Server}/");
            using var response = await http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, timeout.Token);
            if (response.Headers.Date is DateTimeOffset httpDate)
            {
                var finding = ClockCertificateCheck.AnalyzeHttpDate(httpDate, DateTimeOffset.Now);
                if (finding is not null)
                    Log(finding.Value.Level, finding.Value.Message);
            }
            else
            {
                Log(DiagnosticLevel.Detail, "PBX HTTPS response had no Date header, so clock skew versus the PBX could not be measured.");
            }
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or OperationCanceledException or UriFormatException)
        {
            if (cancellationToken.IsCancellationRequested)
                throw;
            Log(DiagnosticLevel.Detail, $"Could not read PBX HTTPS Date for clock comparison: {FriendlyException(ex, cancellationToken)}.");
        }
    }

    private static string FormatHost(IPAddress address) =>
        address.AddressFamily == AddressFamily.InterNetworkV6 ? $"[{address}]" : address.ToString();

    private static string FormatHostForUri(string host) =>
        IPAddress.TryParse(host, out var address) ? FormatHost(address) : host;

    private interface ISipChannel : IAsyncDisposable
    {
        IPEndPoint LocalEndPoint { get; }
        Task SendAsync(string message, CancellationToken cancellationToken);
        Task<string> ReceiveAsync(CancellationToken cancellationToken);
    }

    private sealed class UdpSipChannel : ISipChannel
    {
        private readonly Socket _socket;

        private UdpSipChannel(Socket socket) => _socket = socket;

        public IPEndPoint LocalEndPoint => (IPEndPoint)_socket.LocalEndPoint!;

        public static async Task<UdpSipChannel> OpenAsync(
            IPAddress address,
            int port,
            int localPort,
            CancellationToken cancellationToken)
        {
            var socket = new Socket(address.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
            try
            {
                var any = address.AddressFamily == AddressFamily.InterNetworkV6 ? IPAddress.IPv6Any : IPAddress.Any;
                socket.Bind(new IPEndPoint(any, localPort));
                await socket.ConnectAsync(new IPEndPoint(address, port), cancellationToken);
                return new UdpSipChannel(socket);
            }
            catch
            {
                socket.Dispose();
                throw;
            }
        }

        public async Task SendAsync(string message, CancellationToken cancellationToken)
        {
            var bytes = Encoding.UTF8.GetBytes(message);
            await _socket.SendAsync(bytes, SocketFlags.None, cancellationToken);
        }

        public async Task<string> ReceiveAsync(CancellationToken cancellationToken)
        {
            var buffer = new byte[65535];
            var count = await _socket.ReceiveAsync(buffer, SocketFlags.None, cancellationToken);
            return Encoding.UTF8.GetString(buffer, 0, count);
        }

        public ValueTask DisposeAsync()
        {
            _socket.Dispose();
            return ValueTask.CompletedTask;
        }
    }

    private sealed class StreamSipChannel : ISipChannel
    {
        private readonly TcpClient _client;
        private readonly Stream _stream;

        private StreamSipChannel(TcpClient client, Stream stream)
        {
            _client = client;
            _stream = stream;
        }

        public IPEndPoint LocalEndPoint => (IPEndPoint)_client.Client.LocalEndPoint!;

        public static async Task<StreamSipChannel> OpenTcpAsync(
            IPAddress address,
            int port,
            int localPort,
            CancellationToken cancellationToken)
        {
            var client = CreateClient(address, localPort);
            try
            {
                await client.ConnectAsync(address, port, cancellationToken);
                return new StreamSipChannel(client, client.GetStream());
            }
            catch
            {
                client.Dispose();
                throw;
            }
        }

        public static async Task<StreamSipChannel> OpenTlsAsync(
            IPAddress address,
            int port,
            int localPort,
            string targetHost,
            bool forceTls12,
            bool ignoreCertificateErrors,
            Action<DiagnosticLevel, string> log,
            CancellationToken cancellationToken)
        {
            var client = CreateClient(address, localPort);
            try
            {
                await client.ConnectAsync(address, port, cancellationToken);
                SslPolicyErrors observedErrors = SslPolicyErrors.None;
                X509Certificate2? observedCertificate = null;
                var ssl = new SslStream(client.GetStream(), false, (_, certificate, _, errors) =>
                {
                    observedErrors = errors;
                    observedCertificate = certificate is null ? null : new X509Certificate2(certificate);
                    return errors == SslPolicyErrors.None || ignoreCertificateErrors;
                });

                var options = new SslClientAuthenticationOptions
                {
                    TargetHost = targetHost,
                    EnabledSslProtocols = forceTls12 ? SslProtocols.Tls12 : SslProtocols.None,
                    CertificateRevocationCheckMode = X509RevocationMode.NoCheck
                };
                try
                {
                    await ssl.AuthenticateAsClientAsync(options, cancellationToken);
                }
                catch
                {
                    LogCertificateClock(observedCertificate, log);
                    throw;
                }

                log(DiagnosticLevel.Success,
                    $"TLS handshake succeeded: protocol={ssl.SslProtocol}; cipher={ssl.NegotiatedCipherSuite}.");
                LogCertificateClock(observedCertificate, log);
                if (observedErrors == SslPolicyErrors.None)
                    log(DiagnosticLevel.Success, "TLS certificate hostname and trust validation passed.");
                else if (ignoreCertificateErrors)
                    log(DiagnosticLevel.Warning,
                        $"TLS certificate validation reported {observedErrors}; ignored for this diagnostic run only.");

                return new StreamSipChannel(client, ssl);
            }
            catch
            {
                client.Dispose();
                throw;
            }
        }

        private static void LogCertificateClock(X509Certificate2? certificate, Action<DiagnosticLevel, string> log)
        {
            if (certificate is null)
                return;
            foreach (var finding in ClockCertificateCheck.AnalyzeCertificate(certificate, DateTimeOffset.Now))
                log(finding.Level, finding.Message);
        }

        private static TcpClient CreateClient(IPAddress address, int localPort)
        {
            var client = new TcpClient(address.AddressFamily);
            if (localPort > 0)
            {
                var any = address.AddressFamily == AddressFamily.InterNetworkV6 ? IPAddress.IPv6Any : IPAddress.Any;
                client.Client.Bind(new IPEndPoint(any, localPort));
            }
            return client;
        }

        public async Task SendAsync(string message, CancellationToken cancellationToken)
        {
            var bytes = Encoding.UTF8.GetBytes(message);
            await _stream.WriteAsync(bytes, cancellationToken);
            await _stream.FlushAsync(cancellationToken);
        }

        public async Task<string> ReceiveAsync(CancellationToken cancellationToken)
        {
            var buffer = new byte[4096];
            using var output = new MemoryStream();
            int requiredLength = -1;

            while (requiredLength < 0 || output.Length < requiredLength)
            {
                var count = await _stream.ReadAsync(buffer, cancellationToken);
                if (count == 0)
                    throw new IOException("The remote side closed the connection before a complete SIP response arrived.");
                output.Write(buffer, 0, count);

                if (requiredLength < 0)
                {
                    var current = Encoding.UTF8.GetString(output.GetBuffer(), 0, (int)output.Length);
                    var headerEnd = current.IndexOf("\r\n\r\n", StringComparison.Ordinal);
                    if (headerEnd >= 0)
                    {
                        var contentLength = 0;
                        foreach (var line in current[..headerEnd].Split(new[] { "\r\n" }, StringSplitOptions.None))
                        {
                            if (line.StartsWith("Content-Length:", StringComparison.OrdinalIgnoreCase) &&
                                int.TryParse(line[(line.IndexOf(':') + 1)..].Trim(), out var parsed))
                            {
                                contentLength = parsed;
                                break;
                            }
                        }
                        requiredLength = headerEnd + 4 + contentLength;
                    }
                }
            }

            return Encoding.UTF8.GetString(output.GetBuffer(), 0, requiredLength);
        }

        public async ValueTask DisposeAsync()
        {
            await _stream.DisposeAsync();
            _client.Dispose();
        }
    }
}
