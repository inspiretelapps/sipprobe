using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using InspireTel.SipProbe.Core;

var tests = new List<(string Name, Func<Task> Run)>
{
    ("SIP response parser", TestSipResponseParser),
    ("RFC digest calculation", TestDigestCalculation),
    ("UDP REGISTER exchange", () => TestRegisterExchange(SipTransport.Udp)),
    ("TCP REGISTER exchange", () => TestRegisterExchange(SipTransport.Tcp)),
    ("TLS REGISTER exchange", () => TestRegisterExchange(SipTransport.Tls)),
    ("Transport matrix uses configured ports", TestMatrixPorts),
    ("SIP ALG Via rewrite detection", TestAlgDetection),
    ("Clock versus certificate and private NTP", TestClockAndNtp),
    ("Yealink config NTP and ports", TestYealinkParser),
    ("Yealink config blocking-problem audit", TestYealinkAudit),
    ("SIP capture challenges and reveals auth name", TestSipCapture),
    ("SIP capture answers keepalives and collapses retransmissions", TestSipCaptureAnswersKeepalives),
    ("Yeastar PBX API extension and blocked IP", TestYeastarPbxDiagnostic),
    ("Diagnosis: UDP silent TLS 401 is the router", TestDiagnosisRouterUdpBlocked),
    ("Diagnosis: Via rewrite is SIP ALG", TestDiagnosisSipAlg),
    ("Diagnosis: all transports fail is not ALG", TestDiagnosisPathBlocked),
    ("Diagnosis: TLS handshake with TCP/UDP working", TestDiagnosisTlsHandshake),
    ("Diagnosis: registered on TLS still warns about UDP", TestDiagnosisRegisteredOnTls),
    ("Diagnosis: empty outbound proxy stays first", TestDiagnosisPhoneConfigFirst)
};

var failed = 0;
foreach (var test in tests)
{
    try
    {
        await test.Run();
        Console.WriteLine($"PASS  {test.Name}");
    }
    catch (Exception ex)
    {
        failed++;
        Console.WriteLine($"FAIL  {test.Name}: {ex.Message}");
    }
}

Console.WriteLine($"\n{tests.Count - failed}/{tests.Count} tests passed.");
return failed == 0 ? 0 : 1;

static Task TestSipResponseParser()
{
    const string raw = "SIP/2.0 401 Unauthorized\r\n" +
                       "Via: SIP/2.0/UDP 10.0.0.2:5060;rport=49152\r\n" +
                       "WWW-Authenticate: Digest realm=\"pbx\",\r\n" +
                       " nonce=\"abc\", algorithm=MD5, qop=\"auth\"\r\n" +
                       "Content-Length: 0\r\n\r\n";
    var response = SipResponse.Parse(raw);
    Assert(response.StatusCode == 401, "status code");
    Assert(response.ReasonPhrase == "Unauthorized", "reason phrase");
    Assert(response.GetHeader("www-authenticate")!.Contains("nonce=\"abc\""), "folded header");
    Assert(response.GetHeader("Via")!.Contains("rport=49152"), "case-insensitive header lookup");
    return Task.CompletedTask;
}

static Task TestDigestCalculation()
{
    var challenge = DigestChallenge.Parse(
        "Digest realm=\"testrealm@host.com\", qop=\"auth,auth-int\", algorithm=MD5, " +
        "nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", opaque=\"5ccc069c403ebaf9f0171e9517f40e41\"",
        false);
    var authorization = challenge.CreateAuthorization(
        "Mufasa",
        "Circle Of Life",
        "GET",
        "/dir/index.html",
        "00000001",
        "0a4f113b");
    Assert(authorization.Contains("response=\"6629fae49393a05397450978507c4ef1\""), "RFC 2617 response hash");
    Assert(authorization.Contains("qop=auth"), "qop selection");
    return Task.CompletedTask;
}

static async Task TestRegisterExchange(SipTransport transport)
{
    using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(8));
    var server = transport switch
    {
        SipTransport.Udp => StartUdpServer(timeout.Token),
        SipTransport.Tcp => StartTcpServer(timeout.Token),
        SipTransport.Tls => StartTlsServer(timeout.Token),
        _ => throw new ArgumentOutOfRangeException(nameof(transport))
    };
    var port = await server.Port;

    var engine = new SipDiagnosticEngine();
    var result = await engine.RunAsync(new DiagnosticProfile
    {
        Server = "127.0.0.1",
        Port = port,
        Transport = transport,
        SipUser = "101",
        AuthenticationName = "auth101",
        Password = "Secret123!",
        TimeoutSeconds = 3,
        RegistrationExpirySeconds = 600,
        ForceTls12 = true,
        IgnoreTlsCertificateErrors = transport == SipTransport.Tls,
        Authenticate = true
    }, timeout.Token);

    await server.Completion;
    Assert(result.Registered, $"{transport} engine registration result: {result.Summary}");
    Assert(result.FinalStatusCode == 200, $"{transport} final status");
    Assert(result.Stage == FailureStage.Success, $"{transport} success stage");
    Assert(result.Transport == transport, $"{transport} recorded on result");
    Assert(result.Entries.All(entry => !entry.Message.Contains("Secret123!")), "password redaction");
}

static (Task<int> Port, Task Completion) StartUdpServer(CancellationToken token)
{
    var ready = new TaskCompletionSource<int>(TaskCreationOptions.RunContinuationsAsynchronously);
    var completion = Task.Run(async () =>
    {
        using var udp = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        ready.SetResult(((IPEndPoint)udp.Client.LocalEndPoint!).Port);

        var first = await udp.ReceiveAsync(token);
        var firstText = Encoding.UTF8.GetString(first.Buffer);
        Assert(firstText.StartsWith("REGISTER "), "initial UDP REGISTER");
        await udp.SendAsync(Encoding.UTF8.GetBytes(Build401(firstText)), first.RemoteEndPoint, token);

        var second = await udp.ReceiveAsync(token);
        var secondText = Encoding.UTF8.GetString(second.Buffer);
        Assert(secondText.Contains("Authorization: Digest "), "authenticated UDP REGISTER");
        await udp.SendAsync(Encoding.UTF8.GetBytes(Build200(secondText)), second.RemoteEndPoint, token);

        var third = await udp.ReceiveAsync(token);
        var thirdText = Encoding.UTF8.GetString(third.Buffer);
        Assert(thirdText.Contains("Expires: 0"), "UDP diagnostic unregister");
        await udp.SendAsync(Encoding.UTF8.GetBytes(Build200(thirdText)), third.RemoteEndPoint, token);
    }, token);
    return (ready.Task, completion);
}

static (Task<int> Port, Task Completion) StartTcpServer(CancellationToken token)
{
    var ready = new TaskCompletionSource<int>(TaskCreationOptions.RunContinuationsAsynchronously);
    var completion = Task.Run(async () =>
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        ready.SetResult(((IPEndPoint)listener.LocalEndpoint).Port);
        try
        {
            using var client = await listener.AcceptTcpClientAsync(token);
            await using var stream = client.GetStream();
            var firstText = await ReadSipRequest(stream, token);
            Assert(firstText.StartsWith("REGISTER "), "initial TCP REGISTER");
            await stream.WriteAsync(Encoding.UTF8.GetBytes(Build401(firstText)), token);
            var secondText = await ReadSipRequest(stream, token);
            Assert(secondText.Contains("Authorization: Digest "), "authenticated TCP REGISTER");
            await stream.WriteAsync(Encoding.UTF8.GetBytes(Build200(secondText)), token);
            var thirdText = await ReadSipRequest(stream, token);
            Assert(thirdText.Contains("Expires: 0"), "TCP diagnostic unregister");
            await stream.WriteAsync(Encoding.UTF8.GetBytes(Build200(thirdText)), token);
        }
        finally
        {
            listener.Stop();
        }
    }, token);
    return (ready.Task, completion);
}

static (Task<int> Port, Task Completion) StartTlsServer(CancellationToken token)
{
    var ready = new TaskCompletionSource<int>(TaskCreationOptions.RunContinuationsAsynchronously);
    var completion = Task.Run(async () =>
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest("CN=localhost", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var san = new SubjectAlternativeNameBuilder();
        san.AddDnsName("localhost");
        san.AddIpAddress(IPAddress.Loopback);
        request.CertificateExtensions.Add(san.Build());
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
        using var certificate = request.CreateSelfSigned(DateTimeOffset.Now.AddMinutes(-5), DateTimeOffset.Now.AddDays(1));

        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        ready.SetResult(((IPEndPoint)listener.LocalEndpoint).Port);
        try
        {
            using var client = await listener.AcceptTcpClientAsync(token);
            await using var ssl = new SslStream(client.GetStream(), false);
            await ssl.AuthenticateAsServerAsync(new SslServerAuthenticationOptions
            {
                ServerCertificate = certificate,
                ClientCertificateRequired = false,
                EnabledSslProtocols = SslProtocols.Tls12,
                CertificateRevocationCheckMode = X509RevocationMode.NoCheck
            }, token);
            var firstText = await ReadSipRequest(ssl, token);
            Assert(firstText.StartsWith("REGISTER "), "initial TLS REGISTER");
            await ssl.WriteAsync(Encoding.UTF8.GetBytes(Build401(firstText)), token);
            var secondText = await ReadSipRequest(ssl, token);
            Assert(secondText.Contains("Authorization: Digest "), "authenticated TLS REGISTER");
            await ssl.WriteAsync(Encoding.UTF8.GetBytes(Build200(secondText)), token);
            var thirdText = await ReadSipRequest(ssl, token);
            Assert(thirdText.Contains("Expires: 0"), "TLS diagnostic unregister");
            await ssl.WriteAsync(Encoding.UTF8.GetBytes(Build200(thirdText)), token);
        }
        finally
        {
            listener.Stop();
        }
    }, token);
    return (ready.Task, completion);
}

static async Task<string> ReadSipRequest(Stream stream, CancellationToken token)
{
    var buffer = new byte[4096];
    using var output = new MemoryStream();
    while (true)
    {
        var count = await stream.ReadAsync(buffer, token);
        if (count == 0)
            throw new IOException("Client closed the mock connection.");
        output.Write(buffer, 0, count);
        var text = Encoding.UTF8.GetString(output.ToArray());
        if (text.Contains("\r\n\r\n", StringComparison.Ordinal))
            return text;
    }
}

static string Build401(string request)
{
    var headers = ReadRequestHeaders(request);
    return "SIP/2.0 401 Unauthorized\r\n" +
           $"Via: {headers["Via"]}\r\n" +
           $"From: {headers["From"]}\r\n" +
           $"To: {headers["To"]};tag=mock\r\n" +
           $"Call-ID: {headers["Call-ID"]}\r\n" +
           $"CSeq: {headers["CSeq"]}\r\n" +
           "WWW-Authenticate: Digest realm=\"mockpbx\", nonce=\"abcdef123456\", algorithm=MD5, qop=\"auth\"\r\n" +
           "Content-Length: 0\r\n\r\n";
}

static string Build200(string request)
{
    var headers = ReadRequestHeaders(request);
    return "SIP/2.0 200 OK\r\n" +
           $"Via: {headers["Via"]}\r\n" +
           $"From: {headers["From"]}\r\n" +
           $"To: {headers["To"]};tag=mock\r\n" +
           $"Call-ID: {headers["Call-ID"]}\r\n" +
           $"CSeq: {headers["CSeq"]}\r\n" +
           "Contact: <sip:101@127.0.0.1>;expires=600\r\n" +
           "Content-Length: 0\r\n\r\n";
}

static Dictionary<string, string> ReadRequestHeaders(string request) => request
    .Split(new[] { "\r\n" }, StringSplitOptions.RemoveEmptyEntries)
    .Skip(1)
    .Where(line => line.Contains(':'))
    .Select(line => line.Split(':', 2))
    .ToDictionary(parts => parts[0], parts => parts[1].Trim(), StringComparer.OrdinalIgnoreCase);

static Task TestMatrixPorts()
{
    var profile = new DiagnosticProfile
    {
        Server = "pbx.example.com",
        SipUser = "101",
        Transport = SipTransport.Tcp,
        Port = 5090,
        UdpPort = 5070,
        TcpPort = 5080,
        TlsPort = 5061
    }.Validate();
    var targets = profile.MatrixTargets();
    Assert(targets.Contains((SipTransport.Udp, 5070)), "UDP matrix port");
    Assert(targets.Contains((SipTransport.Tcp, 5080)), "TCP matrix port");
    Assert(targets.Contains((SipTransport.Tls, 5061)), "TLS matrix port");
    Assert(targets.Contains((SipTransport.Tcp, 5090)), "custom destination included");
    Assert(targets.Count == 4, "no duplicate when custom dest is extra");
    return Task.CompletedTask;
}

static Task TestAlgDetection()
{
    var sent = new SipRegisterMessage(
        Text: "REGISTER sip:pbx SIP/2.0\r\n",
        ViaValue: "SIP/2.0/UDP 10.0.0.2:5060;branch=z9hG4bK-abc;rport",
        ContactUri: "sip:101@10.0.0.2:5060;transport=udp",
        Branch: "z9hG4bK-abc",
        SentByHost: "10.0.0.2",
        SentByPort: 5060);
    var local = new IPEndPoint(IPAddress.Parse("10.0.0.2"), 5060);

    var intact = SipResponse.Parse(
        "SIP/2.0 401 Unauthorized\r\n" +
        "Via: SIP/2.0/UDP 10.0.0.2:5060;branch=z9hG4bK-abc;rport\r\n" +
        "Content-Length: 0\r\n\r\n");
    Assert(SipAlgDetector.Analyze(sent, intact, local).Verdict == AlgVerdict.NoRewrite, "intact Via");

    var nat = SipResponse.Parse(
        "SIP/2.0 401 Unauthorized\r\n" +
        "Via: SIP/2.0/UDP 10.0.0.2:5060;branch=z9hG4bK-abc;received=198.51.100.9;rport=45000\r\n" +
        "Content-Length: 0\r\n\r\n");
    Assert(SipAlgDetector.Analyze(sent, nat, local).Verdict == AlgVerdict.NatMapping, "received/rport is NAT");

    var rewritten = SipResponse.Parse(
        "SIP/2.0 401 Unauthorized\r\n" +
        "Via: SIP/2.0/UDP 198.51.100.9:45000;branch=z9hG4bK-abc;rport\r\n" +
        "Content-Length: 0\r\n\r\n");
    var alg = SipAlgDetector.Analyze(sent, rewritten, local);
    Assert(alg.Verdict == AlgVerdict.AlgRewrite, "sent-by rewrite is ALG");
    Assert(alg.Findings.Any(finding => finding.Message.Contains("SIP ALG likely", StringComparison.Ordinal)), "ALG warning text");

    var compact = SipResponse.Parse(
        "SIP/2.0 401 Unauthorized\r\n" +
        "v: SIP/2.0/UDP 10.0.0.2:5060;branch=z9hG4bK-abc;rport\r\n" +
        "Content-Length: 0\r\n\r\n");
    Assert(compact.GetHeader("Via")!.Contains("10.0.0.2"), "compact Via header alias");
    return Task.CompletedTask;
}

static Task TestClockAndNtp()
{
    Assert(ClockCertificateCheck.IsPrivateOrLocalHost("172.19.0.10"), "172.19 is RFC1918");
    Assert(ClockCertificateCheck.IsPrivateOrLocalHost("192.168.1.1"), "192.168 is RFC1918");
    Assert(!ClockCertificateCheck.IsPrivateOrLocalHost("pool.ntp.org"), "hostname is not treated as private");
    Assert(!ClockCertificateCheck.IsPrivateOrLocalHost("1.1.1.1"), "public IP");

    var ntp = ClockCertificateCheck.AnalyzeNtpServers(new[] { "172.19.1.8", "pool.ntp.org" });
    Assert(ntp.Any(finding => finding.Level == DiagnosticLevel.Warning && finding.Message.Contains("172.19.1.8")), "private NTP warning");
    Assert(ntp.Any(finding => finding.Message.Contains("pool.ntp.org")), "public NTP noted");

    using var rsa = RSA.Create(2048);
    var request = new CertificateRequest("CN=pbx.example.com", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
    using var cert = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));
    var inside = ClockCertificateCheck.AnalyzeCertificate(cert, DateTimeOffset.UtcNow);
    Assert(inside.Any(finding => finding.Level == DiagnosticLevel.Success && finding.Message.Contains("inside the certificate validity")), "clock inside window");
    var behind = ClockCertificateCheck.AnalyzeCertificate(cert, DateTimeOffset.UtcNow.AddDays(-10));
    Assert(behind.Any(finding => finding.Level == DiagnosticLevel.Error && finding.Message.Contains("behind")), "clock behind NotBefore");
    return Task.CompletedTask;
}

static Task TestYealinkParser()
{
    var settings = YealinkConfigParser.Parse(new[]
    {
        "account.1.sip_server.1.address = pbx.example.com",
        "account.1.user_name = 101",
        "account.1.auth_name = 101abc",
        "account.1.password = Secret123!",
        "account.1.sip_server.1.transport_type = 2",
        "account.1.sip_server.1.port = 5061",
        "account.1.sip_server.1.expires = 600",
        "local_time.ntp_server1 = 172.19.0.1",
        "local_time.ntp_server2 = pool.ntp.org",
        "account.1.outbound_proxy_enable = 1",
        "account.1.outbound_proxy.1.address = ",
        "account.1.nat.udp_update_enable = 1",
        "account.1.nat.udp_update_time = 30",
        "account.1.sip_server.2.address = %NULL%"
    });
    Assert(settings.Server == "pbx.example.com", "server");
    Assert(settings.Transport == SipTransport.Tls, "TLS transport");
    Assert(settings.Port == 5061, "TLS port from cfg");
    Assert(settings.NtpServers.Contains("172.19.0.1"), "primary NTP");
    Assert(settings.NtpServers.Contains("pool.ntp.org"), "secondary NTP");
    Assert(settings.OutboundProxyEnabled == true, "outbound proxy enabled");
    Assert(string.IsNullOrWhiteSpace(settings.OutboundProxyAddress), "empty outbound proxy");
    Assert(settings.KeepAliveEnabled, "keep-alive enabled");
    Assert(settings.KeepAliveSeconds == 30, "keep-alive interval");
    Assert(settings.Warnings().Any(warning => warning.Message.Contains("empty", StringComparison.OrdinalIgnoreCase)), "empty proxy warning");
    return Task.CompletedTask;
}

static async Task TestYeastarPbxDiagnostic()
{
    var handler = new ScriptedHandler((request, _) =>
    {
        var path = request.RequestUri!.AbsolutePath;
        if (path.EndsWith("/get_token", StringComparison.Ordinal))
            return Json(new { errcode = 0, errmsg = "SUCCESS", access_token = "token-1" });
        if (path.Contains("/system/information", StringComparison.Ordinal))
            return Json(new { errcode = 0, data = new { name = "JQuad", version = "83.18.0.22" } });
        if (path.Contains("/extension/search", StringComparison.Ordinal))
        {
            return Json(new
            {
                errcode = 0,
                data = new[]
                {
                    new
                    {
                        id = 12,
                        number = "101",
                        caller_id_name = "Afrox",
                        online_status = new
                        {
                            sip_phone = new { status = 0, ext_dev_type = "sip" },
                            linkus_desktop = new { status = 0 },
                            linkus_mobile = new { status = 0 },
                            linkus_web = new { status = 0 }
                        }
                    }
                }
            });
        }
        if (path.Contains("/extension/get", StringComparison.Ordinal))
            return Json(new { errcode = 0, data = new { id = 12, number = "101", transport = "tls", concurrent_registrations = 1, reg_name = "101abc" } });
        if (path.Contains("/phone/search", StringComparison.Ordinal))
            return Json(new { errcode = 0, data = new[] { new { mac = "80:5e:c0:00:00:01", model = "T40G", assigned_ext_num = "101", ip = "", firmware = "" } } });
        if (path.Contains("/blockedip/list", StringComparison.Ordinal))
            return Json(new { errcode = 0, data = new[] { new { ip = "203.0.113.10", defense_type = "SIP" } } });
        return Json(new { errcode = 4001, errmsg = "INTERFACE NOT EXIST" });
    });

    var diagnostic = new YeastarPbxDiagnostic(handler);
    await diagnostic.RunAsync(new YeastarPbxCheckRequest
    {
        ApiBaseUrl = "https://pbx.example.com",
        ClientId = "id",
        ClientSecret = "secret-value",
        ExtensionNumber = "101",
        AuthenticationName = "wrong-auth"
    });

    Assert(diagnostic.Entries.Any(entry => entry.Message.Contains("OpenAPI authentication succeeded")), "token");
    Assert(diagnostic.Entries.Any(entry => entry.Message.Contains("SIP phone is not registered")), "SIP offline");
    Assert(diagnostic.Entries.Any(entry => entry.Message.Contains("does not match PBX registration name")), "reg name mismatch");
    Assert(diagnostic.Entries.Any(entry => entry.Message.Contains("no reported IP or firmware")), "phone status empty");
    Assert(diagnostic.Entries.Any(entry => entry.Message.Contains("blockedip/list")), "blocked IP endpoint");
    Assert(diagnostic.Entries.All(entry => !entry.Message.Contains("secret-value", StringComparison.Ordinal)), "API secret redaction");
}

static Task TestYealinkAudit()
{
    // The real-world case: outbound proxy switched on with no address.
    var broken = YealinkConfigParser.Parse(new[]
    {
        "account.1.enable = 1",
        "account.1.sip_server.1.address = pbx.example.com",
        "account.1.user_name = 101",
        "account.1.auth_name = 101abc",
        "account.1.password = Secret123!",
        "account.1.sip_server.1.transport_type = 2",
        "account.1.sip_server.1.port = 5061",
        "account.1.outbound_proxy_enable = 1",
        "account.1.outbound_proxy.1.address = %NULL%"
    });

    Assert(broken.HasBlockingProblem, "empty outbound proxy is a blocking problem");
    Assert(broken.Audit().Any(f => f.Level == DiagnosticLevel.Error && f.Message.Contains("Outbound proxy is enabled")),
        "empty outbound proxy is an error");

    // A disabled account can never register.
    var disabled = YealinkConfigParser.Parse(new[]
    {
        "account.1.enable = 0",
        "account.1.sip_server.1.address = pbx.example.com",
        "account.1.user_name = 101",
        "account.1.auth_name = 101abc",
        "account.1.password = Secret123!"
    });
    Assert(disabled.Audit().Any(f => f.Level == DiagnosticLevel.Error && f.Message.Contains("disabled")), "disabled account");

    // TLS on 5060 is a transport/port mismatch.
    var mismatch = YealinkConfigParser.Parse(new[]
    {
        "account.1.enable = 1",
        "account.1.sip_server.1.address = pbx.example.com",
        "account.1.user_name = 101",
        "account.1.auth_name = 101abc",
        "account.1.password = Secret123!",
        "account.1.sip_server.1.transport_type = 2",
        "account.1.sip_server.1.port = 5060"
    });
    Assert(mismatch.Audit().Any(f => f.Level == DiagnosticLevel.Warning && f.Message.Contains("normally 5061")), "transport/port mismatch");
    Assert(!mismatch.HasBlockingProblem, "a mismatch warns but does not block");

    // Static DNS with no servers stops hostname resolution on every transport.
    var noDns = YealinkConfigParser.Parse(new[]
    {
        "account.1.enable = 1",
        "account.1.sip_server.1.address = pbx.example.com",
        "account.1.user_name = 101",
        "account.1.auth_name = 101abc",
        "account.1.password = Secret123!",
        "static.network.static_dns_enable = 1"
    });
    Assert(noDns.Audit().Any(f => f.Level == DiagnosticLevel.Error && f.Message.Contains("DNS")), "static DNS with no servers");

    // A clean file should produce no errors at all.
    var clean = YealinkConfigParser.Parse(new[]
    {
        "account.1.enable = 1",
        "account.1.sip_server.1.address = pbx.example.com",
        "account.1.user_name = 101",
        "account.1.auth_name = 101abc",
        "account.1.password = Secret123!",
        "account.1.sip_server.1.transport_type = 2",
        "account.1.sip_server.1.port = 5061",
        "account.1.outbound_proxy_enable = 0"
    });
    Assert(!clean.HasBlockingProblem, "clean config has no blocking problem");
    return Task.CompletedTask;
}

static async Task TestSipCapture()
{
    await using var listener = new SipCaptureListener();
    var port = FreeUdpPort();
    await listener.StartAsync(new SipCaptureOptions { Port = port, Realm = "probe-test" });

    using var phone = new UdpClient(AddressFamily.InterNetwork);
    var target = new IPEndPoint(IPAddress.Loopback, port);

    // First REGISTER, no credentials: the listener should answer 401.
    var register =
        "REGISTER sip:pbx.example.com SIP/2.0\r\n" +
        $"Via: SIP/2.0/UDP 10.0.0.9:5060;branch=z9hG4bK-{Guid.NewGuid():N}\r\n" +
        "From: <sip:101@pbx.example.com>;tag=abc\r\n" +
        "To: <sip:101@pbx.example.com>\r\n" +
        "Call-ID: capture-test\r\n" +
        "CSeq: 1 REGISTER\r\n" +
        "Contact: <sip:101@10.0.0.9:5060>\r\n" +
        "User-Agent: Yealink SIP-T40G 76.85.0.5\r\n" +
        "Expires: 3600\r\n" +
        "Content-Length: 0\r\n\r\n";
    var payload = Encoding.UTF8.GetBytes(register);
    await phone.SendAsync(payload, payload.Length, target);

    var first = await ReceiveWithTimeout(phone);
    Assert(first.StartsWith("SIP/2.0 401", StringComparison.Ordinal), "listener challenges an unauthenticated REGISTER");
    Assert(first.Contains("realm=\"probe-test\""), "challenge carries the configured realm");
    Assert(first.Contains("received=127.0.0.1"), "challenge echoes received");

    // Second REGISTER carrying credentials: the listener should answer 200 OK.
    var authenticated = register.Replace(
        "CSeq: 1 REGISTER",
        "CSeq: 2 REGISTER\r\nAuthorization: Digest username=\"101abc\", realm=\"probe-test\", " +
        "nonce=\"deadbeef\", uri=\"sip:pbx.example.com\", response=\"secrethash\", algorithm=MD5");
    payload = Encoding.UTF8.GetBytes(authenticated);
    await phone.SendAsync(payload, payload.Length, target);

    var second = await ReceiveWithTimeout(phone);
    Assert(second.StartsWith("SIP/2.0 200", StringComparison.Ordinal), "listener accepts an authenticated REGISTER");

    var entries = listener.Entries;
    Assert(entries.Any(e => e.Message.Contains("authenticating as '101abc'")), "auth name is surfaced");
    Assert(entries.Any(e => e.Message.Contains("Yealink SIP-T40G")), "user agent is surfaced");
    Assert(entries.All(e => !e.Message.Contains("secrethash", StringComparison.Ordinal)), "digest response is never logged");
    Assert(listener.MessageCount == 2, "both messages counted");
}

static async Task TestSipCaptureAnswersKeepalives()
{
    await using var listener = new SipCaptureListener();
    var port = FreeUdpPort();
    await listener.StartAsync(new SipCaptureOptions { Port = port });

    using var phone = new UdpClient(AddressFamily.InterNetwork);
    var target = new IPEndPoint(IPAddress.Loopback, port);

    // A Yealink keep-alive. Earlier builds only answered REGISTER/OPTIONS/SUBSCRIBE,
    // so INFO went unanswered and the handset retransmitted for ever.
    var info =
        $"INFO sip:127.0.0.1:{port} SIP/2.0\r\n" +
        "Via: SIP/2.0/UDP 10.0.0.9:5060;branch=z9hG4bK-keepalive-1\r\n" +
        "From: \"101\" <sip:101@10.0.0.9>;tag=keepalive\r\n" +
        $"To: <sip:127.0.0.1:{port}>\r\n" +
        "Call-ID: keepalive-test\r\n" +
        "CSeq: 1 INFO\r\n" +
        "User-Agent: Yealink SIP-T40G 76.84.0.125\r\n" +
        "Content-Length: 0\r\n\r\n";
    var payload = Encoding.UTF8.GetBytes(info);
    await phone.SendAsync(payload, payload.Length, target);

    var answer = await ReceiveWithTimeout(phone);
    Assert(answer.StartsWith("SIP/2.0 200", StringComparison.Ordinal), "INFO keep-alive is answered");

    // Resending the identical transaction should collapse rather than repeat the full dump.
    await phone.SendAsync(payload, payload.Length, target);
    await ReceiveWithTimeout(phone);
    await phone.SendAsync(payload, payload.Length, target);
    await ReceiveWithTimeout(phone);

    var starts = listener.Entries.Count(e => e.Message.Contains("INFO sip:"));
    Assert(starts == 1, $"retransmissions collapse to one full entry (saw {starts})");
    Assert(listener.Entries.Any(e => e.Message.Contains("retransmitted (x2)")), "retransmission is reported");
}

static async Task<string> ReceiveWithTimeout(UdpClient client)
{
    using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
    var result = await client.ReceiveAsync(cts.Token);
    return Encoding.UTF8.GetString(result.Buffer);
}

static int FreeUdpPort()
{
    using var probe = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
    return ((IPEndPoint)probe.Client.LocalEndPoint!).Port;
}

static HttpResponseMessage Json(object payload) =>
    new(HttpStatusCode.OK)
    {
        Content = new StringContent(System.Text.Json.JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json")
    };

static Task TestDiagnosisRouterUdpBlocked()
{
    var diagnosis = DiagnosisEngine.From(
        new[]
        {
            Outcome(SipTransport.Udp, 5060, FailureStage.NoSipResponse),
            Outcome(SipTransport.Tcp, 5060, FailureStage.Success, status: 401),
            Outcome(SipTransport.Tls, 5061, FailureStage.Success, status: 401)
        },
        Phone(SipTransport.Udp, stun: true, keepalive: true, privateNtp: true));

    Assert(diagnosis.Cause == DiagnosisCause.RouterUdpBlocked, "UDP silent + TLS 401 is the router");
    Assert(diagnosis.Headline.Contains("router", StringComparison.OrdinalIgnoreCase), "headline names the router");
    Assert(diagnosis.SuggestedTransport == SipTransport.Tls, "suggest TLS");
    Assert(diagnosis.SuggestedPort == 5061, "suggest 5061");
    Assert(diagnosis.DoNow.Any(step => step.Detail.Contains("transport_type = 2")), "Yealink TLS keys");
    Assert(diagnosis.DoNow.Any(step => step.Title.Contains("keep-alive", StringComparison.OrdinalIgnoreCase)),
        "keep-alive will not beat ALG");
    Assert(diagnosis.IfYouHaveRouterAccess.Count > 0, "optional router steps");
    Assert(diagnosis.DoNot.Any(step => step.Title.Contains("STUN", StringComparison.OrdinalIgnoreCase)), "do not use STUN");
    Assert(diagnosis.FormatAdviceBody().Contains("no router access", StringComparison.OrdinalIgnoreCase), "advice body");
    return Task.CompletedTask;
}

static Task TestDiagnosisSipAlg()
{
    var diagnosis = DiagnosisEngine.From(
        new[]
        {
            Outcome(SipTransport.Udp, 5060, FailureStage.Success, status: 401, alg: AlgVerdict.AlgRewrite),
            Outcome(SipTransport.Tcp, 5060, FailureStage.Success, status: 401),
            Outcome(SipTransport.Tls, 5061, FailureStage.Success, status: 401)
        },
        Phone(SipTransport.Udp));

    Assert(diagnosis.Cause == DiagnosisCause.RouterSipAlg, "Via rewrite is ALG");
    Assert(diagnosis.Headline.Contains("ALG", StringComparison.OrdinalIgnoreCase), "headline says ALG");
    Assert(diagnosis.SuggestedTransport == SipTransport.Tls, "ALG bypass is TLS");
    Assert(diagnosis.DoNot.Any(step => step.Title.Contains("STUN", StringComparison.OrdinalIgnoreCase)), "STUN is not the ALG fix");
    return Task.CompletedTask;
}

static Task TestDiagnosisPathBlocked()
{
    var diagnosis = DiagnosisEngine.From(
        new[]
        {
            Outcome(SipTransport.Udp, 5060, FailureStage.Connect),
            Outcome(SipTransport.Tcp, 5060, FailureStage.Connect),
            Outcome(SipTransport.Tls, 5061, FailureStage.Connect)
        });

    Assert(diagnosis.Cause == DiagnosisCause.PathBlocked, "all connect failures are not ALG");
    Assert(!diagnosis.Headline.Contains("ALG", StringComparison.OrdinalIgnoreCase), "do not call it ALG");
    Assert(diagnosis.DoNow.Any(step => step.Title.Contains("hotspot", StringComparison.OrdinalIgnoreCase)), "hotspot isolation");
    return Task.CompletedTask;
}

static Task TestDiagnosisTlsHandshake()
{
    var diagnosis = DiagnosisEngine.From(
        new[]
        {
            Outcome(SipTransport.Udp, 5060, FailureStage.Success, status: 401),
            Outcome(SipTransport.Tcp, 5060, FailureStage.Success, status: 401),
            Outcome(SipTransport.Tls, 5061, FailureStage.TlsHandshake)
        },
        Phone(SipTransport.Tls, privateNtp: true));

    Assert(diagnosis.Cause == DiagnosisCause.TlsHandshake, "TLS handshake isolated");
    Assert(diagnosis.DoNow.Any(step => step.Detail.Contains("pool.ntp.org")), "public NTP");
    Assert(diagnosis.SuggestedTransport == SipTransport.Tcp, "TCP fallback when UDP is healthy");
    return Task.CompletedTask;
}

static Task TestDiagnosisRegisteredOnTls()
{
    var path = new[]
    {
        Outcome(SipTransport.Udp, 5060, FailureStage.NoSipResponse),
        Outcome(SipTransport.Tcp, 5060, FailureStage.Success, status: 401),
        Outcome(SipTransport.Tls, 5061, FailureStage.Success, status: 401)
    };
    var registered = Outcome(SipTransport.Tls, 5061, FailureStage.Success, status: 200, registered: true);
    var diagnosis = DiagnosisEngine.From(path, Phone(SipTransport.Udp), registered);

    Assert(diagnosis.Cause == DiagnosisCause.RouterUdpBlocked, "router warning survives a TLS REGISTER");
    Assert(diagnosis.Severity == DiagnosisSeverity.Warn, "warn, not a clean pass");
    Assert(diagnosis.Headline.Contains("Registered", StringComparison.OrdinalIgnoreCase), "says this laptop registered");
    Assert(diagnosis.DoNow.Any(step => step.Detail.Contains("transport_type = 2")), "still tell them to put the phone on TLS");
    return Task.CompletedTask;
}

static Task TestDiagnosisPhoneConfigFirst()
{
    var path = new[]
    {
        Outcome(SipTransport.Udp, 5060, FailureStage.Success, status: 401),
        Outcome(SipTransport.Tcp, 5060, FailureStage.Success, status: 401),
        Outcome(SipTransport.Tls, 5061, FailureStage.Success, status: 401)
    };
    var diagnosis = DiagnosisEngine.From(path, Phone(SipTransport.Tls, emptyProxy: true));

    Assert(diagnosis.Cause == DiagnosisCause.PhoneConfig, "blocking cfg wins");
    Assert(diagnosis.Severity == DiagnosisSeverity.Fail, "config fail");
    Assert(diagnosis.DoNow.Any(step => step.Title.Contains("template", StringComparison.OrdinalIgnoreCase)), "fix template first");
    return Task.CompletedTask;
}

static DiagnosticResult Outcome(
    SipTransport transport,
    int port,
    FailureStage stage,
    AlgVerdict? alg = null,
    int? status = null,
    bool registered = false)
{
    var sip = stage is FailureStage.Success or FailureStage.SipReject;
    return new DiagnosticResult(
        NetworkReachable: stage is not (FailureStage.Dns or FailureStage.Connect or FailureStage.TlsHandshake),
        SipResponseReceived: sip,
        Registered: registered,
        FinalStatusCode: sip ? status ?? (stage == FailureStage.SipReject ? 403 : 401) : null,
        Summary: stage.ToString(),
        Entries: Array.Empty<DiagnosticLogEntry>(),
        Stage: stage,
        Transport: transport,
        Port: port,
        Alg: alg);
}

static YealinkAccountSettings Phone(
    SipTransport transport,
    bool stun = false,
    bool privateNtp = false,
    bool keepalive = false,
    bool emptyProxy = false) =>
    new()
    {
        Server = "pbx.example.com",
        SipUser = "101",
        AuthenticationName = "101",
        Password = "secret",
        Transport = transport,
        Port = transport == SipTransport.Tls ? 5061 : 5060,
        AccountEnabled = true,
        OutboundProxyEnabled = emptyProxy ? true : false,
        OutboundProxyAddress = emptyProxy ? "" : null,
        StunEnabled = stun,
        StunServer = stun ? "stun.example.com" : null,
        NtpServers = privateNtp ? new[] { "172.19.0.1" } : Array.Empty<string>(),
        KeepAliveMode = keepalive ? 1 : null,
        KeepAliveSeconds = keepalive ? 30 : null
    };

static void Assert(bool condition, string description)
{
    if (!condition)
        throw new InvalidOperationException("Assertion failed: " + description);
}

file sealed class ScriptedHandler : HttpMessageHandler
{
    private readonly Func<HttpRequestMessage, string, HttpResponseMessage> _handler;

    public ScriptedHandler(Func<HttpRequestMessage, string, HttpResponseMessage> handler) => _handler = handler;

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var body = request.Content is null ? string.Empty : await request.Content.ReadAsStringAsync(cancellationToken);
        return _handler(request, body);
    }
}
