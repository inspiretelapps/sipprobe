using System.Net;
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
    ("TLS REGISTER exchange", () => TestRegisterExchange(SipTransport.Tls))
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

static void Assert(bool condition, string description)
{
    if (!condition)
        throw new InvalidOperationException("Assertion failed: " + description);
}
