using InspireTel.SipProbe.Core;

namespace InspireTel.SipProbe.Mac;

internal static class CliProbe
{
    public static async Task<int> RunAsync(string[] args)
    {
        var cfgPath = GetCfgPath(args);
        if (cfgPath is null)
        {
            Console.Error.WriteLine("Usage: InspireTel.SIPProbe --cli --cfg <file.cfg> [--matrix] [--register]");
            return 2;
        }

        if (!File.Exists(cfgPath))
        {
            Console.Error.WriteLine("Config file not found: " + cfgPath);
            return 2;
        }

        var settings = YealinkConfigParser.Parse(File.ReadLines(cfgPath));
        if (settings.LoadedFields.Count == 0)
        {
            Console.Error.WriteLine("No supported account.1 Yealink SIP parameters were found.");
            return 2;
        }

        Write(DiagnosticLevel.Info, $"Loaded '{Path.GetFileName(cfgPath)}': {string.Join(", ", settings.LoadedFields)}.");
        Write(DiagnosticLevel.Info,
            $"SIP {settings.SipUser} → {settings.Server}:{settings.Port} {settings.Transport?.ToString().ToUpperInvariant()} expiry={settings.ExpirySeconds}.");
        Write(DiagnosticLevel.Detail, "Password and digest values are never written to the log.");
        foreach (var finding in ClockCertificateCheck.AnalyzeNtpServers(settings.NtpServers))
            Write(finding.Level, finding.Message);
        foreach (var warning in settings.Warnings())
            Write(warning.Level, warning.Message);

        var runMatrix = args.Contains("--matrix", StringComparer.OrdinalIgnoreCase) ||
                        !args.Contains("--register", StringComparer.OrdinalIgnoreCase);
        var runRegister = args.Contains("--register", StringComparer.OrdinalIgnoreCase) ||
                          !args.Contains("--matrix", StringComparer.OrdinalIgnoreCase);

        var baseProfile = new DiagnosticProfile
        {
            Server = settings.Server ?? string.Empty,
            Port = settings.Port ?? 5061,
            UdpPort = settings.Transport == SipTransport.Udp ? settings.Port ?? 5060 : 5060,
            TcpPort = settings.Transport == SipTransport.Tcp ? settings.Port ?? 5060 : 5060,
            TlsPort = settings.Transport is null or SipTransport.Tls ? settings.Port ?? 5061 : 5061,
            Transport = settings.Transport ?? SipTransport.Tls,
            SipUser = settings.SipUser ?? string.Empty,
            AuthenticationName = settings.AuthenticationName ?? string.Empty,
            Password = settings.Password ?? string.Empty,
            RegistrationExpirySeconds = settings.ExpirySeconds ?? 600,
            TimeoutSeconds = 8,
            ForceTls12 = true,
            IgnoreTlsCertificateErrors = false,
            Authenticate = false,
            NtpServers = settings.NtpServers
        }.Validate();

        using var timeout = new CancellationTokenSource(TimeSpan.FromMinutes(3));
        var failed = false;

        if (runMatrix)
        {
            foreach (var item in baseProfile.MatrixTargets())
            {
                WriteSeparator($"MATRIX: {item.Transport.ToString().ToUpperInvariant()} / {item.Port} (NO AUTH)");
                var result = await RunEngineAsync(baseProfile with
                {
                    Transport = item.Transport,
                    Port = item.Port,
                    Authenticate = false,
                    Password = string.Empty
                }, timeout.Token);
                failed |= !result.SipResponseReceived;
            }
        }

        if (runRegister)
        {
            WriteSeparator($"TEST SIP REGISTRATION  {baseProfile.Transport.ToString().ToUpperInvariant()}");
            var result = await RunEngineAsync(baseProfile with { Authenticate = true }, timeout.Token);
            failed |= !result.Registered;
            Write(result.Registered ? DiagnosticLevel.Success : DiagnosticLevel.Warning, result.Summary);
        }

        return failed ? 1 : 0;
    }

    private static async Task<DiagnosticResult> RunEngineAsync(DiagnosticProfile profile, CancellationToken token)
    {
        var engine = new SipDiagnosticEngine();
        engine.EntryAdded += entry => Write(entry.Level, entry.Message);
        return await engine.RunAsync(profile, token);
    }

    private static string? GetCfgPath(string[] args)
    {
        for (var i = 0; i < args.Length; i++)
        {
            if (args[i] is "--cfg" or "--config" && i + 1 < args.Length)
                return args[i + 1];
            if (args[i].EndsWith(".cfg", StringComparison.OrdinalIgnoreCase) && File.Exists(args[i]))
                return args[i];
        }
        return null;
    }

    private static void WriteSeparator(string title) =>
        Console.WriteLine(Environment.NewLine + "=== " + title + " ===");

    private static void Write(DiagnosticLevel level, string message)
    {
        var color = level switch
        {
            DiagnosticLevel.Success => ConsoleColor.Green,
            DiagnosticLevel.Warning => ConsoleColor.Yellow,
            DiagnosticLevel.Error => ConsoleColor.Red,
            DiagnosticLevel.Detail => ConsoleColor.DarkGray,
            _ => ConsoleColor.Gray
        };
        var previous = Console.ForegroundColor;
        Console.ForegroundColor = color;
        Console.WriteLine($"{DateTimeOffset.Now:HH:mm:ss.fff} [{level.ToString().ToUpperInvariant(),-7}] {message}");
        Console.ForegroundColor = previous;
    }
}
