using System.Text;

namespace InspireTel.SipProbe.Core;

public enum DiagnosisCause
{
    PhoneConfig,
    RouterUdpBlocked,
    RouterSipAlg,
    Dns,
    PathBlocked,
    TlsHandshake,
    Credentials,
    PathOk,
    Registered
}

public enum DiagnosisSeverity
{
    Pass,
    Warn,
    Fail
}

public sealed record AdviceStep(string Title, string Detail);

public sealed record Diagnosis(
    DiagnosisCause Cause,
    DiagnosisSeverity Severity,
    string Headline,
    string Summary,
    IReadOnlyList<string> Evidence,
    IReadOnlyList<AdviceStep> DoNow,
    IReadOnlyList<AdviceStep> IfYouHaveRouterAccess,
    IReadOnlyList<AdviceStep> DoNot,
    SipTransport? SuggestedTransport = null,
    int? SuggestedPort = null)
{
    public bool HasAdvice => DoNow.Count > 0 || IfYouHaveRouterAccess.Count > 0 || DoNot.Count > 0;

    public string FormatAdviceBody()
    {
        var builder = new StringBuilder();
        AppendSection(builder, "Do now — no router access needed", DoNow);
        AppendSection(builder, "If you can get into the router", IfYouHaveRouterAccess);
        AppendSection(builder, "Do not", DoNot);
        return builder.ToString().TrimEnd();
    }

    public IReadOnlyList<(DiagnosticLevel Level, string Message)> ToTraceLines()
    {
        var level = Severity switch
        {
            DiagnosisSeverity.Pass => DiagnosticLevel.Success,
            DiagnosisSeverity.Warn => DiagnosticLevel.Warning,
            DiagnosisSeverity.Fail => DiagnosticLevel.Error,
            _ => throw new ArgumentOutOfRangeException(nameof(Severity), Severity, null)
        };
        var lines = new List<(DiagnosticLevel, string)>
        {
            (level, Headline),
            (DiagnosticLevel.Info, Summary)
        };
        foreach (var item in Evidence)
            lines.Add((DiagnosticLevel.Detail, "Evidence: " + item));
        foreach (var step in DoNow)
            lines.Add((DiagnosticLevel.Info, "Do now (no router access): " + FormatStep(step)));
        foreach (var step in IfYouHaveRouterAccess)
            lines.Add((DiagnosticLevel.Info, "If you can get into the router: " + FormatStep(step)));
        foreach (var step in DoNot)
            lines.Add((DiagnosticLevel.Warning, "Do not: " + FormatStep(step)));
        return lines;
    }

    private static void AppendSection(StringBuilder builder, string heading, IReadOnlyList<AdviceStep> steps)
    {
        if (steps.Count == 0)
            return;
        if (builder.Length > 0)
            builder.AppendLine().AppendLine();
        builder.Append(heading);
        foreach (var step in steps)
        {
            builder.AppendLine().Append("• ").Append(step.Title);
            if (!string.IsNullOrWhiteSpace(step.Detail))
            {
                foreach (var line in step.Detail.Split('\n'))
                    builder.AppendLine().Append("  ").Append(line.TrimEnd());
            }
        }
    }

    private static string FormatStep(AdviceStep step) =>
        string.IsNullOrWhiteSpace(step.Detail) ? step.Title : step.Title + " " + step.Detail.Replace('\n', ' ');
}

public static class DiagnosisEngine
{
    public static Diagnosis From(
        IReadOnlyList<DiagnosticResult> pathResults,
        YealinkAccountSettings? handset = null,
        DiagnosticResult? registration = null)
    {
        var path = ClassifyPath(pathResults, handset);
        if (handset?.HasBlockingProblem == true)
            return OverlayPhoneConfig(path, handset);
        if (registration is { Registered: true })
            return OverlayRegistered(path, registration, handset);
        if (registration is { Stage: FailureStage.SipReject })
            return OverlayCredentials(path, registration);
        return path;
    }

    private static Diagnosis ClassifyPath(
        IReadOnlyList<DiagnosticResult> pathResults,
        YealinkAccountSettings? handset)
    {
        if (pathResults.Count == 0)
        {
            return new Diagnosis(
                DiagnosisCause.PathOk,
                DiagnosisSeverity.Pass,
                "Run Test Path first",
                "Test Path tries UDP, TCP and TLS without the password. That is what shows whether the router is interfering.",
                Array.Empty<string>(),
                new[] { new AdviceStep("Click Test Path.", "A 401/407 means that transport works. No password is sent.") },
                Array.Empty<AdviceStep>(),
                Array.Empty<AdviceStep>());
        }

        var udp = Last(pathResults, SipTransport.Udp);
        var tcp = Last(pathResults, SipTransport.Tcp);
        var tls = Last(pathResults, SipTransport.Tls);
        var evidence = pathResults.Select(Describe).ToArray();
        var udpOk = Answered(udp);
        var tcpOk = Answered(tcp);
        var tlsOk = Answered(tls);
        var anyOk = pathResults.Any(Answered);
        var alg = udp?.Alg == AlgVerdict.AlgRewrite;
        var suggested = Suggest(tcp, tls);

        if (alg)
            return RouterAlg(tcpOk, tlsOk, evidence, handset, suggested);

        if (!udpOk && (tcpOk || tlsOk))
            return RouterUdpBlocked(tcpOk, tlsOk, evidence, handset, suggested);

        if (pathResults.All(result => result.Stage == FailureStage.Dns))
            return DnsFailure(evidence);

        if (!tlsOk && tls is not null && (tcpOk || udpOk) &&
            tls.Stage is FailureStage.TlsHandshake or FailureStage.NoSipResponse or FailureStage.Connect)
        {
            return TlsProblem(tls, udpOk, tcpOk, tcp, evidence);
        }

        if (!anyOk)
            return PathBlocked(pathResults, evidence);

        if (handset?.Transport is { } phoneTransport)
        {
            var phonePath = Last(pathResults, phoneTransport);
            if (phonePath is { SipResponseReceived: false } && anyOk)
                return PhoneOnFailingTransport(phonePath, evidence, handset, suggested, tcpOk, tlsOk);
        }

        return PathReachable(pathResults, evidence, handset);
    }

    private static Diagnosis OverlayPhoneConfig(Diagnosis path, YealinkAccountSettings handset)
    {
        var errors = handset.Audit()
            .Where(finding => finding.Level == DiagnosticLevel.Error)
            .Select(finding => finding.Message)
            .ToArray();
        var evidence = errors.Concat(path.Evidence).ToArray();
        var doNow = new List<AdviceStep>
        {
            new(
                "Fix the handset template first. These faults stop the Yealink registering on every transport, even when this laptop succeeds.",
                string.Join(Environment.NewLine, errors))
        };
        doNow.AddRange(path.DoNow.Where(step => !step.Title.StartsWith("Click Test SIP", StringComparison.Ordinal)));
        return new Diagnosis(
            DiagnosisCause.PhoneConfig,
            DiagnosisSeverity.Fail,
            "Handset config will not register",
            errors.FirstOrDefault() ?? path.Summary,
            evidence,
            doNow,
            path.IfYouHaveRouterAccess,
            MergeDoNot(path.DoNot, handset, routerInterfering: path.Cause is DiagnosisCause.RouterUdpBlocked or DiagnosisCause.RouterSipAlg),
            path.SuggestedTransport,
            path.SuggestedPort);
    }

    private static Diagnosis OverlayRegistered(
        Diagnosis path,
        DiagnosticResult registration,
        YealinkAccountSettings? handset)
    {
        var transport = registration.Transport.ToString().ToUpperInvariant();
        if (path.Cause is DiagnosisCause.RouterUdpBlocked or DiagnosisCause.RouterSipAlg)
        {
            return path with
            {
                Severity = DiagnosisSeverity.Warn,
                Headline = path.Cause == DiagnosisCause.RouterSipAlg
                    ? $"Registered on {transport} — SIP ALG still breaks UDP on the phone"
                    : $"Registered on {transport} — the router still breaks UDP on the phone",
                Summary = $"Credentials work from this laptop on {transport}. " + path.Summary
            };
        }

        var phoneSide = new List<AdviceStep>
        {
            new(
                "If the Yealink still shows Registering, this LAN is not the problem.",
                "Check public NTP (not 172.19.x.x), outbound proxy, and TLS trust on the phone. This probe bypasses the handset stack.")
        };
        if (HasPrivateNtp(handset))
        {
            phoneSide.Insert(0, new AdviceStep(
                "Set a public NTP server on the template. Private NTP will fail TLS on the handset even though this laptop registered.",
                "local_time.ntp_server1 = pool.ntp.org"));
        }

        return new Diagnosis(
            DiagnosisCause.Registered,
            DiagnosisSeverity.Pass,
            "SIP registration succeeded from this computer",
            $"The PBX accepted this extension on {transport}/{registration.Port}. If the handset still shows Registering, the fault is phone-side, not this router path.",
            path.Evidence.Append(Describe(registration)).ToArray(),
            phoneSide,
            Array.Empty<AdviceStep>(),
            Array.Empty<AdviceStep>());
    }

    private static Diagnosis OverlayCredentials(Diagnosis path, DiagnosticResult registration)
    {
        var code = registration.FinalStatusCode;
        var headline = code switch
        {
            401 => "The PBX rejected the credentials",
            403 => "The PBX forbade registration",
            404 => "The PBX does not know this SIP identity",
            423 => "The registration expiry is below the PBX minimum",
            429 => "The PBX is rate-limiting this source",
            _ => "The PBX rejected SIP registration"
        };
        var doNow = code switch
        {
            401 => new AdviceStep(
                "Check the registration / authentication name and the SIP password against the Yeastar extension.",
                "Test Path already proved the network. Repeated 401s can lock the extension — stop hammering it."),
            403 => new AdviceStep(
                "This is PBX policy, not the router. Check transport permission, registration security, and blocked IPs.",
                "Use Check PBX Status if you have OpenAPI credentials."),
            404 => new AdviceStep(
                "Check the SIP user / extension number and the registration name.",
                string.Empty),
            423 => new AdviceStep(
                "Raise registration expiry to the Min-Expires value the PBX returned (Yeastar Cloud is usually 600s).",
                "account.1.sip_server.1.expires = 600"),
            429 => new AdviceStep(
                "Stop testing. Check whether this public IP was rate-limited or blocked on the PBX.",
                string.Empty),
            _ => new AdviceStep(
                "Inspect the SIP response and the PBX log for the policy reason.",
                string.Empty)
        };
        return new Diagnosis(
            DiagnosisCause.Credentials,
            DiagnosisSeverity.Fail,
            headline,
            registration.Summary,
            path.Evidence.Append(Describe(registration)).ToArray(),
            new[] { doNow },
            Array.Empty<AdviceStep>(),
            Array.Empty<AdviceStep>());
    }

    private static Diagnosis RouterUdpBlocked(
        bool tcpOk,
        bool tlsOk,
        IReadOnlyList<string> evidence,
        YealinkAccountSettings? handset,
        (SipTransport Transport, int Port)? suggested)
    {
        var working = tlsOk ? "TLS" : "TCP";
        var phoneOnUdp = handset?.Transport is null or SipTransport.Udp;
        var summary = phoneOnUdp
            ? $"UDP SIP did not come back; {working} did. That is the router (SIP ALG or a UDP SIP filter), not the PBX. The handset template still uses UDP, so the Yealink will stay on Registering."
            : $"UDP SIP did not come back; {working} did. That is the router (SIP ALG or a UDP SIP filter). The loaded template already uses TLS, which is the working path on this LAN.";
        var doNow = new List<AdviceStep>();
        if (tlsOk && suggested is { Transport: SipTransport.Tls })
            doNow.Add(TlsOnHandset(suggested.Value.Port, HasPrivateNtp(handset)));
        else if (tcpOk && suggested is { Transport: SipTransport.Tcp })
            doNow.Add(TcpOnHandset(suggested.Value.Port));
        if (HasPrivateNtp(handset) && tlsOk)
        {
            doNow.Add(new AdviceStep(
                "TLS on the phone also needs a public NTP server. Private NTP such as 172.19.x.x leaves the clock wrong and TLS fails on the handset.",
                "local_time.ntp_server1 = pool.ntp.org"));
        }

        if (!phoneOnUdp && tlsOk)
        {
            doNow.Add(new AdviceStep(
                "The handset is already on TLS, which works from this network. If it still shows Registering, look at NTP, outbound proxy, and TLS trust — not the router.",
                string.Empty));
        }

        if (handset?.KeepAliveEnabled == true)
        {
            doNow.Add(new AdviceStep(
                "SIP keep-alive is already on. It will not beat a router that drops or rewrites UDP SIP. Switch the phone to TLS.",
                string.Empty));
        }

        return new Diagnosis(
            DiagnosisCause.RouterUdpBlocked,
            DiagnosisSeverity.Warn,
            "The router is interfering with UDP SIP",
            summary,
            evidence,
            doNow,
            RouterAccessSteps(includeAlg: true),
            MergeDoNot(StunDoNot(handset), handset, routerInterfering: true),
            suggested?.Transport,
            suggested?.Port);
    }

    private static Diagnosis RouterAlg(
        bool tcpOk,
        bool tlsOk,
        IReadOnlyList<string> evidence,
        YealinkAccountSettings? handset,
        (SipTransport Transport, int Port)? suggested)
    {
        var doNow = new List<AdviceStep>();
        if (tlsOk && suggested is { Transport: SipTransport.Tls })
            doNow.Add(TlsOnHandset(suggested.Value.Port, HasPrivateNtp(handset)));
        else if (tcpOk && suggested is { Transport: SipTransport.Tcp })
            doNow.Add(TcpOnHandset(suggested.Value.Port));
        else
        {
            doNow.Add(new AdviceStep(
                "Put the Yealink on TLS if the PBX allows it. Encrypted SIP is not rewritten by SIP ALG.",
                "account.1.sip_server.1.transport_type = 2\naccount.1.sip_server.1.port = 5061\naccount.1.nat.nat_traversal = 0"));
        }

        if (handset?.KeepAliveEnabled == true)
        {
            doNow.Add(new AdviceStep(
                "Keep-alive is already on; it will not beat SIP ALG. ALG rewrites Via and Contact. TLS avoids that.",
                string.Empty));
        }

        return new Diagnosis(
            DiagnosisCause.RouterSipAlg,
            DiagnosisSeverity.Warn,
            "SIP ALG on the router is rewriting SIP",
            "The PBX echoed a rewritten Via sent-by or branch. That is SIP ALG, not normal NAT (received=/rport= alone is fine). Phones often stay on Registering even when this laptop got a 401.",
            evidence,
            doNow,
            RouterAccessSteps(includeAlg: true),
            MergeDoNot(StunDoNot(handset), handset, routerInterfering: true),
            suggested?.Transport,
            suggested?.Port);
    }

    private static Diagnosis DnsFailure(IReadOnlyList<string> evidence) =>
        new(
            DiagnosisCause.Dns,
            DiagnosisSeverity.Fail,
            "The PBX hostname did not resolve",
            "DNS failed before any SIP was sent. This is not SIP ALG. Check the hostname, or the site's DNS filter.",
            evidence,
            new[]
            {
                new AdviceStep(
                    "Confirm the PBX hostname. If the site uses filtered DNS, try the PBX by IP only as a diagnostic — TLS to an IP will fail certificate hostname checks on the handset.",
                    string.Empty)
            },
            Array.Empty<AdviceStep>(),
            Array.Empty<AdviceStep>());

    private static Diagnosis TlsProblem(
        DiagnosticResult tls,
        bool udpOk,
        bool tcpOk,
        DiagnosticResult? tcp,
        IReadOnlyList<string> evidence)
    {
        var doNow = new List<AdviceStep>
        {
            new(
                "Fix time first. A Yealink with private NTP (172.19.x.x) fails TLS while this laptop succeeds.",
                "local_time.ntp_server1 = pool.ntp.org")
        };
        if (tls.Stage == FailureStage.TlsHandshake)
        {
            doNow.Add(new AdviceStep(
                "If NTP is already public, run Test Path again with Ignore certificate errors ticked — diagnostic only. That splits a trust-store problem from a blocked TLS connection.",
                "A success while ignoring certificates does not mean the Yealink will trust the certificate."));
        }

        if (tcpOk && udpOk)
        {
            doNow.Add(TcpOnHandset(tcp?.Port ?? 5060));
        }
        else if (tcpOk && !udpOk)
        {
            doNow.Add(new AdviceStep(
                "TLS is broken and UDP is also blocked. Without router access, use a VPN to the PBX, Yeastar remote access, or a phone hotspot to prove it is this network.",
                string.Empty));
        }

        return new Diagnosis(
            DiagnosisCause.TlsHandshake,
            DiagnosisSeverity.Fail,
            tls.Stage == FailureStage.TlsHandshake
                ? "TLS failed — clock, certificate, or TLS inspection"
                : "TLS did not complete — inspection, wrong port, or the TLS listener is down",
            "TCP or UDP still reached the PBX, so this is not a total SIP block. TLS inspection on the router is another common cause when you cannot disable it.",
            evidence,
            doNow,
            new[]
            {
                new AdviceStep(
                    "If this is TLS inspection, exclude the PBX hostname from HTTPS/SIP inspection, or disable inspection on that device.",
                    string.Empty)
            },
            Array.Empty<AdviceStep>(),
            tcpOk && udpOk ? SipTransport.Tcp : null,
            tcpOk && udpOk ? tcp?.Port : null);
    }

    private static Diagnosis PathBlocked(
        IReadOnlyList<DiagnosticResult> pathResults,
        IReadOnlyList<string> evidence)
    {
        var allConnect = pathResults.All(result => result.Stage == FailureStage.Connect);
        var headline = allConnect
            ? "This network is blocking the SIP ports"
            : "No SIP path reached the PBX from this computer";
        return new Diagnosis(
            DiagnosisCause.PathBlocked,
            DiagnosisSeverity.Fail,
            headline,
            "UDP, TCP and TLS all failed. That is not a specific SIP ALG signature — it is a firewall, ISP policy, wrong hostname/port, or the PBX is down.",
            evidence,
            new[]
            {
                new AdviceStep(
                    "Confirm the PBX hostname and ports (UDP/TCP 5060, TLS 5061 unless this tenant uses others).",
                    string.Empty),
                new AdviceStep(
                    "Tether a phone hotspot and run Test Path again. If it works on hotspot, this site's router or firewall is blocking SIP.",
                    string.Empty),
                new AdviceStep(
                    "If you cannot change the router and hotspot is the only working path, use a VPN to the PBX, Yeastar remote access, or leave the phone on cellular.",
                    string.Empty)
            },
            new[]
            {
                new AdviceStep(
                    "Allow outbound UDP 5060, TCP 5060 and TLS 5061 to the PBX. Disable SIP ALG if the device has that switch.",
                    string.Empty)
            },
            Array.Empty<AdviceStep>());
    }

    private static Diagnosis PhoneOnFailingTransport(
        DiagnosticResult phonePath,
        IReadOnlyList<string> evidence,
        YealinkAccountSettings? handset,
        (SipTransport Transport, int Port)? suggested,
        bool tcpOk,
        bool tlsOk)
    {
        var phone = phonePath.Transport.ToString().ToUpperInvariant();
        var doNow = new List<AdviceStep>();
        if (tlsOk && suggested is { Transport: SipTransport.Tls })
            doNow.Add(TlsOnHandset(suggested.Value.Port, HasPrivateNtp(handset)));
        else if (tcpOk && suggested is { Transport: SipTransport.Tcp })
            doNow.Add(TcpOnHandset(suggested.Value.Port));

        return new Diagnosis(
            DiagnosisCause.RouterUdpBlocked,
            DiagnosisSeverity.Warn,
            $"This LAN is fine on another transport; the template still puts the handset on {phone}",
            $"The loaded phone config uses {phone}/{phonePath.Port}, which failed from this computer. Another transport answered. Change the template to the working transport — you do not need the router.",
            evidence,
            doNow,
            RouterAccessSteps(includeAlg: phonePath.Transport == SipTransport.Udp),
            MergeDoNot(StunDoNot(handset), handset, routerInterfering: phonePath.Transport == SipTransport.Udp),
            suggested?.Transport,
            suggested?.Port);
    }

    private static Diagnosis PathReachable(
        IReadOnlyList<DiagnosticResult> pathResults,
        IReadOnlyList<string> evidence,
        YealinkAccountSettings? handset)
    {
        var names = string.Join(", ", pathResults.Where(Answered).Select(result => result.Transport.ToString().ToUpperInvariant()).Distinct());
        var doNow = new List<AdviceStep>
        {
            new("Click Test SIP Registration.", "Path is proven. A 200 OK means credentials work from this computer.")
        };
        if (HasPrivateNtp(handset))
        {
            doNow.Add(new AdviceStep(
                "The template still has private NTP. The handset will fail TLS even though the path is open.",
                "local_time.ntp_server1 = pool.ntp.org"));
        }

        return new Diagnosis(
            DiagnosisCause.PathOk,
            DiagnosisSeverity.Pass,
            "Path reachable — " + names,
            "The PBX answered on the tested transports. Next: Test SIP Registration.",
            evidence,
            doNow,
            Array.Empty<AdviceStep>(),
            Array.Empty<AdviceStep>());
    }

    private static AdviceStep TlsOnHandset(int port, bool privateNtp)
    {
        var keys = "account.1.sip_server.1.transport_type = 2\n" +
                   $"account.1.sip_server.1.port = {port}\n" +
                   "account.1.nat.nat_traversal = 0";
        if (privateNtp)
            keys += "\nlocal_time.ntp_server1 = pool.ntp.org";
        return new AdviceStep(
            "Put the Yealink on TLS. SIP ALG and UDP SIP filters almost never inspect TLS, so this is the fix when you cannot change the router.",
            keys);
    }

    private static AdviceStep TcpOnHandset(int port) =>
        new(
            "Put the Yealink on TCP if TLS is not available. Connection-oriented SIP is less often inspected than UDP 5060.",
            "account.1.sip_server.1.transport_type = 1\n" +
            $"account.1.sip_server.1.port = {port}\n" +
            "account.1.nat.nat_traversal = 0");

    private static IReadOnlyList<AdviceStep> RouterAccessSteps(bool includeAlg)
    {
        var steps = new List<AdviceStep>();
        if (includeAlg)
        {
            steps.Add(new AdviceStep(
                "Disable SIP ALG / SIP helper / SIP fixup. Names vary: SIP ALG, SIP Passthrough (set to Disable), sip helper on MikroTik.",
                "You often will not have the admin password. If not, skip this and use TLS on the phone."));
        }

        steps.Add(new AdviceStep(
            "Allow outbound UDP 5060 and TLS 5061 to the PBX. Do not enable STUN as a substitute for disabling ALG.",
            string.Empty));
        return steps;
    }

    private static IReadOnlyList<AdviceStep> StunDoNot(YealinkAccountSettings? handset)
    {
        if (handset?.StunEnabled == true)
        {
            return new[]
            {
                new AdviceStep(
                    "Turn STUN off on the template. STUN does not fix SIP ALG and often makes registration worse.",
                    "account.1.nat.nat_traversal = 0")
            };
        }

        return new[]
        {
            new AdviceStep(
                "Do not enable STUN to 'fix' this. STUN fights SIP ALG. Use TLS instead.",
                "account.1.nat.nat_traversal = 0")
        };
    }

    private static IReadOnlyList<AdviceStep> MergeDoNot(
        IReadOnlyList<AdviceStep> existing,
        YealinkAccountSettings? handset,
        bool routerInterfering)
    {
        var steps = existing.ToList();
        if (routerInterfering)
        {
            foreach (var step in StunDoNot(handset))
            {
                if (!steps.Any(item => item.Title == step.Title))
                    steps.Add(step);
            }
        }

        if (handset?.OutboundProxyEnabled == true && string.IsNullOrWhiteSpace(handset.OutboundProxyAddress))
        {
            steps.Add(new AdviceStep(
                "Do not leave outbound proxy enabled with an empty address.",
                "account.1.outbound_proxy_enable = 0"));
        }

        return steps;
    }

    private static (SipTransport Transport, int Port)? Suggest(DiagnosticResult? tcp, DiagnosticResult? tls)
    {
        if (Answered(tls))
            return (SipTransport.Tls, tls!.Port);
        if (Answered(tcp))
            return (SipTransport.Tcp, tcp!.Port);
        return null;
    }

    private static bool Answered(DiagnosticResult? result) => result is { SipResponseReceived: true };

    private static DiagnosticResult? Last(IReadOnlyList<DiagnosticResult> results, SipTransport transport)
    {
        for (var index = results.Count - 1; index >= 0; index--)
        {
            if (results[index].Transport == transport)
                return results[index];
        }

        return null;
    }

    private static bool HasPrivateNtp(YealinkAccountSettings? handset) =>
        handset?.NtpServers.Any(ClockCertificateCheck.IsPrivateOrLocalHost) == true;

    internal static string Describe(DiagnosticResult result)
    {
        var name = result.Transport.ToString().ToUpperInvariant() + "/" + result.Port;
        var stage = result.Stage switch
        {
            FailureStage.Success when result.FinalStatusCode is { } code =>
                $"PBX answered (SIP {code})",
            FailureStage.SipReject when result.FinalStatusCode is { } code =>
                $"PBX replied SIP {code}",
            FailureStage.NoSipResponse => "no SIP reply",
            FailureStage.TlsHandshake => "TLS handshake failed",
            FailureStage.Connect => "could not connect",
            FailureStage.Dns => "DNS failed",
            FailureStage.Success => result.Summary,
            FailureStage.SipReject => result.Summary,
            _ => throw new ArgumentOutOfRangeException(nameof(result.Stage), result.Stage, null)
        };
        if (result.Alg == AlgVerdict.AlgRewrite)
            stage += "; SIP ALG rewrite";
        return name + ": " + stage;
    }
}
