using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;

namespace InspireTel.SipProbe.Core;

public static class ClockCertificateCheck
{
    public static IReadOnlyList<(DiagnosticLevel Level, string Message)> AnalyzeCertificate(
        X509Certificate2 certificate,
        DateTimeOffset now)
    {
        var findings = new List<(DiagnosticLevel, string)>
        {
            (DiagnosticLevel.Detail,
                $"Certificate subject={certificate.Subject}; issuer={certificate.Issuer}; valid={certificate.NotBefore:u} to {certificate.NotAfter:u}."),
            (DiagnosticLevel.Detail, $"Local clock is {now:u}.")
        };

        var san = DescribeSubjectAlternativeNames(certificate);
        if (!string.IsNullOrWhiteSpace(san))
            findings.Add((DiagnosticLevel.Detail, san));

        var notBefore = AsOffset(certificate.NotBefore);
        var notAfter = AsOffset(certificate.NotAfter);

        if (now < notBefore)
        {
            var skew = notBefore - now;
            findings.Add((DiagnosticLevel.Error,
                $"Local clock is {FormatDuration(skew)} behind the certificate NotBefore. TLS on a Yealink will fail until the phone time is corrected (private NTP such as 172.19.x.x is a common cause)."));
        }
        else if (now > notAfter)
        {
            var skew = now - notAfter;
            findings.Add((DiagnosticLevel.Error,
                $"Local clock is {FormatDuration(skew)} ahead of the certificate NotAfter (or the certificate has expired). Handset TLS will fail until time or the certificate is fixed."));
        }
        else
        {
            findings.Add((DiagnosticLevel.Success,
                $"Local clock is inside the certificate validity window ({certificate.NotBefore:u} to {certificate.NotAfter:u})."));
            var remaining = notAfter - now;
            if (remaining < TimeSpan.FromDays(14))
            {
                findings.Add((DiagnosticLevel.Warning,
                    $"Certificate expires in {FormatDuration(remaining)}. Renew it before the handset starts failing TLS."));
            }
        }

        return findings;
    }

    public static IReadOnlyList<(DiagnosticLevel Level, string Message)> AnalyzeNtpServers(
        IEnumerable<string> servers)
    {
        var findings = new List<(DiagnosticLevel, string)>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var raw in servers)
        {
            var server = raw.Trim();
            if (server.Length == 0 || !seen.Add(server))
                continue;

            if (IsPrivateOrLocalHost(server))
            {
                findings.Add((DiagnosticLevel.Warning,
                    $"NTP server '{server}' is a private/CGNAT address. A remote handset cannot reach the PBX's internal NTP, so its clock stays wrong and TLS certificate validation fails. Set a public NTP server (for example pool.ntp.org) as primary in the template."));
            }
            else
            {
                findings.Add((DiagnosticLevel.Info, $"NTP server '{server}' looks publicly reachable."));
            }
        }

        return findings;
    }

    public static (DiagnosticLevel Level, string Message)? AnalyzeHttpDate(DateTimeOffset httpDate, DateTimeOffset now)
    {
        var skew = httpDate - now;
        var abs = skew.Duration();
        if (abs <= TimeSpan.FromMinutes(2))
        {
            return (DiagnosticLevel.Success,
                $"Local clock agrees with the PBX HTTPS Date header ({httpDate:u}; skew {FormatDuration(abs)}).");
        }

        var direction = skew > TimeSpan.Zero ? "behind" : "ahead of";
        return (DiagnosticLevel.Warning,
            $"Local clock is {FormatDuration(abs)} {direction} the PBX HTTPS Date header ({httpDate:u}). A Yealink using unreachable NTP will fail TLS even when this laptop does not.");
    }

    public static bool IsPrivateOrLocalHost(string host)
    {
        var value = SipAlgDetector.UnwrapHost(host.Trim());
        if (!IPAddress.TryParse(value, out var address))
            return false;
        return IsPrivateOrLocal(address);
    }

    public static bool IsPrivateOrLocal(IPAddress address)
    {
        if (address.IsIPv4MappedToIPv6)
            address = address.MapToIPv4();
        if (IPAddress.IsLoopback(address))
            return true;
        if (address.AddressFamily == AddressFamily.InterNetworkV6)
            return address.IsIPv6LinkLocal || address.IsIPv6SiteLocal || address.IsIPv6UniqueLocal;

        var bytes = address.GetAddressBytes();
        return bytes[0] == 10
               || bytes[0] == 127
               || (bytes[0] == 169 && bytes[1] == 254)
               || (bytes[0] == 192 && bytes[1] == 168)
               || (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31)
               || (bytes[0] == 100 && bytes[1] >= 64 && bytes[1] <= 127);
    }

    private static DateTimeOffset AsOffset(DateTime value) =>
        value.Kind == DateTimeKind.Unspecified
            ? new DateTimeOffset(DateTime.SpecifyKind(value, DateTimeKind.Utc))
            : new DateTimeOffset(value);

    public static string FormatDuration(TimeSpan value)
    {
        var abs = value.Duration();
        if (abs.TotalSeconds < 60)
            return $"{abs.TotalSeconds:0}s";
        if (abs.TotalMinutes < 60)
            return $"{abs.TotalMinutes:0.0} minutes";
        if (abs.TotalHours < 48)
            return $"{abs.TotalHours:0.0} hours";
        return $"{abs.TotalDays:0.0} days";
    }

    private static string DescribeSubjectAlternativeNames(X509Certificate2 certificate)
    {
        var extension = certificate.Extensions.OfType<X509SubjectAlternativeNameExtension>().FirstOrDefault();
        if (extension is null)
            return string.Empty;

        var names = new List<string>();
        names.AddRange(extension.EnumerateDnsNames().Select(name => "DNS:" + name));
        names.AddRange(extension.EnumerateIPAddresses().Select(ip => "IP:" + ip));
        return names.Count == 0 ? string.Empty : "Certificate SAN: " + string.Join(", ", names);
    }
}
