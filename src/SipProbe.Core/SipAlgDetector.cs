using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text.RegularExpressions;

namespace InspireTel.SipProbe.Core;

public sealed record SipRegisterMessage(
    string Text,
    string ViaValue,
    string ContactUri,
    string Branch,
    string SentByHost,
    int SentByPort);

public enum AlgVerdict
{
    NoRewrite,
    NatMapping,
    AlgRewrite,
    Inconclusive
}

public sealed record AlgAnalysis(
    AlgVerdict Verdict,
    string Summary,
    IReadOnlyList<(DiagnosticLevel Level, string Message)> Findings);

public static class SipAlgDetector
{
    public static AlgAnalysis Analyze(
        SipRegisterMessage sent,
        SipResponse response,
        IPEndPoint local)
    {
        var findings = new List<(DiagnosticLevel, string)>();
        var vias = response.GetHeaders("Via");
        if (vias.Count == 0)
        {
            findings.Add((DiagnosticLevel.Warning,
                "The SIP response had no Via header, so SIP ALG rewrite could not be checked."));
            return new AlgAnalysis(AlgVerdict.Inconclusive, "No Via header to compare.", findings);
        }

        if (vias.Count > 1)
        {
            findings.Add((DiagnosticLevel.Warning,
                $"The response contains {vias.Count} Via headers. An extra Via is unusual for a direct REGISTER to the PBX and can indicate a SIP-aware proxy or ALG."));
        }

        var echoed = ParseVia(vias[0]);
        if (echoed is null)
        {
            findings.Add((DiagnosticLevel.Warning, $"Could not parse the echoed Via: {vias[0]}"));
            return new AlgAnalysis(AlgVerdict.Inconclusive, "Via could not be parsed.", findings);
        }

        findings.Add((DiagnosticLevel.Detail, $"Echoed Via: {vias[0]}"));

        var sentByRewritten = !HostEquals(echoed.Host, sent.SentByHost) || echoed.Port != sent.SentByPort;
        var branchRewritten = !string.IsNullOrEmpty(echoed.Branch) &&
                              !string.Equals(echoed.Branch, sent.Branch, StringComparison.Ordinal);
        var natHints = !string.IsNullOrWhiteSpace(echoed.Received) || echoed.Rport is not null;

        if (echoed.Received is not null)
            findings.Add((DiagnosticLevel.Detail, $"NAT received={echoed.Received} (RFC 3581; this alone is not SIP ALG)."));
        if (echoed.Rport is not null)
            findings.Add((DiagnosticLevel.Detail, $"NAT rport={echoed.Rport} (RFC 3581; this alone is not SIP ALG)."));

        if (sentByRewritten)
        {
            findings.Add((DiagnosticLevel.Warning,
                $"SIP ALG likely: the PBX echoed Via sent-by {FormatHost(echoed.Host)}:{echoed.Port} instead of the address we sent ({FormatHost(sent.SentByHost)}:{sent.SentByPort}). A SIP-aware router rewrote the request."));
        }

        if (branchRewritten)
        {
            findings.Add((DiagnosticLevel.Warning,
                $"SIP ALG likely: the Via branch was rewritten from {sent.Branch} to {echoed.Branch}."));
        }

        var contact = response.GetHeader("Contact");
        if (!string.IsNullOrWhiteSpace(contact))
        {
            var parsedContact = ParseSipUri(contact);
            if (parsedContact is not null &&
                (!HostEquals(parsedContact.Value.Host, sent.SentByHost) ||
                 (parsedContact.Value.Port is not null && parsedContact.Value.Port != sent.SentByPort)))
            {
                if (sentByRewritten)
                {
                    findings.Add((DiagnosticLevel.Warning,
                        $"Contact was also rewritten to {contact.Trim()}. Combined with the Via sent-by change, this is a strong SIP ALG signature."));
                }
                else
                {
                    findings.Add((DiagnosticLevel.Info,
                        $"The registrar stored Contact as {contact.Trim()} rather than the LAN address {sent.ContactUri}. That is normal NAT mapping when Via sent-by was left intact."));
                }
            }
        }

        if (!sentByRewritten && !branchRewritten)
        {
            var localHost = FormatHost(local.Address);
            findings.Add((DiagnosticLevel.Success,
                natHints
                    ? $"No SIP ALG rewrite of Via sent-by or branch. The PBX added NAT mapping on top of {localHost}:{local.Port}."
                    : $"No SIP ALG rewrite detected. Via sent-by {FormatHost(sent.SentByHost)}:{sent.SentByPort} was echoed unchanged."));
            return new AlgAnalysis(
                natHints ? AlgVerdict.NatMapping : AlgVerdict.NoRewrite,
                natHints ? "NAT mapping only; Via sent-by intact." : "No Via/Contact ALG rewrite.",
                findings);
        }

        return new AlgAnalysis(AlgVerdict.AlgRewrite, "SIP ALG rewrite detected on Via/Contact.", findings);
    }

    public static ViaHeader? ParseVia(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
            return null;

        var text = value.Trim();
        var match = Regex.Match(
            text,
            @"^SIP/2\.0/(?<transport>\S+)\s+(?<sentby>.+?)(?:;(?<params>.*))?$",
            RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        if (!match.Success)
            return null;

        if (!TrySplitSentBy(match.Groups["sentby"].Value.Trim(), out var host, out var port))
            return null;

        string? branch = null;
        string? received = null;
        int? rport = null;
        var paramsGroup = match.Groups["params"];
        if (paramsGroup.Success)
        {
            foreach (var part in paramsGroup.Value.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                var separator = part.IndexOf('=');
                var name = (separator < 0 ? part : part[..separator]).Trim();
                var rawValue = separator < 0 ? string.Empty : part[(separator + 1)..].Trim().Trim('"');
                if (name.Equals("branch", StringComparison.OrdinalIgnoreCase))
                    branch = rawValue;
                else if (name.Equals("received", StringComparison.OrdinalIgnoreCase))
                    received = rawValue;
                else if (name.Equals("rport", StringComparison.OrdinalIgnoreCase) &&
                         int.TryParse(rawValue, NumberStyles.None, CultureInfo.InvariantCulture, out var parsedRport))
                    rport = parsedRport;
            }
        }

        return new ViaHeader(match.Groups["transport"].Value.ToUpperInvariant(), host, port, branch, received, rport, text);
    }

    public static (string Host, int? Port)? ParseSipUri(string value)
    {
        var match = Regex.Match(
            value,
            @"sip:([^@;>\s]+@)?(?<host>\[[^\]]+\]|[^;>:]+)(:(?<port>\d+))?",
            RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        if (!match.Success)
            return null;

        var host = UnwrapHost(match.Groups["host"].Value);
        int? port = null;
        if (match.Groups["port"].Success &&
            int.TryParse(match.Groups["port"].Value, NumberStyles.None, CultureInfo.InvariantCulture, out var parsed))
            port = parsed;
        return (host, port);
    }

    public static bool HostEquals(string left, string right) =>
        string.Equals(UnwrapHost(left), UnwrapHost(right), StringComparison.OrdinalIgnoreCase);

    public static string FormatHost(IPAddress address) =>
        address.AddressFamily == AddressFamily.InterNetworkV6 ? $"[{address}]" : address.ToString();

    public static string FormatHost(string host)
    {
        var unwrapped = UnwrapHost(host);
        return IPAddress.TryParse(unwrapped, out var address) && address.AddressFamily == AddressFamily.InterNetworkV6
            ? $"[{address}]"
            : unwrapped;
    }

    public static string UnwrapHost(string host)
    {
        var value = host.Trim();
        if (value.StartsWith('[') && value.EndsWith(']') && value.Length > 2)
            return value[1..^1];
        return value;
    }

    private static bool TrySplitSentBy(string sentBy, out string host, out int port)
    {
        host = string.Empty;
        port = 5060;
        var value = sentBy.Trim();
        if (value.StartsWith('['))
        {
            var close = value.IndexOf(']');
            if (close <= 1)
                return false;
            host = value[1..close];
            if (close + 1 < value.Length && value[close + 1] == ':')
            {
                if (!int.TryParse(value[(close + 2)..], NumberStyles.None, CultureInfo.InvariantCulture, out port))
                    return false;
            }
            return true;
        }

        var separator = value.LastIndexOf(':');
        if (separator > 0 && value.IndexOf(':') == separator)
        {
            host = value[..separator];
            return int.TryParse(value[(separator + 1)..], NumberStyles.None, CultureInfo.InvariantCulture, out port);
        }

        host = value;
        return true;
    }

    public sealed record ViaHeader(
        string Transport,
        string Host,
        int Port,
        string? Branch,
        string? Received,
        int? Rport,
        string Raw);
}
