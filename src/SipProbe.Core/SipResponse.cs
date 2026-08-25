using System.Globalization;

namespace InspireTel.SipProbe.Core;

public sealed class SipResponse
{
    private readonly Dictionary<string, List<string>> _headers =
        new(StringComparer.OrdinalIgnoreCase);

    public required string Raw { get; init; }
    public required int StatusCode { get; init; }
    public required string ReasonPhrase { get; init; }
    public IReadOnlyDictionary<string, List<string>> Headers => _headers;

    public string? GetHeader(string name) =>
        _headers.TryGetValue(name, out var values) ? values.FirstOrDefault() : null;

    public static SipResponse Parse(string raw)
    {
        if (string.IsNullOrWhiteSpace(raw))
            throw new FormatException("The SIP response was empty.");

        var headerEnd = raw.IndexOf("\r\n\r\n", StringComparison.Ordinal);
        var headerText = headerEnd >= 0 ? raw[..headerEnd] : raw;
        var physicalLines = headerText.Split(new[] { "\r\n" }, StringSplitOptions.None);
        if (physicalLines.Length == 0 || !physicalLines[0].StartsWith("SIP/2.0 ", StringComparison.OrdinalIgnoreCase))
            throw new FormatException($"Not a SIP response: {physicalLines.FirstOrDefault()}");

        var statusParts = physicalLines[0].Split(' ', 3, StringSplitOptions.RemoveEmptyEntries);
        if (statusParts.Length < 2 || !int.TryParse(statusParts[1], NumberStyles.None, CultureInfo.InvariantCulture, out var code))
            throw new FormatException($"Invalid SIP status line: {physicalLines[0]}");

        var response = new SipResponse
        {
            Raw = raw,
            StatusCode = code,
            ReasonPhrase = statusParts.Length >= 3 ? statusParts[2] : string.Empty
        };

        string? currentName = null;
        var currentValue = string.Empty;

        void CommitHeader()
        {
            if (currentName is null)
                return;
            if (!response._headers.TryGetValue(currentName, out var values))
            {
                values = new List<string>();
                response._headers[currentName] = values;
            }
            values.Add(currentValue.Trim());
        }

        foreach (var line in physicalLines.Skip(1))
        {
            if ((line.StartsWith(' ') || line.StartsWith('\t')) && currentName is not null)
            {
                currentValue += " " + line.Trim();
                continue;
            }

            CommitHeader();
            var separator = line.IndexOf(':');
            if (separator <= 0)
            {
                currentName = null;
                currentValue = string.Empty;
                continue;
            }

            currentName = line[..separator].Trim();
            currentValue = line[(separator + 1)..].Trim();
        }
        CommitHeader();

        return response;
    }
}
