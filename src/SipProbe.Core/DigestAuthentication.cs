using System.Security.Cryptography;
using System.Text;

namespace InspireTel.SipProbe.Core;

public sealed record DigestChallenge(
    string Realm,
    string Nonce,
    string Algorithm,
    string? Qop,
    string? Opaque,
    bool IsProxy)
{
    public static DigestChallenge Parse(string value, bool isProxy)
    {
        if (string.IsNullOrWhiteSpace(value))
            throw new FormatException("Digest challenge is empty.");

        var trimmed = value.Trim();
        if (!trimmed.StartsWith("Digest ", StringComparison.OrdinalIgnoreCase))
            throw new NotSupportedException($"Only Digest authentication is supported. Challenge: {trimmed.Split(' ', 2)[0]}");

        var fields = SplitFields(trimmed[7..])
            .Select(part => part.Split('=', 2))
            .Where(parts => parts.Length == 2)
            .ToDictionary(
                parts => parts[0].Trim(),
                parts => Unquote(parts[1].Trim()),
                StringComparer.OrdinalIgnoreCase);

        if (!fields.TryGetValue("realm", out var realm) || string.IsNullOrEmpty(realm))
            throw new FormatException("Digest challenge has no realm.");
        if (!fields.TryGetValue("nonce", out var nonce) || string.IsNullOrEmpty(nonce))
            throw new FormatException("Digest challenge has no nonce.");

        fields.TryGetValue("algorithm", out var algorithm);
        fields.TryGetValue("qop", out var qopList);
        fields.TryGetValue("opaque", out var opaque);

        string? qop = null;
        if (!string.IsNullOrWhiteSpace(qopList))
        {
            qop = qopList.Split(',')
                .Select(item => item.Trim())
                .FirstOrDefault(item => item.Equals("auth", StringComparison.OrdinalIgnoreCase));
            if (qop is null)
                throw new NotSupportedException($"Server offered unsupported digest qop: {qopList}");
        }

        return new DigestChallenge(realm, nonce, algorithm ?? "MD5", qop, opaque, isProxy);
    }

    public string CreateAuthorization(
        string username,
        string password,
        string method,
        string uri,
        string nonceCount = "00000001",
        string? cnonce = null)
    {
        cnonce ??= Convert.ToHexString(RandomNumberGenerator.GetBytes(12)).ToLowerInvariant();
        var algorithm = Algorithm.Trim();
        var session = algorithm.EndsWith("-sess", StringComparison.OrdinalIgnoreCase);
        var baseAlgorithm = session ? algorithm[..^5] : algorithm;

        var ha1 = HashHex(baseAlgorithm, $"{username}:{Realm}:{password}");
        if (session)
            ha1 = HashHex(baseAlgorithm, $"{ha1}:{Nonce}:{cnonce}");
        var ha2 = HashHex(baseAlgorithm, $"{method}:{uri}");
        var response = Qop is null
            ? HashHex(baseAlgorithm, $"{ha1}:{Nonce}:{ha2}")
            : HashHex(baseAlgorithm, $"{ha1}:{Nonce}:{nonceCount}:{cnonce}:{Qop}:{ha2}");

        var items = new List<string>
        {
            $"username=\"{Escape(username)}\"",
            $"realm=\"{Escape(Realm)}\"",
            $"nonce=\"{Escape(Nonce)}\"",
            $"uri=\"{Escape(uri)}\"",
            $"response=\"{response}\"",
            $"algorithm={algorithm}"
        };

        if (!string.IsNullOrEmpty(Opaque))
            items.Add($"opaque=\"{Escape(Opaque)}\"");
        if (Qop is not null)
        {
            items.Add($"qop={Qop}");
            items.Add($"nc={nonceCount}");
            items.Add($"cnonce=\"{cnonce}\"");
        }

        return "Digest " + string.Join(", ", items);
    }

    private static string HashHex(string algorithm, string value)
    {
        var bytes = Encoding.UTF8.GetBytes(value);
        byte[] digest = algorithm.ToUpperInvariant() switch
        {
            "MD5" => MD5.HashData(bytes),
            "SHA-256" => SHA256.HashData(bytes),
            _ => throw new NotSupportedException($"Digest algorithm '{algorithm}' is not supported.")
        };
        return Convert.ToHexString(digest).ToLowerInvariant();
    }

    private static IEnumerable<string> SplitFields(string input)
    {
        var start = 0;
        var quoted = false;
        var escaped = false;
        for (var i = 0; i < input.Length; i++)
        {
            var c = input[i];
            if (escaped)
            {
                escaped = false;
                continue;
            }
            if (c == '\\' && quoted)
            {
                escaped = true;
                continue;
            }
            if (c == '"')
            {
                quoted = !quoted;
                continue;
            }
            if (c == ',' && !quoted)
            {
                yield return input[start..i].Trim();
                start = i + 1;
            }
        }
        if (start < input.Length)
            yield return input[start..].Trim();
    }

    private static string Unquote(string value) =>
        value.Length >= 2 && value[0] == '"' && value[^1] == '"'
            ? value[1..^1].Replace("\\\"", "\"").Replace("\\\\", "\\")
            : value;

    private static string Escape(string value) => value.Replace("\\", "\\\\").Replace("\"", "\\\"");
}
