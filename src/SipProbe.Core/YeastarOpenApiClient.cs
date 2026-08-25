using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;

namespace InspireTel.SipProbe.Core;

public sealed class YeastarOpenApiClient : IDisposable
{
    private readonly HttpClient _http;
    private readonly bool _ownsClient;
    private readonly string _baseUrl;

    public YeastarOpenApiClient(string baseUrl, HttpClient? httpClient = null)
    {
        _baseUrl = NormalizeBaseUrl(baseUrl);
        if (httpClient is null)
        {
            _http = new HttpClient { Timeout = TimeSpan.FromSeconds(20) };
            _ownsClient = true;
        }
        else
        {
            _http = httpClient;
            _ownsClient = false;
        }

        if (_http.DefaultRequestHeaders.UserAgent.Count == 0)
            _http.DefaultRequestHeaders.TryAddWithoutValidation("User-Agent", "OpenAPI");
    }

    public string BaseUrl => _baseUrl;

    public async Task<JsonElement> GetTokenAsync(string clientId, string clientSecret, CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, $"{_baseUrl}/openapi/v1.0/get_token")
        {
            Content = JsonContent(new { username = clientId, password = clientSecret })
        };
        request.Headers.TryAddWithoutValidation("User-Agent", "OpenAPI");
        return await SendAsync(request, cancellationToken);
    }

    public async Task<JsonElement> GetAsync(
        string endpoint,
        string accessToken,
        IReadOnlyDictionary<string, string>? query,
        CancellationToken cancellationToken)
    {
        var url = new StringBuilder($"{_baseUrl}/openapi/v1.0/{endpoint.TrimStart('/')}?access_token={Uri.EscapeDataString(accessToken)}");
        if (query is not null)
        {
            foreach (var pair in query)
                url.Append('&').Append(Uri.EscapeDataString(pair.Key)).Append('=').Append(Uri.EscapeDataString(pair.Value));
        }

        using var request = new HttpRequestMessage(HttpMethod.Get, url.ToString());
        request.Headers.TryAddWithoutValidation("User-Agent", "OpenAPI");
        return await SendAsync(request, cancellationToken);
    }

    public void Dispose()
    {
        if (_ownsClient)
            _http.Dispose();
    }

    private async Task<JsonElement> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        using var response = await _http.SendAsync(request, cancellationToken);
        var body = await response.Content.ReadAsStringAsync(cancellationToken);
        JsonElement document;
        try
        {
            using var parsed = JsonDocument.Parse(string.IsNullOrWhiteSpace(body) ? "{}" : body);
            document = parsed.RootElement.Clone();
        }
        catch (JsonException ex)
        {
            throw new InvalidOperationException(
                $"PBX API returned HTTP {(int)response.StatusCode} with a non-JSON body: {ex.Message}");
        }

        if (document.ValueKind == JsonValueKind.Object &&
            document.TryGetProperty("errcode", out var err) &&
            err.ValueKind == JsonValueKind.Number &&
            err.GetInt32() != 0)
        {
            var message = document.TryGetProperty("errmsg", out var errmsg) ? errmsg.ToString() : "FAILURE";
            throw new YeastarApiException(err.GetInt32(), message, document);
        }

        if (!response.IsSuccessStatusCode)
            throw new InvalidOperationException($"PBX API returned HTTP {(int)response.StatusCode} {response.ReasonPhrase}.");

        return document;
    }

    public static string NormalizeBaseUrl(string value)
    {
        var url = value.Trim();
        if (url.Length == 0)
            throw new ArgumentException("PBX API URL is required.");
        if (!url.Contains("://", StringComparison.Ordinal))
            url = "https://" + url;
        url = url.TrimEnd('/');
        const string openApi = "/openapi/v1.0";
        if (url.EndsWith(openApi, StringComparison.OrdinalIgnoreCase))
            url = url[..^openApi.Length];
        return url;
    }

    private static StringContent JsonContent(object payload) =>
        new(JsonSerializer.Serialize(payload), Encoding.UTF8, new MediaTypeHeaderValue("application/json"));
}

public sealed class YeastarApiException : Exception
{
    public YeastarApiException(int errorCode, string errorMessage, JsonElement body)
        : base($"Yeastar API error {errorCode}: {errorMessage}")
    {
        ErrorCode = errorCode;
        ErrorMessage = errorMessage;
        Body = body;
    }

    public int ErrorCode { get; }
    public string ErrorMessage { get; }
    public JsonElement Body { get; }

    public bool IsMissingInterface =>
        ErrorMessage.Contains("INTERFACE NOT EXIST", StringComparison.OrdinalIgnoreCase) ||
        ErrorMessage.Contains("not exist", StringComparison.OrdinalIgnoreCase);
}
