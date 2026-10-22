using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.JsonWebTokens;

namespace McpDotnet.Auth.OAuthProxy;

/// <summary>Talks to the upstream identity provider: discovery, code exchange, refresh and user info.</summary>
internal sealed class UpstreamClient
{
    public const string HttpClientName = "McpDotnet.Upstream";

    private readonly UpstreamIdentityProvider _upstream;
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly ILogger _logger;
    private readonly SemaphoreSlim _discoveryLock = new(1, 1);
    private Endpoints? _endpoints;

    public UpstreamClient(OAuthProxyOptions options, IHttpClientFactory httpClientFactory, ILogger<UpstreamClient> logger)
    {
        _upstream = options.Upstream;
        _httpClientFactory = httpClientFactory;
        _logger = logger;
    }

    public async Task<string> BuildAuthorizationUrlAsync(string redirectUri, string state, string? codeVerifier, CancellationToken cancellationToken)
    {
        var endpoints = await GetEndpointsAsync(cancellationToken).ConfigureAwait(false);
        var query = new Dictionary<string, string?>
        {
            ["response_type"] = "code",
            ["client_id"] = _upstream.ClientId,
            ["redirect_uri"] = redirectUri,
            ["scope"] = string.Join(' ', _upstream.Scopes.Distinct(StringComparer.Ordinal)),
            ["state"] = state,
        };
        if (codeVerifier is not null)
        {
            query["code_challenge"] = OAuthCrypto.CodeChallenge(codeVerifier);
            query["code_challenge_method"] = "S256";
        }
        foreach (var (key, value) in _upstream.AdditionalAuthorizationParameters)
        {
            query[key] = value;
        }
        return QueryHelpers.AddQueryString(endpoints.Authorization, query);
    }

    public Task<UpstreamTokenResponse> ExchangeCodeAsync(string code, string redirectUri, string? codeVerifier, CancellationToken cancellationToken)
    {
        var form = new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code",
            ["code"] = code,
            ["redirect_uri"] = redirectUri,
        };
        if (codeVerifier is not null)
        {
            form["code_verifier"] = codeVerifier;
        }
        return RequestTokenAsync(form, cancellationToken);
    }

    public Task<UpstreamTokenResponse> RefreshAsync(string refreshToken, CancellationToken cancellationToken) =>
        RequestTokenAsync(new Dictionary<string, string>
        {
            ["grant_type"] = "refresh_token",
            ["refresh_token"] = refreshToken,
        }, cancellationToken);

    /// <summary>
    /// Gets the user's claims: from the ID token when there is one (it came straight from the token endpoint over
    /// TLS, so per OpenID Connect Core 3.1.3.7 its signature needn't be checked), otherwise from the user info endpoint.
    /// </summary>
    public async Task<Dictionary<string, string>> GetUserClaimsAsync(UpstreamTokenResponse tokens, CancellationToken cancellationToken)
    {
        var endpoints = await GetEndpointsAsync(cancellationToken).ConfigureAwait(false);
        if (tokens.IdToken is { } idToken)
        {
            var jwt = new JsonWebToken(idToken);
            if (!jwt.Audiences.Contains(_upstream.ClientId, StringComparer.Ordinal))
            {
                throw new UpstreamException("The upstream ID token was issued to a different client.");
            }
            if (endpoints.Issuer is { } issuer && !string.Equals(jwt.Issuer, issuer, StringComparison.Ordinal))
            {
                throw new UpstreamException("The upstream ID token has an unexpected issuer.");
            }
            return jwt.Claims
                .GroupBy(c => c.Type, StringComparer.Ordinal)
                .ToDictionary(g => g.Key, g => g.First().Value, StringComparer.Ordinal);
        }

        if (endpoints.UserInfo is null)
        {
            throw new UpstreamException("The upstream provider returned no ID token and no user info endpoint is configured.");
        }

        using var request = new HttpRequestMessage(HttpMethod.Get, endpoints.UserInfo);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", tokens.AccessToken);
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        request.Headers.UserAgent.Add(new ProductInfoHeaderValue("McpDotnet", "1.0"));
        using var response = await Http.SendAsync(request, cancellationToken).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
        {
            throw new UpstreamException($"The upstream user info endpoint returned HTTP {(int)response.StatusCode}.");
        }
        using var document = await JsonDocument.ParseAsync(
            await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false),
            cancellationToken: cancellationToken).ConfigureAwait(false);

        var claims = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var property in document.RootElement.EnumerateObject())
        {
            if (property.Value.ValueKind is JsonValueKind.String or JsonValueKind.Number or JsonValueKind.True or JsonValueKind.False)
            {
                claims[property.Name] = property.Value.ValueKind == JsonValueKind.String ? property.Value.GetString()! : property.Value.GetRawText();
            }
        }
        return claims;
    }

    private HttpClient Http => _httpClientFactory.CreateClient(HttpClientName);

    private async Task<UpstreamTokenResponse> RequestTokenAsync(Dictionary<string, string> form, CancellationToken cancellationToken)
    {
        var endpoints = await GetEndpointsAsync(cancellationToken).ConfigureAwait(false);
        using var request = new HttpRequestMessage(HttpMethod.Post, endpoints.Token);
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        if (_upstream.UseBasicAuthentication && _upstream.ClientSecret is not null)
        {
            var credentials = Uri.EscapeDataString(_upstream.ClientId) + ":" + Uri.EscapeDataString(_upstream.ClientSecret);
            request.Headers.Authorization = new AuthenticationHeaderValue("Basic", Convert.ToBase64String(Encoding.UTF8.GetBytes(credentials)));
        }
        else
        {
            form["client_id"] = _upstream.ClientId;
            if (_upstream.ClientSecret is not null)
            {
                form["client_secret"] = _upstream.ClientSecret;
            }
        }
        request.Content = new FormUrlEncodedContent(form);

        using var response = await Http.SendAsync(request, cancellationToken).ConfigureAwait(false);
        var body = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
        {
            _logger.LogWarning("Upstream token request failed with HTTP {StatusCode}: {Body}", (int)response.StatusCode, body);
            throw new UpstreamException($"The upstream token endpoint returned HTTP {(int)response.StatusCode}.");
        }

        using var document = JsonDocument.Parse(body);
        var root = document.RootElement;
        var accessToken = GetString(root, "access_token") ?? throw new UpstreamException("The upstream token response has no access_token.");
        DateTimeOffset? expiresAt = root.TryGetProperty("expires_in", out var expiresIn)
            && (expiresIn.ValueKind == JsonValueKind.Number ? expiresIn.TryGetInt64(out var seconds) : long.TryParse(expiresIn.GetString(), out seconds))
            ? DateTimeOffset.UtcNow.AddSeconds(seconds)
            : null;
        return new UpstreamTokenResponse(
            accessToken,
            GetString(root, "refresh_token"),
            GetString(root, "id_token"),
            expiresAt,
            GetString(root, "scope"));
    }

    private static string? GetString(JsonElement element, string name) =>
        element.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() : null;

    private async Task<Endpoints> GetEndpointsAsync(CancellationToken cancellationToken)
    {
        if (_endpoints is { } endpoints)
        {
            return endpoints;
        }

        await _discoveryLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (_endpoints is not null)
            {
                return _endpoints;
            }

            string? issuer = null, authorization = _upstream.AuthorizationEndpoint, token = _upstream.TokenEndpoint, userInfo = _upstream.UserInfoEndpoint;
            if (_upstream.Authority is { } authority)
            {
                var url = authority.TrimEnd('/') + "/.well-known/openid-configuration";
                using var response = await Http.GetAsync(url, cancellationToken).ConfigureAwait(false);
                if (!response.IsSuccessStatusCode)
                {
                    throw new UpstreamException($"OpenID Connect discovery at {url} returned HTTP {(int)response.StatusCode}.");
                }
                using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false));
                var root = document.RootElement;
                issuer = GetString(root, "issuer");
                authorization ??= GetString(root, "authorization_endpoint");
                token ??= GetString(root, "token_endpoint");
                userInfo ??= GetString(root, "userinfo_endpoint");
            }

            if (authorization is null || token is null)
            {
                throw new InvalidOperationException(
                    "The upstream identity provider needs an Authority for discovery, or explicit AuthorizationEndpoint and TokenEndpoint.");
            }
            return _endpoints = new Endpoints(issuer, authorization, token, userInfo);
        }
        finally
        {
            _discoveryLock.Release();
        }
    }

    private sealed record Endpoints(string? Issuer, string Authorization, string Token, string? UserInfo);
}

internal sealed record UpstreamTokenResponse(string AccessToken, string? RefreshToken, string? IdToken, DateTimeOffset? ExpiresAt, string? Scope);

internal sealed class UpstreamException(string message) : Exception(message);
