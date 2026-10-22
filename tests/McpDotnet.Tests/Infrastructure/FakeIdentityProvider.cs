using System.Collections.Concurrent;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace McpDotnet.Tests.Infrastructure;

/// <summary>A minimal OpenID Connect provider: discovery, a scripted sign-in and the token endpoint.</summary>
internal sealed class FakeIdentityProvider : HttpMessageHandler
{
    public const string Issuer = "https://idp.test";
    public const string ClientId = "upstream-client";
    public const string ClientSecret = "upstream-secret";

    private readonly ConcurrentDictionary<string, (string Challenge, string RedirectUri)> _codes = new();
    private int _accessTokenCounter;

    public string UserId { get; set; } = "user-123";

    public string UserName { get; set; } = "Ada Lovelace";

    public int TokenRequests;

    public int RefreshRequests;

    /// <summary>Lifetime of issued upstream access tokens.</summary>
    public int ExpiresInSeconds { get; set; } = 3600;

    public string LastAccessToken => "upstream-access-" + _accessTokenCounter;

    /// <summary>Simulates the user signing in: validates the request and returns the callback URL.</summary>
    public Uri SignIn(Uri authorizeUrl)
    {
        var query = QueryHelpers.ParseQuery(authorizeUrl.Query);
        Assert.Equal(Issuer + "/authorize", authorizeUrl.GetLeftPart(UriPartial.Path));
        Assert.Equal(ClientId, query["client_id"].ToString());
        Assert.Equal("code", query["response_type"].ToString());
        Assert.Equal("S256", query["code_challenge_method"].ToString());

        var code = "upstream-code-" + Guid.NewGuid().ToString("N");
        var redirectUri = query["redirect_uri"].ToString();
        _codes[code] = (query["code_challenge"].ToString(), redirectUri);
        return new Uri(QueryHelpers.AddQueryString(redirectUri, new Dictionary<string, string?>
        {
            ["code"] = code,
            ["state"] = query["state"].ToString(),
        }));
    }

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var url = request.RequestUri!.ToString();
        if (url == Issuer + "/.well-known/openid-configuration")
        {
            return Json(new
            {
                issuer = Issuer,
                authorization_endpoint = Issuer + "/authorize",
                token_endpoint = Issuer + "/token",
            });
        }

        if (url == Issuer + "/token" && request.Method == HttpMethod.Post)
        {
            Interlocked.Increment(ref TokenRequests);
            var form = QueryHelpers.ParseQuery(await request.Content!.ReadAsStringAsync(cancellationToken));
            if (form["client_id"] != ClientId || form["client_secret"] != ClientSecret)
            {
                return Error("invalid_client");
            }

            if (form["grant_type"] == "authorization_code")
            {
                if (!_codes.TryRemove(form["code"].ToString(), out var issued)
                    || issued.RedirectUri != form["redirect_uri"]
                    || issued.Challenge != WebEncoders.Base64UrlEncode(SHA256.HashData(Encoding.ASCII.GetBytes(form["code_verifier"].ToString()))))
                {
                    return Error("invalid_grant");
                }
                return Json(new
                {
                    access_token = NextAccessToken(),
                    refresh_token = "upstream-refresh",
                    id_token = CreateIdToken(),
                    expires_in = ExpiresInSeconds,
                    token_type = "Bearer",
                });
            }

            if (form["grant_type"] == "refresh_token" && form["refresh_token"] == "upstream-refresh")
            {
                Interlocked.Increment(ref RefreshRequests);
                return Json(new { access_token = NextAccessToken(), expires_in = 3600, token_type = "Bearer" });
            }
            return Error("invalid_grant");
        }

        return new HttpResponseMessage(HttpStatusCode.NotFound);
    }

    private string NextAccessToken() => "upstream-access-" + Interlocked.Increment(ref _accessTokenCounter);

    private string CreateIdToken() => new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
    {
        Issuer = Issuer,
        Audience = ClientId,
        Claims = new Dictionary<string, object>
        {
            ["sub"] = UserId,
            ["name"] = UserName,
            ["email"] = "ada@example.com",
        },
        SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(RandomNumberGenerator.GetBytes(32)), SecurityAlgorithms.HmacSha256),
    });

    private static HttpResponseMessage Json(object body) => new(HttpStatusCode.OK)
    {
        Content = new StringContent(JsonSerializer.Serialize(body), Encoding.UTF8, "application/json"),
    };

    private static HttpResponseMessage Error(string error) => new(HttpStatusCode.BadRequest)
    {
        Content = new StringContent(JsonSerializer.Serialize(new { error }), Encoding.UTF8, "application/json"),
    };
}
