using System.Security.Cryptography;
using McpDotnet.Storage;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace McpDotnet.Auth.OAuthProxy;

/// <summary>Issues the proxy's own access tokens (JWTs bound to the MCP resource) and rotating refresh tokens.</summary>
internal sealed class TokenService
{
    /// <summary>Claim linking an access token to the stored upstream tokens.</summary>
    public const string UpstreamGrantClaim = "mcp_upstream_grant";

    private readonly OAuthProxyOptions _options;
    private readonly IOAuthStateStore _store;
    private readonly SigningCredentials _signingCredentials;
    private readonly JsonWebTokenHandler _handler = new();

    public TokenService(OAuthProxyOptions options, IOAuthStateStore store, ProxySigningKey signingKey)
    {
        _options = options;
        _store = store;
        _signingCredentials = signingKey.Credentials;
    }

    public async Task<TokenResponse> IssueAsync(Grant grant, string issuer, CancellationToken cancellationToken)
    {
        var now = DateTime.UtcNow;
        var claims = new Dictionary<string, object>(StringComparer.Ordinal)
        {
            ["sub"] = grant.Subject,
            ["client_id"] = grant.ClientId,
            ["jti"] = OAuthCrypto.RandomToken(),
            [UpstreamGrantClaim] = grant.UpstreamGrantId,
        };
        if (grant.Scopes.Count > 0)
        {
            claims["scope"] = string.Join(' ', grant.Scopes);
        }
        foreach (var (type, value) in grant.Claims)
        {
            claims.TryAdd(type, value);
        }

        var accessToken = _handler.CreateToken(new SecurityTokenDescriptor
        {
            Issuer = issuer,
            Audience = grant.Resource,
            IssuedAt = now,
            NotBefore = now,
            Expires = now + _options.AccessTokenLifetime,
            Claims = claims,
            SigningCredentials = _signingCredentials,
            TokenType = "at+jwt",
        });

        var refreshToken = OAuthCrypto.RandomToken();
        var refreshGrant = grant with { RedirectUri = null, CodeChallenge = null };
        await _store.SetAsync(StoreKeys.RefreshToken(refreshToken), refreshGrant, _options.RefreshTokenLifetime, cancellationToken).ConfigureAwait(false);

        return new TokenResponse(accessToken, (int)_options.AccessTokenLifetime.TotalSeconds, refreshToken, grant.Scopes.Count > 0 ? string.Join(' ', grant.Scopes) : null);
    }
}

internal sealed record TokenResponse(string AccessToken, int ExpiresIn, string RefreshToken, string? Scope);

/// <summary>The key access tokens are signed and validated with.</summary>
internal sealed class ProxySigningKey
{
    public ProxySigningKey(SecurityKey? configured)
    {
        Key = configured ?? new SymmetricSecurityKey(RandomNumberGenerator.GetBytes(32)) { KeyId = "ephemeral" };
        IsEphemeral = configured is null;
        var algorithm = Key switch
        {
            SymmetricSecurityKey => SecurityAlgorithms.HmacSha256,
            ECDsaSecurityKey => SecurityAlgorithms.EcdsaSha256,
            JsonWebKey { Kty: "EC" } => SecurityAlgorithms.EcdsaSha256,
            JsonWebKey { Kty: "oct" } => SecurityAlgorithms.HmacSha256,
            _ => SecurityAlgorithms.RsaSha256,
        };
        Credentials = new SigningCredentials(Key, algorithm);
    }

    public SecurityKey Key { get; }

    public bool IsEphemeral { get; }

    public SigningCredentials Credentials { get; }
}
