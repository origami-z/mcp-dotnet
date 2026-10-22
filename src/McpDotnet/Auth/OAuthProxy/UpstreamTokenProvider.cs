using System.Security.Claims;
using McpDotnet.Storage;
using Microsoft.Extensions.Logging;

namespace McpDotnet.Auth.OAuthProxy;

internal sealed class UpstreamTokenProvider : IUpstreamTokenProvider
{
    private static readonly TimeSpan RefreshSkew = TimeSpan.FromMinutes(1);

    private readonly IOAuthStateStore _store;
    private readonly UpstreamClient _upstream;
    private readonly OAuthProxyOptions _options;
    private readonly ILogger _logger;

    public UpstreamTokenProvider(IOAuthStateStore store, UpstreamClient upstream, OAuthProxyOptions options, ILogger<UpstreamTokenProvider> logger)
    {
        _store = store;
        _upstream = upstream;
        _options = options;
        _logger = logger;
    }

    public async Task<string?> GetAccessTokenAsync(ClaimsPrincipal user, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(user);
        if (user.FindFirst(TokenService.UpstreamGrantClaim)?.Value is not { } grantId)
        {
            return null;
        }

        var key = StoreKeys.Upstream(grantId);
        var grant = await _store.GetAsync<UpstreamGrant>(key, cancellationToken).ConfigureAwait(false);
        if (grant is null)
        {
            return null;
        }
        if (grant.ExpiresAt is not { } expiresAt || expiresAt - RefreshSkew > DateTimeOffset.UtcNow)
        {
            return grant.AccessToken;
        }
        if (grant.RefreshToken is null)
        {
            return null;
        }

        try
        {
            var refreshed = await _upstream.RefreshAsync(grant.RefreshToken, cancellationToken).ConfigureAwait(false);
            grant = new UpstreamGrant
            {
                AccessToken = refreshed.AccessToken,
                RefreshToken = refreshed.RefreshToken ?? grant.RefreshToken,
                ExpiresAt = refreshed.ExpiresAt,
                Scope = refreshed.Scope ?? grant.Scope,
            };
            await _store.SetAsync(key, grant, _options.RefreshTokenLifetime, cancellationToken).ConfigureAwait(false);
            return grant.AccessToken;
        }
        catch (UpstreamException ex)
        {
            _logger.LogWarning(ex, "Refreshing the upstream access token failed");
            return null;
        }
    }
}
