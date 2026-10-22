using System.Security.Claims;

namespace McpDotnet.Auth;

/// <summary>
/// Gives tools access to the user's token from the upstream identity provider (for example a Microsoft Graph token
/// when proxying Entra ID), refreshing it when it has expired. Only available with the OAuth proxy.
/// </summary>
public interface IUpstreamTokenProvider
{
    /// <summary>
    /// Gets the upstream access token for <paramref name="user"/>, or <see langword="null"/> if the user did not sign in
    /// through the OAuth proxy or the upstream grant has expired.
    /// </summary>
    Task<string?> GetAccessTokenAsync(ClaimsPrincipal user, CancellationToken cancellationToken = default);
}
