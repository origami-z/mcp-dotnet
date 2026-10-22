using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;

namespace McpDotnet.Auth;

/// <summary>
/// Information about the authenticated caller of the current MCP request. Add a parameter of this type to a
/// tool, resource or prompt and it is injected, much like FastMCP's <c>get_access_token()</c>.
/// </summary>
public sealed class McpAuthContext
{
    private readonly IHttpContextAccessor _httpContextAccessor;
    private readonly IServiceProvider _services;

    /// <summary>Creates the context. Normally resolved from dependency injection.</summary>
    public McpAuthContext(IHttpContextAccessor httpContextAccessor, IServiceProvider services)
    {
        _httpContextAccessor = httpContextAccessor;
        _services = services;
    }

    /// <summary>Gets the caller, or an anonymous principal for stdio and unauthenticated servers.</summary>
    public ClaimsPrincipal User => _httpContextAccessor.HttpContext?.User ?? new ClaimsPrincipal(new ClaimsIdentity());

    /// <summary>Gets whether the caller presented a valid access token.</summary>
    public bool IsAuthenticated => User.Identity?.IsAuthenticated == true;

    /// <summary>Gets the subject (<c>sub</c> claim) of the caller.</summary>
    public string? Subject => User.FindFirst("sub")?.Value;

    /// <summary>Gets the OAuth client the caller used (<c>client_id</c> claim).</summary>
    public string? ClientId => User.FindFirst("client_id")?.Value ?? User.FindFirst("azp")?.Value;

    /// <summary>Gets the scopes granted to the access token.</summary>
    public IReadOnlyList<string> Scopes => ScopeHelper.GetScopes(User).ToArray();

    /// <summary>Gets the value of a claim of the caller.</summary>
    public string? GetClaim(string type) => User.FindFirst(type)?.Value;

    /// <summary>
    /// Gets the caller's access token from the upstream identity provider, refreshing it if needed.
    /// Returns <see langword="null"/> when the server doesn't use the OAuth proxy.
    /// </summary>
    public Task<string?> GetUpstreamAccessTokenAsync(CancellationToken cancellationToken = default)
    {
        var provider = _services.GetService<IUpstreamTokenProvider>();
        return provider is null || !IsAuthenticated
            ? Task.FromResult<string?>(null)
            : provider.GetAccessTokenAsync(User, cancellationToken);
    }
}
