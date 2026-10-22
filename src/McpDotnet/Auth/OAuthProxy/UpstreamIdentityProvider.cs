namespace McpDotnet.Auth.OAuthProxy;

/// <summary>
/// The identity provider users actually sign in with (Entra ID, Google, Okta, GitHub, ...). The OAuth proxy
/// uses one pre-registered client ID with it on behalf of all MCP clients, so MCP clients never need one.
/// </summary>
/// <remarks>
/// Register <c>{BaseUrl}/auth/callback</c> as a redirect URI of the upstream application.
/// Use <see cref="Oidc"/> for any OpenID Connect provider, <see cref="EntraId"/> for Microsoft Entra ID, or set
/// the endpoints yourself for plain OAuth 2.0 providers.
/// </remarks>
public sealed class UpstreamIdentityProvider
{
    /// <summary>Gets or sets the client ID registered with the upstream provider.</summary>
    public required string ClientId { get; set; }

    /// <summary>Gets or sets the client secret registered with the upstream provider. <see langword="null"/> for public clients.</summary>
    public string? ClientSecret { get; set; }

    /// <summary>
    /// Gets or sets the OpenID Connect issuer. When set, endpoints not configured explicitly are read from
    /// <c>{Authority}/.well-known/openid-configuration</c>.
    /// </summary>
    public string? Authority { get; set; }

    /// <summary>Gets or sets the authorization endpoint. Discovered from <see cref="Authority"/> if not set.</summary>
    public string? AuthorizationEndpoint { get; set; }

    /// <summary>Gets or sets the token endpoint. Discovered from <see cref="Authority"/> if not set.</summary>
    public string? TokenEndpoint { get; set; }

    /// <summary>
    /// Gets or sets the user info endpoint, used to identify the user when the token response has no ID token.
    /// Discovered from <see cref="Authority"/> if not set.
    /// </summary>
    public string? UserInfoEndpoint { get; set; }

    /// <summary>Gets the scopes requested from the upstream provider.</summary>
    public IList<string> Scopes { get; init; } = ["openid", "profile", "email"];

    /// <summary>Gets or sets the upstream claim that identifies the user; becomes <c>sub</c> in issued tokens. Defaults to <c>sub</c>.</summary>
    public string SubjectClaim { get; set; } = "sub";

    /// <summary>Gets or sets whether the proxy uses PKCE with the upstream provider. Defaults to <see langword="true"/>.</summary>
    public bool UsePkce { get; set; } = true;

    /// <summary>Gets or sets whether the client secret is sent with HTTP Basic authentication instead of in the form body.</summary>
    public bool UseBasicAuthentication { get; set; }

    /// <summary>Gets extra query parameters added to the upstream authorization request (e.g. <c>prompt=select_account</c>).</summary>
    public IDictionary<string, string> AdditionalAuthorizationParameters { get; init; } = new Dictionary<string, string>();

    /// <summary>Creates an upstream for any OpenID Connect provider using discovery.</summary>
    /// <param name="authority">The issuer, e.g. <c>https://accounts.google.com</c>.</param>
    /// <param name="clientId">The client ID registered with the provider.</param>
    /// <param name="clientSecret">The client secret registered with the provider.</param>
    /// <param name="scopes">The scopes to request. Defaults to <c>openid profile email offline_access</c>.</param>
    public static UpstreamIdentityProvider Oidc(string authority, string clientId, string? clientSecret, IEnumerable<string>? scopes = null) => new()
    {
        Authority = authority,
        ClientId = clientId,
        ClientSecret = clientSecret,
        Scopes = scopes?.ToList() ?? ["openid", "profile", "email", "offline_access"],
    };

    /// <summary>Creates an upstream for Microsoft Entra ID (v2.0 endpoints).</summary>
    /// <param name="tenantId">The tenant ID or domain, or <c>organizations</c> / <c>common</c> for multi-tenant apps.</param>
    /// <param name="clientId">The application (client) ID of the app registration.</param>
    /// <param name="clientSecret">A client secret of the app registration.</param>
    /// <param name="scopes">
    /// Extra scopes to request, e.g. <c>User.Read</c> for Microsoft Graph or <c>api://{app-id}/access</c> for your
    /// own API. <c>openid profile email offline_access</c> are always added.
    /// </param>
    /// <param name="cloudInstance">The login host. Defaults to the public cloud.</param>
    public static UpstreamIdentityProvider EntraId(
        string tenantId,
        string clientId,
        string? clientSecret,
        IEnumerable<string>? scopes = null,
        string cloudInstance = "https://login.microsoftonline.com")
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(tenantId);
        var baseUrl = $"{cloudInstance.TrimEnd('/')}/{tenantId}";
        var multiTenant = tenantId is "common" or "organizations" or "consumers";
        return new UpstreamIdentityProvider
        {
            // Multi-tenant ID tokens carry the user's tenant as issuer, so discovery is only used for single tenants.
            Authority = multiTenant ? null : $"{baseUrl}/v2.0",
            AuthorizationEndpoint = $"{baseUrl}/oauth2/v2.0/authorize",
            TokenEndpoint = $"{baseUrl}/oauth2/v2.0/token",
            ClientId = clientId,
            ClientSecret = clientSecret,
            Scopes = ["openid", "profile", "email", "offline_access", .. scopes ?? []],
            // "sub" is pairwise per application in Entra; "oid" is the stable user ID across applications.
            SubjectClaim = "oid",
        };
    }
}
