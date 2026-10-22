using Microsoft.IdentityModel.Tokens;

namespace McpDotnet.Auth.OAuthProxy;

/// <summary>Configures <see cref="OAuthProxyProvider"/>.</summary>
public sealed class OAuthProxyOptions
{
    /// <summary>
    /// Gets or sets the public base URL of this server, e.g. <c>https://mcp.example.com</c>. It is the OAuth issuer,
    /// and the MCP resource is <c>{BaseUrl}{FastMcp.Path}</c>. Required. Must be HTTPS except for localhost.
    /// </summary>
    public string BaseUrl { get; set; } = "";

    /// <summary>Gets or sets the upstream identity provider users sign in with. Required.</summary>
    public UpstreamIdentityProvider Upstream { get; set; } = null!;

    /// <summary>Gets how MCP clients may identify themselves. All mechanisms are enabled by default.</summary>
    public ClientRegistrationOptions Clients { get; } = new();

    /// <summary>
    /// Gets the scopes this server issues and advertises. Empty means clients don't need to request any scope.
    /// These are scopes of the MCP server, not of the upstream provider (see <see cref="UpstreamIdentityProvider.Scopes"/>).
    /// </summary>
    public IList<string> ScopesSupported { get; } = [];

    /// <summary>
    /// Gets or sets whether users see a consent page before being sent to the upstream provider. Defaults to
    /// <see langword="true"/>. Because every client shares the proxy's single upstream client ID, the upstream
    /// provider may skip its own consent screen; this page stops a malicious client from silently obtaining tokens
    /// (the "confused deputy" problem). Only disable it if every client is trusted.
    /// </summary>
    public bool RequireConsent { get; set; } = true;

    /// <summary>Gets or sets the lifetime of issued access tokens. Defaults to one hour.</summary>
    public TimeSpan AccessTokenLifetime { get; set; } = TimeSpan.FromHours(1);

    /// <summary>Gets or sets the lifetime of issued refresh tokens and of the stored upstream tokens. Defaults to 30 days.</summary>
    public TimeSpan RefreshTokenLifetime { get; set; } = TimeSpan.FromDays(30);

    /// <summary>Gets or sets the lifetime of authorization codes. Defaults to five minutes.</summary>
    public TimeSpan AuthorizationCodeLifetime { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>Gets or sets how long a user has to finish signing in. Defaults to fifteen minutes.</summary>
    public TimeSpan AuthorizationTimeout { get; set; } = TimeSpan.FromMinutes(15);

    /// <summary>
    /// Gets or sets the key used to sign issued access tokens (symmetric, RSA or ECDSA). If not set, a random key is
    /// generated at startup: tokens then stop working after a restart and can't be shared between instances.
    /// </summary>
    public SecurityKey? SigningKey { get; set; }

    /// <summary>Gets or sets the path of the upstream redirect URI. Register <c>{BaseUrl}{CallbackPath}</c> with the upstream provider.</summary>
    public string CallbackPath { get; set; } = "/auth/callback";

    /// <summary>
    /// Gets the claims copied from the upstream identity into issued access tokens (and so visible to tools via
    /// <see cref="McpAuthContext"/>).
    /// </summary>
    public IList<string> ForwardedClaims { get; } = ["name", "email", "preferred_username", "given_name", "family_name", "oid", "tid", "login"];

    /// <summary>Gets or sets the display name shown on the consent page. Defaults to the MCP server name.</summary>
    public string? ServerDisplayName { get; set; }
}

/// <summary>Configures how MCP clients may identify themselves to the OAuth proxy.</summary>
public sealed class ClientRegistrationOptions
{
    /// <summary>
    /// Gets or sets whether clients may use an HTTPS URL pointing at their metadata as <c>client_id</c>
    /// (OAuth Client ID Metadata Documents, the MCP-preferred mechanism). Defaults to <see langword="true"/>.
    /// </summary>
    public bool EnableClientIdMetadataDocuments { get; set; } = true;

    /// <summary>Gets or sets whether the RFC 7591 Dynamic Client Registration endpoint is enabled. Defaults to <see langword="true"/>.</summary>
    public bool EnableDynamicClientRegistration { get; set; } = true;

    /// <summary>Gets clients with a fixed <c>client_id</c> configured ahead of time.</summary>
    public IList<PreRegisteredClient> PreRegisteredClients { get; } = [];

    /// <summary>
    /// Gets redirect URI patterns clients may use, with <c>*</c> as a wildcard (e.g. <c>http://127.0.0.1:*</c>,
    /// <c>https://claude.ai/api/mcp/auth_callback</c>). Empty allows any HTTPS URI, any loopback HTTP URI and
    /// private-use schemes for native apps. Doesn't apply to <see cref="PreRegisteredClients"/>.
    /// </summary>
    public IList<string> AllowedRedirectUris { get; } = [];

    /// <summary>
    /// Gets the hosts metadata documents may be fetched from (exact host names or <c>*.example.com</c>).
    /// Empty allows any public host.
    /// </summary>
    public IList<string> AllowedClientMetadataHosts { get; } = [];

    /// <summary>
    /// Gets or sets whether metadata documents may be fetched from private, loopback or link-local addresses.
    /// Defaults to <see langword="false"/> to prevent server-side request forgery.
    /// </summary>
    public bool AllowPrivateNetworkClientMetadata { get; set; }

    /// <summary>Gets or sets the maximum size of a client metadata document in bytes. Defaults to 10 KB.</summary>
    public int MaxClientMetadataBytes { get; set; } = 10 * 1024;

    /// <summary>Gets or sets how long metadata documents are cached when the response has no <c>Cache-Control: max-age</c>. Defaults to five minutes.</summary>
    public TimeSpan ClientMetadataCacheDuration { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>Gets or sets the longest a metadata document is cached, whatever its <c>Cache-Control</c>. Defaults to one day.</summary>
    public TimeSpan MaxClientMetadataCacheDuration { get; set; } = TimeSpan.FromDays(1);

    /// <summary>Gets or sets how long dynamically registered clients are kept. <see langword="null"/> (default) keeps them indefinitely.</summary>
    public TimeSpan? DynamicClientLifetime { get; set; }
}

/// <summary>A client configured ahead of time with a fixed <c>client_id</c>.</summary>
public sealed class PreRegisteredClient
{
    /// <summary>Gets or sets the client ID.</summary>
    public required string ClientId { get; set; }

    /// <summary>Gets or sets the client secret. <see langword="null"/> for public clients, which must use PKCE.</summary>
    public string? ClientSecret { get; set; }

    /// <summary>Gets or sets the allowed redirect URIs (exact match; loopback ports may vary).</summary>
    public required IList<string> RedirectUris { get; set; }

    /// <summary>Gets or sets the name shown on the consent page.</summary>
    public string? ClientName { get; set; }

    /// <summary>Gets or sets whether this client skips the consent page. Defaults to <see langword="false"/>.</summary>
    public bool Trusted { get; set; }
}
