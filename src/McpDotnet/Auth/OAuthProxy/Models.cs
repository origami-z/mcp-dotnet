namespace McpDotnet.Auth.OAuthProxy;

internal enum ClientSource
{
    PreRegistered,
    Dynamic,
    MetadataDocument,
}

/// <summary>A client known to the proxy, however it was registered.</summary>
internal sealed record OAuthClient
{
    public required string ClientId { get; init; }
    public required ClientSource Source { get; init; }
    public required IReadOnlyList<string> RedirectUris { get; init; }
    public string? ClientName { get; init; }
    public string? ClientUri { get; init; }
    public string? LogoUri { get; init; }

    /// <summary>SHA-256 of the client secret; <see langword="null"/> for public clients.</summary>
    public string? ClientSecretHash { get; init; }
    public string TokenEndpointAuthMethod { get; init; } = "none";
    public IReadOnlyList<string> GrantTypes { get; init; } = ["authorization_code", "refresh_token"];
    public bool Trusted { get; init; }
    public long IssuedAt { get; init; }

    public bool IsConfidential => ClientSecretHash is not null;
}

/// <summary>An authorization request waiting for consent and the upstream sign-in.</summary>
internal sealed record PendingAuthorization
{
    public required string Id { get; init; }
    public required string ClientId { get; init; }
    public required string RedirectUri { get; init; }
    public required string CodeChallenge { get; init; }
    public string? State { get; init; }
    public required IReadOnlyList<string> Scopes { get; init; }
    public required string Resource { get; init; }

    /// <summary>Random value also stored in a cookie, binding the flow to the browser that started it.</summary>
    public required string BrowserBinding { get; init; }
    public string? UpstreamCodeVerifier { get; init; }
}

/// <summary>What an authorization code or refresh token grants.</summary>
internal sealed record Grant
{
    public required string ClientId { get; init; }
    public required string Subject { get; init; }
    public required IReadOnlyList<string> Scopes { get; init; }
    public required string Resource { get; init; }
    public required string UpstreamGrantId { get; init; }
    public required Dictionary<string, string> Claims { get; init; }

    // Only set for authorization codes.
    public string? RedirectUri { get; init; }
    public string? CodeChallenge { get; init; }
}

/// <summary>The user's tokens from the upstream provider, kept server-side.</summary>
internal sealed record UpstreamGrant
{
    public required string AccessToken { get; init; }
    public string? RefreshToken { get; init; }
    public DateTimeOffset? ExpiresAt { get; init; }
    public string? Scope { get; init; }
}

internal static class StoreKeys
{
    public static string Client(string clientId) => "client:" + clientId;
    public static string Pending(string id) => "pending:" + id;
    public static string Code(string code) => "code:" + OAuthCrypto.Hash(code);
    public static string RefreshToken(string token) => "refresh:" + OAuthCrypto.Hash(token);
    public static string Upstream(string grantId) => "upstream:" + grantId;
}
