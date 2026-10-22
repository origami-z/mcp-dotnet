using Microsoft.Extensions.DependencyInjection;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using ModelContextProtocol.Authentication;

namespace McpDotnet.Auth;

/// <summary>
/// Resource-server-only authentication: access tokens are issued by an external authorization server
/// (Auth0, Keycloak, WorkOS, ...) and validated here. Use this when that server already supports
/// Client ID Metadata Documents or Dynamic Client Registration itself; otherwise use
/// <see cref="OAuthProxy.OAuthProxyProvider"/>.
/// </summary>
public sealed class RemoteAuthProvider : AuthProvider
{
    /// <summary>Creates the provider.</summary>
    /// <param name="authority">The issuer of the external authorization server. Its OpenID/OAuth metadata is used to validate tokens.</param>
    /// <param name="baseUrl">The public base URL of this server, e.g. <c>https://mcp.example.com</c>.</param>
    public RemoteAuthProvider(string authority, string baseUrl)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(authority);
        ArgumentException.ThrowIfNullOrWhiteSpace(baseUrl);
        Authority = authority;
        BaseUrl = baseUrl;
    }

    /// <summary>Gets the issuer of the external authorization server.</summary>
    public string Authority { get; }

    /// <summary>Gets the public base URL of this server.</summary>
    public string BaseUrl { get; }

    /// <summary>Gets or sets the expected token audience. Defaults to the MCP endpoint URL (RFC 8707 resource).</summary>
    public string? Audience { get; init; }

    /// <summary>Gets the scopes advertised in the protected resource metadata.</summary>
    public IList<string> ScopesSupported { get; init; } = [];

    /// <summary>Gets or sets a callback for further JWT bearer configuration.</summary>
    public Action<JwtBearerOptions>? ConfigureJwtBearer { get; init; }

    /// <inheritdoc />
    protected internal override void ConfigureServices(IServiceCollection services, FastMcp server)
    {
        var resource = server.ResourceUrl(BaseUrl);
        AddBearerAuthentication(
            services,
            jwt =>
            {
                jwt.Authority = Authority;
                jwt.Audience = Audience ?? resource;
                jwt.RequireHttpsMetadata = Authority.StartsWith("https://", StringComparison.OrdinalIgnoreCase);
                ConfigureJwtBearer?.Invoke(jwt);
            },
            mcp =>
            {
                mcp.ResourceMetadataUri = ResourceMetadataUri(BaseUrl, server);
                mcp.ResourceMetadata = new ProtectedResourceMetadata
                {
                    Resource = resource,
                    AuthorizationServers = [Authority],
                    ScopesSupported = [.. ScopesSupported],
                };
            });
    }
}
