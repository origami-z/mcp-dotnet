using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using ModelContextProtocol.AspNetCore.Authentication;

namespace McpDotnet.Auth;

/// <summary>
/// Protects the MCP endpoint of a <see cref="FastMcp"/> server. Built-in providers are
/// <see cref="OAuthProxy.OAuthProxyProvider"/> (this server acts as the authorization server and proxies login
/// to an upstream identity provider) and <see cref="RemoteAuthProvider"/> (tokens come from an external
/// authorization server).
/// </summary>
public abstract class AuthProvider
{
    /// <summary>The authorization policy applied to the MCP endpoint.</summary>
    public const string AuthorizationPolicyName = "McpDotnet";

    /// <summary>The JWT bearer authentication scheme used to validate access tokens on the MCP endpoint.</summary>
    public const string BearerScheme = "McpDotnet.Bearer";

    /// <summary>Gets the scopes every access token must carry to call the MCP endpoint.</summary>
    public IList<string> RequiredScopes { get; init; } = [];

    /// <summary>Registers the services the provider needs.</summary>
    protected internal abstract void ConfigureServices(IServiceCollection services, FastMcp server);

    /// <summary>Maps any HTTP endpoints the provider needs, alongside the MCP endpoint.</summary>
    protected internal virtual void MapEndpoints(IEndpointRouteBuilder endpoints, FastMcp server)
    {
    }

    /// <summary>
    /// The RFC 9728 metadata URL for the MCP endpoint, built from the configured public base URL rather than the
    /// request host so challenges stay correct behind reverse proxies.
    /// </summary>
    protected static Uri ResourceMetadataUri(string baseUrl, FastMcp server)
    {
        ArgumentNullException.ThrowIfNull(server);
        return new Uri(baseUrl.TrimEnd('/') + "/.well-known/oauth-protected-resource/" + server.Path.Trim('/'));
    }

    /// <summary>
    /// Adds JWT bearer validation for the MCP endpoint, the SDK's MCP authentication handler (which serves
    /// RFC 9728 protected resource metadata and issues <c>WWW-Authenticate</c> challenges), and the
    /// <see cref="AuthorizationPolicyName"/> policy. The application's default schemes are left untouched.
    /// </summary>
    protected AuthenticationBuilder AddBearerAuthentication(
        IServiceCollection services,
        Action<JwtBearerOptions> configureJwtBearer,
        Action<McpAuthenticationOptions> configureMcp)
    {
        ArgumentNullException.ThrowIfNull(services);
        var requiredScopes = RequiredScopes.ToArray();
        services.AddAuthorizationBuilder().AddPolicy(AuthorizationPolicyName, policy =>
        {
            policy.AddAuthenticationSchemes(BearerScheme);
            policy.RequireAuthenticatedUser();
            if (requiredScopes.Length > 0)
            {
                policy.RequireAssertion(ctx => requiredScopes.All(scope => ScopeHelper.HasScope(ctx.User, scope)));
            }
        });

        return services.AddAuthentication()
            .AddJwtBearer(BearerScheme, options =>
            {
                options.MapInboundClaims = false;
                // Challenges go to the MCP handler so 401s point clients at the resource metadata document.
                options.ForwardChallenge = McpAuthenticationDefaults.AuthenticationScheme;
                configureJwtBearer(options);
            })
            .AddMcp(configureMcp);
    }
}
