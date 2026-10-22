using McpDotnet.Storage;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using ModelContextProtocol.Authentication;

namespace McpDotnet.Auth.OAuthProxy;

/// <summary>
/// Makes this server an OAuth 2.1 authorization server for MCP clients while users actually sign in with an
/// upstream identity provider, like FastMCP's <c>OAuthProxy</c>.
/// </summary>
/// <remarks>
/// <para>
/// MCP clients never need a pre-provisioned client ID: they identify themselves with a Client ID Metadata Document
/// URL, register on the fly with Dynamic Client Registration, or use a pre-registered client. The proxy uses its
/// own single client registration with the upstream provider (which needs neither CIMD nor DCR support), keeps the
/// upstream tokens server-side and issues its own short-lived JWTs whose audience is this MCP server.
/// </para>
/// <para>Endpoints mapped relative to the application root:</para>
/// <list type="bullet">
/// <item><c>/.well-known/oauth-protected-resource/{mcp path}</c> (RFC 9728)</item>
/// <item><c>/.well-known/oauth-authorization-server</c> (RFC 8414)</item>
/// <item><c>/authorize</c>, <c>/token</c>, <c>/register</c>, <c>/revoke</c> and the upstream callback</item>
/// </list>
/// </remarks>
public sealed class OAuthProxyProvider : AuthProvider
{
    /// <summary>Creates the provider.</summary>
    public OAuthProxyProvider(OAuthProxyOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        if (string.IsNullOrWhiteSpace(options.BaseUrl)
            || !Uri.TryCreate(options.BaseUrl, UriKind.Absolute, out var baseUri)
            || !string.IsNullOrEmpty(baseUri.Query) || !string.IsNullOrEmpty(baseUri.Fragment))
        {
            throw new ArgumentException("OAuthProxyOptions.BaseUrl must be an absolute URL without query or fragment.", nameof(options));
        }
        if (baseUri.Scheme != Uri.UriSchemeHttps && !baseUri.IsLoopback)
        {
            throw new ArgumentException("OAuthProxyOptions.BaseUrl must use HTTPS unless it is a localhost URL.", nameof(options));
        }
        if (options.Upstream is null)
        {
            throw new ArgumentException("OAuthProxyOptions.Upstream is required.", nameof(options));
        }
        Options = options;
    }

    /// <summary>Creates the provider, configuring the options with a callback.</summary>
    public OAuthProxyProvider(Action<OAuthProxyOptions> configure)
        : this(Configure(configure))
    {
    }

    /// <summary>Gets the options.</summary>
    public OAuthProxyOptions Options { get; }

    /// <inheritdoc />
    protected internal override void ConfigureServices(IServiceCollection services, FastMcp server)
    {
        var issuer = Options.BaseUrl.TrimEnd('/');
        var resource = server.ResourceUrl(Options.BaseUrl);
        var signingKey = new ProxySigningKey(Options.SigningKey);

        services.AddSingleton(Options);
        services.AddSingleton(signingKey);
        services.TryAddSingleton<IOAuthStateStore, InMemoryOAuthStateStore>();
        services.AddMemoryCache();
        services.AddDataProtection();
        services.AddSingleton<ClientMetadataDocumentResolver>();
        services.AddSingleton<ClientRegistry>();
        services.AddSingleton<UpstreamClient>();
        services.AddSingleton<TokenService>();
        services.AddSingleton<OAuthProxyEndpoints>();
        services.AddSingleton<IUpstreamTokenProvider, UpstreamTokenProvider>();

        services.AddHttpClient(ClientMetadataDocumentResolver.HttpClientName, c => c.Timeout = TimeSpan.FromSeconds(10))
            .ConfigurePrimaryHttpMessageHandler(() => ClientMetadataDocumentResolver.CreateHandler(Options.Clients));
        services.AddHttpClient(UpstreamClient.HttpClientName, c => c.Timeout = TimeSpan.FromSeconds(30));

        AddBearerAuthentication(
            services,
            jwt => jwt.TokenValidationParameters = new TokenValidationParameters
            {
                ValidIssuer = issuer,
                ValidAudiences = [resource, resource.TrimEnd('/') + "/"],
                IssuerSigningKey = signingKey.Key,
                ValidAlgorithms = [signingKey.Credentials.Algorithm],
                ValidTypes = ["at+jwt"],
                ClockSkew = TimeSpan.FromSeconds(30),
                NameClaimType = "name",
            },
            mcp =>
            {
                mcp.ResourceMetadataUri = ResourceMetadataUri(Options.BaseUrl, server);
                mcp.ResourceMetadata = new ProtectedResourceMetadata
                {
                    Resource = resource,
                    AuthorizationServers = [issuer],
                    ScopesSupported = [.. Options.ScopesSupported],
                    ResourceName = server.Name,
                };
            });
    }

    /// <inheritdoc />
    protected internal override void MapEndpoints(IEndpointRouteBuilder endpoints, FastMcp server)
    {
        var handlers = endpoints.ServiceProvider.GetRequiredService<OAuthProxyEndpoints>();
        if (endpoints.ServiceProvider.GetRequiredService<ProxySigningKey>().IsEphemeral)
        {
            endpoints.ServiceProvider.GetRequiredService<ILoggerFactory>().CreateLogger<OAuthProxyProvider>().LogWarning(
                "OAuthProxyOptions.SigningKey is not set: using a random key. Issued tokens stop working after a restart " +
                "and are not valid on other instances.");
        }

        var group = endpoints.MapGroup("").AllowAnonymous().ExcludeFromDescription();
        // The consent form carries its own CSRF protection (a token bound to a browser cookie).
        group.MapGet(OAuthProxyEndpoints.MetadataPath, () => handlers.Metadata());
        group.MapGet(OAuthProxyEndpoints.AuthorizePath, Handle(handlers.AuthorizeAsync));
        group.MapPost(OAuthProxyEndpoints.AuthorizePath, Handle(handlers.ConsentAsync)).DisableAntiforgery();
        group.MapGet("/" + Options.CallbackPath.TrimStart('/'), Handle(handlers.CallbackAsync));
        group.MapPost(OAuthProxyEndpoints.TokenPath, Handle(handlers.TokenAsync)).DisableAntiforgery();
        group.MapPost(OAuthProxyEndpoints.RevokePath, Handle(handlers.RevokeAsync)).DisableAntiforgery();
        if (Options.Clients.EnableDynamicClientRegistration)
        {
            group.MapPost(OAuthProxyEndpoints.RegisterPath, Handle(handlers.RegisterAsync));
        }
    }

    // Typed as Func (not RequestDelegate) so minimal APIs write the returned IResult.
    private static Delegate Handle(Func<HttpContext, Task<IResult>> handler) => handler;

    private static OAuthProxyOptions Configure(Action<OAuthProxyOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(configure);
        var options = new OAuthProxyOptions();
        configure(options);
        return options;
    }
}
