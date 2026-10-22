using McpDotnet;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>Registers a <see cref="FastMcp"/> server in an ASP.NET Core application.</summary>
public static class FastMcpServiceCollectionExtensions
{
    /// <summary>
    /// Adds the MCP server described by <paramref name="server"/> with the Streamable HTTP transport,
    /// plus its <see cref="FastMcp.Auth"/> provider if one is set. Call
    /// <see cref="Microsoft.AspNetCore.Builder.FastMcpEndpointRouteBuilderExtensions.MapFastMcp"/> to expose it.
    /// </summary>
    /// <returns>The SDK builder, for further configuration.</returns>
    public static IMcpServerBuilder AddFastMcp(this IServiceCollection services, FastMcp server)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(server);
        if (services.Any(d => d.ServiceType == typeof(FastMcp)))
        {
            throw new InvalidOperationException("AddFastMcp has already been called for this service collection.");
        }

        services.TryAddSingleton(server);
        var builder = server.AddCore(services).WithHttpTransport(server.ConfigureHttpTransportOptions);
        server.Auth?.ConfigureServices(services, server);
        return builder;
    }

    /// <summary>Creates, configures and adds a <see cref="FastMcp"/> server.</summary>
    /// <param name="services">The service collection.</param>
    /// <param name="name">The server name reported to clients.</param>
    /// <param name="configure">Registers tools, resources, prompts and auth.</param>
    public static IMcpServerBuilder AddFastMcp(this IServiceCollection services, string name, Action<FastMcp> configure)
    {
        ArgumentNullException.ThrowIfNull(configure);
        var server = new FastMcp(name);
        configure(server);
        return services.AddFastMcp(server);
    }
}
