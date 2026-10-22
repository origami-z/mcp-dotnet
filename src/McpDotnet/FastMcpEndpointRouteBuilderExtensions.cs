using McpDotnet;
using McpDotnet.Auth;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;

namespace Microsoft.AspNetCore.Builder;

/// <summary>Maps the endpoints of a <see cref="FastMcp"/> server.</summary>
public static class FastMcpEndpointRouteBuilderExtensions
{
    /// <summary>
    /// Maps the MCP endpoint at <see cref="FastMcp.Path"/>. When an <see cref="AuthProvider"/> is configured,
    /// also maps its endpoints (metadata, authorize, token, register, ...) and requires authorization on the MCP endpoint.
    /// </summary>
    public static IEndpointConventionBuilder MapFastMcp(this IEndpointRouteBuilder endpoints)
    {
        ArgumentNullException.ThrowIfNull(endpoints);
        var server = endpoints.ServiceProvider.GetService<FastMcp>()
            ?? throw new InvalidOperationException("Call services.AddFastMcp(...) before MapFastMcp().");

        var mcp = endpoints.MapMcp(server.Path);
        if (server.Auth is { } auth)
        {
            auth.MapEndpoints(endpoints, server);
            mcp.RequireAuthorization(AuthProvider.AuthorizationPolicyName);
        }
        return mcp;
    }
}
