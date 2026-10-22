// An existing ASP.NET Core app that adds an MCP endpoint protected by Microsoft Entra ID.
// MCP clients (Claude, VS Code, Cursor, ...) connect to {BaseUrl}/mcp without any client ID:
// they identify themselves with a Client ID Metadata Document or register dynamically, and the
// OAuth proxy signs users in with the single Entra app registration configured below.

using System.ComponentModel;
using System.Net.Http.Headers;
using McpDotnet;
using McpDotnet.Auth;
using McpDotnet.Auth.OAuthProxy;
using Microsoft.IdentityModel.Tokens;

var builder = WebApplication.CreateBuilder(args);
var entra = builder.Configuration.GetSection("Entra");
var baseUrl = builder.Configuration["BaseUrl"] ?? "http://localhost:5000";

var mcp = new FastMcp("Contoso Directory", instructions: "Look up information about the signed-in user.")
{
    Auth = new OAuthProxyProvider(options =>
    {
        options.BaseUrl = baseUrl;
        options.Upstream = UpstreamIdentityProvider.EntraId(
            tenantId: entra["TenantId"] ?? throw new InvalidOperationException("Set Entra:TenantId"),
            clientId: entra["ClientId"] ?? throw new InvalidOperationException("Set Entra:ClientId"),
            clientSecret: entra["ClientSecret"],
            scopes: ["User.Read"]);

        // A stable key keeps issued tokens valid across restarts and instances.
        if (builder.Configuration["SigningKey"] is { } signingKey)
        {
            options.SigningKey = new SymmetricSecurityKey(Convert.FromBase64String(signingKey));
        }
    }),
};

mcp.Tool("whoami", (McpAuthContext auth) => new
{
    auth.Subject,
    Name = auth.GetClaim("name"),
    Email = auth.GetClaim("preferred_username"),
    Tenant = auth.GetClaim("tid"),
    auth.ClientId,
}, "Returns who you are signed in as.");

mcp.Tool(GetMyProfile);

mcp.Resource("contoso://about", () => "Contoso Directory MCP server, powered by McpDotnet.", mimeType: "text/plain");

mcp.Prompt("summarize_profile", () => "Call get_my_profile and summarize it in two sentences.");

builder.Services.AddHttpClient("graph", c => c.BaseAddress = new Uri("https://graph.microsoft.com/v1.0/"));
builder.Services.AddFastMcp(mcp);

var app = builder.Build();
app.MapGet("/", () => "Hello from an ordinary ASP.NET Core app. The MCP endpoint is at /mcp.");
app.MapFastMcp();
app.Run();

[Description("Gets the signed-in user's Microsoft Graph profile.")]
static async Task<string> GetMyProfile(McpAuthContext auth, IHttpClientFactory httpClientFactory, CancellationToken cancellationToken)
{
    // The proxy keeps the user's Entra token server-side and refreshes it when needed.
    var token = await auth.GetUpstreamAccessTokenAsync(cancellationToken)
        ?? throw new InvalidOperationException("No Microsoft Graph token is available; sign in again.");
    using var request = new HttpRequestMessage(HttpMethod.Get, "me");
    request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
    using var response = await httpClientFactory.CreateClient("graph").SendAsync(request, cancellationToken);
    return await response.Content.ReadAsStringAsync(cancellationToken);
}
