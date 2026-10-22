# McpDotnet

A [FastMCP](https://gofastmcp.com)-style library for building [Model Context Protocol](https://modelcontextprotocol.io) servers in .NET, built on the official [MCP C# SDK](https://github.com/modelcontextprotocol/csharp-sdk).

- **Little ceremony.** A tool is one line, and MCP fits into an existing ASP.NET Core app with two calls.
- **Clients need no client ID.** The built-in OAuth proxy accepts three kinds of client:
  - [Client ID Metadata Documents](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization) (CIMD), the MCP-preferred mechanism
  - [Dynamic Client Registration](https://datatracker.ietf.org/doc/html/rfc7591) (DCR)
  - classic pre-registered clients

  Users sign in with your existing identity provider (Entra ID, Google, Okta, Auth0, GitHub, ...) through one app registration, even if that provider supports neither CIMD nor DCR.
- **Targets .NET 8 and .NET 10.**

```csharp
var mcp = new FastMcp("Calculator");
mcp.Tool("add", (double a, double b) => a + b, "Adds two numbers.");
await mcp.RunAsync(args); // stdio by default; "--transport http" for Streamable HTTP
```

## Contents

- [Defining a server](#defining-a-server)
- [Running it](#running-it)
- [Authentication](#authentication)
  - [OAuth proxy (recommended)](#oauth-proxy-recommended)
  - [How clients connect without a client ID](#how-clients-connect-without-a-client-id)
  - [Using the caller's identity in tools](#using-the-callers-identity-in-tools)
  - [Remote authorization server](#remote-authorization-server)
  - [Production checklist](#production-checklist)
- [Security model](#security-model)
- [Samples](#samples)
- [Building](#building)

## Defining a server

```csharp
using System.ComponentModel;
using McpDotnet;

var mcp = new FastMcp("Weather", version: "1.2.0", instructions: "Use get_forecast for forecasts.");

// Lambdas need a name; method groups and local functions use their own name and [Description].
mcp.Tool("get_forecast", async (string city, int days, IWeatherService weather, CancellationToken ct) =>
    await weather.GetForecastAsync(city, days, ct), "Gets the forecast for a city.");

mcp.Tool(GetAlerts, configure: o => o.ReadOnly = true);

// Resources and resource templates
mcp.Resource("weather://stations", () => File.ReadAllText("stations.json"), mimeType: "application/json");
mcp.Resource("weather://stations/{id}", (string id) => $"Station {id}", name: "station");

// Prompts
mcp.Prompt("plan_trip", (string city) => $"Check the forecast for {city} and suggest what to pack.");

// Attribute-based classes from the official SDK work too
mcp.Tools<MyAttributedTools>();       // or .Resources<T>(), .Prompts<T>(), .FromAssembly()

[Description("Lists active weather alerts.")]
static string[] GetAlerts(string region) => [];
```

Tool parameters become the JSON input schema. These parameter types are injected instead of coming from the input:

| Parameter type | Value injected |
| --- | --- |
| `CancellationToken` | Cancelled when the client cancels the request |
| `McpServer` | The current server |
| `IProgress<ProgressNotificationValue>` | Sends progress notifications to the client |
| `IServiceProvider` and any registered service | Resolved from dependency injection |
| `McpAuthContext` | The authenticated caller, described [below](#using-the-callers-identity-in-tools) |

`ConfigureServer(b => ...)` exposes the SDK's `IMcpServerBuilder` for filters and custom handlers.

## Running it

**Standalone.** `RunAsync(args)` reads the transport from the command line:

```bash
dotnet run                                                 # stdio
dotnet run -- --transport http --url http://127.0.0.1:8000 # Streamable HTTP at /mcp
```

You can also call `RunStdioAsync()` or `RunHttpAsync(url)` directly.

**Inside an existing ASP.NET Core app.** Add the server to your services, then map its endpoint:

```csharp
var builder = WebApplication.CreateBuilder(args);
builder.Services.AddFastMcp(mcp);       // or AddFastMcp("Name", mcp => { ... })

var app = builder.Build();
app.MapFastMcp();                        // MCP endpoint at mcp.Path ("/mcp"), plus auth endpoints
app.Run();
```

`AddFastMcp` leaves your app's default authentication schemes alone. The MCP endpoint uses its own bearer scheme and authorization policy.

## Authentication

### OAuth proxy (recommended)

```csharp
using McpDotnet.Auth.OAuthProxy;

mcp.Auth = new OAuthProxyProvider(options =>
{
    options.BaseUrl = "https://mcp.contoso.com";       // public URL; the OAuth issuer
    options.Upstream = UpstreamIdentityProvider.EntraId(
        tenantId: "contoso.onmicrosoft.com",
        clientId: "<app registration client id>",
        clientSecret: "<app registration secret>",
        scopes: ["User.Read"]);                        // upstream scopes, e.g. for Microsoft Graph
    options.SigningKey = new SymmetricSecurityKey(key); // stable key, see the production checklist
});
```

In your identity provider, register **one** web application with the redirect URI `{BaseUrl}/auth/callback`. Then pick the upstream factory that fits:

| Upstream | Configuration |
| --- | --- |
| Microsoft Entra ID | `UpstreamIdentityProvider.EntraId(tenantId, clientId, secret, scopes)`. Uses the stable `oid` claim as the subject. |
| Any OpenID Connect provider (Google, Okta, Auth0, Keycloak, ...) | `UpstreamIdentityProvider.Oidc(authority, clientId, secret, scopes)`. Endpoints come from discovery. |
| Plain OAuth 2.0 (e.g. GitHub) | `new UpstreamIdentityProvider { AuthorizationEndpoint = ..., TokenEndpoint = ..., UserInfoEndpoint = ..., SubjectClaim = "id", ... }` |

The proxy maps these endpoints:

| Endpoint | Purpose |
| --- | --- |
| `/.well-known/oauth-protected-resource/mcp` | Protected Resource Metadata ([RFC 9728](https://datatracker.ietf.org/doc/html/rfc9728)) |
| `/.well-known/oauth-authorization-server` | Authorization Server Metadata ([RFC 8414](https://datatracker.ietf.org/doc/html/rfc8414)). Advertises `client_id_metadata_document_supported`. |
| `GET /authorize` and `POST /authorize` | Authorization request, and the consent page that answers it |
| `/auth/callback` | Return point from the upstream provider |
| `/token` | `authorization_code` (PKCE S256 required) and rotating `refresh_token` grants |
| `/register` | Dynamic Client Registration ([RFC 7591](https://datatracker.ietf.org/doc/html/rfc7591)) |
| `/revoke` | Token revocation ([RFC 7009](https://datatracker.ietf.org/doc/html/rfc7009)) |

### How clients connect without a client ID

When a client such as Claude, VS Code or Cursor connects to `https://mcp.contoso.com/mcp`, the proxy does the following:

1. It answers `401` with `WWW-Authenticate: Bearer resource_metadata="..."`. The client follows that link to this server's authorization server metadata.
2. The client identifies itself in one of three ways:
   - **CIMD:** it uses an HTTPS URL such as `https://client.example/oauth/metadata.json` as its `client_id`. The proxy fetches that document, checks that its `client_id` matches the URL, and reads the client's name and redirect URIs from it. No registration step is needed.
   - **DCR:** it `POST`s to `/register` and gets a `client_id` on the spot.
   - **Pre-registered:** it uses a `client_id` you configured in `options.Clients.PreRegisteredClients`.
3. The user sees a consent page naming the client and where they'll be sent afterwards. They then sign in at the upstream provider, using the proxy's own app registration.
4. The proxy keeps the upstream tokens server-side. It issues its own short-lived JWT, whose audience is this MCP server, plus a rotating refresh token.

Each mechanism can be switched on or off:

```csharp
options.Clients.EnableClientIdMetadataDocuments = true;           // default
options.Clients.EnableDynamicClientRegistration = true;           // default
options.Clients.AllowedRedirectUris.Add("http://127.0.0.1:*");    // optional allow-list
options.Clients.AllowedClientMetadataHosts.Add("*.trusted.dev");  // optional CIMD host allow-list
options.Clients.PreRegisteredClients.Add(new PreRegisteredClient
{
    ClientId = "internal-cli",
    RedirectUris = ["http://127.0.0.1/callback"],
    Trusted = true,                                               // skips the consent page
});
options.ScopesSupported.Add("mcp:tools");                         // scopes of *this* server
mcp.Auth = new OAuthProxyProvider(options) { RequiredScopes = ["mcp:tools"] };
```

### Using the caller's identity in tools

Add an `McpAuthContext` parameter to any tool:

```csharp
mcp.Tool("my_profile", async (McpAuthContext auth, IHttpClientFactory http, CancellationToken ct) =>
{
    var who = $"{auth.Subject} {auth.GetClaim("name")} via {auth.ClientId}";
    var graphToken = await auth.GetUpstreamAccessTokenAsync(ct); // refreshed automatically when expired
    // ... call Microsoft Graph or your own API with graphToken
    return who;
});
```

`ForwardedClaims` controls which upstream claims are copied into issued tokens. The defaults are `name`, `email`, `preferred_username`, `given_name`, `family_name`, `oid`, `tid` and `login`.

### Remote authorization server

If your authorization server already supports CIMD or DCR (for example Auth0, Keycloak or WorkOS), skip the proxy and only validate its tokens:

```csharp
mcp.Auth = new RemoteAuthProvider(authority: "https://auth.contoso.com", baseUrl: "https://mcp.contoso.com")
{
    ScopesSupported = ["mcp:tools"],
};
```

### Production checklist

- **Set `SigningKey`.** Without it, a random key is generated at startup, so tokens break on restart and aren't valid on other instances. Use a `SymmetricSecurityKey` of 32 or more random bytes, an `RsaSecurityKey` or an `ECDsaSecurityKey`.
- **Use a shared state store** for multiple instances. Two ways to do that:
  - Register `IOAuthStateStore` before `AddFastMcp`:
    ```csharp
    builder.Services.AddStackExchangeRedisCache(...);
    builder.Services.AddSingleton<IOAuthStateStore>(sp =>
        new DistributedCacheOAuthStateStore(sp.GetRequiredService<IDistributedCache>()));
    ```
  - Implement `IOAuthStateStore` over your own database.
- **Persist Data Protection keys** (`services.AddDataProtection().PersistKeysTo...`). The "remembered consent" cookie is encrypted with them.
- **Check `BaseUrl`.** It must be the public HTTPS URL clients use. Behind a reverse proxy, also enable [forwarded headers](https://learn.microsoft.com/aspnet/core/host-and-deploy/proxy-load-balancer).
- **Consider `AllowedRedirectUris` and `AllowedClientMetadataHosts`** if you know which clients will connect.

## Security model

- **PKCE (S256) is mandatory.** Authorization codes are single-use, last 5 minutes, and are bound to the client and redirect URI.
- **Access tokens are audience-bound** to `{BaseUrl}{Path}` ([RFC 8707](https://datatracker.ietf.org/doc/html/rfc8707)) and typed `at+jwt`. Upstream tokens are never passed through to clients.
- **Refresh tokens rotate.** Revoking one also deletes the stored upstream tokens.
- **Consent page (on by default).** All clients share the proxy's single upstream registration, so the upstream provider may skip its own consent screen. The proxy therefore shows its own, so a malicious dynamically registered client can't silently obtain tokens (the "confused deputy" problem).
- **Browser binding.** The authorization flow is bound to the browser that started it with a `SameSite=Lax` cookie. Consent forms and upstream callbacks replayed from another browser are rejected.
- **CIMD fetches are hardened against SSRF.** The proxy only connects to public IP addresses, checked after DNS resolution. It follows no redirects, enforces a 10 KB size limit and a timeout, and caches documents within bounds. `client_id` must match the document URL exactly, and secrets in documents are rejected.
- **Redirect URIs are validated.** They must be HTTPS, loopback HTTP (with any port, per RFC 8252) or private-use schemes for native apps. `javascript:`, `data:`, `file:` and fragments are rejected.
- **Client secrets, authorization codes and refresh tokens are stored only as SHA-256 hashes.** Upstream tokens must be usable, so they are stored as-is in `IOAuthStateStore`. Protect that store accordingly.

## Samples

- [`samples/StdioServer`](samples/StdioServer/Program.cs) is a minimal calculator that runs over stdio or HTTP.
- [`samples/EntraIdServer`](samples/EntraIdServer/Program.cs) is an ASP.NET Core app with an Entra ID-protected MCP endpoint that calls Microsoft Graph on the user's behalf. To run it:

  ```bash
  dotnet run --project samples/EntraIdServer -- \
    --Entra:TenantId <tenant> --Entra:ClientId <app id> --Entra:ClientSecret <secret>
  ```

  Then add `http://localhost:5000/mcp` as a remote MCP server in your client. No client ID is needed.

## Building

```bash
dotnet build
dotnet test     # unit tests plus end-to-end OAuth flows using the official SDK client against a fake IdP
dotnet pack src/McpDotnet -c Release
```
