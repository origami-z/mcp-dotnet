using McpDotnet.Auth;
using McpDotnet.Tests.Infrastructure;
using ModelContextProtocol.Authentication;
using ModelContextProtocol.Protocol;

namespace McpDotnet.Tests;

/// <summary>Drives the full flow with the official MCP C# SDK client, which never gets a pre-provisioned client ID.</summary>
public class OAuthProxyEndToEndTests
{
    private static FastMcp CreateServer(Action<Auth.OAuthProxy.OAuthProxyOptions>? configure = null)
    {
        var mcp = new FastMcp("Secure Server") { Auth = TestApp.CreateProxy(configure) };
        mcp.Tool("whoami", async (McpAuthContext auth, CancellationToken ct) =>
            $"{auth.Subject}|{auth.GetClaim("name")}|{auth.ClientId}|{await auth.GetUpstreamAccessTokenAsync(ct)}");
        return mcp;
    }

    [Fact]
    public async Task ClientIdMetadataDocumentClientConnectsWithoutClientId()
    {
        await using var app = await TestApp.StartAsync(CreateServer());
        var browser = app.CreateBrowser();

        await using var client = await app.ConnectAsync(new ClientOAuthOptions
        {
            RedirectUri = new Uri(TestApp.ClientRedirectUri),
            ClientMetadataDocumentUri = new Uri(TestApp.MetadataDocumentUrl),
        }, browser);

        Assert.True(browser.SawConsentPage);
        var result = await client.CallToolAsync("whoami");
        var text = Assert.IsType<TextContentBlock>(result.Content.Single()).Text;
        Assert.Equal($"user-123|Ada Lovelace|{TestApp.MetadataDocumentUrl}|{app.Idp.LastAccessToken}", text);
        Assert.Equal(1, app.MetadataHost.RequestCount);
    }

    [Fact]
    public async Task DynamicClientRegistrationClientConnectsWithoutClientId()
    {
        await using var app = await TestApp.StartAsync(CreateServer(o => o.Clients.EnableClientIdMetadataDocuments = false));

        await using var client = await app.ConnectAsync(new ClientOAuthOptions
        {
            RedirectUri = new Uri(TestApp.ClientRedirectUri),
            DynamicClientRegistration = new DynamicClientRegistrationOptions { ClientName = "DCR Test Client" },
        });

        var result = await client.CallToolAsync("whoami");
        var parts = Assert.IsType<TextContentBlock>(result.Content.Single()).Text.Split('|');
        Assert.Equal("user-123", parts[0]);
        Assert.StartsWith("mcp_", parts[2]);
    }

    [Fact]
    public async Task PreRegisteredClientConnects()
    {
        await using var app = await TestApp.StartAsync(CreateServer(o => o.Clients.PreRegisteredClients.Add(new()
        {
            ClientId = "my-cli",
            RedirectUris = [TestApp.ClientRedirectUri],
            Trusted = true,
        })));
        var browser = app.CreateBrowser();

        await using var client = await app.ConnectAsync(new ClientOAuthOptions
        {
            ClientId = "my-cli",
            RedirectUri = new Uri(TestApp.ClientRedirectUri),
        }, browser);

        Assert.False(browser.SawConsentPage);
        var result = await client.CallToolAsync("whoami");
        Assert.Contains("|my-cli|", Assert.IsType<TextContentBlock>(result.Content.Single()).Text);
    }

    [Fact]
    public async Task ConsentIsRememberedPerBrowser()
    {
        await using var app = await TestApp.StartAsync(CreateServer());
        var browser = app.CreateBrowser();
        var oauth = () => new ClientOAuthOptions
        {
            RedirectUri = new Uri(TestApp.ClientRedirectUri),
            ClientMetadataDocumentUri = new Uri(TestApp.MetadataDocumentUrl),
        };

        await using (await app.ConnectAsync(oauth(), browser))
        {
            Assert.True(browser.SawConsentPage);
        }
        await using (await app.ConnectAsync(oauth(), browser))
        {
            Assert.False(browser.SawConsentPage);
        }
        await using (await app.ConnectAsync(oauth(), app.CreateBrowser()))
        {
        }
    }

    [Fact]
    public async Task UpstreamTokenIsRefreshedWhenExpired()
    {
        await using var app = await TestApp.StartAsync(CreateServer());
        app.Idp.ExpiresInSeconds = 30; // inside the refresh skew, so the next use refreshes

        await using var client = await app.ConnectAsync(new ClientOAuthOptions
        {
            RedirectUri = new Uri(TestApp.ClientRedirectUri),
            ClientMetadataDocumentUri = new Uri(TestApp.MetadataDocumentUrl),
        });

        var result = await client.CallToolAsync("whoami");
        Assert.EndsWith("|upstream-access-2", Assert.IsType<TextContentBlock>(result.Content.Single()).Text);
        Assert.Equal(1, app.Idp.RefreshRequests);
    }
}
