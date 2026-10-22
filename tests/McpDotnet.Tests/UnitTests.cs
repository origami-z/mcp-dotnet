using System.Net;
using System.Text.Json;
using McpDotnet.Auth;
using McpDotnet.Auth.OAuthProxy;
using McpDotnet.Storage;
using McpDotnet.Tests.Infrastructure;

namespace McpDotnet.Tests;

public class RedirectUriTests
{
    [Theory]
    [InlineData("https://claude.ai/api/mcp/auth_callback", true)]
    [InlineData("http://127.0.0.1:33418/callback", true)]
    [InlineData("http://localhost/cb", true)]
    [InlineData("http://[::1]:8080/cb", true)]
    [InlineData("cursor://anysphere.cursor-retrieval/oauth/callback", true)]
    [InlineData("http://example.com/cb", false)]
    [InlineData("javascript:alert(1)", false)]
    [InlineData("data:text/html,hi", false)]
    [InlineData("https://example.com/cb#frag", false)]
    [InlineData("/relative", false)]
    public void ValidatesRegisteredRedirectUris(string uri, bool valid) =>
        Assert.Equal(valid, RedirectUris.Validate(uri, []) is null);

    [Theory]
    [InlineData("http://127.0.0.1:5000/callback", "http://127.0.0.1:1234/callback", true)]
    [InlineData("http://127.0.0.1:5000/other", "http://127.0.0.1:1234/callback", false)]
    [InlineData("https://app.example/cb", "https://app.example/cb", true)]
    [InlineData("https://app.example:444/cb", "https://app.example/cb", false)]
    [InlineData("https://app.example/cb?x=1", "https://app.example/cb", false)]
    public void MatchesRegisteredRedirectUris(string requested, string registered, bool match) =>
        Assert.Equal(match, RedirectUris.IsRegistered(requested, [registered]));

    [Theory]
    [InlineData("8.8.8.8", true)]
    [InlineData("2606:4700:4700::1111", true)]
    [InlineData("127.0.0.1", false)]
    [InlineData("10.1.2.3", false)]
    [InlineData("172.20.0.1", false)]
    [InlineData("192.168.1.1", false)]
    [InlineData("169.254.169.254", false)]
    [InlineData("100.64.0.1", false)]
    [InlineData("0.0.0.0", false)]
    [InlineData("::1", false)]
    [InlineData("fe80::1", false)]
    [InlineData("fd00::1", false)]
    [InlineData("::ffff:10.0.0.1", false)]
    public void DetectsPublicAddresses(string address, bool isPublic) =>
        Assert.Equal(isPublic, ClientMetadataDocumentResolver.IsPublic(IPAddress.Parse(address)));
}

public class StateStoreTests
{
    [Fact]
    public async Task TakeRemovesTheValue()
    {
        var store = new InMemoryOAuthStateStore();
        await store.SetAsync("k", new[] { "a" }, TimeSpan.FromMinutes(1));
        Assert.Equal(["a"], (await store.TakeAsync<string[]>("k"))!);
        Assert.Null(await store.TakeAsync<string[]>("k"));
    }

    [Fact]
    public async Task ExpiredValuesAreGone()
    {
        var time = new ManualTimeProvider();
        var store = new InMemoryOAuthStateStore(time);
        await store.SetAsync("k", "v", TimeSpan.FromSeconds(10));
        time.Advance(TimeSpan.FromSeconds(11));
        Assert.Null(await store.GetAsync<string>("k"));
    }

    [Fact]
    public async Task DistributedCacheStoreRoundTrips()
    {
        var cache = new Microsoft.Extensions.Caching.Distributed.MemoryDistributedCache(
            Microsoft.Extensions.Options.Options.Create(new Microsoft.Extensions.Caching.Memory.MemoryDistributedCacheOptions()));
        var store = new DistributedCacheOAuthStateStore(cache);
        await store.SetAsync("k", new Dictionary<string, int> { ["x"] = 1 }, null);
        Assert.Equal(1, (await store.GetAsync<Dictionary<string, int>>("k"))!["x"]);
        Assert.NotNull(await store.TakeAsync<Dictionary<string, int>>("k"));
        Assert.Null(await store.GetAsync<Dictionary<string, int>>("k"));
    }

    private sealed class ManualTimeProvider : TimeProvider
    {
        private DateTimeOffset _now = DateTimeOffset.UtcNow;

        public override DateTimeOffset GetUtcNow() => _now;

        public void Advance(TimeSpan by) => _now += by;
    }
}

public class RemoteAuthProviderTests
{
    [Fact]
    public async Task PublishesExternalAuthorizationServer()
    {
        var mcp = new FastMcp("Remote")
        {
            Auth = new RemoteAuthProvider("https://auth.example.com", TestApp.BaseUrl) { ScopesSupported = ["mcp"] },
        };
        await using var app = await TestApp.StartAsync(mcp);
        var http = app.CreateHttpClient();

        using var prm = JsonDocument.Parse(await http.GetStringAsync("/.well-known/oauth-protected-resource/mcp"));
        Assert.Equal("https://auth.example.com", prm.RootElement.GetProperty("authorization_servers")[0].GetString());
        Assert.Equal("mcp", prm.RootElement.GetProperty("scopes_supported")[0].GetString());

        var response = await http.PostAsync("/mcp", new StringContent("{}", System.Text.Encoding.UTF8, "application/json"));
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await http.GetAsync("/.well-known/oauth-authorization-server")).StatusCode);
    }
}

public class OptionsValidationTests
{
    [Theory]
    [InlineData("")]
    [InlineData("http://mcp.example.com")]
    [InlineData("https://mcp.example.com/?x=1")]
    public void RejectsBadBaseUrls(string baseUrl) =>
        Assert.Throws<ArgumentException>(() => new OAuthProxyProvider(o =>
        {
            o.BaseUrl = baseUrl;
            o.Upstream = UpstreamIdentityProvider.Oidc("https://idp.example", "id", "secret");
        }));

    [Fact]
    public void EntraIdPresetUsesStableObjectId()
    {
        var upstream = UpstreamIdentityProvider.EntraId("contoso.onmicrosoft.com", "app-id", "secret", ["User.Read"]);
        Assert.Equal("oid", upstream.SubjectClaim);
        Assert.Equal("https://login.microsoftonline.com/contoso.onmicrosoft.com/v2.0", upstream.Authority);
        Assert.Contains("offline_access", upstream.Scopes);
        Assert.Contains("User.Read", upstream.Scopes);
        Assert.Null(UpstreamIdentityProvider.EntraId("organizations", "app-id", null).Authority);
    }
}
