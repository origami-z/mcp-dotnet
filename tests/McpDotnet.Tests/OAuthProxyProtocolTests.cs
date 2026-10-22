using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using McpDotnet.Tests.Infrastructure;
using Microsoft.AspNetCore.WebUtilities;

namespace McpDotnet.Tests;

/// <summary>Exercises the OAuth endpoints directly, including the failure paths.</summary>
public class OAuthProxyProtocolTests
{
    private const string Verifier = "test-verifier-0123456789-abcdefghijklmnopqrstuvwxyz";

    private static async Task<TestApp> StartAsync(Action<Auth.OAuthProxy.OAuthProxyOptions>? configure = null)
    {
        var mcp = new FastMcp("Secure") { Auth = TestApp.CreateProxy(configure) };
        mcp.Tool("ping", () => "pong");
        return await TestApp.StartAsync(mcp);
    }

    [Fact]
    public async Task UnauthenticatedRequestIsChallengedWithResourceMetadata()
    {
        await using var app = await StartAsync();
        var http = app.CreateHttpClient();

        var response = await http.PostAsync("/mcp", new StringContent("{}", Encoding.UTF8, "application/json"));
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        var challenge = response.Headers.WwwAuthenticate.ToString();
        Assert.Contains("resource_metadata=", challenge);
        Assert.Contains("resource_metadata=\"http://localhost/.well-known/oauth-protected-resource/mcp\"", challenge);

        using var prm = JsonDocument.Parse(await http.GetStringAsync("/.well-known/oauth-protected-resource/mcp"));
        Assert.Equal("http://localhost/mcp", prm.RootElement.GetProperty("resource").GetString());
        Assert.Equal("http://localhost", prm.RootElement.GetProperty("authorization_servers")[0].GetString());
    }

    [Fact]
    public async Task AuthorizationServerMetadataAdvertisesCimdAndDcr()
    {
        await using var app = await StartAsync();
        using var doc = JsonDocument.Parse(await app.CreateHttpClient().GetStringAsync("/.well-known/oauth-authorization-server"));
        var root = doc.RootElement;
        Assert.Equal("http://localhost", root.GetProperty("issuer").GetString());
        Assert.True(root.GetProperty("client_id_metadata_document_supported").GetBoolean());
        Assert.Equal("http://localhost/register", root.GetProperty("registration_endpoint").GetString());
        Assert.Equal("S256", root.GetProperty("code_challenge_methods_supported")[0].GetString());
    }

    [Fact]
    public async Task DisabledDcrIsNotAdvertisedOrMapped()
    {
        await using var app = await StartAsync(o => o.Clients.EnableDynamicClientRegistration = false);
        var http = app.CreateHttpClient();
        using var doc = JsonDocument.Parse(await http.GetStringAsync("/.well-known/oauth-authorization-server"));
        Assert.False(doc.RootElement.TryGetProperty("registration_endpoint", out _));
        var response = await http.PostAsJsonAsync("/register", new { redirect_uris = new[] { TestApp.ClientRedirectUri } });
        Assert.NotEqual(HttpStatusCode.Created, response.StatusCode);
    }

    [Theory]
    [InlineData("http://evil.example/callback")]
    [InlineData("javascript:alert(1)")]
    [InlineData("https://ok.example/cb#fragment")]
    [InlineData("not a uri")]
    public async Task RegistrationRejectsUnsafeRedirectUris(string redirectUri)
    {
        await using var app = await StartAsync();
        var response = await app.CreateHttpClient().PostAsJsonAsync("/register", new { redirect_uris = new[] { redirectUri } });
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Equal("invalid_redirect_uri", doc.RootElement.GetProperty("error").GetString());
    }

    [Fact]
    public async Task RegistrationHonorsAllowedRedirectUriPatterns()
    {
        await using var app = await StartAsync(o => o.Clients.AllowedRedirectUris.Add("http://localhost:*/callback"));
        var http = app.CreateHttpClient();
        Assert.Equal(HttpStatusCode.Created, (await http.PostAsJsonAsync("/register", new { redirect_uris = new[] { TestApp.ClientRedirectUri } })).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await http.PostAsJsonAsync("/register", new { redirect_uris = new[] { "https://other.example/cb" } })).StatusCode);
    }

    [Fact]
    public async Task ConfidentialDcrClientMustAuthenticate()
    {
        await using var app = await StartAsync(o => o.RequireConsent = false);
        var http = app.CreateHttpClient();
        var registration = await RegisterAsync(http, "client_secret_post");
        var clientId = registration.GetProperty("client_id").GetString()!;
        var secret = registration.GetProperty("client_secret").GetString()!;

        var code = await AuthorizeAsync(app, clientId);
        var wrongSecret = await RedeemAsync(http, clientId, code, Verifier, secret: "wrong");
        Assert.Equal(HttpStatusCode.Unauthorized, wrongSecret.StatusCode);

        code = await AuthorizeAsync(app, clientId);
        var ok = await RedeemAsync(http, clientId, code, Verifier, secret: secret);
        Assert.Equal(HttpStatusCode.OK, ok.StatusCode);
    }

    [Fact]
    public async Task TokenEndpointEnforcesPkceAndSingleUseCodes()
    {
        await using var app = await StartAsync(o => o.RequireConsent = false);
        var http = app.CreateHttpClient();
        var clientId = (await RegisterAsync(http, "none")).GetProperty("client_id").GetString()!;

        var code = await AuthorizeAsync(app, clientId);
        await AssertErrorAsync(await RedeemAsync(http, clientId, code, "wrong-verifier-wrong-verifier-wrong-verifier-123"), "invalid_grant");
        // The failed attempt consumed the code.
        await AssertErrorAsync(await RedeemAsync(http, clientId, code, Verifier), "invalid_grant");

        code = await AuthorizeAsync(app, clientId);
        var tokens = await ReadJsonAsync(await RedeemAsync(http, clientId, code, Verifier));
        Assert.Equal("Bearer", tokens.GetProperty("token_type").GetString());
        await AssertErrorAsync(await RedeemAsync(http, clientId, code, Verifier), "invalid_grant");
    }

    [Fact]
    public async Task CodesAreBoundToTheirClient()
    {
        await using var app = await StartAsync(o => o.RequireConsent = false);
        var http = app.CreateHttpClient();
        var clientA = (await RegisterAsync(http, "none")).GetProperty("client_id").GetString()!;
        var clientB = (await RegisterAsync(http, "none")).GetProperty("client_id").GetString()!;

        var code = await AuthorizeAsync(app, clientA);
        await AssertErrorAsync(await RedeemAsync(http, clientB, code, Verifier), "invalid_grant");
    }

    [Fact]
    public async Task RefreshTokensRotate()
    {
        await using var app = await StartAsync(o => o.RequireConsent = false);
        var http = app.CreateHttpClient();
        var clientId = (await RegisterAsync(http, "none")).GetProperty("client_id").GetString()!;
        var tokens = await ReadJsonAsync(await RedeemAsync(http, clientId, await AuthorizeAsync(app, clientId), Verifier));
        var refreshToken = tokens.GetProperty("refresh_token").GetString()!;

        var refreshed = await ReadJsonAsync(await RefreshAsync(http, clientId, refreshToken));
        Assert.NotEqual(refreshToken, refreshed.GetProperty("refresh_token").GetString());
        await AssertErrorAsync(await RefreshAsync(http, clientId, refreshToken), "invalid_grant");
    }

    [Fact]
    public async Task RevokedRefreshTokenStopsWorking()
    {
        await using var app = await StartAsync(o => o.RequireConsent = false);
        var http = app.CreateHttpClient();
        var clientId = (await RegisterAsync(http, "none")).GetProperty("client_id").GetString()!;
        var tokens = await ReadJsonAsync(await RedeemAsync(http, clientId, await AuthorizeAsync(app, clientId), Verifier));
        var refreshToken = tokens.GetProperty("refresh_token").GetString()!;

        var revoke = await http.PostAsync("/revoke", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["client_id"] = clientId,
            ["token"] = refreshToken,
        }));
        Assert.Equal(HttpStatusCode.OK, revoke.StatusCode);
        await AssertErrorAsync(await RefreshAsync(http, clientId, refreshToken), "invalid_grant");
    }

    [Fact]
    public async Task AccessTokenIsAcceptedOnlyForThisResource()
    {
        await using var app = await StartAsync(o => o.RequireConsent = false);
        var http = app.CreateHttpClient();
        var clientId = (await RegisterAsync(http, "none")).GetProperty("client_id").GetString()!;
        var tokens = await ReadJsonAsync(await RedeemAsync(http, clientId, await AuthorizeAsync(app, clientId), Verifier));

        var withToken = new HttpRequestMessage(HttpMethod.Post, "/mcp") { Content = InitializeRequest() };
        withToken.Headers.Authorization = new("Bearer", tokens.GetProperty("access_token").GetString());
        withToken.Headers.Accept.ParseAdd("application/json, text/event-stream");
        Assert.Equal(HttpStatusCode.OK, (await http.SendAsync(withToken)).StatusCode);

        var forged = new HttpRequestMessage(HttpMethod.Post, "/mcp") { Content = InitializeRequest() };
        forged.Headers.Authorization = new("Bearer", "upstream-access-1"); // an upstream token is not accepted
        forged.Headers.Accept.ParseAdd("application/json, text/event-stream");
        Assert.Equal(HttpStatusCode.Unauthorized, (await http.SendAsync(forged)).StatusCode);
    }

    [Fact]
    public async Task AuthorizeRejectsWrongResource()
    {
        await using var app = await StartAsync(o => o.RequireConsent = false);
        var result = await app.CreateBrowser().AuthorizeAsync(AuthorizeUrl(TestApp.MetadataDocumentUrl, resource: "https://other.example/mcp"));
        Assert.Equal("invalid_target", result.Error);
    }

    [Fact]
    public async Task AuthorizeRequiresPkce()
    {
        await using var app = await StartAsync();
        var url = AuthorizeUrl(TestApp.MetadataDocumentUrl).ToString().Replace("code_challenge_method=S256", "code_challenge_method=plain");
        var result = await app.CreateBrowser().AuthorizeAsync(new Uri(url));
        Assert.Equal("invalid_request", result.Error);
    }

    [Fact]
    public async Task UnregisteredRedirectUriIsNotRedirectedTo()
    {
        await using var app = await StartAsync();
        var response = await app.CreateBrowser().Http.GetAsync(AuthorizeUrl(TestApp.MetadataDocumentUrl, redirectUri: "https://attacker.example/cb"));
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Null(response.Headers.Location);
    }

    [Fact]
    public async Task LoopbackRedirectPortMayVary()
    {
        await using var app = await StartAsync(o => o.RequireConsent = false);
        var result = await app.CreateBrowser().AuthorizeAsync(AuthorizeUrl(TestApp.MetadataDocumentUrl, redirectUri: "http://localhost:50123/callback"));
        Assert.NotNull(result.Code);
        Assert.Equal(50123, result.RedirectUri.Port);
    }

    [Fact]
    public async Task DeniedConsentReturnsAccessDenied()
    {
        await using var app = await StartAsync();
        var result = await app.CreateBrowser().AuthorizeAsync(AuthorizeUrl(TestApp.MetadataDocumentUrl), approve: false);
        Assert.Equal("access_denied", result.Error);
        Assert.Equal("xyz", result.State);
    }

    [Fact]
    public async Task ConsentCannotBeSubmittedFromAnotherBrowser()
    {
        await using var app = await StartAsync();
        var attacker = app.CreateBrowser();
        var html = await (await attacker.Http.GetAsync(AuthorizeUrl(TestApp.MetadataDocumentUrl))).Content.ReadAsStringAsync();

        // The attacker knows the form values, but the victim's browser lacks the binding cookie.
        var victim = app.CreateBrowser();
        var response = await victim.Http.PostAsync("/authorize", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["request_id"] = Browser.HiddenField(html, "request_id"),
            ["consent_token"] = Browser.HiddenField(html, "consent_token"),
            ["decision"] = "approve",
        }));
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task UpstreamCallbackMustReturnToTheSameBrowser()
    {
        await using var app = await StartAsync(o => o.RequireConsent = false);
        var attacker = app.CreateBrowser();
        var upstreamUrl = (await attacker.Http.GetAsync(AuthorizeUrl(TestApp.MetadataDocumentUrl))).Headers.Location!;
        var callback = app.Idp.SignIn(upstreamUrl);

        var victim = app.CreateBrowser();
        Assert.Equal(HttpStatusCode.BadRequest, (await victim.Http.GetAsync(callback)).StatusCode);
    }

    [Fact]
    public async Task MetadataDocumentMustMatchItsUrl()
    {
        await using var app = await StartAsync();
        const string url = "https://client.test/mismatched.json";
        app.MetadataHost.AddJson(url, """{"client_id":"https://client.test/other.json","redirect_uris":["http://localhost:1179/callback"]}""");
        var response = await app.CreateBrowser().Http.GetAsync(AuthorizeUrl(url));
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Contains("does not match", await response.Content.ReadAsStringAsync());
    }

    [Theory]
    [InlineData("""{"client_id":"https://client.test/c.json","redirect_uris":["http://localhost:1179/callback"],"token_endpoint_auth_method":"client_secret_basic"}""")]
    [InlineData("""{"client_id":"https://client.test/c.json","redirect_uris":["http://localhost:1179/callback"],"client_secret":"s"}""")]
    [InlineData("""{"client_id":"https://client.test/c.json","redirect_uris":["http://evil.example/cb"]}""")]
    [InlineData("""{"client_id":"https://client.test/c.json"}""")]
    [InlineData("not json")]
    public async Task InvalidMetadataDocumentsAreRejected(string document)
    {
        await using var app = await StartAsync();
        app.MetadataHost.AddJson("https://client.test/c.json", document);
        var response = await app.CreateBrowser().Http.GetAsync(AuthorizeUrl("https://client.test/c.json"));
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task MetadataDocumentHostAllowListIsEnforced()
    {
        await using var app = await StartAsync(o => o.Clients.AllowedClientMetadataHosts.Add("*.trusted.example"));
        var response = await app.CreateBrowser().Http.GetAsync(AuthorizeUrl(TestApp.MetadataDocumentUrl));
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal(0, app.MetadataHost.RequestCount);
    }

    [Fact]
    public async Task MetadataDocumentsCanBeDisabled()
    {
        await using var app = await StartAsync(o => o.Clients.EnableClientIdMetadataDocuments = false);
        var response = await app.CreateBrowser().Http.GetAsync(AuthorizeUrl(TestApp.MetadataDocumentUrl));
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal(0, app.MetadataHost.RequestCount);
    }

    [Fact]
    public async Task UnsupportedScopesAreRejected()
    {
        await using var app = await StartAsync(o =>
        {
            o.RequireConsent = false;
            o.ScopesSupported.Add("mcp:tools");
        });
        var result = await app.CreateBrowser().AuthorizeAsync(AuthorizeUrl(TestApp.MetadataDocumentUrl, scope: "admin"));
        Assert.Equal("invalid_scope", result.Error);
    }

    private static Uri AuthorizeUrl(string clientId, string redirectUri = TestApp.ClientRedirectUri, string? resource = null, string? scope = null) =>
        new(QueryHelpers.AddQueryString("http://localhost/authorize", new Dictionary<string, string?>
        {
            ["response_type"] = "code",
            ["client_id"] = clientId,
            ["redirect_uri"] = redirectUri,
            ["code_challenge"] = WebEncoders.Base64UrlEncode(SHA256.HashData(Encoding.ASCII.GetBytes(Verifier))),
            ["code_challenge_method"] = "S256",
            ["state"] = "xyz",
            ["resource"] = resource ?? "http://localhost/mcp",
            ["scope"] = scope,
        }.Where(p => p.Value is not null)));

    private static async Task<string> AuthorizeAsync(TestApp app, string clientId)
    {
        var result = await app.CreateBrowser().AuthorizeAsync(AuthorizeUrl(clientId));
        Assert.Null(result.Error);
        Assert.Equal("xyz", result.State);
        Assert.Equal("http://localhost", result.Iss);
        return result.Code!;
    }

    private static async Task<JsonElement> RegisterAsync(HttpClient http, string authMethod)
    {
        var response = await http.PostAsJsonAsync("/register", new
        {
            client_name = "Test",
            redirect_uris = new[] { TestApp.ClientRedirectUri },
            token_endpoint_auth_method = authMethod,
        });
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        return await ReadJsonAsync(response, HttpStatusCode.Created);
    }

    private static Task<HttpResponseMessage> RedeemAsync(HttpClient http, string clientId, string code, string verifier, string? secret = null)
    {
        var form = new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code",
            ["client_id"] = clientId,
            ["code"] = code,
            ["code_verifier"] = verifier,
            ["redirect_uri"] = TestApp.ClientRedirectUri,
        };
        if (secret is not null)
        {
            form["client_secret"] = secret;
        }
        return http.PostAsync("/token", new FormUrlEncodedContent(form));
    }

    private static Task<HttpResponseMessage> RefreshAsync(HttpClient http, string clientId, string refreshToken) =>
        http.PostAsync("/token", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "refresh_token",
            ["client_id"] = clientId,
            ["refresh_token"] = refreshToken,
        }));

    private static async Task<JsonElement> ReadJsonAsync(HttpResponseMessage response, HttpStatusCode expected = HttpStatusCode.OK)
    {
        var body = await response.Content.ReadAsStringAsync();
        Assert.True(response.StatusCode == expected, $"Expected {expected} but got {response.StatusCode}: {body}");
        return JsonDocument.Parse(body).RootElement.Clone();
    }

    private static async Task AssertErrorAsync(HttpResponseMessage response, string error)
    {
        var body = await response.Content.ReadAsStringAsync();
        Assert.True(response.StatusCode is HttpStatusCode.BadRequest or HttpStatusCode.Unauthorized, body);
        Assert.Equal(error, JsonDocument.Parse(body).RootElement.GetProperty("error").GetString());
    }

    private static StringContent InitializeRequest() => new(
        """{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}""",
        Encoding.UTF8,
        "application/json");
}
