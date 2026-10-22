using System.Net;
using McpDotnet.Auth.OAuthProxy;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using ModelContextProtocol.Authentication;
using ModelContextProtocol.Client;

namespace McpDotnet.Tests.Infrastructure;

/// <summary>An in-memory server hosting a <see cref="FastMcp"/>, with a fake upstream IdP and client metadata host.</summary>
internal sealed class TestApp : IAsyncDisposable
{
    public const string BaseUrl = "http://localhost";
    public const string ClientRedirectUri = "http://localhost:1179/callback";
    public const string MetadataDocumentUrl = "https://client.test/oauth/client-metadata.json";

    private TestApp(WebApplication app, FakeIdentityProvider idp, FakeHttpHandler metadataHost)
    {
        App = app;
        Server = app.GetTestServer();
        Idp = idp;
        MetadataHost = metadataHost;
    }

    public WebApplication App { get; }

    public TestServer Server { get; }

    public FakeIdentityProvider Idp { get; }

    public FakeHttpHandler MetadataHost { get; }

    public static async Task<TestApp> StartAsync(FastMcp mcp, Action<IServiceCollection>? configureServices = null)
    {
        var idp = new FakeIdentityProvider();
        var metadataHost = new FakeHttpHandler();
        metadataHost.AddJson(MetadataDocumentUrl, $$"""
            {
              "client_id": "{{MetadataDocumentUrl}}",
              "client_name": "Test CIMD Client",
              "redirect_uris": ["{{ClientRedirectUri}}"],
              "grant_types": ["authorization_code", "refresh_token"],
              "token_endpoint_auth_method": "none"
            }
            """);

        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Logging.ClearProviders();
        builder.Services.AddFastMcp(mcp);
        builder.Services.AddHttpClient(UpstreamClient.HttpClientName)
            .ConfigurePrimaryHttpMessageHandler(() => idp)
            .SetHandlerLifetime(Timeout.InfiniteTimeSpan);
        builder.Services.AddHttpClient(ClientMetadataDocumentResolver.HttpClientName)
            .ConfigurePrimaryHttpMessageHandler(() => metadataHost)
            .SetHandlerLifetime(Timeout.InfiniteTimeSpan);
        configureServices?.Invoke(builder.Services);

        var app = builder.Build();
        app.MapFastMcp();
        await app.StartAsync();
        return new TestApp(app, idp, metadataHost);
    }

    public static OAuthProxyProvider CreateProxy(Action<OAuthProxyOptions>? configure = null) => new(options =>
    {
        options.BaseUrl = BaseUrl;
        options.Upstream = UpstreamIdentityProvider.Oidc(FakeIdentityProvider.Issuer, FakeIdentityProvider.ClientId, FakeIdentityProvider.ClientSecret);
        configure?.Invoke(options);
    });

    public HttpClient CreateHttpClient() => Server.CreateClient();

    public Browser CreateBrowser() => new(Server, Idp);

    /// <summary>Connects the official SDK client, driving the OAuth flow through <paramref name="browser"/> if challenged.</summary>
    public Task<McpClient> ConnectAsync(ClientOAuthOptions? oauth = null, Browser? browser = null)
    {
        if (oauth is not null)
        {
            browser ??= CreateBrowser();
            oauth.RedirectUri ??= new Uri(ClientRedirectUri);
            oauth.AuthorizationCallbackHandler ??= async (context, ct) =>
            {
                var result = await browser.AuthorizeAsync(context.AuthorizationUri);
                Assert.Null(result.Error);
                return new AuthorizationResult { Code = result.Code!, State = result.State, Iss = result.Iss };
            };
        }

        var transport = new HttpClientTransport(
            new HttpClientTransportOptions
            {
                Endpoint = new Uri(BaseUrl + "/mcp"),
                TransportMode = HttpTransportMode.StreamableHttp,
                OAuth = oauth,
            },
            CreateHttpClient(),
            ownsHttpClient: true);
        return McpClient.CreateAsync(transport);
    }

    public async ValueTask DisposeAsync()
    {
        await App.StopAsync();
        await App.DisposeAsync();
    }
}

/// <summary>Serves canned responses for absolute URLs.</summary>
internal sealed class FakeHttpHandler : HttpMessageHandler
{
    private readonly Dictionary<string, Func<HttpResponseMessage>> _responses = new(StringComparer.Ordinal);

    public int RequestCount { get; private set; }

    public void AddJson(string url, string json, string? cacheControl = null) => _responses[url] = () =>
    {
        var response = new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(json, System.Text.Encoding.UTF8, "application/json") };
        if (cacheControl is not null)
        {
            response.Headers.TryAddWithoutValidation("Cache-Control", cacheControl);
        }
        return response;
    };

    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        RequestCount++;
        return Task.FromResult(_responses.TryGetValue(request.RequestUri!.ToString(), out var factory)
            ? factory()
            : new HttpResponseMessage(HttpStatusCode.NotFound));
    }
}
