using System.Net;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.TestHost;
using Microsoft.AspNetCore.WebUtilities;

namespace McpDotnet.Tests.Infrastructure;

/// <summary>Plays the user's browser: keeps cookies, approves the consent page and signs in at the fake IdP.</summary>
internal sealed class Browser
{
    private readonly FakeIdentityProvider _idp;

    public Browser(TestServer server, FakeIdentityProvider idp)
    {
        _idp = idp;
        Cookies = new CookieContainer();
        Http = new HttpClient(new CookieHandler(Cookies) { InnerHandler = server.CreateHandler() }) { BaseAddress = server.BaseAddress };
    }

    public CookieContainer Cookies { get; }

    public HttpClient Http { get; }

    /// <summary>Whether the last authorization showed the consent page.</summary>
    public bool SawConsentPage { get; private set; }

    /// <summary>Runs an authorization request to completion and returns the parameters sent to the client's redirect URI.</summary>
    public async Task<AuthorizationResponse> AuthorizeAsync(Uri authorizeUrl, bool approve = true)
    {
        SawConsentPage = false;
        var response = await Http.GetAsync(authorizeUrl);
        if (response.StatusCode == HttpStatusCode.OK)
        {
            SawConsentPage = true;
            var html = await response.Content.ReadAsStringAsync();
            response = await Http.PostAsync("/authorize", new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["request_id"] = HiddenField(html, "request_id"),
                ["consent_token"] = HiddenField(html, "consent_token"),
                ["decision"] = approve ? "approve" : "deny",
            }));
        }

        var location = RequireRedirect(response);
        if (location.Host == "idp.test")
        {
            var callback = _idp.SignIn(location);
            location = RequireRedirect(await Http.GetAsync(callback));
        }

        var query = QueryHelpers.ParseQuery(location.Query);
        return new AuthorizationResponse(
            location,
            query.TryGetValue("code", out var code) ? code.ToString() : null,
            query.TryGetValue("error", out var error) ? error.ToString() : null,
            query.TryGetValue("state", out var state) ? state.ToString() : null,
            query.TryGetValue("iss", out var iss) ? iss.ToString() : null);
    }

    public static string HiddenField(string html, string name)
    {
        var match = Regex.Match(html, $"name=\"{name}\" value=\"([^\"]+)\"");
        Assert.True(match.Success, $"Hidden field {name} not found in:\n{html}");
        return WebUtility.HtmlDecode(match.Groups[1].Value);
    }

    private static Uri RequireRedirect(HttpResponseMessage response)
    {
        Assert.True(
            response.StatusCode is HttpStatusCode.Redirect or HttpStatusCode.SeeOther,
            $"Expected a redirect but got {(int)response.StatusCode}: {response.Content.ReadAsStringAsync().Result}");
        return response.Headers.Location!;
    }

    private sealed class CookieHandler(CookieContainer cookies) : DelegatingHandler
    {
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var header = cookies.GetCookieHeader(request.RequestUri!);
            if (!string.IsNullOrEmpty(header))
            {
                request.Headers.Add("Cookie", header);
            }
            var response = await base.SendAsync(request, cancellationToken);
            if (response.Headers.TryGetValues("Set-Cookie", out var setCookies))
            {
                foreach (var setCookie in setCookies)
                {
                    cookies.SetCookies(request.RequestUri!, setCookie);
                }
            }
            return response;
        }
    }
}

internal sealed record AuthorizationResponse(Uri RedirectUri, string? Code, string? Error, string? State, string? Iss);
