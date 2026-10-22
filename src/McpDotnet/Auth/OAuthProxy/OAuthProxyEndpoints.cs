using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using McpDotnet.Storage;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Logging;

namespace McpDotnet.Auth.OAuthProxy;

/// <summary>The authorization server endpoints of the OAuth proxy.</summary>
internal sealed class OAuthProxyEndpoints
{
    public const string AuthorizePath = "/authorize";
    public const string TokenPath = "/token";
    public const string RegisterPath = "/register";
    public const string RevokePath = "/revoke";
    public const string MetadataPath = "/.well-known/oauth-authorization-server";

    private const string BindingCookiePrefix = "mcpdotnet_flow_";
    private const string ApprovedClientsCookie = "mcpdotnet_approved";
    private const int MaxRememberedApprovals = 20;

    private static readonly HashSet<string> ReservedClaims = new(StringComparer.Ordinal)
    {
        "iss", "aud", "exp", "nbf", "iat", "jti", "sub", "scope", "scp", "client_id", "azp", "nonce", "at_hash", "c_hash",
        TokenService.UpstreamGrantClaim,
    };

    private readonly OAuthProxyOptions _options;
    private readonly IOAuthStateStore _store;
    private readonly ClientRegistry _clients;
    private readonly UpstreamClient _upstream;
    private readonly TokenService _tokens;
    private readonly IDataProtector _protector;
    private readonly ILogger _logger;
    private readonly string _issuer;
    private readonly string _resource;
    private readonly string _serverName;

    public OAuthProxyEndpoints(
        OAuthProxyOptions options,
        IOAuthStateStore store,
        ClientRegistry clients,
        UpstreamClient upstream,
        TokenService tokens,
        IDataProtectionProvider dataProtection,
        ILogger<OAuthProxyEndpoints> logger,
        FastMcp server)
    {
        _options = options;
        _store = store;
        _clients = clients;
        _upstream = upstream;
        _tokens = tokens;
        _protector = dataProtection.CreateProtector("McpDotnet.OAuthProxy.Consent");
        _logger = logger;
        _issuer = options.BaseUrl.TrimEnd('/');
        _resource = server.ResourceUrl(options.BaseUrl);
        _serverName = options.ServerDisplayName ?? server.Name;
    }

    private string CallbackUrl => _issuer + "/" + _options.CallbackPath.TrimStart('/');

    // RFC 8414 authorization server metadata.
    public IResult Metadata()
    {
        var metadata = new JsonObject
        {
            ["issuer"] = _issuer,
            ["authorization_endpoint"] = _issuer + AuthorizePath,
            ["token_endpoint"] = _issuer + TokenPath,
            ["revocation_endpoint"] = _issuer + RevokePath,
            ["response_types_supported"] = new JsonArray("code"),
            ["response_modes_supported"] = new JsonArray("query"),
            ["grant_types_supported"] = new JsonArray("authorization_code", "refresh_token"),
            ["code_challenge_methods_supported"] = new JsonArray("S256"),
            ["token_endpoint_auth_methods_supported"] = new JsonArray("none", "client_secret_post", "client_secret_basic"),
            ["revocation_endpoint_auth_methods_supported"] = new JsonArray("none", "client_secret_post", "client_secret_basic"),
            ["authorization_response_iss_parameter_supported"] = true,
            ["client_id_metadata_document_supported"] = _options.Clients.EnableClientIdMetadataDocuments,
        };
        if (_options.Clients.EnableDynamicClientRegistration)
        {
            metadata["registration_endpoint"] = _issuer + RegisterPath;
        }
        if (_options.ScopesSupported.Count > 0)
        {
            metadata["scopes_supported"] = new JsonArray(_options.ScopesSupported.Select(s => (JsonNode)s!).ToArray());
        }
        return Results.Json(metadata);
    }

    // GET /authorize: validate the request, then show the consent page or go straight to the upstream provider.
    public async Task<IResult> AuthorizeAsync(HttpContext context)
    {
        var query = context.Request.Query;
        string? clientId = query["client_id"], redirectUri = query["redirect_uri"], state = query["state"];

        if (string.IsNullOrEmpty(clientId))
        {
            return ErrorPage("Invalid request", "The client_id parameter is missing.");
        }

        OAuthClient client;
        try
        {
            client = await _clients.GetAsync(clientId, context.RequestAborted);
        }
        catch (OAuthException ex)
        {
            return ErrorPage("Unknown application", ex.Message);
        }

        if (string.IsNullOrEmpty(redirectUri))
        {
            if (client.RedirectUris.Count != 1)
            {
                return ErrorPage("Invalid request", "The redirect_uri parameter is missing.");
            }
            redirectUri = client.RedirectUris[0];
        }
        else if (!RedirectUris.IsRegistered(redirectUri, client.RedirectUris))
        {
            return ErrorPage("Invalid redirect URI", $"'{redirectUri}' is not a registered redirect URI for this application.");
        }

        // From here on errors go back to the client.
        if (query["response_type"] != "code")
        {
            return RedirectError(redirectUri, state, "unsupported_response_type", "Only response_type=code is supported.");
        }
        string? codeChallenge = query["code_challenge"];
        if (string.IsNullOrEmpty(codeChallenge) || query["code_challenge_method"] != "S256")
        {
            return RedirectError(redirectUri, state, "invalid_request", "PKCE with code_challenge_method=S256 is required.");
        }
        if (!client.GrantTypes.Contains("authorization_code"))
        {
            return RedirectError(redirectUri, state, "unauthorized_client", "The client may not use the authorization code grant.");
        }

        string? resource = query["resource"];
        if (!string.IsNullOrEmpty(resource) && !IsOurResource(resource))
        {
            return RedirectError(redirectUri, state, "invalid_target", $"Unknown resource '{resource}'.");
        }

        string[] scopes;
        try
        {
            scopes = ValidateScopes(ScopeHelper.Split(query["scope"]));
        }
        catch (OAuthException ex)
        {
            return RedirectError(redirectUri, state, ex.Error, ex.Message);
        }

        var pending = new PendingAuthorization
        {
            Id = OAuthCrypto.RandomToken(),
            ClientId = client.ClientId,
            RedirectUri = redirectUri,
            CodeChallenge = codeChallenge,
            State = state,
            Scopes = scopes,
            Resource = _resource,
            BrowserBinding = OAuthCrypto.RandomToken(),
            UpstreamCodeVerifier = _options.Upstream.UsePkce ? OAuthCrypto.RandomToken() : null,
        };
        await _store.SetAsync(StoreKeys.Pending(pending.Id), pending, _options.AuthorizationTimeout, context.RequestAborted);
        SetBindingCookie(context, pending);

        if (NeedsConsent(context, client, redirectUri))
        {
            return Html(ConsentPage.Render(_serverName, client, pending, _issuer + AuthorizePath), StatusCodes.Status200OK, context);
        }
        return await RedirectUpstreamAsync(pending, context.RequestAborted);
    }

    // POST /authorize: the user's answer on the consent page.
    public async Task<IResult> ConsentAsync(HttpContext context)
    {
        if (!context.Request.HasFormContentType)
        {
            return ErrorPage("Invalid request", "Expected a form submission.");
        }
        var form = await context.Request.ReadFormAsync(context.RequestAborted);
        string? requestId = form["request_id"], token = form["consent_token"];
        var pending = string.IsNullOrEmpty(requestId) ? null : await _store.GetAsync<PendingAuthorization>(StoreKeys.Pending(requestId), context.RequestAborted);
        if (pending is null)
        {
            return ErrorPage("Request expired", "This authorization request has expired. Start the connection again from your application.");
        }
        if (string.IsNullOrEmpty(token)
            || !OAuthCrypto.FixedTimeEquals(token, pending.BrowserBinding)
            || !IsBoundToBrowser(context, pending))
        {
            return ErrorPage("Invalid request", "The consent form could not be verified. Start the connection again from your application.");
        }

        if (form["decision"] != "approve")
        {
            await _store.RemoveAsync(StoreKeys.Pending(pending.Id), context.RequestAborted);
            return RedirectError(pending.RedirectUri, pending.State, "access_denied", "The user denied the request.");
        }

        RememberApproval(context, pending.ClientId, pending.RedirectUri);
        return await RedirectUpstreamAsync(pending, context.RequestAborted);
    }

    // GET {CallbackPath}: the upstream provider sends the user back here.
    public async Task<IResult> CallbackAsync(HttpContext context)
    {
        var query = context.Request.Query;
        string? state = query["state"];
        var pending = string.IsNullOrEmpty(state) ? null : await _store.TakeAsync<PendingAuthorization>(StoreKeys.Pending(state), context.RequestAborted);
        if (pending is null)
        {
            return ErrorPage("Request expired", "This sign-in has expired or was already used. Start the connection again from your application.");
        }
        if (!IsBoundToBrowser(context, pending))
        {
            return ErrorPage("Invalid request", "This sign-in was started in a different browser. Start the connection again from your application.");
        }
        context.Response.Cookies.Delete(BindingCookieName(pending), CookieOptions(context, TimeSpan.Zero));

        if (!string.IsNullOrEmpty(query["error"]))
        {
            var error = query["error"] == "access_denied" ? "access_denied" : "server_error";
            return RedirectError(pending.RedirectUri, pending.State, error, $"The identity provider returned '{query["error"]}'.");
        }
        string? code = query["code"];
        if (string.IsNullOrEmpty(code))
        {
            return RedirectError(pending.RedirectUri, pending.State, "server_error", "The identity provider returned no authorization code.");
        }

        UpstreamTokenResponse upstreamTokens;
        Dictionary<string, string> userClaims;
        try
        {
            upstreamTokens = await _upstream.ExchangeCodeAsync(code, CallbackUrl, pending.UpstreamCodeVerifier, context.RequestAborted);
            userClaims = await _upstream.GetUserClaimsAsync(upstreamTokens, context.RequestAborted);
        }
        catch (UpstreamException ex)
        {
            _logger.LogWarning(ex, "Upstream sign-in failed");
            return RedirectError(pending.RedirectUri, pending.State, "server_error", "Signing in with the identity provider failed.");
        }

        var subject = userClaims.GetValueOrDefault(_options.Upstream.SubjectClaim) ?? userClaims.GetValueOrDefault("sub");
        if (string.IsNullOrEmpty(subject))
        {
            _logger.LogWarning("Upstream identity has no '{Claim}' claim", _options.Upstream.SubjectClaim);
            return RedirectError(pending.RedirectUri, pending.State, "server_error", "The identity provider did not identify the user.");
        }

        var upstreamGrantId = OAuthCrypto.RandomToken();
        await _store.SetAsync(StoreKeys.Upstream(upstreamGrantId), new UpstreamGrant
        {
            AccessToken = upstreamTokens.AccessToken,
            RefreshToken = upstreamTokens.RefreshToken,
            ExpiresAt = upstreamTokens.ExpiresAt,
            Scope = upstreamTokens.Scope,
        }, _options.RefreshTokenLifetime, context.RequestAborted);

        var authorizationCode = OAuthCrypto.RandomToken();
        await _store.SetAsync(StoreKeys.Code(authorizationCode), new Grant
        {
            ClientId = pending.ClientId,
            Subject = subject,
            Scopes = pending.Scopes,
            Resource = pending.Resource,
            UpstreamGrantId = upstreamGrantId,
            Claims = _options.ForwardedClaims
                .Where(c => !ReservedClaims.Contains(c) && userClaims.ContainsKey(c))
                .ToDictionary(c => c, c => userClaims[c], StringComparer.Ordinal),
            RedirectUri = pending.RedirectUri,
            CodeChallenge = pending.CodeChallenge,
        }, _options.AuthorizationCodeLifetime, context.RequestAborted);

        return Results.Redirect(QueryHelpers.AddQueryString(pending.RedirectUri, new Dictionary<string, string?>
        {
            ["code"] = authorizationCode,
            ["state"] = pending.State,
            ["iss"] = _issuer,
        }));
    }

    // POST /token
    public async Task<IResult> TokenAsync(HttpContext context)
    {
        try
        {
            if (!context.Request.HasFormContentType)
            {
                throw OAuthException.InvalidRequest("The request must be application/x-www-form-urlencoded.");
            }
            var form = await context.Request.ReadFormAsync(context.RequestAborted);
            var client = await AuthenticateClientAsync(context, form);
            TokenResponse response = form["grant_type"].ToString() switch
            {
                "authorization_code" => await RedeemCodeAsync(client, form, context.RequestAborted),
                "refresh_token" => await RefreshAsync(client, form, context.RequestAborted),
                _ => throw new OAuthException("unsupported_grant_type", "Only authorization_code and refresh_token are supported."),
            };

            NoStore(context);
            var json = new JsonObject
            {
                ["access_token"] = response.AccessToken,
                ["token_type"] = "Bearer",
                ["expires_in"] = response.ExpiresIn,
                ["refresh_token"] = response.RefreshToken,
            };
            if (response.Scope is not null)
            {
                json["scope"] = response.Scope;
            }
            return Results.Json(json);
        }
        catch (OAuthException ex)
        {
            return OAuthError(context, ex);
        }
    }

    // POST /register (RFC 7591)
    public async Task<IResult> RegisterAsync(HttpContext context)
    {
        try
        {
            JsonObject? request;
            try
            {
                request = await JsonSerializer.DeserializeAsync<JsonObject>(context.Request.Body, cancellationToken: context.RequestAborted);
            }
            catch (JsonException)
            {
                throw new OAuthException("invalid_client_metadata", "The request body is not valid JSON.");
            }
            if (request is null)
            {
                throw new OAuthException("invalid_client_metadata", "The request body is empty.");
            }

            var redirectUris = ReadStrings(request, "redirect_uris");
            if (redirectUris.Length == 0)
            {
                throw new OAuthException("invalid_redirect_uri", "At least one redirect URI is required.");
            }
            foreach (var uri in redirectUris)
            {
                if (RedirectUris.Validate(uri, _options.Clients.AllowedRedirectUris) is { } error)
                {
                    throw new OAuthException("invalid_redirect_uri", error);
                }
            }

            var authMethod = ReadString(request, "token_endpoint_auth_method") ?? "client_secret_basic";
            if (authMethod is not ("none" or "client_secret_post" or "client_secret_basic"))
            {
                throw new OAuthException("invalid_client_metadata", $"token_endpoint_auth_method '{authMethod}' is not supported.");
            }
            var grantTypes = ReadStrings(request, "grant_types") is { Length: > 0 } g ? g : ["authorization_code", "refresh_token"];
            if (grantTypes.Any(t => t is not ("authorization_code" or "refresh_token")))
            {
                throw new OAuthException("invalid_client_metadata", "Only the authorization_code and refresh_token grant types are supported.");
            }
            var responseTypes = ReadStrings(request, "response_types") is { Length: > 0 } r ? r : ["code"];
            if (responseTypes.Any(t => t != "code"))
            {
                throw new OAuthException("invalid_client_metadata", "Only the code response type is supported.");
            }
            if (ReadString(request, "scope") is { } scope)
            {
                ValidateScopes(ScopeHelper.Split(scope));
            }

            var clientSecret = authMethod == "none" ? null : OAuthCrypto.RandomToken();
            var client = new OAuthClient
            {
                ClientId = "mcp_" + OAuthCrypto.RandomToken(),
                Source = ClientSource.Dynamic,
                RedirectUris = redirectUris,
                ClientName = ReadString(request, "client_name"),
                ClientUri = ReadString(request, "client_uri"),
                LogoUri = ReadString(request, "logo_uri"),
                ClientSecretHash = clientSecret is null ? null : OAuthCrypto.Hash(clientSecret),
                TokenEndpointAuthMethod = authMethod,
                GrantTypes = grantTypes,
                IssuedAt = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            };
            await _clients.SaveDynamicAsync(client, context.RequestAborted);
            _logger.LogInformation("Registered client {ClientId} ({ClientName})", client.ClientId, client.ClientName);

            // Echo the registered metadata back, as RFC 7591 section 3.2.1 requires.
            var response = request.DeepClone().AsObject();
            response["client_id"] = client.ClientId;
            response["client_id_issued_at"] = client.IssuedAt;
            response["redirect_uris"] = new JsonArray(redirectUris.Select(u => (JsonNode)u!).ToArray());
            response["token_endpoint_auth_method"] = authMethod;
            response["grant_types"] = new JsonArray(grantTypes.Select(t => (JsonNode)t!).ToArray());
            response["response_types"] = new JsonArray(responseTypes.Select(t => (JsonNode)t!).ToArray());
            if (clientSecret is not null)
            {
                response["client_secret"] = clientSecret;
                response["client_secret_expires_at"] = 0;
            }
            NoStore(context);
            return Results.Json(response, statusCode: StatusCodes.Status201Created);
        }
        catch (OAuthException ex)
        {
            return OAuthError(context, ex);
        }
    }

    // POST /revoke (RFC 7009). Revoking a refresh token also drops the stored upstream tokens.
    public async Task<IResult> RevokeAsync(HttpContext context)
    {
        try
        {
            if (!context.Request.HasFormContentType)
            {
                throw OAuthException.InvalidRequest("The request must be application/x-www-form-urlencoded.");
            }
            var form = await context.Request.ReadFormAsync(context.RequestAborted);
            var client = await AuthenticateClientAsync(context, form);
            string? token = form["token"];
            if (string.IsNullOrEmpty(token))
            {
                throw OAuthException.InvalidRequest("The token parameter is required.");
            }

            var key = StoreKeys.RefreshToken(token);
            if (await _store.GetAsync<Grant>(key, context.RequestAborted) is { } grant && grant.ClientId == client.ClientId)
            {
                await _store.RemoveAsync(key, context.RequestAborted);
                await _store.RemoveAsync(StoreKeys.Upstream(grant.UpstreamGrantId), context.RequestAborted);
            }
            // Access tokens are self-contained JWTs and expire on their own; unknown tokens are not an error.
            return Results.Ok();
        }
        catch (OAuthException ex)
        {
            return OAuthError(context, ex);
        }
    }

    private async Task<TokenResponse> RedeemCodeAsync(OAuthClient client, IFormCollection form, CancellationToken cancellationToken)
    {
        string? code = form["code"];
        if (string.IsNullOrEmpty(code))
        {
            throw OAuthException.InvalidRequest("The code parameter is required.");
        }
        var grant = await _store.TakeAsync<Grant>(StoreKeys.Code(code), cancellationToken)
            ?? throw OAuthException.InvalidGrant("The authorization code is invalid, expired or already used.");

        if (grant.ClientId != client.ClientId)
        {
            throw OAuthException.InvalidGrant("The authorization code was issued to another client.");
        }
        string? redirectUri = form["redirect_uri"];
        if (!string.IsNullOrEmpty(redirectUri) && redirectUri != grant.RedirectUri)
        {
            throw OAuthException.InvalidGrant("redirect_uri does not match the authorization request.");
        }
        if (!OAuthCrypto.VerifyPkce(form["code_verifier"], grant.CodeChallenge!))
        {
            throw OAuthException.InvalidGrant("PKCE verification failed.");
        }
        CheckResource(form["resource"], grant);
        return await _tokens.IssueAsync(grant, _issuer, cancellationToken);
    }

    private async Task<TokenResponse> RefreshAsync(OAuthClient client, IFormCollection form, CancellationToken cancellationToken)
    {
        if (!client.GrantTypes.Contains("refresh_token"))
        {
            throw new OAuthException("unauthorized_client", "The client may not use refresh tokens.");
        }
        string? refreshToken = form["refresh_token"];
        if (string.IsNullOrEmpty(refreshToken))
        {
            throw OAuthException.InvalidRequest("The refresh_token parameter is required.");
        }

        // Refresh tokens rotate: the presented one is consumed and a new one is issued.
        var grant = await _store.TakeAsync<Grant>(StoreKeys.RefreshToken(refreshToken), cancellationToken)
            ?? throw OAuthException.InvalidGrant("The refresh token is invalid, expired or already used.");
        if (grant.ClientId != client.ClientId)
        {
            throw OAuthException.InvalidGrant("The refresh token was issued to another client.");
        }
        if (await _store.GetAsync<UpstreamGrant>(StoreKeys.Upstream(grant.UpstreamGrantId), cancellationToken) is null)
        {
            throw OAuthException.InvalidGrant("The sign-in has expired; please sign in again.");
        }
        CheckResource(form["resource"], grant);

        var requested = ScopeHelper.Split(form["scope"]);
        if (requested.Length > 0)
        {
            if (requested.Except(grant.Scopes, StringComparer.Ordinal).Any())
            {
                throw OAuthException.InvalidScope("A refresh request may not add scopes.");
            }
            grant = grant with { Scopes = requested };
        }
        return await _tokens.IssueAsync(grant, _issuer, cancellationToken);
    }

    private async Task<OAuthClient> AuthenticateClientAsync(HttpContext context, IFormCollection form)
    {
        string? clientId = form["client_id"], clientSecret = form["client_secret"];
        if (AuthenticationHeaderValue.TryParse(context.Request.Headers.Authorization, out var header)
            && string.Equals(header.Scheme, "Basic", StringComparison.OrdinalIgnoreCase)
            && header.Parameter is not null)
        {
            string decoded;
            try
            {
                decoded = Encoding.UTF8.GetString(Convert.FromBase64String(header.Parameter));
            }
            catch (FormatException)
            {
                throw OAuthException.InvalidClient("Malformed Basic authorization header.");
            }
            var separator = decoded.IndexOf(':', StringComparison.Ordinal);
            if (separator < 0)
            {
                throw OAuthException.InvalidClient("Malformed Basic authorization header.");
            }
            clientId = Uri.UnescapeDataString(decoded[..separator]);
            clientSecret = Uri.UnescapeDataString(decoded[(separator + 1)..]);
        }
        return await _clients.AuthenticateAsync(clientId, clientSecret, context.RequestAborted);
    }

    private void CheckResource(string? resource, Grant grant)
    {
        if (!string.IsNullOrEmpty(resource) && !SameResource(resource, grant.Resource))
        {
            throw OAuthException.InvalidTarget($"Unknown resource '{resource}'.");
        }
    }

    private string[] ValidateScopes(string[] requested)
    {
        if (_options.ScopesSupported.Count == 0)
        {
            return [];
        }
        if (requested.Length == 0)
        {
            return [.. _options.ScopesSupported];
        }
        var unknown = requested.Where(s => !_options.ScopesSupported.Contains(s)).ToArray();
        if (unknown.Length > 0)
        {
            throw OAuthException.InvalidScope($"Unknown scope(s): {string.Join(' ', unknown)}.");
        }
        return requested;
    }

    private bool IsOurResource(string resource) => SameResource(resource, _resource);

    private static bool SameResource(string a, string b) =>
        string.Equals(a.TrimEnd('/'), b.TrimEnd('/'), StringComparison.OrdinalIgnoreCase);

    private async Task<IResult> RedirectUpstreamAsync(PendingAuthorization pending, CancellationToken cancellationToken) =>
        Results.Redirect(await _upstream.BuildAuthorizationUrlAsync(CallbackUrl, pending.Id, pending.UpstreamCodeVerifier, cancellationToken));

    private bool NeedsConsent(HttpContext context, OAuthClient client, string redirectUri)
    {
        if (!_options.RequireConsent || client.Trusted)
        {
            return false;
        }
        return !ReadApprovals(context).Contains(ApprovalKey(client.ClientId, redirectUri));
    }

    private void RememberApproval(HttpContext context, string clientId, string redirectUri)
    {
        var approvals = ReadApprovals(context);
        approvals.Remove(ApprovalKey(clientId, redirectUri));
        approvals.Insert(0, ApprovalKey(clientId, redirectUri));
        var payload = JsonSerializer.Serialize(approvals.Take(MaxRememberedApprovals));
        context.Response.Cookies.Append(ApprovedClientsCookie, _protector.Protect(payload), CookieOptions(context, TimeSpan.FromDays(365)));
    }

    private List<string> ReadApprovals(HttpContext context)
    {
        if (context.Request.Cookies[ApprovedClientsCookie] is not { } cookie)
        {
            return [];
        }
        try
        {
            return JsonSerializer.Deserialize<List<string>>(_protector.Unprotect(cookie)) ?? [];
        }
        catch (Exception ex) when (ex is System.Security.Cryptography.CryptographicException or JsonException)
        {
            return [];
        }
    }

    private static string ApprovalKey(string clientId, string redirectUri) => OAuthCrypto.Hash(clientId + "\n" + redirectUri);

    private static string BindingCookieName(PendingAuthorization pending) => BindingCookiePrefix + pending.Id[..16];

    private static void SetBindingCookie(HttpContext context, PendingAuthorization pending) =>
        context.Response.Cookies.Append(BindingCookieName(pending), pending.BrowserBinding, CookieOptions(context, null));

    private static bool IsBoundToBrowser(HttpContext context, PendingAuthorization pending) =>
        context.Request.Cookies[BindingCookieName(pending)] is { } value && OAuthCrypto.FixedTimeEquals(value, pending.BrowserBinding);

    private static CookieOptions CookieOptions(HttpContext context, TimeSpan? maxAge) => new()
    {
        HttpOnly = true,
        Secure = context.Request.IsHttps,
        // Lax so the cookie survives the top-level redirect back from the upstream provider.
        SameSite = SameSiteMode.Lax,
        Path = context.Request.PathBase.HasValue ? context.Request.PathBase.Value : "/",
        MaxAge = maxAge,
        IsEssential = true,
    };

    private IResult RedirectError(string redirectUri, string? state, string error, string description) =>
        Results.Redirect(QueryHelpers.AddQueryString(redirectUri, new Dictionary<string, string?>
        {
            ["error"] = error,
            ["error_description"] = description,
            ["state"] = state,
            ["iss"] = _issuer,
        }));

    private static IResult OAuthError(HttpContext context, OAuthException ex)
    {
        NoStore(context);
        if (ex.StatusCode == StatusCodes.Status401Unauthorized)
        {
            context.Response.Headers.WWWAuthenticate = "Basic";
        }
        return Results.Json(new JsonObject { ["error"] = ex.Error, ["error_description"] = ex.Message }, statusCode: ex.StatusCode);
    }

    private static IResult ErrorPage(string title, string message) =>
        Results.Content(ConsentPage.RenderError(title, message), "text/html; charset=utf-8", statusCode: StatusCodes.Status400BadRequest);

    private static IResult Html(string html, int statusCode, HttpContext context)
    {
        NoStore(context);
        context.Response.Headers.XFrameOptions = "DENY";
        context.Response.Headers.ContentSecurityPolicy = "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'";
        context.Response.Headers["Referrer-Policy"] = "no-referrer";
        return Results.Content(html, "text/html; charset=utf-8", statusCode: statusCode);
    }

    private static void NoStore(HttpContext context)
    {
        context.Response.Headers.CacheControl = "no-store";
        context.Response.Headers.Pragma = "no-cache";
    }

    private static string? ReadString(JsonObject obj, string name) =>
        obj[name] is JsonValue value && value.TryGetValue<string>(out var s) ? s : null;

    private static string[] ReadStrings(JsonObject obj, string name)
    {
        if (obj[name] is not JsonArray array)
        {
            return [];
        }
        return array.Select(n => n is JsonValue v && v.TryGetValue<string>(out var s) ? s : null)
            .Where(s => !string.IsNullOrEmpty(s))
            .Select(s => s!)
            .ToArray();
    }
}
