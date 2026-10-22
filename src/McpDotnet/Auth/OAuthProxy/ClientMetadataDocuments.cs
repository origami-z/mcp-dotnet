using System.Net;
using System.Net.Http.Headers;
using System.Net.Sockets;
using System.Text.Json;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging;

namespace McpDotnet.Auth.OAuthProxy;

/// <summary>
/// Resolves OAuth Client ID Metadata Documents: a client uses an HTTPS URL as its <c>client_id</c>, and the
/// document at that URL describes the client (name, redirect URIs, ...). No registration step is needed.
/// </summary>
internal sealed class ClientMetadataDocumentResolver
{
    public const string HttpClientName = "McpDotnet.ClientMetadata";

    private readonly IHttpClientFactory _httpClientFactory;
    private readonly IMemoryCache _cache;
    private readonly ClientRegistrationOptions _options;
    private readonly ILogger _logger;

    public ClientMetadataDocumentResolver(
        IHttpClientFactory httpClientFactory,
        IMemoryCache cache,
        OAuthProxyOptions options,
        ILogger<ClientMetadataDocumentResolver> logger)
    {
        _httpClientFactory = httpClientFactory;
        _cache = cache;
        _options = options.Clients;
        _logger = logger;
    }

    /// <summary>Whether a client_id has the shape of a metadata document URL.</summary>
    public static bool IsMetadataDocumentClientId(string clientId) =>
        clientId.StartsWith("https://", StringComparison.OrdinalIgnoreCase);

    /// <summary>Fetches, validates and caches the metadata document for <paramref name="clientId"/>.</summary>
    /// <exception cref="OAuthException">The URL or the document is not acceptable.</exception>
    public async Task<OAuthClient> ResolveAsync(string clientId, CancellationToken cancellationToken)
    {
        var uri = ValidateClientIdUrl(clientId);
        if (_cache.TryGetValue(CacheKey(clientId), out OAuthClient? cached) && cached is not null)
        {
            return cached;
        }

        using var request = new HttpRequestMessage(HttpMethod.Get, uri);
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        HttpResponseMessage response;
        try
        {
            response = await _httpClientFactory.CreateClient(HttpClientName)
                .SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException && !cancellationToken.IsCancellationRequested)
        {
            _logger.LogWarning(ex, "Failed to fetch client metadata document {ClientId}", clientId);
            throw OAuthException.InvalidClient("The client metadata document could not be retrieved.");
        }

        using (response)
        {
            if (response.StatusCode != HttpStatusCode.OK)
            {
                throw OAuthException.InvalidClient($"The client metadata document returned HTTP {(int)response.StatusCode}.");
            }

            var json = await ReadLimitedAsync(response, cancellationToken).ConfigureAwait(false);
            var client = Parse(clientId, json);
            _cache.Set(CacheKey(clientId), client, CacheDuration(response.Headers.CacheControl));
            return client;
        }
    }

    private Uri ValidateClientIdUrl(string clientId)
    {
        if (!Uri.TryCreate(clientId, UriKind.Absolute, out var uri) || uri.Scheme != Uri.UriSchemeHttps)
        {
            throw OAuthException.InvalidClient("A URL client_id must be an absolute HTTPS URL.");
        }
        if (uri.AbsolutePath is "" or "/")
        {
            throw OAuthException.InvalidClient("A URL client_id must contain a path.");
        }
        if (!string.IsNullOrEmpty(uri.Fragment) || !string.IsNullOrEmpty(uri.UserInfo))
        {
            throw OAuthException.InvalidClient("A URL client_id must not contain a fragment or user info.");
        }
        if (clientId.Contains("/./", StringComparison.Ordinal) || clientId.Contains("/../", StringComparison.Ordinal)
            || clientId.EndsWith("/.", StringComparison.Ordinal) || clientId.EndsWith("/..", StringComparison.Ordinal))
        {
            throw OAuthException.InvalidClient("A URL client_id must not contain dot segments.");
        }
        if (_options.AllowedClientMetadataHosts.Count > 0
            && !_options.AllowedClientMetadataHosts.Any(h => HostMatches(uri.IdnHost, h)))
        {
            throw OAuthException.InvalidClient($"Client metadata documents from '{uri.Host}' are not allowed.");
        }
        return uri;
    }

    private async Task<byte[]> ReadLimitedAsync(HttpResponseMessage response, CancellationToken cancellationToken)
    {
        var max = _options.MaxClientMetadataBytes;
        if (response.Content.Headers.ContentLength > max)
        {
            throw OAuthException.InvalidClient("The client metadata document is too large.");
        }

        using var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
        using var buffer = new MemoryStream();
        var chunk = new byte[4096];
        int read;
        while ((read = await stream.ReadAsync(chunk, cancellationToken).ConfigureAwait(false)) > 0)
        {
            if (buffer.Length + read > max)
            {
                throw OAuthException.InvalidClient("The client metadata document is too large.");
            }
            buffer.Write(chunk, 0, read);
        }
        return buffer.ToArray();
    }

    private OAuthClient Parse(string clientId, byte[] json)
    {
        ClientMetadata? metadata;
        try
        {
            metadata = JsonSerializer.Deserialize<ClientMetadata>(json);
        }
        catch (JsonException)
        {
            throw OAuthException.InvalidClient("The client metadata document is not valid JSON.");
        }

        if (metadata is null || !string.Equals(metadata.ClientId, clientId, StringComparison.Ordinal))
        {
            throw OAuthException.InvalidClient("The client_id in the metadata document does not match its URL.");
        }
        if (metadata.ClientSecret is not null || metadata.ClientSecretExpiresAt is not null)
        {
            throw OAuthException.InvalidClient("Client metadata documents must not contain a client secret.");
        }
        if (metadata.TokenEndpointAuthMethod is not (null or "none"))
        {
            throw OAuthException.InvalidClient(
                $"token_endpoint_auth_method '{metadata.TokenEndpointAuthMethod}' is not supported for metadata document clients; use 'none'.");
        }
        if (metadata.RedirectUris is not { Length: > 0 })
        {
            throw OAuthException.InvalidClient("The client metadata document must list redirect_uris.");
        }
        foreach (var redirectUri in metadata.RedirectUris)
        {
            if (RedirectUris.Validate(redirectUri, _options.AllowedRedirectUris) is { } error)
            {
                throw OAuthException.InvalidClient(error);
            }
        }

        return new OAuthClient
        {
            ClientId = clientId,
            Source = ClientSource.MetadataDocument,
            RedirectUris = metadata.RedirectUris,
            ClientName = metadata.ClientName,
            ClientUri = metadata.ClientUri,
            LogoUri = metadata.LogoUri,
            GrantTypes = metadata.GrantTypes ?? ["authorization_code", "refresh_token"],
        };
    }

    private TimeSpan CacheDuration(CacheControlHeaderValue? cacheControl)
    {
        if (cacheControl is { NoStore: true } or { NoCache: true })
        {
            return TimeSpan.FromSeconds(1);
        }
        var duration = cacheControl?.MaxAge ?? _options.ClientMetadataCacheDuration;
        if (duration > _options.MaxClientMetadataCacheDuration)
        {
            duration = _options.MaxClientMetadataCacheDuration;
        }
        return duration <= TimeSpan.Zero ? TimeSpan.FromSeconds(1) : duration;
    }

    private static string CacheKey(string clientId) => "McpDotnet.ClientMetadata:" + clientId;

    private static bool HostMatches(string host, string pattern) =>
        pattern.StartsWith("*.", StringComparison.Ordinal)
            ? host.EndsWith(pattern[1..], StringComparison.OrdinalIgnoreCase)
            : string.Equals(host, pattern, StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Creates the handler used to fetch metadata documents: no redirects, no proxy, and (unless private networks
    /// are allowed) connections only to public IP addresses, checked after DNS resolution to defeat rebinding.
    /// </summary>
    internal static SocketsHttpHandler CreateHandler(ClientRegistrationOptions options)
    {
        var handler = new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            UseProxy = false,
            UseCookies = false,
            ConnectTimeout = TimeSpan.FromSeconds(5),
            PooledConnectionLifetime = TimeSpan.FromMinutes(5),
        };
        if (!options.AllowPrivateNetworkClientMetadata)
        {
            handler.ConnectCallback = ConnectToPublicAddressAsync;
        }
        return handler;
    }

    private static async ValueTask<Stream> ConnectToPublicAddressAsync(SocketsHttpConnectionContext context, CancellationToken cancellationToken)
    {
        var addresses = await Dns.GetHostAddressesAsync(context.DnsEndPoint.Host, cancellationToken).ConfigureAwait(false);
        var address = addresses.FirstOrDefault(IsPublic)
            ?? throw new HttpRequestException($"Host '{context.DnsEndPoint.Host}' does not resolve to a public IP address.");

        var socket = new Socket(address.AddressFamily, SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
        try
        {
            await socket.ConnectAsync(new IPEndPoint(address, context.DnsEndPoint.Port), cancellationToken).ConfigureAwait(false);
            return new NetworkStream(socket, ownsSocket: true);
        }
        catch
        {
            socket.Dispose();
            throw;
        }
    }

    internal static bool IsPublic(IPAddress address)
    {
        if (address.IsIPv4MappedToIPv6)
        {
            address = address.MapToIPv4();
        }
        if (IPAddress.IsLoopback(address) || address.Equals(IPAddress.Any) || address.Equals(IPAddress.IPv6Any)
            || address.Equals(IPAddress.Broadcast) || address.Equals(IPAddress.IPv6None))
        {
            return false;
        }

        if (address.AddressFamily == AddressFamily.InterNetwork)
        {
            var b = address.GetAddressBytes();
            return !(b[0] == 0
                || b[0] == 10
                || (b[0] == 100 && b[1] >= 64 && b[1] <= 127) // carrier-grade NAT
                || b[0] == 127
                || (b[0] == 169 && b[1] == 254) // link-local, cloud metadata
                || (b[0] == 172 && b[1] >= 16 && b[1] <= 31)
                || (b[0] == 192 && b[1] == 0 && b[2] == 0)
                || (b[0] == 192 && b[1] == 168)
                || (b[0] == 198 && (b[1] == 18 || b[1] == 19)) // benchmarking
                || b[0] >= 224); // multicast and reserved
        }

        if (address.AddressFamily == AddressFamily.InterNetworkV6)
        {
            var b = address.GetAddressBytes();
            return !(address.IsIPv6LinkLocal
                || address.IsIPv6SiteLocal
                || address.IsIPv6Multicast
                || (b[0] & 0xFE) == 0xFC); // unique local fc00::/7
        }

        return false;
    }

    private sealed class ClientMetadata
    {
        [System.Text.Json.Serialization.JsonPropertyName("client_id")]
        public string? ClientId { get; set; }

        [System.Text.Json.Serialization.JsonPropertyName("client_name")]
        public string? ClientName { get; set; }

        [System.Text.Json.Serialization.JsonPropertyName("client_uri")]
        public string? ClientUri { get; set; }

        [System.Text.Json.Serialization.JsonPropertyName("logo_uri")]
        public string? LogoUri { get; set; }

        [System.Text.Json.Serialization.JsonPropertyName("redirect_uris")]
        public string[]? RedirectUris { get; set; }

        [System.Text.Json.Serialization.JsonPropertyName("grant_types")]
        public string[]? GrantTypes { get; set; }

        [System.Text.Json.Serialization.JsonPropertyName("token_endpoint_auth_method")]
        public string? TokenEndpointAuthMethod { get; set; }

        [System.Text.Json.Serialization.JsonPropertyName("client_secret")]
        public string? ClientSecret { get; set; }

        [System.Text.Json.Serialization.JsonPropertyName("client_secret_expires_at")]
        public JsonElement? ClientSecretExpiresAt { get; set; }
    }
}
