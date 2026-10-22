using McpDotnet.Storage;

namespace McpDotnet.Auth.OAuthProxy;

/// <summary>Looks up clients by <c>client_id</c> across pre-registered clients, DCR and metadata documents.</summary>
internal sealed class ClientRegistry
{
    private readonly OAuthProxyOptions _options;
    private readonly IOAuthStateStore _store;
    private readonly ClientMetadataDocumentResolver _metadataDocuments;
    private readonly Dictionary<string, OAuthClient> _preRegistered;

    public ClientRegistry(OAuthProxyOptions options, IOAuthStateStore store, ClientMetadataDocumentResolver metadataDocuments)
    {
        _options = options;
        _store = store;
        _metadataDocuments = metadataDocuments;
        _preRegistered = options.Clients.PreRegisteredClients.ToDictionary(
            c => c.ClientId,
            c => new OAuthClient
            {
                ClientId = c.ClientId,
                Source = ClientSource.PreRegistered,
                RedirectUris = [.. c.RedirectUris],
                ClientName = c.ClientName,
                ClientSecretHash = c.ClientSecret is null ? null : OAuthCrypto.Hash(c.ClientSecret),
                TokenEndpointAuthMethod = c.ClientSecret is null ? "none" : "client_secret_basic",
                Trusted = c.Trusted,
            },
            StringComparer.Ordinal);
    }

    /// <summary>Finds a client.</summary>
    /// <exception cref="OAuthException">The client is unknown or its metadata document is invalid.</exception>
    public async Task<OAuthClient> GetAsync(string clientId, CancellationToken cancellationToken)
    {
        if (_preRegistered.TryGetValue(clientId, out var preRegistered))
        {
            return preRegistered;
        }
        if (ClientMetadataDocumentResolver.IsMetadataDocumentClientId(clientId))
        {
            if (!_options.Clients.EnableClientIdMetadataDocuments)
            {
                throw OAuthException.InvalidClient("Client ID metadata documents are not enabled on this server.");
            }
            return await _metadataDocuments.ResolveAsync(clientId, cancellationToken).ConfigureAwait(false);
        }
        if (_options.Clients.EnableDynamicClientRegistration
            && await _store.GetAsync<OAuthClient>(StoreKeys.Client(clientId), cancellationToken).ConfigureAwait(false) is { } registered)
        {
            return registered;
        }
        throw OAuthException.InvalidClient("Unknown client_id.");
    }

    /// <summary>Authenticates a client at the token endpoint.</summary>
    public async Task<OAuthClient> AuthenticateAsync(string? clientId, string? clientSecret, CancellationToken cancellationToken)
    {
        if (string.IsNullOrEmpty(clientId))
        {
            throw OAuthException.InvalidClient("client_id is required.");
        }
        var client = await GetAsync(clientId, cancellationToken).ConfigureAwait(false);
        if (client.IsConfidential
            && (clientSecret is null || !OAuthCrypto.FixedTimeEquals(OAuthCrypto.Hash(clientSecret), client.ClientSecretHash!)))
        {
            throw OAuthException.InvalidClient("Client authentication failed.");
        }
        return client;
    }

    public Task SaveDynamicAsync(OAuthClient client, CancellationToken cancellationToken) =>
        _store.SetAsync(StoreKeys.Client(client.ClientId), client, _options.Clients.DynamicClientLifetime, cancellationToken);
}
