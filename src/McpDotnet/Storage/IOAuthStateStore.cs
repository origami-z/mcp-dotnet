namespace McpDotnet.Storage;

/// <summary>
/// Key/value storage for OAuth proxy state: registered clients, pending authorizations, authorization codes,
/// refresh tokens and upstream tokens. Values are serialized with System.Text.Json.
/// </summary>
/// <remarks>
/// The default <see cref="InMemoryOAuthStateStore"/> only works for a single instance and loses state on restart.
/// Use <see cref="DistributedCacheOAuthStateStore"/> (backed by Redis, SQL Server, ... via <c>IDistributedCache</c>)
/// for multi-instance deployments, or implement this interface over your own database.
/// </remarks>
public interface IOAuthStateStore
{
    /// <summary>Stores <paramref name="value"/> under <paramref name="key"/>, replacing any existing value.</summary>
    /// <param name="key">The key.</param>
    /// <param name="value">The value.</param>
    /// <param name="lifetime">How long to keep the value; <see langword="null"/> keeps it indefinitely.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    Task SetAsync<T>(string key, T value, TimeSpan? lifetime, CancellationToken cancellationToken = default);

    /// <summary>Gets the value stored under <paramref name="key"/>, or <see langword="default"/> if none.</summary>
    Task<T?> GetAsync<T>(string key, CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets and removes the value stored under <paramref name="key"/>. Used for single-use values such as
    /// authorization codes, so implementations should make this atomic where the backing store allows.
    /// </summary>
    Task<T?> TakeAsync<T>(string key, CancellationToken cancellationToken = default);

    /// <summary>Removes the value stored under <paramref name="key"/>.</summary>
    Task RemoveAsync(string key, CancellationToken cancellationToken = default);
}
