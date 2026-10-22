using System.Text.Json;
using Microsoft.Extensions.Caching.Distributed;

namespace McpDotnet.Storage;

/// <summary>
/// An <see cref="IOAuthStateStore"/> backed by <see cref="IDistributedCache"/> (Redis, SQL Server, ...), so several
/// server instances can share OAuth state.
/// </summary>
/// <remarks>
/// <see cref="IDistributedCache"/> has no atomic get-and-remove, so <see cref="TakeAsync{T}"/> is a get followed
/// by a remove. Two instances racing to redeem the same authorization code within that window could both succeed;
/// implement <see cref="IOAuthStateStore"/> directly over your store (e.g. Redis <c>GETDEL</c>) if that matters to you.
/// </remarks>
public sealed class DistributedCacheOAuthStateStore : IOAuthStateStore
{
    private readonly IDistributedCache _cache;
    private readonly string _prefix;

    /// <summary>Creates the store.</summary>
    /// <param name="cache">The distributed cache.</param>
    /// <param name="keyPrefix">A prefix for all keys, to share a cache with other data.</param>
    public DistributedCacheOAuthStateStore(IDistributedCache cache, string keyPrefix = "mcpdotnet:")
    {
        _cache = cache;
        _prefix = keyPrefix;
    }

    /// <inheritdoc />
    public Task SetAsync<T>(string key, T value, TimeSpan? lifetime, CancellationToken cancellationToken = default)
        => _cache.SetAsync(
            _prefix + key,
            JsonSerializer.SerializeToUtf8Bytes(value),
            new DistributedCacheEntryOptions { AbsoluteExpirationRelativeToNow = lifetime },
            cancellationToken);

    /// <inheritdoc />
    public async Task<T?> GetAsync<T>(string key, CancellationToken cancellationToken = default)
    {
        var bytes = await _cache.GetAsync(_prefix + key, cancellationToken).ConfigureAwait(false);
        return bytes is null ? default : JsonSerializer.Deserialize<T>(bytes);
    }

    /// <inheritdoc />
    public async Task<T?> TakeAsync<T>(string key, CancellationToken cancellationToken = default)
    {
        var value = await GetAsync<T>(key, cancellationToken).ConfigureAwait(false);
        if (value is not null)
        {
            await _cache.RemoveAsync(_prefix + key, cancellationToken).ConfigureAwait(false);
        }
        return value;
    }

    /// <inheritdoc />
    public Task RemoveAsync(string key, CancellationToken cancellationToken = default)
        => _cache.RemoveAsync(_prefix + key, cancellationToken);
}
