using System.Collections.Concurrent;
using System.Text.Json;

namespace McpDotnet.Storage;

/// <summary>An in-process <see cref="IOAuthStateStore"/>. Suitable for development and single-instance servers.</summary>
public sealed class InMemoryOAuthStateStore : IOAuthStateStore
{
    private readonly ConcurrentDictionary<string, Entry> _entries = new(StringComparer.Ordinal);
    private readonly TimeProvider _timeProvider;
    private long _writes;

    /// <summary>Creates the store.</summary>
    public InMemoryOAuthStateStore(TimeProvider? timeProvider = null)
    {
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    /// <inheritdoc />
    public Task SetAsync<T>(string key, T value, TimeSpan? lifetime, CancellationToken cancellationToken = default)
    {
        var expires = lifetime is { } l ? _timeProvider.GetUtcNow() + l : (DateTimeOffset?)null;
        _entries[key] = new Entry(JsonSerializer.SerializeToUtf8Bytes(value), expires);
        if (Interlocked.Increment(ref _writes) % 1024 == 0)
        {
            PurgeExpired();
        }
        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public Task<T?> GetAsync<T>(string key, CancellationToken cancellationToken = default)
        => Task.FromResult(_entries.TryGetValue(key, out var entry) ? Read<T>(key, entry) : default);

    /// <inheritdoc />
    public Task<T?> TakeAsync<T>(string key, CancellationToken cancellationToken = default)
        => Task.FromResult(_entries.TryRemove(key, out var entry) ? Read<T>(null, entry) : default);

    /// <inheritdoc />
    public Task RemoveAsync(string key, CancellationToken cancellationToken = default)
    {
        _entries.TryRemove(key, out _);
        return Task.CompletedTask;
    }

    private T? Read<T>(string? key, Entry entry)
    {
        if (entry.Expires is { } expires && expires <= _timeProvider.GetUtcNow())
        {
            if (key is not null)
            {
                _entries.TryRemove(new KeyValuePair<string, Entry>(key, entry));
            }
            return default;
        }
        return JsonSerializer.Deserialize<T>(entry.Json);
    }

    private void PurgeExpired()
    {
        var now = _timeProvider.GetUtcNow();
        foreach (var pair in _entries)
        {
            if (pair.Value.Expires is { } expires && expires <= now)
            {
                _entries.TryRemove(pair);
            }
        }
    }

    private sealed record Entry(byte[] Json, DateTimeOffset? Expires);
}
