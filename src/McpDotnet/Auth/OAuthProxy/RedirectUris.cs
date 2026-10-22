using System.Net;
using System.Text.RegularExpressions;

namespace McpDotnet.Auth.OAuthProxy;

internal static class RedirectUris
{
    private static readonly HashSet<string> ForbiddenSchemes = new(StringComparer.OrdinalIgnoreCase)
    {
        "javascript", "data", "file", "vbscript", "about", "blob", "filesystem", "ftp", "ws", "wss",
    };

    /// <summary>
    /// Validates a redirect URI a client registers (via DCR or a metadata document).
    /// Returns an error description, or <see langword="null"/> if the URI is acceptable.
    /// </summary>
    public static string? Validate(string uri, IList<string> allowedPatterns)
    {
        if (!Uri.TryCreate(uri, UriKind.Absolute, out var parsed))
        {
            return $"Redirect URI '{uri}' is not an absolute URI.";
        }
        if (!string.IsNullOrEmpty(parsed.Fragment))
        {
            return $"Redirect URI '{uri}' must not contain a fragment.";
        }
        if (ForbiddenSchemes.Contains(parsed.Scheme))
        {
            return $"Redirect URI scheme '{parsed.Scheme}' is not allowed.";
        }
        if (parsed.Scheme == Uri.UriSchemeHttp && !IsLoopback(parsed))
        {
            return $"Redirect URI '{uri}' must use HTTPS unless it targets a loopback address.";
        }
        if (allowedPatterns.Count > 0 && !allowedPatterns.Any(p => MatchesPattern(uri, p)))
        {
            return $"Redirect URI '{uri}' is not in the server's list of allowed redirect URIs.";
        }
        return null;
    }

    /// <summary>
    /// Checks a redirect URI from an authorization request against the client's registered URIs: exact match,
    /// except that the port of loopback HTTP URIs may vary (RFC 8252 section 7.3).
    /// </summary>
    public static bool IsRegistered(string requested, IEnumerable<string> registered)
    {
        foreach (var candidate in registered)
        {
            if (string.Equals(requested, candidate, StringComparison.Ordinal))
            {
                return true;
            }
            if (Uri.TryCreate(requested, UriKind.Absolute, out var r)
                && Uri.TryCreate(candidate, UriKind.Absolute, out var c)
                && r.Scheme == Uri.UriSchemeHttp && c.Scheme == Uri.UriSchemeHttp
                && IsLoopback(r)
                && string.Equals(r.Host, c.Host, StringComparison.OrdinalIgnoreCase)
                && string.Equals(r.PathAndQuery, c.PathAndQuery, StringComparison.Ordinal)
                && string.IsNullOrEmpty(r.UserInfo))
            {
                return true;
            }
        }
        return false;
    }

    public static bool MatchesPattern(string uri, string pattern)
    {
        var regex = "^" + Regex.Escape(pattern).Replace("\\*", ".*", StringComparison.Ordinal) + "$";
        return Regex.IsMatch(uri, regex, RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(100));
    }

    private static bool IsLoopback(Uri uri) =>
        uri.IsLoopback || (IPAddress.TryParse(uri.Host.Trim('[', ']'), out var ip) && IPAddress.IsLoopback(ip));
}
