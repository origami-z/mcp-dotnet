using System.Security.Claims;

namespace McpDotnet.Auth;

internal static class ScopeHelper
{
    public static IEnumerable<string> GetScopes(ClaimsPrincipal user) => user
        .FindAll(c => c.Type is "scope" or "scp")
        .SelectMany(c => c.Value.Split(' ', StringSplitOptions.RemoveEmptyEntries));

    public static bool HasScope(ClaimsPrincipal user, string scope) => GetScopes(user).Contains(scope, StringComparer.Ordinal);

    public static string[] Split(string? scopes) =>
        string.IsNullOrWhiteSpace(scopes) ? [] : scopes.Split(' ', StringSplitOptions.RemoveEmptyEntries).Distinct(StringComparer.Ordinal).ToArray();
}
