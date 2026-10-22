using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.WebUtilities;

namespace McpDotnet.Auth.OAuthProxy;

internal static class OAuthCrypto
{
    /// <summary>A URL-safe random token with 256 bits of entropy.</summary>
    public static string RandomToken() => WebEncoders.Base64UrlEncode(RandomNumberGenerator.GetBytes(32));

    public static string Hash(string value) => WebEncoders.Base64UrlEncode(SHA256.HashData(Encoding.UTF8.GetBytes(value)));

    public static string CodeChallenge(string verifier) => Hash(verifier);

    public static bool FixedTimeEquals(string a, string b) =>
        CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(a), Encoding.UTF8.GetBytes(b));

    /// <summary>Checks an RFC 7636 code verifier against an S256 challenge.</summary>
    public static bool VerifyPkce(string? verifier, string challenge)
    {
        if (verifier is null || verifier.Length is < 43 or > 128 || !verifier.All(IsUnreserved))
        {
            return false;
        }
        return FixedTimeEquals(CodeChallenge(verifier), challenge);
    }

    private static bool IsUnreserved(char c) => char.IsAsciiLetterOrDigit(c) || c is '-' or '.' or '_' or '~';
}
