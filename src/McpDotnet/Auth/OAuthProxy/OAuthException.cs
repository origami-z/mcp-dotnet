namespace McpDotnet.Auth.OAuthProxy;

/// <summary>An OAuth protocol error (RFC 6749 section 5.2) returned to the client.</summary>
internal sealed class OAuthException : Exception
{
    public OAuthException(string error, string description, int statusCode = 400)
        : base(description)
    {
        Error = error;
        StatusCode = statusCode;
    }

    public string Error { get; }

    public int StatusCode { get; }

    public static OAuthException InvalidRequest(string description) => new("invalid_request", description);

    public static OAuthException InvalidClient(string description) => new("invalid_client", description, 401);

    public static OAuthException InvalidGrant(string description) => new("invalid_grant", description);

    public static OAuthException InvalidScope(string description) => new("invalid_scope", description);

    public static OAuthException InvalidTarget(string description) => new("invalid_target", description);
}
