using System.Text;
using System.Text.Encodings.Web;

namespace McpDotnet.Auth.OAuthProxy;

internal static class ConsentPage
{
    public static string Render(string serverName, OAuthClient client, PendingAuthorization pending, string formAction)
    {
        var enc = HtmlEncoder.Default;
        var clientName = client.ClientName ?? client.ClientId;
        var redirectHost = Uri.TryCreate(pending.RedirectUri, UriKind.Absolute, out var redirect) ? redirect.GetLeftPart(UriPartial.Authority) : pending.RedirectUri;
        var source = client.Source switch
        {
            ClientSource.MetadataDocument => "Identified by its metadata document at " + client.ClientId,
            ClientSource.Dynamic => "Dynamically registered client " + client.ClientId,
            _ => "Client " + client.ClientId,
        };

        var scopes = new StringBuilder();
        foreach (var scope in pending.Scopes)
        {
            scopes.Append("<li><code>").Append(enc.Encode(scope)).Append("</code></li>");
        }

        return $$"""
            <!doctype html>
            <html lang="en">
            <head>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <title>Authorize {{enc.Encode(clientName)}}</title>
            <style>
            :root { color-scheme: light dark; --fg: #1f2328; --muted: #59636e; --bg: #f6f8fa; --card: #fff; --border: #d1d9e0; --accent: #0969da; }
            @media (prefers-color-scheme: dark) { :root { --fg: #e6edf3; --muted: #9198a1; --bg: #0d1117; --card: #151b23; --border: #3d444d; --accent: #4493f8; } }
            body { margin: 0; font: 15px/1.5 system-ui, -apple-system, "Segoe UI", sans-serif; color: var(--fg); background: var(--bg); }
            main { max-width: 460px; margin: 10vh auto; padding: 0 16px; }
            .card { background: var(--card); border: 1px solid var(--border); border-radius: 12px; padding: 28px; }
            h1 { font-size: 20px; margin: 0 0 12px; }
            p, li { color: var(--muted); }
            .meta { font-size: 13px; word-break: break-all; }
            code { font-size: 13px; }
            .buttons { display: flex; gap: 12px; margin-top: 24px; }
            button { flex: 1; padding: 10px; border-radius: 8px; border: 1px solid var(--border); font: inherit; cursor: pointer; background: var(--card); color: var(--fg); }
            button.primary { background: var(--accent); border-color: var(--accent); color: #fff; }
            </style>
            </head>
            <body>
            <main>
            <div class="card">
            <h1><strong>{{enc.Encode(clientName)}}</strong> wants to access {{enc.Encode(serverName)}}</h1>
            <p>After you sign in, you will be sent back to <strong>{{enc.Encode(redirectHost)}}</strong>. Only continue if you started this connection and trust this application.</p>
            {{(scopes.Length > 0 ? "<p>Requested permissions:</p><ul>" + scopes + "</ul>" : "")}}
            <p class="meta">{{enc.Encode(source)}}</p>
            <form method="post" action="{{enc.Encode(formAction)}}">
            <input type="hidden" name="request_id" value="{{enc.Encode(pending.Id)}}">
            <input type="hidden" name="consent_token" value="{{enc.Encode(pending.BrowserBinding)}}">
            <div class="buttons">
            <button type="submit" name="decision" value="deny">Deny</button>
            <button type="submit" name="decision" value="approve" class="primary">Allow</button>
            </div>
            </form>
            </div>
            </main>
            </body>
            </html>
            """;
    }

    public static string RenderError(string title, string message)
    {
        var enc = HtmlEncoder.Default;
        return $$"""
            <!doctype html>
            <html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
            <title>{{enc.Encode(title)}}</title>
            <style>:root { color-scheme: light dark; } body { font: 15px/1.5 system-ui, sans-serif; max-width: 460px; margin: 10vh auto; padding: 0 16px; }</style>
            </head><body><h1>{{enc.Encode(title)}}</h1><p>{{enc.Encode(message)}}</p></body></html>
            """;
    }
}
