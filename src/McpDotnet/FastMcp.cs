using System.Diagnostics.CodeAnalysis;
using System.Reflection;
using McpDotnet.Auth;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using ModelContextProtocol.AspNetCore;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;

namespace McpDotnet;

/// <summary>
/// A FastMCP-style definition of an MCP server: a name, a set of tools, resources and prompts,
/// and an optional <see cref="AuthProvider"/>.
/// </summary>
/// <remarks>
/// <para>Run it on its own:</para>
/// <code>
/// var mcp = new FastMcp("Demo");
/// mcp.Tool("add", (int a, int b) => a + b, "Adds two numbers");
/// await mcp.RunAsync(args); // stdio by default, "--transport http" for Streamable HTTP
/// </code>
/// <para>Or add it to an existing ASP.NET Core app with
/// <see cref="FastMcpServiceCollectionExtensions.AddFastMcp(IServiceCollection, FastMcp)"/> and
/// <see cref="FastMcpEndpointRouteBuilderExtensions.MapFastMcp"/>.</para>
/// </remarks>
public sealed class FastMcp
{
    private readonly List<Action<IServiceCollection>> _registrations = [];
    private readonly List<Action<IMcpServerBuilder>> _serverConfigurations = [];
    private Action<HttpServerTransportOptions>? _configureHttpTransport;

    /// <summary>Creates a new MCP server definition.</summary>
    /// <param name="name">The server name reported to clients.</param>
    /// <param name="version">The server version reported to clients.</param>
    /// <param name="instructions">Optional instructions describing how to use the server.</param>
    public FastMcp(string name, string? version = null, string? instructions = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        Name = name;
        Version = version ?? "1.0.0";
        Instructions = instructions;
    }

    /// <summary>Gets the server name reported to clients.</summary>
    public string Name { get; }

    /// <summary>Gets the server version reported to clients.</summary>
    public string Version { get; }

    /// <summary>Gets or sets the instructions sent to clients during initialization.</summary>
    public string? Instructions { get; set; }

    /// <summary>Gets or sets the HTTP path the MCP endpoint is mapped to. Defaults to <c>/mcp</c>.</summary>
    public string Path { get; set; } = "/mcp";

    /// <summary>Gets or sets whether the Streamable HTTP transport runs in stateless mode.</summary>
    public bool Stateless { get; set; }

    /// <summary>
    /// Gets or sets the authentication provider protecting the HTTP endpoint.
    /// <see langword="null"/> leaves the server unauthenticated. Ignored for stdio.
    /// </summary>
    public AuthProvider? Auth { get; set; }

    /// <summary>Registers a tool from a delegate.</summary>
    /// <param name="name">The tool name. Required for lambdas.</param>
    /// <param name="handler">The tool implementation. Parameters become the input schema;
    /// <see cref="CancellationToken"/>, <see cref="McpServer"/>, <see cref="IServiceProvider"/> and
    /// registered services (such as <see cref="McpAuthContext"/>) are injected.</param>
    /// <param name="description">The tool description. Falls back to a <c>[Description]</c> attribute on the method.</param>
    /// <param name="configure">Optional callback to set annotations such as <c>ReadOnly</c> or <c>Destructive</c>.</param>
    public FastMcp Tool(string name, Delegate handler, string? description = null, Action<McpServerToolCreateOptions>? configure = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        ArgumentNullException.ThrowIfNull(handler);
        _registrations.Add(services => services.AddSingleton(sp =>
        {
            var options = new McpServerToolCreateOptions { Services = sp, Name = name, Description = description };
            configure?.Invoke(options);
            return McpServerTool.Create(handler, options);
        }));
        return this;
    }

    /// <summary>Registers a tool from a named method, using the method name as the tool name.</summary>
    public FastMcp Tool(Delegate handler, string? description = null, Action<McpServerToolCreateOptions>? configure = null)
        => Tool(NameOf(handler, "tool"), handler, description, configure);

    /// <summary>Registers every <c>[McpServerTool]</c> method on <typeparamref name="T"/>.</summary>
    public FastMcp Tools<[DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicMethods | DynamicallyAccessedMemberTypes.NonPublicMethods | DynamicallyAccessedMemberTypes.PublicConstructors)] T>()
    {
        _serverConfigurations.Add(builder => builder.WithTools<T>());
        return this;
    }

    /// <summary>Registers a resource (or a resource template when <paramref name="uri"/> contains <c>{placeholders}</c>).</summary>
    /// <param name="uri">The resource URI or URI template, e.g. <c>config://app</c> or <c>users://{id}/profile</c>.</param>
    /// <param name="handler">The resource implementation. Template placeholders bind to parameters of the same name.</param>
    /// <param name="name">The resource name. Defaults to the method name, or the URI for lambdas.</param>
    /// <param name="description">The resource description.</param>
    /// <param name="mimeType">The MIME type of the content.</param>
    public FastMcp Resource(string uri, Delegate handler, string? name = null, string? description = null, string? mimeType = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(uri);
        ArgumentNullException.ThrowIfNull(handler);
        name ??= IsCompilerGenerated(handler) ? uri : handler.Method.Name;
        _registrations.Add(services => services.AddSingleton(sp => McpServerResource.Create(handler, new McpServerResourceCreateOptions
        {
            Services = sp,
            UriTemplate = uri,
            Name = name,
            Description = description,
            MimeType = mimeType,
        })));
        return this;
    }

    /// <summary>Registers every <c>[McpServerResource]</c> method on <typeparamref name="T"/>.</summary>
    public FastMcp Resources<[DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicMethods | DynamicallyAccessedMemberTypes.NonPublicMethods | DynamicallyAccessedMemberTypes.PublicConstructors)] T>()
    {
        _serverConfigurations.Add(builder => builder.WithResources<T>());
        return this;
    }

    /// <summary>Registers a prompt from a delegate.</summary>
    public FastMcp Prompt(string name, Delegate handler, string? description = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        ArgumentNullException.ThrowIfNull(handler);
        _registrations.Add(services => services.AddSingleton(sp => McpServerPrompt.Create(handler, new McpServerPromptCreateOptions
        {
            Services = sp,
            Name = name,
            Description = description,
        })));
        return this;
    }

    /// <summary>Registers a prompt from a named method, using the method name as the prompt name.</summary>
    public FastMcp Prompt(Delegate handler, string? description = null)
        => Prompt(NameOf(handler, "prompt"), handler, description);

    /// <summary>Registers every <c>[McpServerPrompt]</c> method on <typeparamref name="T"/>.</summary>
    public FastMcp Prompts<[DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicMethods | DynamicallyAccessedMemberTypes.NonPublicMethods | DynamicallyAccessedMemberTypes.PublicConstructors)] T>()
    {
        _serverConfigurations.Add(builder => builder.WithPrompts<T>());
        return this;
    }

    /// <summary>Registers all attributed tools, resources and prompts in an assembly (the calling assembly by default).</summary>
    [RequiresUnreferencedCode("Scans the assembly for attributed types.")]
    public FastMcp FromAssembly(Assembly? assembly = null)
    {
        assembly ??= Assembly.GetCallingAssembly();
        _serverConfigurations.Add(builder => builder
            .WithToolsFromAssembly(assembly)
            .WithResourcesFromAssembly(assembly)
            .WithPromptsFromAssembly(assembly));
        return this;
    }

    /// <summary>Escape hatch to configure the underlying SDK <see cref="IMcpServerBuilder"/> (filters, handlers, ...).</summary>
    public FastMcp ConfigureServer(Action<IMcpServerBuilder> configure)
    {
        ArgumentNullException.ThrowIfNull(configure);
        _serverConfigurations.Add(configure);
        return this;
    }

    /// <summary>Registers additional services, e.g. dependencies your tools need when running standalone.</summary>
    public FastMcp ConfigureServices(Action<IServiceCollection> configure)
    {
        ArgumentNullException.ThrowIfNull(configure);
        _registrations.Add(configure);
        return this;
    }

    /// <summary>Configures the Streamable HTTP transport.</summary>
    public FastMcp ConfigureHttpTransport(Action<HttpServerTransportOptions> configure)
    {
        _configureHttpTransport += configure;
        return this;
    }

    /// <summary>
    /// Runs the server, choosing the transport from the command line:
    /// <c>--transport stdio</c> (default) or <c>--transport http [--url http://127.0.0.1:8000]</c>.
    /// </summary>
    public Task RunAsync(string[]? args = null, CancellationToken cancellationToken = default)
    {
        args ??= [];
        var transport = GetArg(args, "--transport") ?? "stdio";
        return transport.ToLowerInvariant() switch
        {
            "stdio" => RunStdioAsync(cancellationToken),
            "http" or "streamable-http" => RunHttpAsync(GetArg(args, "--url") ?? "http://127.0.0.1:8000", args, cancellationToken),
            _ => throw new ArgumentException($"Unknown transport '{transport}'. Use 'stdio' or 'http'.", nameof(args)),
        };
    }

    /// <summary>Runs the server over stdio. Logs go to stderr so they don't corrupt the protocol stream.</summary>
    public async Task RunStdioAsync(CancellationToken cancellationToken = default)
    {
        var builder = Host.CreateApplicationBuilder();
        builder.Logging.ClearProviders();
        builder.Logging.AddConsole(o => o.LogToStandardErrorThreshold = LogLevel.Trace);
        AddCore(builder.Services).WithStdioServerTransport();
        using var host = builder.Build();
        await host.RunAsync(cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Runs the server over Streamable HTTP on <paramref name="url"/>.</summary>
    public async Task RunHttpAsync(string url = "http://127.0.0.1:8000", string[]? args = null, CancellationToken cancellationToken = default)
    {
        var builder = WebApplication.CreateBuilder(args ?? []);
        builder.WebHost.UseUrls(url);
        builder.Services.AddFastMcp(this);
        await using var app = builder.Build();
        app.MapFastMcp();
        await app.RunAsync(cancellationToken).ConfigureAwait(false);
    }

    internal string ResourceUrl(string baseUrl) => baseUrl.TrimEnd('/') + "/" + Path.TrimStart('/');

    internal IMcpServerBuilder AddCore(IServiceCollection services)
    {
        services.AddHttpContextAccessor();
        services.AddTransient<McpAuthContext>();
        var builder = services.AddMcpServer(o =>
        {
            o.ServerInfo = new Implementation { Name = Name, Version = Version };
            o.ServerInstructions = Instructions;
        });
        foreach (var register in _registrations)
        {
            register(services);
        }
        foreach (var configure in _serverConfigurations)
        {
            configure(builder);
        }
        return builder;
    }

    internal void ConfigureHttpTransportOptions(HttpServerTransportOptions options)
    {
        options.Stateless = Stateless;
        _configureHttpTransport?.Invoke(options);
    }

    private static bool IsCompilerGenerated(Delegate handler) => handler.Method.Name.Contains('<');

    private static string NameOf(Delegate handler, string kind)
    {
        ArgumentNullException.ThrowIfNull(handler);
        var methodName = handler.Method.Name;
        if (!IsCompilerGenerated(handler))
        {
            return methodName;
        }

        // Local functions compile to "<Outer>g__Name|0_0"; recover "Name". Lambdas have no usable name.
        var start = methodName.IndexOf(">g__", StringComparison.Ordinal);
        var end = methodName.IndexOf('|', StringComparison.Ordinal);
        if (start >= 0 && end > start + 4)
        {
            return methodName[(start + 4)..end];
        }
        throw new ArgumentException($"A name is required when the {kind} is a lambda.", nameof(handler));
    }

    private static string? GetArg(string[] args, string name)
    {
        for (var i = 0; i < args.Length; i++)
        {
            if (args[i] == name && i + 1 < args.Length)
            {
                return args[i + 1];
            }
            if (args[i].StartsWith(name + "=", StringComparison.Ordinal))
            {
                return args[i][(name.Length + 1)..];
            }
        }
        return null;
    }
}
