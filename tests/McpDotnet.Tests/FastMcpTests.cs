using System.ComponentModel;
using McpDotnet.Tests.Infrastructure;
using ModelContextProtocol.Protocol;

namespace McpDotnet.Tests;

public class FastMcpTests
{
    [Fact]
    public async Task ExposesToolsResourcesAndPrompts()
    {
        var mcp = new FastMcp("Test Server", "2.0.0", "Use the add tool.");
        mcp.Tool("add", (int a, int b) => a + b, "Adds two numbers");
        mcp.Tool(Multiply);
        mcp.Resource("config://version", () => "2.0.0", description: "The version", mimeType: "text/plain");
        mcp.Resource("users://{id}/profile", (string id) => $"Profile of {id}", name: "user_profile");
        mcp.Prompt("review", (string code) => $"Please review:\n{code}", "Asks for a code review");

        await using var app = await TestApp.StartAsync(mcp);
        await using var client = await app.ConnectAsync();

        Assert.Equal("Test Server", client.ServerInfo!.Name);
        Assert.Equal("2.0.0", client.ServerInfo.Version);
        Assert.Equal("Use the add tool.", client.ServerInstructions);

        var tools = await client.ListToolsAsync();
        Assert.Equal(["add", "Multiply"], tools.Select(t => t.Name).Order().ToArray());
        Assert.Equal("Adds two numbers", tools.Single(t => t.Name == "add").Description);
        Assert.Equal("Multiplies two numbers", tools.Single(t => t.Name == "Multiply").Description);

        var sum = await client.CallToolAsync("add", new Dictionary<string, object?> { ["a"] = 2, ["b"] = 3 });
        Assert.Equal("5", Assert.IsType<TextContentBlock>(sum.Content.Single()).Text);

        var version = await client.ReadResourceAsync("config://version");
        Assert.Equal("2.0.0", Assert.IsType<TextResourceContents>(version.Contents.Single()).Text);

        var profile = await client.ReadResourceAsync("users://42/profile");
        Assert.Equal("Profile of 42", Assert.IsType<TextResourceContents>(profile.Contents.Single()).Text);

        var prompt = await client.GetPromptAsync("review", new Dictionary<string, object?> { ["code"] = "x++" });
        Assert.Contains("x++", Assert.IsType<TextContentBlock>(prompt.Messages.Single().Content).Text);
    }

    [Fact]
    public async Task UsesLocalFunctionNames()
    {
        [Description("Greets someone")]
        static string Greet(string name) => $"Hello, {name}!";

        var mcp = new FastMcp("Test").Tool(Greet);
        await using var app = await TestApp.StartAsync(mcp);
        await using var client = await app.ConnectAsync();

        var tool = Assert.Single(await client.ListToolsAsync());
        Assert.Equal("Greet", tool.Name);
        var result = await client.CallToolAsync("Greet", new Dictionary<string, object?> { ["name"] = "Ada" });
        Assert.Equal("Hello, Ada!", Assert.IsType<TextContentBlock>(result.Content.Single()).Text);
    }

    [Fact]
    public void LambdaToolsNeedAName()
    {
        var mcp = new FastMcp("Test");
        var ex = Assert.Throws<ArgumentException>(() => mcp.Tool(() => 1));
        Assert.Contains("name is required", ex.Message);
    }

    [Fact]
    public async Task UnauthenticatedServerHasNoAuthEndpoints()
    {
        await using var app = await TestApp.StartAsync(new FastMcp("Test"));
        var response = await app.CreateHttpClient().GetAsync("/.well-known/oauth-authorization-server");
        Assert.Equal(System.Net.HttpStatusCode.NotFound, response.StatusCode);
    }

    [Description("Multiplies two numbers")]
    private static int Multiply(int a, int b) => a * b;
}
