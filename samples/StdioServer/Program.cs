// The smallest possible server, FastMCP style.
//   dotnet run                                   -> stdio (for Claude Desktop, VS Code, ...)
//   dotnet run -- --transport http --url http://127.0.0.1:8000  -> Streamable HTTP at /mcp

using System.ComponentModel;
using McpDotnet;
using ModelContextProtocol.Server;

var mcp = new FastMcp("Calculator");

mcp.Tool("add", (double a, double b) => a + b, "Adds two numbers.");
mcp.Tool(Divide, configure: o => o.ReadOnly = true);
mcp.Tools<UnitTools>();
mcp.Resource("calc://constants/{name}", (string name) => name switch
{
    "pi" => Math.PI.ToString(),
    "e" => Math.E.ToString(),
    _ => throw new ArgumentException($"Unknown constant '{name}'."),
}, name: "constant", description: "A mathematical constant.");

await mcp.RunAsync(args);

[Description("Divides a by b.")]
static double Divide(double a, double b) => b == 0 ? throw new ArgumentException("Cannot divide by zero.") : a / b;

// Attribute-based tools work too, exactly as in the official SDK.
[McpServerToolType]
public sealed class UnitTools
{
    [McpServerTool(Name = "celsius_to_fahrenheit"), Description("Converts Celsius to Fahrenheit.")]
    public static double CelsiusToFahrenheit(double celsius) => celsius * 9 / 5 + 32;
}
