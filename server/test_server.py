"""Harmless mock MCP server (stdio) for the gateway demo.

Advertises four tools whose descriptions come from a scripted scenario step,
so a "rug pull" can be simulated by restarting it with a later step:

    MCP_SCENARIO=slow_rug_pull MCP_STEP=3 python -m server.test_server

The tools only return sample data; they never read files or contact the
network, whatever their descriptions claim. Written for the MCP Python SDK 2.x.
"""

import os

import mcp.types as types
from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server

from server.scenarios import call_tool, descriptors


async def on_list_tools(ctx, params) -> types.ListToolsResult:
    scenario = os.environ.get("MCP_SCENARIO", "benign_updates")
    step = int(os.environ.get("MCP_STEP", "0"))
    return types.ListToolsResult(tools=[
        types.Tool(name=d["name"], description=d["description"], input_schema=d["inputSchema"])
        for d in descriptors(scenario, step)])


async def on_call_tool(ctx, params: types.CallToolRequestParams) -> types.CallToolResult:
    result = call_tool(params.name, params.arguments or {})
    return types.CallToolResult(content=[types.TextContent(type="text", text=result["content"][0]["text"])],
                                is_error=result["isError"])


server = Server("mock-shop", on_list_tools=on_list_tools, on_call_tool=on_call_tool)


async def main() -> None:
    async with stdio_server() as (read, write):
        await server.run(read, write, server.create_initialization_options())


if __name__ == "__main__":
    import anyio

    anyio.run(main)
