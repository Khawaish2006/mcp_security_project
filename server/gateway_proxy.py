"""MCP security gateway as a real stdio MCP proxy (MCP Python SDK 2.x).

The AI client connects to this process instead of the upstream server. It
connects to the upstream server itself, filters tools/list through the
Gateway and only forwards tools/call for approved tools. The registry is
persisted, so approvals survive restarts and a later rug pull is compared
with what was approved before.

    python -m server.gateway_proxy -- <upstream command...>
    e.g. python -m server.gateway_proxy -- python -m server.test_server

Environment: GATEWAY_POLICY=mdp|threshold|cumulative_threshold (default mdp),
GATEWAY_STATE=path to the registry JSON (default logs/registry.json).
"""

import os
import sys
from pathlib import Path

import mcp.types as types
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server

from gateway.audit_log import AuditLog
from gateway.descriptor_registry import DescriptorRegistry
from gateway.detector import DualDetector
from gateway.embedder import SentenceEmbedder
from gateway.interceptor import Gateway

ROOT = Path(__file__).resolve().parent.parent


def build_gateway() -> Gateway:
    from experiments.demo import load_policies

    emb = SentenceEmbedder(ROOT / "data" / "cache" / "embeddings.npz")
    detector = DualDetector.load(ROOT / "models" / "detector.joblib", emb)
    policy = load_policies()[os.environ.get("GATEWAY_POLICY", "mdp")]
    state = Path(os.environ.get("GATEWAY_STATE", ROOT / "logs" / "registry.json"))
    return Gateway(detector, policy, DescriptorRegistry(state), AuditLog(ROOT / "logs" / "audit_proxy.jsonl"))


def _blocked(reason: str) -> types.CallToolResult:
    return types.CallToolResult(content=[types.TextContent(type="text", text=f"Blocked by MCP security gateway: {reason}")],
                                is_error=True)


async def serve(command: list[str]) -> None:
    gateway = build_gateway()
    params = StdioServerParameters(command=command[0], args=command[1:], env=dict(os.environ), cwd=str(ROOT))
    async with stdio_client(params) as (up_read, up_write):
        async with ClientSession(up_read, up_write) as upstream:
            await upstream.initialize()

            async def on_list_tools(ctx, req) -> types.ListToolsResult:
                tools = (await upstream.list_tools()).tools
                raw = [{"name": t.name, "description": t.description or "", "inputSchema": t.input_schema}
                       for t in tools]
                allowed = {d["name"] for d in gateway.review_tools(raw)}
                return types.ListToolsResult(tools=[t for t in tools if t.name in allowed])

            async def on_call_tool(ctx, req: types.CallToolRequestParams) -> types.CallToolResult:
                ok, reason = gateway.authorize_call(req.name)
                gateway.audit.log(tool=req.name, event="tool_call", action="ALLOW" if ok else "BLOCK", reason=reason)
                if not ok:
                    return _blocked(reason)
                return await upstream.call_tool(req.name, req.arguments or {})

            server = Server("mcp-security-gateway", on_list_tools=on_list_tools, on_call_tool=on_call_tool)
            async with stdio_server() as (read, write):
                await server.run(read, write, server.create_initialization_options())


def main() -> None:
    import anyio

    argv = sys.argv[1:]
    command = argv[argv.index("--") + 1:] if "--" in argv else [sys.executable, "-m", "server.test_server"]
    anyio.run(serve, command)


if __name__ == "__main__":
    main()
