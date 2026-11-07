"""Real MCP end-to-end check: client -> gateway proxy -> mock server, over stdio.

Restarts the mock server at successive scenario steps (simulating the
server pushing description updates between sessions) while the gateway
keeps its registry on disk, and prints which tools the client can see and
whether a tool call goes through.

Usage (from the mcp-security folder):
    python -m experiments.mcp_e2e [scenario] [policy]
"""

import os
import sys
import tempfile
from pathlib import Path

import anyio
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from server.scenarios import SCENARIOS, n_steps

ROOT = Path(__file__).resolve().parent.parent
ARGS = {"simple_division": {"a": 6, "b": 3}, "calculate_total": {"price": 2.5, "quantity": 4},
        "search_products": {"query": "lamp"}, "get_weather": {"city": "Delhi"}}


async def one_session(scenario: str, step: int, policy: str, state: Path) -> tuple[list[str], str]:
    env = dict(os.environ, MCP_SCENARIO=scenario, MCP_STEP=str(step), GATEWAY_POLICY=policy, GATEWAY_STATE=str(state))
    params = StdioServerParameters(command=sys.executable,
                                   args=["-m", "server.gateway_proxy", "--", sys.executable, "-m", "server.test_server"],
                                   env=env, cwd=str(ROOT))
    tool = next(iter(SCENARIOS[scenario]))
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            names = [t.name for t in (await session.list_tools()).tools]
            result = await session.call_tool(tool, ARGS[tool])
            text = " ".join(getattr(c, "text", "") for c in result.content)
            return names, ("ERROR: " if result.is_error else "OK: ") + text


async def run(scenario: str, policy: str) -> list[tuple[int, list[str], str]]:
    out = []
    with tempfile.TemporaryDirectory() as tmp:
        state = Path(tmp) / "registry.json"
        for step in range(n_steps(scenario)):
            names, call = await one_session(scenario, step, policy, state)
            out.append((step, names, call))
    return out


def main() -> int:
    scenario = sys.argv[1] if len(sys.argv) > 1 else "slow_rug_pull"
    policy = sys.argv[2] if len(sys.argv) > 2 else "mdp"
    tool = next(iter(SCENARIOS[scenario]))
    print(f"scenario={scenario} policy={policy} watched tool={tool}")
    for step, names, call in anyio.run(run, scenario, policy):
        print(f"  server v{step}: client sees {tool}: {tool in names} | call -> {call[:90]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
