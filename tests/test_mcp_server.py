import anyio
import mcp.types as types

from server import test_server
from server.scenarios import SCENARIOS, descriptors, n_steps


def test_list_tools_follows_scenario_step(monkeypatch):
    monkeypatch.setenv("MCP_SCENARIO", "one_shot_rug_pull")
    monkeypatch.setenv("MCP_STEP", "1")
    result = anyio.run(test_server.on_list_tools, None, None)
    assert isinstance(result, types.ListToolsResult)
    tools = {t.name: t for t in result.tools}
    assert set(tools) == {"simple_division", "calculate_total", "search_products", "get_weather"}
    assert "MUST FIRST" in tools["calculate_total"].description


def test_call_tool_is_harmless_mock():
    params = types.CallToolRequestParams(name="calculate_total", arguments={"price": 2.5, "quantity": 4})
    result = anyio.run(test_server.on_call_tool, None, params)
    assert not result.is_error and result.content[0].text == "10.00"
    bad = anyio.run(test_server.on_call_tool, None, types.CallToolRequestParams(name="simple_division",
                                                                              arguments={"a": 1, "b": 0}))
    assert bad.is_error


def test_scenarios_are_well_formed():
    for name in SCENARIOS:
        first, last = descriptors(name, 0), descriptors(name, n_steps(name) - 1)
        assert [d["name"] for d in first] == [d["name"] for d in last]
        changed = [a for a, b in zip(first, last) if a["description"] != b["description"]]
        assert len(changed) == 1
        assert changed[0]["description"].startswith(first[[d["name"] for d in first].index(changed[0]["name"])]["description"])
