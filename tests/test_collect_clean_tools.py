import json

from benchmark.collect_clean_tools import HARD_NEGATIVES, OUT, extract_tools


def test_ts_register_tool_with_concatenation():
    src = '''server.registerTool(
    "read_text_file",
    {
      title: "Read Text File",
      description:
        "Read a file as text. " +
        "Handles encodings.",
      inputSchema: {},
    });'''
    assert extract_tools(src) == [("read_text_file", "Read a file as text. Handles encodings.")]


def test_ts_tool_object_ignores_property_descriptions():
    src = '''const postMessageTool: Tool = {
  name: "slack_post_message",
  description: "Post a new message to a Slack channel",
  inputSchema: { properties: { text: { type: "string", description: "The message text" } } },
};'''
    assert extract_tools(src) == [("slack_post_message", "Post a new message to a Slack channel")]


def test_python_enum_name_and_named_constant():
    src = '''class TimeTools(str, Enum):
    GET_CURRENT_TIME = "get_current_time"
FETCH_DESCRIPTION = """Fetches a URL."""
tools = [
    Tool(name=TimeTools.GET_CURRENT_TIME.value, description="Get current time"),
    Tool(name="fetch", description=FETCH_DESCRIPTION),
]'''
    assert extract_tools(src) == [("get_current_time", "Get current time"), ("fetch", "Fetches a URL.")]


def test_prompt_arguments_and_server_metadata_are_skipped():
    src = '''types.PromptArgument(name="topic", description="Topic to seed", required=True)
const server = new Server({ name: "redis", version: "0.0.1" });
'''
    assert extract_tools(src) == []


def test_clean_tools_file():
    rows = [json.loads(line) for line in open(OUT, encoding="utf-8")]
    ids = [r["tool_id"] for r in rows]
    assert len(rows) >= 100
    assert len(ids) == len(set(ids))
    assert all(r["description"] and r["source_url"].startswith("https://") for r in rows)
    assert {r["tool_id"] for r in rows if r["hard_negative"]} == HARD_NEGATIVES
