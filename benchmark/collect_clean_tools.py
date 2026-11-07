"""Collect clean tool descriptions from the official MCP reference servers.

Downloads each server's source file(s) from GitHub, extracts every tool's
name and description, and writes data/clean_tools.jsonl with the source URL.
These are the "clean" (approved) starting versions d0 for RugPullBench.

Downloaded source is treated as text only; it is never imported or executed.

Usage (from the mcp-security folder):
    python -m benchmark.collect_clean_tools            # download + extract
    python -m benchmark.collect_clean_tools --offline  # reuse data/raw_sources/
"""

import json
import re
import sys
import urllib.request
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RAW = ROOT / "data" / "raw_sources"
OUT = ROOT / "data" / "clean_tools.jsonl"

_MAIN = "https://raw.githubusercontent.com/modelcontextprotocol/servers/main/src/"
_ARCHIVED = "https://raw.githubusercontent.com/modelcontextprotocol/servers-archived/main/src/"

# Server name (matching MCPTox server_name where one exists) -> source files.
SOURCES = {
    "FileSystem": [_MAIN + "filesystem/server.ts"],
    "Memory": [_MAIN + "memory/index.ts"],
    "Git": [_MAIN + "git/src/mcp_server_git/server.py"],
    "Fetch": [_MAIN + "fetch/src/mcp_server_fetch/server.py"],
    "Time": [_MAIN + "time/src/mcp_server_time/server.py"],
    "Sequential Thinking": [_MAIN + "sequentialthinking/index.ts"],
    "Everything": [_MAIN + f"everything/tools/{t}.ts" for t in (
        "echo", "get-sum", "get-env", "get-tiny-image", "trigger-long-running-operation")],
    "SQLite": [_ARCHIVED + "sqlite/src/mcp_server_sqlite/server.py"],
    "Slack": [_ARCHIVED + "slack/index.ts"],
    "Github": [_ARCHIVED + "github/index.ts"],
    "Puppeteer": [_ARCHIVED + "puppeteer/index.ts"],
    "BraveSearch": [_ARCHIVED + "brave-search/index.ts"],
    "Google Maps": [_ARCHIVED + "google-maps/index.ts"],
    "Gitlab": [_ARCHIVED + "gitlab/index.ts"],
    "Redis": [_ARCHIVED + "redis/src/index.ts"],
    "Postgres": [_ARCHIVED + "postgres/index.ts"],
    "GoogleDrive": [_ARCHIVED + "gdrive/index.ts"],
    "EverArt": [_ARCHIVED + "everart/index.ts"],
    "Sentry": [_ARCHIVED + "sentry/src/mcp_server_sentry/server.py"],
    "AWSKnowledgeBase": [_ARCHIVED + "aws-kb-retrieval-server/index.ts"],
}

# Legitimate descriptions that look suspicious (instructions aimed at the
# model, mentions of secrets, code execution). Reported separately in eval.
HARD_NEGATIVES = {
    "Fetch/fetch",                     # tells the model it "now" has internet access
    "Everything/get-env",              # mentions keys, tokens, secrets, passwords
    "Puppeteer/puppeteer_evaluate",    # executes JavaScript
    "FileSystem/write_file",           # overwrites files
    "SQLite/write_query",              # modifies the database
    "Github/push_files",               # writes to a remote repository
}

# Where a tool name is declared. Group 1 is a literal name, group 2 an
# identifier to resolve (Python enum member or named constant).
_NAME_PATTERNS = [
    re.compile(r"registerTool\(\s*[\"'`]([\w\-]+)[\"'`]"),
    re.compile(r"\bconst\s+name\s*=\s*[\"']([\w\-]+)[\"']"),
    re.compile(r"\bname:\s*[\"']([\w\-]+)[\"']"),
    re.compile(r"\bTool\(\s*name\s*=\s*(?:[\"']([\w\-]+)[\"']|\w+\.(\w+)\.value)"),
    re.compile(r"(?<![\w.])name\s*=\s*(?:[\"']([\w\-]+)[\"']|\w+\.(\w+)\.value)"),
]
_DESC = re.compile(r"\bdescription\s*[:=]\s*")
_STRING = re.compile(
    r'"""(.*?)"""|\'\'\'(.*?)\'\'\'|"((?:[^"\\\n]|\\.)*)"|\'((?:[^\'\\\n]|\\.)*)\'|`((?:[^`\\]|\\.)*)`',
    re.DOTALL,
)
_SEPARATOR = re.compile(r"(?:\s|\+|\(|#[^\n]*|//[^\n]*)*")
# Python prompt arguments, resources and prompts also have name/description.
_NOT_A_TOOL = re.compile(r"PromptArgument\(|types\.Prompt\(|types\.Resource\(|mimeType|uri\s*=")
# Server metadata looks like { name: "x", version: "1.0" }.
_SERVER_META = re.compile(r"^\s*,\s*version\s*:")
# A tool name must be followed by its description within this many characters.
_WINDOW = 700


def _unescape(s: str) -> str:
    return s.replace("\\n", " ").replace('\\"', '"').replace("\\'", "'").replace("\\\\", "\\")


def read_strings(src: str, pos: int) -> tuple[str, int]:
    """Read one or more concatenated string literals starting near `pos`."""
    parts = []
    while True:
        pos = _SEPARATOR.match(src, pos).end()
        m = _STRING.match(src, pos)
        if not m:
            break
        parts.append(_unescape(next(g for g in m.groups() if g is not None)))
        pos = m.end()
    return " ".join(" ".join(parts).split()), pos


def resolve_constant(src: str, ident: str) -> str:
    m = re.search(rf"(?:const\s+)?\b{re.escape(ident)}\s*[:=]\s*", src)
    if not m:
        return ""
    return read_strings(src, m.end())[0]


def extract_tools(src: str) -> list[tuple[str, str]]:
    found = {}
    for pattern in _NAME_PATTERNS:
        for m in pattern.finditer(src):
            literal = m.group(1)
            ident = m.group(2) if pattern.groups > 1 else None
            name = literal or (resolve_constant(src, ident) if ident else "")
            if not name or m.start() in found:
                continue
            window = src[m.end(): m.end() + _WINDOW]
            if _NOT_A_TOOL.search(src[max(0, m.start() - 80): m.end() + 300]) or _SERVER_META.match(window):
                continue
            d = _DESC.search(window)
            if not d:
                continue
            desc_pos = m.end() + d.end()
            desc, _ = read_strings(src, desc_pos)
            if not desc:
                ident_m = re.match(r"([A-Z_][A-Z0-9_]*)", src[desc_pos:])
                desc = resolve_constant(src, ident_m.group(1)) if ident_m else ""
            if desc:
                found[m.start()] = (name, desc)
    # Keep the first description seen for each tool name, in source order.
    tools = {}
    for _, (name, desc) in sorted(found.items()):
        tools.setdefault(name, desc)
    return list(tools.items())


def _raw_path(url: str) -> Path:
    tail = url.split("/src/", 1)[1].replace("/", "_")
    prefix = "archived_" if "servers-archived" in url else "main_"
    return RAW / (prefix + tail)


def fetch(url: str, offline: bool) -> str:
    path = _raw_path(url)
    if not offline:
        RAW.mkdir(parents=True, exist_ok=True)
        path.write_bytes(urllib.request.urlopen(url, timeout=30).read())
    return path.read_text(encoding="utf-8")


def collect(offline: bool = False) -> list[dict]:
    rows = []
    for server, urls in SOURCES.items():
        for url in urls:
            for name, desc in extract_tools(fetch(url, offline)):
                tool_id = f"{server}/{name}"
                rows.append({
                    "tool_id": tool_id,
                    "server": server,
                    "tool_name": name,
                    "description": desc,
                    "hard_negative": tool_id in HARD_NEGATIVES,
                    "source": "official_mcp_server",
                    "source_url": url,
                })
    return rows


def main() -> int:
    rows = collect(offline="--offline" in sys.argv)
    with open(OUT, "w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    print(json.dumps(dict(Counter(r["server"] for r in rows)), indent=2))
    print(f"Wrote {len(rows)} clean tools to {OUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
