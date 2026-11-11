"""Mine real tool-description changes from the official MCP servers' git history.

Walks every commit that touched a server's source directory in local clones of
modelcontextprotocol/servers and modelcontextprotocol/servers-archived,
extracts every tool's description at that commit (same extractor as
collect_clean_tools), and records each tool's sequence of distinct
descriptions. These are real, legitimate updates written by maintainers:
the benign counterpart that template-generated edits only approximate.

Writes data/real_histories.jsonl: one row per tool with at least two distinct
descriptions, versions oldest first, each with its commit, date and repo.

Usage (from the mcp-security folder; clones are read, never modified):
    git clone https://github.com/modelcontextprotocol/servers.git <dir>/servers
    git clone https://github.com/modelcontextprotocol/servers-archived.git <dir>/servers-archived
    python -m benchmark.mine_git_history --repos <dir>
"""

import argparse
import json
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path

from benchmark.collect_clean_tools import extract_tools
from gateway.diff import split_sentences

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "data" / "real_histories.jsonl"

# Source directory -> server name used everywhere else in the project.
SERVER_DIRS = {
    "filesystem": "FileSystem", "memory": "Memory", "git": "Git", "fetch": "Fetch", "time": "Time",
    "sequentialthinking": "Sequential Thinking", "everything": "Everything", "sqlite": "SQLite",
    "slack": "Slack", "github": "Github", "puppeteer": "Puppeteer", "brave-search": "BraveSearch",
    "google-maps": "Google Maps", "gitlab": "Gitlab", "redis": "Redis", "postgres": "Postgres",
    "gdrive": "GoogleDrive", "everart": "EverArt", "sentry": "Sentry", "aws-kb-retrieval-server": "AWSKnowledgeBase",
}
REPOS = ("servers", "servers-archived")


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True,
                          encoding="utf-8", errors="replace", check=True).stdout


def _is_source(path: str) -> bool:
    low = path.lower()
    return (low.endswith((".ts", ".py")) and not low.endswith(".d.ts")
            and not any(part in low for part in ("test", "node_modules", "/dist/", "__init__")))


class BlobReader:
    """One long-lived `git cat-file --batch` process per repo."""

    def __init__(self, repo: Path):
        self.proc = subprocess.Popen(["git", "-C", str(repo), "cat-file", "--batch"],
                                     stdin=subprocess.PIPE, stdout=subprocess.PIPE)

    def read(self, rev_path: str) -> str:
        self.proc.stdin.write((rev_path + "\n").encode("utf-8"))
        self.proc.stdin.flush()
        header = self.proc.stdout.readline().decode("utf-8", "replace").split()
        if len(header) < 3 or header[1] == "missing":
            return ""
        data = self.proc.stdout.read(int(header[2]))
        self.proc.stdout.read(1)  # trailing newline
        return data.decode("utf-8", "replace")

    def close(self) -> None:
        self.proc.stdin.close()
        self.proc.wait()


def tools_at(repo: Path, reader: BlobReader, sha: str, src_dir: str) -> dict[str, str]:
    files = [f for f in _git(repo, "ls-tree", "-r", "--name-only", sha, "--", f"src/{src_dir}").splitlines()
             if _is_source(f)]
    tools: dict[str, str] = {}
    for f in sorted(files):
        for name, desc in extract_tools(reader.read(f"{sha}:{f}")):
            tools.setdefault(name, desc)
    return tools


def drop_transient_truncations(versions: list[dict]) -> list[dict]:
    """Drop a version whose sentences all appear in both neighbours from the same day.

    During code refactors the extractor sometimes sees only the first part of a
    description for one commit; the next commit restores it. That is a parsing
    artifact, not a maintainer's change.
    """
    def sentences(v):
        return set(split_sentences(v["description"]))
    kept = []
    for i, v in enumerate(versions):
        if 0 < i < len(versions) - 1:
            prev, nxt = versions[i - 1], versions[i + 1]
            if (v["date"][:10] in (prev["date"][:10], nxt["date"][:10])
                    and sentences(v) <= sentences(prev) and sentences(v) <= sentences(nxt)):
                continue
        kept.append(v)
    return kept


def mine(repos_dir: Path) -> list[dict]:
    histories: dict[tuple[str, str], list[dict]] = {}
    for repo_name in REPOS:
        repo = repos_dir / repo_name
        reader = BlobReader(repo)
        for src_dir, server in SERVER_DIRS.items():
            log = _git(repo, "log", "--reverse", "--format=%H%x09%cI", "--", f"src/{src_dir}").splitlines()
            for line in log:
                sha, date = line.split("\t")
                for name, desc in tools_at(repo, reader, sha, src_dir).items():
                    versions = histories.setdefault((server, name), [])
                    norm = " ".join(desc.split())
                    if norm in {" ".join(v["description"].split()) for v in versions}:
                        continue  # seen before (also dedupes the history the two repos share)
                    versions.append({"description": desc, "commit": sha, "date": date, "repo": repo_name})
        reader.close()
    rows = []
    for (server, name), versions in sorted(histories.items()):
        versions = drop_transient_truncations(sorted(versions, key=lambda v: v["date"]))
        if len(versions) >= 2:
            rows.append({"tool_id": f"{server}/{name}", "server": server, "tool_name": name,
                         "source": "real_git_history", "versions": versions})
    return rows


# Community repos: everything outside these folders that looks like source is scanned.
_SKIP_DIRS = ("examples/", "example/", "docs/", "scripts/", ".github/", "test/", "tests/", "__tests__/", "e2e/", "evals/")
_TOOL_NAME = re.compile(r"^[a-z][a-z0-9]*(?:[_\-][a-z0-9]+)*$|^[a-z]+(?:[A-Z][a-z0-9]+)+$")


def _good_tool(name: str, desc: str) -> bool:
    """Drop objects the extractor mistakes for tools (configs, regions, headers)."""
    return bool(_TOOL_NAME.match(name)) and len(desc.split()) >= 3


def mine_community(repo: Path) -> list[dict]:
    """Incremental walk over one community repo's whole history.

    Keeps a per-file tool table and re-extracts only the files each commit changed.
    """
    server = repo.name
    reader = BlobReader(repo)
    log = _git(repo, "log", "--reverse", "--no-renames", "--format=@@%H%x09%cI", "--name-status").splitlines()
    per_file: dict[str, dict[str, str]] = {}
    histories: dict[str, list[dict]] = {}
    sha = date = None
    changed: list[tuple[str, str]] = []

    def flush():
        if sha is None or not changed:
            return
        for status, path in changed:
            if status.startswith("D"):
                per_file.pop(path, None)
            else:
                per_file[path] = {n: d for n, d in extract_tools(reader.read(f"{sha}:{path}")) if _good_tool(n, d)}
        merged: dict[str, str] = {}
        for path in sorted(per_file):
            for n, d in per_file[path].items():
                merged.setdefault(n, d)
        for name, desc in merged.items():
            versions = histories.setdefault(name, [])
            norm = " ".join(desc.split())
            if norm not in {" ".join(v["description"].split()) for v in versions}:
                versions.append({"description": desc, "commit": sha, "date": date, "repo": server})

    for line in log:
        if line.startswith("@@"):
            flush()
            sha, date = line[2:].split("\t")
            changed = []
        elif "\t" in line:
            status, path = line.split("\t", 1)
            if _is_source(path) and not path.lower().startswith(_SKIP_DIRS) and "/test" not in path.lower():
                changed.append((status, path))
    flush()
    reader.close()
    rows = []
    for name, versions in sorted(histories.items()):
        versions = drop_transient_truncations(sorted(versions, key=lambda v: v["date"]))
        if len(versions) >= 2:
            rows.append({"tool_id": f"{server}/{name}", "server": server, "tool_name": name,
                         "source": "community_git_history", "versions": versions})
    return rows


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--repos", type=Path, help="folder holding the servers and servers-archived clones")
    group.add_argument("--community", type=Path,
                       help="folder of community MCP server clones; writes real_histories_community.jsonl")
    parser.add_argument("--out", type=Path, help="output file name inside data/ (default depends on the mode)")
    args = parser.parse_args()
    out = OUT
    if args.community:
        out = ROOT / "data" / (args.out.name if args.out else "real_histories_community.jsonl")
        rows = [r for repo in sorted(p for p in args.community.iterdir() if (p / ".git").exists())
                for r in mine_community(repo)]
    else:
        rows = mine(args.repos)
    with open(out, "w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    changes = sum(len(r["versions"]) - 1 for r in rows)
    print(json.dumps({"tools_with_changes": len(rows), "real_changes": changes,
                      "by_server": dict(Counter(r["server"] for r in rows))}, indent=2))
    print(f"Wrote {out.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
