# How to run this project

This guide covers getting the `mcp-security` folder running on your own laptop. No GPU, GitHub access or API key is needed. Expect about 15 minutes for setup and under 10 minutes for the full experiment run.

For what the project does and what the results mean, see [README.md](README.md). For example inputs and the exact output each command should print, see [EXPECTED_RESULTS.md](EXPECTED_RESULTS.md).

**Got the project from GitHub?** Clone it with `git clone https://github.com/Khawaish2006/mcp_security_project.git`. The MCPTox dataset (`data/pure_tool.json`) is not in the repository. The demo, the MCP check and `try_update` work without it; rebuilding the dataset and rerunning the experiments need it (step 7).

---

## 1. What you need

- **Python 3.11** (3.10–3.12 should also work). Check with `python --version`.
  - Windows: install it from python.org and tick **"Add python.exe to PATH"** during setup.
- **About 2.5 GB of free disk space** for PyTorch and the embedding model.
- An internet connection the first time, for package installs and a 90 MB model download.

## 2. Get the folder

Unzip the folder you were sent anywhere you like, for example `Documents\mcp-security`. Run every command below **from inside that folder**, the one that contains `README.md` and `pytest.ini`.

```bash
cd path/to/mcp-security
```

## 3. Create a Python environment and install packages

**Windows (PowerShell):**

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install torch --index-url https://download.pytorch.org/whl/cpu
pip install -r requirements.txt
```

If PowerShell refuses to run `Activate.ps1`, run this once, then activate again:

```powershell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
```

**macOS / Linux:**

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install torch
pip install -r requirements.txt
```

You'll know the environment is active when your prompt starts with `(.venv)`. Activate it again every time you open a new terminal.

> `requirements.lock.txt` lists the exact versions used for the results in the paper (Windows, CPU). Use `pip install -r requirements.lock.txt` only if you need identical versions; `requirements.txt` is enough for running everything.

## 4. Check that everything works

```bash
python -m pytest -q
```

Expected result: **70 passed** in under a minute, or **64 passed, 6 skipped** in a GitHub clone without the MCPTox data. These tests use a lightweight stand-in for the embedding model, so they need no download.

## 5. Run the project

| What | Command | Time | Output |
|---|---|---|---|
| Score your own description change | `python -m experiments.try_update --tool get_weather --old "..." --new "..."` | under 1 min | risks, flags, each policy's decision |
| Demo: scripted rug-pull scenarios through the gateway | `python -m experiments.demo` | about 1 min | prints decisions; writes `logs/` |
| Real MCP check: client → gateway proxy → mock server | `python -m experiments.mcp_e2e slow_rug_pull mdp` | about 1–2 min | prints what the client can see and call |
| Quick experiment run (fewer seeds, coarser grid) | `python -m experiments.run_eval --quick` | about 3 min | rewrites `results/` and `models/` |
| Full experiment run (numbers in the paper) | `python -m experiments.run_eval` | about 8 min | rewrites `results/` and `models/` |

The first command that uses the embedding model downloads `all-MiniLM-L6-v2` (about 90 MB) automatically.

The folder already includes the trained models and the full-run results, so **the demo and the MCP check work straight away**. Any `run_eval` run **overwrites** `results/` and `models/`. If you want to keep the paper's numbers, copy those two folders somewhere first.

Other scenarios for the MCP check: `benign_updates`, `one_shot_rug_pull`, `hidden_unicode`, `security_note_hard_negative`. Other policies: `threshold`, `cumulative_threshold`.

## 6. Where to look

| Path | What's in it |
|---|---|
| `results/tables.md` | every result table, with confidence intervals |
| `results/asr_by_attack_type.png` | headline figure: attack success, seen vs unseen slow attacks |
| `results/tradeoff_asr_vs_review.png` | attack success vs reviewer workload |
| `results/demo_output.txt` | saved output of the demo |
| `data/benchmark_stats.json` | dataset statistics for the paper |
| `gateway/` | detector, policies, registry, audit log, interceptor |
| `mdp/model.py` | MDP definition and value iteration |
| `benchmark/` | dataset building (RugPullBench) |
| `server/` | mock MCP server and the gateway as a real MCP proxy |

## 7. Rebuilding the dataset (optional)

The built dataset is already in `data/`. To rebuild it from scratch:

```bash
python -m benchmark.prepare_mcptox
python -m benchmark.collect_clean_tools --offline
python -m benchmark.make_sequences
```

`prepare_mcptox` needs `data/pure_tool.json`, the MCPTox dataset. `--offline` reuses the saved server sources in `data/raw_sources/`; drop it to download them from GitHub again. The rebuild is deterministic (seed 42), so you get the same files.

## 8. Troubleshooting

| Problem | Fix |
|---|---|
| `ModuleNotFoundError: No module named 'gateway'` (or `benchmark`, `server`) | You're not inside the `mcp-security` folder. `cd` into it and use `python -m ...` as shown. |
| `ModuleNotFoundError: No module named 'sentence_transformers'` / `torch` | The environment isn't active (no `(.venv)` in the prompt), or step 3 didn't finish. Activate it and rerun the installs. |
| `UnicodeEncodeError: 'charmap' codec ...` on Windows | Run `$env:PYTHONIOENCODING="utf-8"` in PowerShell (or `set PYTHONIOENCODING=utf-8` in cmd), then rerun. |
| Warning about symlinks / Developer Mode on Windows | Harmless; ignore it. |
| `No space left on device` during install | Free up about 2.5 GB, or create the environment on another drive, e.g. `python -m venv D:\mcp-env`, and use that path instead of `.venv`. |
| The first run is slow | It is downloading the embedding model and computing embeddings. Later runs reuse `data/cache/`. |

## 9. Sharing the folder onward

Zip the `mcp-security` folder **without** `.venv/` (each person creates their own environment). `logs/` and `.pytest_cache/` aren't needed either. Keep `data/cache/` if you can: it saves recomputing embeddings.

**Note:** `data/pure_tool.json` and the files built from it come from the MCPTox benchmark. Keep the folder within the team until you've checked MCPTox's license for redistribution.
