# MCP Security Gateway: change-aware, history-aware defense against slow rug pulls

Research prototype. A gateway between an AI client and MCP servers decides whether an update to an already-approved tool description should be **ALLOW**ed, **QUARANTINE**d (human review) or **BLOCK**ed.

- **Layer 1, change-pair detector:** judges the *change* (last approved → new) and the drift since the original approval (original → new), using sentence embeddings, scope consistency and security flags fed to a logistic-regression model trained on our own benchmark.
- **Layer 2, history-aware MDP:** chooses the action from step risk, cumulative risk, number of updates and prior risk, solved by value iteration. It is compared with hash pinning, threshold policies and a hand-written history rule.
- **RugPullBench:** 991 sequences of description versions (benign edits, one-shot, slow-split, slow-decomposed and mixed attacks) built from MCPTox poisons and 118 official MCP tool descriptions.

See [results/tables.md](results/tables.md) for all numbers, [results/](results/) for the figures and [results/demo_output.txt](results/demo_output.txt) for the demo run.

## Main findings (test servers never seen in training; 5 server splits where noted)

1. **Judging the change beats judging the new text.** Per update, the change-pair detector has a false-positive rate of 9.6% vs 28.7% for a classifier that sees only the new description (ROC-AUC 0.95 vs 0.85). On legitimate but suspicious-sounding official tools (Fetch, get-env, …) the false-positive rate is 10.4% vs 35.8%.
2. **Slow rug pulls evade defenses that have only seen one-shot poisons.** Train every defense without slow attacks (as with MCPTox-style data today), and slow-decomposed attacks succeed 46–54% of the time (mean over 5 splits). Overall attack success is 16–20%. Only hash pinning stops them, and it sends every update to a human.
3. **Including slow attacks in training closes the gap.** With slow attacks in training, every change-pair policy stops 100% of slow-decomposed attacks. The history-aware policies have the lowest overall attack success: cumulative threshold 0.8% ± 0.6%, history rule 0.9% ± 0.4%, MDP 1.6% ± 1.1%, vs 2.9% ± 0.9% for the step threshold, while reviewing about 20% of updates (hash pinning reviews 100%).
4. **The MDP does not consistently beat simple history-aware rules.** The cumulative threshold has the lowest mean cost (1.10 ± 0.23 vs MDP 1.27 ± 0.42 and history rule 1.21 ± 0.14). It is cheapest in 12 of 20 cost settings, against 3 for the MDP. Report this honestly: modelling history matters, but a simple "treat total drift like one update" rule captures most of the benefit on this benchmark. The MDP's advantage is the lowest review burden when slow attacks are unseen (6.1% vs 9–11%).
5. **Benchmark shortcuts were found and removed during development:** template memorization, change size as a giveaway, and a miscalibrated cumulative score. Each is described below, because naive versions of this benchmark make every detector look near-perfect.

## Setup

The Python environment lives on D: (C: is nearly full):

```bash
python -m venv D:/mcp-security-tools/venv
D:/mcp-security-tools/venv/Scripts/python -m pip install torch --index-url https://download.pytorch.org/whl/cpu
D:/mcp-security-tools/venv/Scripts/python -m pip install -r requirements.txt
```

Set `HF_HOME=D:/mcp-security-tools/hf-cache` so the embedding model downloads to D: too.

## Reproduce everything

Run these from the `mcp-security` folder (`PY` = `D:/mcp-security-tools/venv/Scripts/python`):

```bash
PY -m benchmark.prepare_mcptox          # MCPTox -> data/mcptox_malicious.jsonl
PY -m benchmark.collect_clean_tools     # official MCP servers -> data/clean_tools.jsonl (--offline reuses data/raw_sources/)
PY -m benchmark.make_sequences          # -> data/sequences.jsonl, data/versions.jsonl, data/benchmark_stats.json
PY -m experiments.run_eval              # train, tune, evaluate -> results/, models/ (about 8 min; --quick for a fast run)
PY -m experiments.demo                  # scripted scenarios through the gateway -> logs/
PY -m experiments.mcp_e2e slow_rug_pull mdp   # real MCP client -> gateway proxy -> mock server
PY -m pytest -q
```

## Layout

| Folder | Contents |
|---|---|
| `benchmark/` | dataset building: MCPTox preparation, clean-tool collection, benign edits, softening, slow attacks, sequences, server-grouped splits |
| `gateway/` | canonical hashing, sentence diff, embeddings, features, detector, policies, registry, audit log, interceptor |
| `mdp/` | MDP definition, estimation from data, value iteration |
| `server/` | harmless mock MCP server, scripted update scenarios, gateway as a real MCP stdio proxy |
| `experiments/` | evaluation pipeline, sequence simulator, report and plots, demo, MCP end-to-end check |
| `results/` | `results.json`, `tables.md`, figures |
| `models/` | trained detector and solved MDP policy |
| `tests/` | unit and end-to-end tests |

## Evaluation protocol

- Splits are grouped by MCP server: test servers are never seen in training.
- The policy-fit set is out-of-fold train scores (5-fold, grouped by server) plus validation scores. The MDP is estimated on it, and every baseline's thresholds are tuned on it with the same cost function. The test split is used only for final numbers.
- Metrics: attack success rate (ASR), false-block rate (FBR), review burden, detection delay, cost per update, plus per-update precision/recall/F1/ROC-AUC for the detectors. Results are averaged over reviewer-error seeds.

## Benchmark design decisions (shortcuts removed)

| Shortcut found | Symptom | Fix |
|---|---|---|
| Attack-only framing sentences | ROC-AUC 0.999 even on "harmless" slow fragments | Benign twins (process notes, sibling-tool references, default values); slow-attack framing and tool links reuse the **same sentences** as legitimate edits |
| Change size | A 3-sentence benign update scored 0.99 | 30% of benign updates bundle 2–3 edits (releases) |
| Step model reused for cumulative pairs | Cumulative risk less informative than per-step risk | Separate cumulative head trained on (original → new) pairs |
| Miss cost charged per fragment | Every policy forced to review nearly everything | Miss cost charged only when an attack completes |
| Single split | Policy ranking changed between runs | Bootstrap CIs plus 5 independent server splits |

## Known limitations

- Benign edits and decomposed attacks are template-generated; the template-holdout experiment measures how much that matters.
- The test split has 13 servers and about 100 attack sequences; differences of 1–2 percentage points between policies are within noise (see the CIs and multi-split std).
- The cumulative head shows a base-description bias. In the demo, it flags the first harmless step on `simple_division` (a base that comes from MCPTox attack data) and gives a low score to a blatant one-shot attack, which the step head catches. Treat the demo as a functional test, not as evidence.
- 76 attacks on servers with no clean description reuse an official description from another server (`base_source = "borrowed"`).
- Helper-tool extraction for decomposed attacks is heuristic.
- The decision problem is really a POMDP; the MDP state summarizes the evidence.
- The reviewer is simulated with a fixed error rate.
- Tool-response scanning is out of scope (future work).

## Safety

Dataset text is untrusted data. Nothing in it is ever executed. The mock tools never read files or use the network.
