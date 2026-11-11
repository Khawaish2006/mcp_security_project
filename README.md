# MCP Security Gateway: change-aware, history-aware defense against slow rug pulls

Research prototype. A gateway between an AI client and MCP servers decides whether an update to an already-approved tool description should be **ALLOW**ed, **QUARANTINE**d (human review) or **BLOCK**ed.

- **Layer 1, change-pair detector:** judges the *change* (last approved → new) and the drift since the original approval (original → new). A step head and a cumulative head each use TF-IDF of the added text plus drift, scope-consistency and security-flag features, fed to logistic regression. The text model was chosen on validation data among TF-IDF, sentence embeddings and a hybrid.
- **Layer 2, decision policies:** threshold, history rule, cumulative threshold and a history-aware MDP solved by value iteration, compared with hash pinning.
- **RugPullBench:** 991 sequences of description versions (benign edits, one-shot, slow-split, slow-decomposed and mixed attacks) built from MCPTox poisons and 118 official MCP tool descriptions.
- **Real-world data:** 53 real description changes from the official MCP servers' git history and 513 from 13 community repos (both used for training), plus a final held-out set of 273 changes from 10 fresh community repos, scored once.

**New to the project? Start with [PROJECT_OVERVIEW.md](PROJECT_OVERVIEW.md)**: the idea, solution, implementation, results and the story of how we got there, in one place.

See [results/tables.md](results/tables.md) for all numbers, [results/](results/) for the figures and [results/demo_output.txt](results/demo_output.txt) for the demo run.

## Main findings (test servers never seen in training; 5 server splits where noted)

1. **Real legitimate updates pass.** On the final held-out set (273 real changes from 10 fresh community repos, never used to fit or tune), the step detector wrongly flags **1.5%** at its validation 5%-FPR threshold (2.9% at 0.5). The previous embedding model flags 10.6% and a classifier of the new text alone 22.0%. The threshold and cumulative policies block none of these real updates and send at most 1.5% to review.
2. **Attacks are caught, including reworded ones.** On test servers, the step detector catches 92.3% of attack updates at that threshold (F1 0.96 at 0.5, ROC-AUC 0.99), all softened attacks, and 82.6% of attacks rewritten in vocabulary the training data never uses (embeddings: 64.1%).
3. **The text model and real data both matter.** With the same training data, sentence embeddings flag 10.6% of held-out real changes; without real changes in training, the chosen TF-IDF model flags 20.5%. Embeddings squash long legitimate documentation and short injected instructions into similar vectors, and synthetic legitimate edits alone don't teach what real maintainer edits look like.
4. **Defender-side augmentation stops slow rug pulls the defense has never seen.** Trained only on one-shot poisons, 47% (cumulative threshold) to 74% (step threshold) of slow-decomposed attacks succeed (5 splits). If the defender splits its own known one-shot poisons into 2–4 synthetic updates (`benchmark/augment.py`, no attacker templates), that drops to 10.5% (MDP) and 10.9% (step threshold). Overall attack success falls from 22–30% to 5–6%, while blocking about 0.1% of legitimate updates and reviewing 3–8%. Results vary across splits (±5 points). With slow attacks in training, every change-aware policy stops all of them (overall attack success 0–0.6%). Note that about half of a decomposed attack's steps are word-for-word identical to legitimate edits, so no per-update detector can flag those steps; history is what stops the attack.
5. **The MDP pays off once it has slow examples to learn from.** With augmentation, the MDP has the lowest cost (1.45 ± 1.23 per update vs 1.60 for the step threshold and 2.71 for the cumulative threshold), and on the primary split its cost is significantly lower than the threshold policies' (paired bootstrap, 95% interval below zero). Without slow examples, the cumulative threshold is the safest choice (22% attack success vs 29–30%). With slow attacks in training, a simple cumulative threshold is cheapest (0.28 ± 0.05). Across 20 cost settings, the MDP is cheapest in 9, the step threshold in 8 and the cumulative threshold in 3.
6. **Benchmark shortcuts were found and removed during development:** template memorization, change size as a giveaway, a miscalibrated cumulative score, and detectors that flagged instruction-like legitimate documentation. Each is described below, because naive versions of this benchmark make every detector look near-perfect.

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
| Synthetic legitimate edits only | 21–54% of real maintainer changes flagged | Real changes mined from git history in training; usage-guidance, deprecation and documentation-rewrite edits; TF-IDF text model chosen on validation |
| Testing on data already looked at | Over-optimistic real-world numbers | Development real sets for choices; a fresh set of 10 community repos scored once at the end |

## Known limitations

- Benign edits and decomposed attacks are template-generated; the template-holdout experiment measures how much that matters.
- The test split has 13 servers and about 100 attack sequences; differences of 1–2 percentage points between policies are within noise (see the CIs and multi-split std).
- In the demo, the first harmless step of the slow attack on `simple_division` (a base description that also appears in MCPTox attack data) already scores high. Treat the demo as a functional test, not as evidence of slow-attack detection.
- The reworded attacks come from a hand-written paraphrase table; real attackers can reword more freely.
- The final held-out set has 273 changes from 10 repos, and some repos contribute many more changes than others; the per-repo average is reported alongside.
- TF-IDF matches words, so attacks phrased in entirely new vocabulary can still be missed (reworded recall 82.6%, against 93.5% for the same attacks as written).
- 76 attacks on servers with no clean description reuse an official description from another server (`base_source = "borrowed"`).
- Helper-tool extraction for decomposed attacks is heuristic.
- The decision problem is really a POMDP; the MDP state summarizes the evidence.
- The reviewer is simulated with a fixed error rate.
- Tool-response scanning is out of scope (future work).

## Safety

Dataset text is untrusted data. Nothing in it is ever executed. The mock tools never read files or use the network.
