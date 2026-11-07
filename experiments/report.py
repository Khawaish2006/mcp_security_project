"""Turn results.json into results/tables.md and figures."""

import json
import sys
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

NICE = {"no_protection": "No protection", "hash_pinning": "Hash pinning", "threshold_new_only": "Classifier (new text only)",
        "threshold": "Change-pair + threshold", "history_rule": "Change-pair + history rule",
        "cumulative_threshold": "Change-pair + cumulative threshold (ours)", "mdp": "Change-pair + MDP (ours)"}
POLICY_COLUMNS = ["hash_pinning", "threshold_new_only", "threshold", "history_rule", "cumulative_threshold", "mdp"]


def _pct(x):
    return "n/a" if x is None or x != x else f"{100 * x:.1f}%"


def _table(header: list[str], rows: list[list]) -> str:
    lines = ["| " + " | ".join(header) + " |", "|" + "---|" * len(header)]
    lines += ["| " + " | ".join(str(c) for c in r) + " |" for r in rows]
    return "\n".join(lines)


def _ci(boot: dict, name: str, key: str, pct: bool = True) -> str:
    if not boot or name not in boot:
        return ""
    lo, hi = boot[name][key][:2]
    return f" [{_pct(lo)}, {_pct(hi)}]" if pct else f" [{lo:.2f}, {hi:.2f}]"


def _policy_section(p: dict) -> list[str]:
    boot = p.get("bootstrap", {})
    md = [_table(["policy", "ASR", "FBR", "review burden", "detection delay", "stopped before payload", "cost/update"],
                 [[NICE.get(r["name"], r["name"]), _pct(r["asr"]) + _ci(boot, r["name"], "asr"),
                   _pct(r["fbr"]) + _ci(boot, r["name"], "fbr"), _pct(r["rb"]) + _ci(boot, r["name"], "rb"),
                   "n/a" if r["dd"] != r["dd"] else f"{r['dd']:.2f}", _pct(r["attacks_stopped_early"]),
                   f"{r['cost_per_update']:.2f}" + _ci(boot, r["name"], "cost_per_update", pct=False)]
                  for r in p["results"]]), "",
          f"Tuned on the policy-fit set: threshold={p['tuned']['threshold']}, new-only threshold="
          f"{p['tuned']['threshold_new_only']}, history rule theta={p['tuned']['history_rule_theta']}, "
          f"MDP risk bins={p['tuned'].get('mdp_risk_bins')}. Value iteration converged in "
          f"{p['mdp_value_iterations']} iterations.", ""]
    paired = [(k.replace("mdp_minus_", ""), v) for k, v in boot.items() if k.startswith("mdp_minus_")]
    if paired:
        md += ["Paired bootstrap, MDP minus baseline (95% CI; share of resamples where the MDP is lower):", "",
               _table(["baseline", "ASR diff", "FBR diff", "review diff", "cost diff", "P(MDP cost lower)"],
                      [[NICE.get(b, b), *(f"[{v[k][0]:+.3f}, {v[k][1]:+.3f}]" for k in ("asr", "fbr", "rb", "cost_per_update")),
                        v["cost_per_update"][2]] for b, v in paired]), ""]
    names = [n for n in POLICY_COLUMNS if n in next(iter(p["by_seq_type"].values()))]
    md += ["Attack success rate by sequence type (benign row shows false-block rate):", "", _table(
        ["type", "n", *(NICE[n] for n in names)],
        [[t, v["n"], *(_pct(v[n]["asr"]) if t != "benign" else f"FBR {_pct(v[n]['fbr'])}" for n in names)]
         for t, v in p["by_seq_type"].items()]), ""]
    return md


def write_report(out: dict, results_dir: Path) -> None:
    md = ["# Results", "", f"Runtime: {out['runtime_seconds']} s. All numbers are on the held-out test split "
          "(servers never seen in training).", ""]

    md += ["## Data", "", _table(["split", "updates", "attack updates"],
                                 [[k, v["updates"], v["attack_updates"]] for k, v in out["data"].items()]), ""]

    d = out["detector"]
    md += ["## Detector (per update)", "", _table(
        ["model", "precision", "recall", "F1", "FPR", "ROC-AUC", "PR-AUC"],
        [[name, *(d[key].get(m, "n/a") for m in ("precision", "recall", "f1", "fpr", "roc_auc", "pr_auc"))]
         for name, key in (("Change-pair step head (ours)", "change_pair"), ("New text only", "new_only"),
                          ("Cumulative head (ours, label: attack added since approval)", "cumulative_head"))
        if key in d]), ""]
    md += ["### Recall / FPR by attack style", "", _table(
        ["style", "n", "change-pair recall", "new-only recall"],
        [[k, v["change_pair"]["n"], v["change_pair"]["recall"], v["new_only"]["recall"]]
         for k, v in d["by_style"].items() if k != "None"]), ""]
    md += ["### By change type", "", _table(
        ["change type", "n", "change-pair flagged", "new-only flagged"],
        [[k, v["change_pair"]["n"],
          _pct(v["change_pair"]["recall"] if "malicious" in k else v["change_pair"]["fpr"]),
          _pct(v["new_only"]["recall"] if "malicious" in k else v["new_only"]["fpr"])]
         for k, v in d["by_change_type"].items()]), "",
           "(For malicious types the share flagged is recall; for benign types it is the false-positive rate.)", ""]
    hn = d.get("hard_negative_fpr_out_of_fold", d["hard_negative_fpr"])
    md += [f"Hard negatives (legitimate but suspicious-sounding official tools such as Fetch and get-env), "
           f"scored out-of-fold: n={hn['n']} updates, FPR change-pair {_pct(hn['change_pair'])}, "
           f"new-only {_pct(hn['new_only'])}.", ""]

    md += ["## Feature ablation (detector, per update)", "", _table(
        ["features", "F1", "recall", "FPR", "ROC-AUC"],
        [[k, v["f1"], v["recall"], v["fpr"], v.get("roc_auc", "n/a")] for k, v in out["ablations"].items()]), ""]
    md += ["## Generalization", "", _table(
        ["held out", "F1", "recall", "FPR", "ROC-AUC"],
        [[f"paradigm {k}", v["f1"], v["recall"], v["fpr"], v.get("roc_auc", "n/a")]
         for k, v in out["leave_one_paradigm_out"].items()]
        + [["template phrasings", out["template_holdout"]["f1"], out["template_holdout"]["recall"],
            out["template_holdout"]["fpr"], out["template_holdout"].get("roc_auc", "n/a")]]), ""]

    if "sequence_level_auc" in out:
        md += ["## Sequence-level detection (ROC-AUC, attack histories vs benign histories)", "", _table(
            ["attack type", "attack seqs", "max per-step risk", "final cumulative risk (d0 -> new)", "new text only"],
            [[t, v["n_attack"], v["max_step_risk"], v["final_cumulative_risk"], v["new_only_final"]]
             for t, v in out["sequence_level_auc"].items()]), ""]

    p = out["policies"]
    md += ["## Gateway policies (per sequence), all attack strategies seen in training", "",
           f"Costs: miss (completed attack)={p['costs']['c_miss']}, false block={p['costs']['c_fb']}, "
           f"review={p['costs']['c_rev']}, reviewer error={p['costs']['eps']}. Averaged over reviewer-error seeds; "
           "brackets are bootstrap 95% CIs over test sequences.", ""]
    md += _policy_section(p)
    if "unseen_slow" in out:
        u = out["unseen_slow"]
        md += ["## Unseen attack strategy: defenses trained without any slow attack", "",
               f"Detectors, thresholds and the MDP are fitted on {u['train_updates']} training updates with every "
               "slow-split, slow-decomposed and mixed-slow sequence removed (as if only one-shot poisons such as "
               "MCPTox were known). The test set is unchanged.", ""]
        md += _policy_section(u)
        md += ["### Sequence-level detection when slow attacks are unseen (ROC-AUC)", "", _table(
            ["attack type", "attack seqs", "max per-step risk", "final cumulative risk", "new text only"],
            [[t, v["n_attack"], v["max_step_risk"], v["final_cumulative_risk"], v["new_only_final"]]
             for t, v in u["sequence_level_auc"].items()]), ""]

    if "multi_split" in out:
        for name, title in (("seen", "all strategies seen in training"), ("unseen_slow", "slow strategies unseen")):
            ms = out["multi_split"][name]
            md += [f"## Robustness over {len(ms['splits'])} server splits: {title}", "",
                   "Mean ± std across independent server-grouped splits (seeds "
                   f"{ms['splits']}); last column counts splits where the policy had the lowest cost.", "",
                   _table(["policy", "ASR", "slow-decomposed ASR", "FBR", "review burden", "cost/update", "lowest-cost splits"],
                          [[NICE.get(p, p), *(f"{_pct(v[k][0])} ± {_pct(v[k][1])}" if k in v else "n/a"
                                               for k in ("asr", "slow_decomposed_asr", "fbr", "rb")),
                            f"{v['cost_per_update'][0]:.2f} ± {v['cost_per_update'][1]:.2f}", v["lowest_cost_splits"]]
                           for p, v in ms["summary"].items()]), ""]

    md += ["## Sensitivity (cost per update, lower is better)", "", _table(
        ["c_miss", "reviewer error", "threshold", "history rule", "cumulative threshold", "MDP", "MDP ASR",
         "MDP review burden"],
        [[s["c_miss"], s["eps"], s["thr"]["cost"], s["rule"]["cost"], s.get("cum", {}).get("cost", "n/a"),
          s["mdp"]["cost"], _pct(s["mdp"]["asr"]), _pct(s["mdp"]["rb"])] for s in out["sensitivity"]]), ""]
    best = lambda s: min(("threshold", s["thr"]["cost"]), ("history rule", s["rule"]["cost"]),  # noqa: E731
                         ("cumulative threshold", s.get("cum", {}).get("cost", 1e9)), ("MDP", s["mdp"]["cost"]),
                         key=lambda x: x[1])[0]
    counts = {}
    for s in out["sensitivity"]:
        counts[best(s)] = counts.get(best(s), 0) + 1
    md += ["Lowest-cost policy per setting: " + ", ".join(f"{k} {v}/{len(out['sensitivity'])}" for k, v in counts.items())
           + ".", ""]

    acted = [s for s in out["mdp_policy_table"] if s["visits"] > 0]
    md += ["## Learned MDP policy (visited states)", "", _table(
        ["step risk", "cumulative risk", "updates", "prior max", "visits", "P(attack)", "action"],
        [[("low", "med", "high")[s["state"]["step_risk"]], ("low", "med", "high")[s["state"]["cum_risk"]],
          s["state"]["updates"] + 1, ("low", "med", "high")[s["state"]["prior_max"]], s["visits"], s["p_attack"],
          s["action"]] for s in sorted(acted, key=lambda s: -s["visits"])]), ""]
    (results_dir / "tables.md").write_text("\n".join(md), encoding="utf-8")

    fig, ax = plt.subplots(figsize=(6.5, 4.5))
    for name, pts in out["tradeoff_curves"].items():
        pts = sorted(pts, key=lambda q: q["rb"])
        ax.plot([100 * q["rb"] for q in pts], [100 * q["asr"] for q in pts], marker="o", label=NICE[name])
    for r in p["results"]:
        if r["name"] in ("no_protection", "hash_pinning", "threshold_new_only"):
            ax.scatter(100 * r["rb"], 100 * r["asr"], marker="x", s=60, label=NICE[r["name"]])
    ax.set_xlabel("Review burden (% of updates sent to a human)")
    ax.set_ylabel("Attack success rate (%)")
    ax.set_title("Security vs. reviewer workload (test servers)")
    ax.grid(alpha=0.3)
    ax.legend(fontsize=8)
    fig.tight_layout()
    fig.savefig(results_dir / "tradeoff_asr_vs_review.png", dpi=150)
    plt.close(fig)

    panels = [("All strategies seen in training", p)]
    if "unseen_slow" in out:
        panels.append(("Slow strategies unseen in training", out["unseen_slow"]))
    fig, axes = plt.subplots(1, len(panels), figsize=(6.5 * len(panels), 4.2), sharey=True, squeeze=False)
    for ax, (title, section) in zip(axes[0], panels):
        types = [t for t in section["by_seq_type"] if t != "benign"]
        names = [n for n in POLICY_COLUMNS if n in section["by_seq_type"][types[0]]]
        width = 0.8 / len(names)
        for i, n in enumerate(names):
            ax.bar([j + i * width for j in range(len(types))],
                   [100 * section["by_seq_type"][t][n]["asr"] for t in types], width, label=NICE[n])
        ax.set_xticks([j + 0.4 - width / 2 for j in range(len(types))], types)
        ax.set_title(title)
        ax.grid(axis="y", alpha=0.3)
    axes[0][0].set_ylabel("Attack success rate (%)")
    axes[0][-1].legend(fontsize=7)
    fig.tight_layout()
    fig.savefig(results_dir / "asr_by_attack_type.png", dpi=150)
    plt.close(fig)


if __name__ == "__main__":
    root = Path(__file__).resolve().parent.parent / "results"
    write_report(json.loads((root / "results.json").read_text(encoding="utf-8")), root)
