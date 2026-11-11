"""Run every experiment and write results/ (tables, JSON, plots) and models/.

Protocol (no test data is used for any fitting or tuning):
  1. Train the change-pair detector on the train split.
  2. Policy-fit set = out-of-fold train scores (5-fold, grouped by server) + val scores.
     The MDP is estimated on it and every baseline's thresholds are tuned on it,
     all minimizing the same expected cost.
  3. Evaluate detectors (per update) and policies (per sequence) on the test split.

Usage (from the mcp-security folder):
    python -m experiments.run_eval            # full run
    python -m experiments.run_eval --quick    # fewer seeds and a coarser grid
"""

import json
import sys
import time
from collections import defaultdict
from pathlib import Path

import numpy as np
from sklearn.metrics import (average_precision_score, f1_score, precision_recall_curve, precision_score, recall_score,
                             roc_auc_score, roc_curve)
from sklearn.model_selection import GroupKFold

from benchmark.augment import augment_slow
from benchmark.reword_attacks import reword_update
from experiments.baselines import TfidfDetector
from experiments.simulate import simulate, simulate_avg
from gateway.detector import ChangeDetector, DualDetector
from gateway.embedder import SentenceEmbedder
from gateway.features import FeatureConfig
from gateway.policy_engine import AllowAll, CumulativeRule, HashPin, MDPPolicy, Threshold
from benchmark.splits import assign_splits
from mdp.model import ACTIONS, MDP, Costs, StateSpace

ROOT = Path(__file__).resolve().parent.parent
DATA, RESULTS, MODELS = ROOT / "data", ROOT / "results", ROOT / "models"
QUICK = "--quick" in sys.argv
SEEDS = range(2 if QUICK else 5)
GRID = np.round(np.linspace(0.05, 0.95, 10 if QUICK else 19), 3)


def load_rows() -> list[dict]:
    """versions.jsonl plus cum_label: has attack content been added at any step so far?"""
    with open(DATA / "versions.jsonl", encoding="utf-8") as f:
        rows = [json.loads(line) for line in f]
    seen: dict[str, int] = {}
    for r in sorted(rows, key=lambda r: (r["seq_id"], r["step"])):
        seen[r["seq_id"]] = max(seen.get(r["seq_id"], 0), r["step_label"])
        r["cum_label"] = seen[r["seq_id"]]
    return rows


def score_rows(det: DualDetector, rows: list[dict]) -> tuple[np.ndarray, np.ndarray]:
    return det.predict(rows)


def to_sequences(rows: list[dict], r_step: np.ndarray, r_cum: np.ndarray) -> list[dict]:
    seqs: dict[str, dict] = {}
    for row, rs, rc in zip(rows, r_step, r_cum):
        s = seqs.setdefault(row["seq_id"], {"seq_id": row["seq_id"], "seq_type": row["seq_type"],
                                            "style": row["style"], "paradigm": row["paradigm"],
                                            "hard_negative": row["hard_negative"], "steps": []})
        s["steps"].append({"step": row["step"], "r_step": float(rs), "r_cum": float(rc),
                           "label": row["step_label"], "payload_complete": row["payload_complete"]})
    for s in seqs.values():
        s["steps"].sort(key=lambda st: st["step"])
    return list(seqs.values())


def recall_at_fpr(y, p, target: float) -> tuple[float, float]:
    """Highest recall with false-positive rate <= target, and the threshold that gives it."""
    fpr, tpr, thr = roc_curve(y, p)
    ok = np.where(fpr <= target)[0]
    i = ok[np.argmax(tpr[ok])]
    return float(tpr[i]), float(min(thr[i], 1.0))


def detector_metrics(y, p, thr: float = 0.5) -> dict:
    y, p = np.asarray(y), np.asarray(p)
    pred = (p >= thr).astype(int)
    out = {"n": int(len(y)), "precision": precision_score(y, pred, zero_division=0),
           "recall": recall_score(y, pred, zero_division=0), "f1": f1_score(y, pred, zero_division=0),
           "fpr": float(((pred == 1) & (y == 0)).sum() / max((y == 0).sum(), 1))}
    if len(set(y)) == 2:
        out["roc_auc"] = roc_auc_score(y, p)
        out["pr_auc"] = average_precision_score(y, p)
        out["recall_at_fpr5"] = recall_at_fpr(y, p, 0.05)[0]
        out["recall_at_fpr10"] = recall_at_fpr(y, p, 0.10)[0]
    return {k: round(float(v), 4) if isinstance(v, float) else v for k, v in out.items()}


def pr_points(y, p, n: int = 40) -> list[list[float]]:
    """A downsampled precision-recall curve for plotting."""
    prec, rec, _ = precision_recall_curve(y, p)
    idx = np.unique(np.linspace(0, len(prec) - 1, n).astype(int))
    return [[round(float(rec[i]), 4), round(float(prec[i]), 4)] for i in idx]


def load_real_rows(path: Path | None = None) -> list[dict]:
    """Real maintainer changes mined from git history, as legitimate update rows."""
    path = path or DATA / "real_histories.jsonl"
    if not path.exists():
        return []
    rows = []
    prefix = "realc" if "community" in path.name else "realf" if "final" in path.name else "real"
    with open(path, encoding="utf-8") as f:
        for i, line in enumerate(f):
            h = json.loads(line)
            v = [x["description"] for x in h["versions"]]
            for k in range(1, len(v)):
                rows.append({"seq_id": f"{prefix}_{i:03d}", "step": k, "n_steps": len(v) - 1, "tool_id": h["tool_id"],
                             "server": h["server"], "tool_name": h["tool_name"], "d0": v[0], "prev": v[k - 1],
                             "new": v[k], "change_type": "real_change", "template_id": "real", "step_label": 0,
                             "cum_label": 0, "payload_complete": False, "seq_type": "benign_real", "seq_label": 0,
                             "style": None, "paradigm": None, "source_id": None, "base_source": "real_git_history",
                             "hard_negative": False, "split": "real"})
    return rows


# Detector settings shared by every DualDetector built in this run (set by select_heads).
DETECTOR_KW: dict = {}
# Frozen after the development checks (experiments/generalization.py, dev_community_cv.py).
# Candidates per head: (feature config, text mode, TF-IDF weight); C is tuned alongside.
# Selection: validation recall at FPR <= 5%, then ROC-AUC.
HEAD_CANDIDATES = {
    "tfidf_features": (FeatureConfig(embed_added=False, embed_diff=False), "tfidf", 3.0),
    "tfidf_features_w10": (FeatureConfig(embed_added=False, embed_diff=False), "tfidf", 10.0),
    "embed_pooled": (FeatureConfig(embed_diff=False, drift=False, scope=False, sentence_pool=True), "embed", 1.0),
    "hybrid": (FeatureConfig(embed_diff=False, sentence_pool=True), "hybrid", 10.0),
}
C_CANDIDATES = (0.1, 0.5, 2.0)
REAL_WEIGHT = 20          # official servers' real changes (development set 1)
COMMUNITY_WEIGHT = 1      # community real changes (development set 2), chosen in dev_community_cv.py
COMMUNITY = DATA / "real_histories_community.jsonl"
FINAL = DATA / "real_histories_final.jsonl"   # final held-out set: fresh community repos, scored once


def real_for_training(real_dev: list[dict], train_rows: list[dict]) -> list[dict]:
    """Development real changes whose server is a training server, weighted.

    Real changes of a server in val or test would leak that server's text into training.
    """
    servers = {r["server"] for r in train_rows}
    return [dict(r, weight=REAL_WEIGHT) for r in real_dev if r["server"] in servers]


def select_heads(emb, train: list[dict], val: list[dict]) -> dict:
    """Pick each head's feature set and regularization on validation data (never test).

    Criterion: recall at FPR <= 5% on validation, then ROC-AUC.
    """
    table, chosen = [], {}
    for head, label_key, cum in (("step", "step_label", False), ("cum", "cum_label", True)):
        tr = [dict(r, prev=r["d0"]) for r in train] if cum else train
        va = [dict(r, prev=r["d0"]) for r in val] if cum else val
        y_va = [r[label_key] for r in va]
        best = None
        for name, (cfg, text, scale) in HEAD_CANDIDATES.items():
            for C in C_CANDIDATES:
                p = ChangeDetector(emb, cfg, C=C, text=text, tfidf_scale=scale).fit(
                    tr, [r[label_key] for r in tr]).predict_proba(va)
                score = (round(recall_at_fpr(y_va, p, 0.05)[0], 4), round(float(roc_auc_score(y_va, p)), 4))
                table.append({"head": head, "features": name, "C": C, "val_recall_at_fpr5": score[0], "val_roc_auc": score[1]})
                if best is None or score > best[0]:
                    best = (score, name, C)
        chosen[head] = {"features": best[1], "C": best[2]}
    step, cum = HEAD_CANDIDATES[chosen["step"]["features"]], HEAD_CANDIDATES[chosen["cum"]["features"]]
    DETECTOR_KW.update(config=step[0], step_text=step[1], step_scale=step[2], step_C=chosen["step"]["C"],
                       cum_config=cum[0], cum_text=cum[1], cum_scale=cum[2], cum_C=chosen["cum"]["C"])
    return {"chosen": chosen, "candidates": table}


def out_of_fold(make, rows: list[dict]) -> tuple[np.ndarray, np.ndarray]:
    groups = [r["server"] for r in rows]
    y = np.array([r["step_label"] for r in rows])
    r_step, r_cum = np.zeros(len(rows)), np.zeros(len(rows))
    for tr, te in GroupKFold(n_splits=5).split(rows, y, groups):
        det = make().fit([rows[i] for i in tr])
        a, b = score_rows(det, [rows[i] for i in te])
        r_step[te], r_cum[te] = a, b
    return r_step, r_cum


# --- policy fitting -----------------------------------------------------------

def tune_threshold(fit_seqs, costs, key="r_step"):
    best = None
    for lo in GRID:
        for hi in [h for h in GRID if h >= lo] + [1.01]:
            pol = Threshold(float(lo), float(hi), key=key)
            c = simulate(pol, fit_seqs, costs, 0).cost_per_update
            if best is None or c < best[0]:
                best = (c, pol)
    return best[1]


def tune_rule(fit_seqs, costs, step: Threshold):
    best = None
    for theta in list(GRID) + [1.01]:
        pol = CumulativeRule(step, float(theta))
        c = simulate(pol, fit_seqs, costs, 0).cost_per_update
        if best is None or c < best[0]:
            best = (c, pol)
    return best[1]


def fit_mdp(fit_seqs, costs, space=StateSpace()):
    episodes = []
    for s in fit_seqs:
        ep, prev_max = [], None
        for k, st in enumerate(s["steps"]):
            ep.append({"state": space.index(st["r_step"], st["r_cum"], k + 1, prev_max), "label": st["label"],
                       "complete": int(st["payload_complete"])})
            prev_max = st["r_step"] if prev_max is None else max(prev_max, st["r_step"])
        episodes.append(ep)
    mdp = MDP.estimate(episodes, space, costs)
    V, table, iters = mdp.solve()
    return MDPPolicy(space, table), mdp, V, iters


# Candidate risk-bin edges for the MDP state; tuned on the fit set like the baselines' thresholds.
MDP_BINS = [(0.05, 0.5), (0.1, 0.5), (0.1, 0.7), (0.2, 0.6), (0.3, 0.7), (0.2, 0.9), (0.05, 0.9), (0.1, 0.9)]


def tune_mdp(fit_seqs, costs):
    best = None
    for bins in MDP_BINS:
        pol, mdp, V, iters = fit_mdp(fit_seqs, costs, StateSpace(bins))
        c = simulate(pol, fit_seqs, costs, 0).cost_per_update
        if best is None or c < best[0]:
            best = (c, (pol, mdp, V, iters))
    return best[1]


def fit_policies(fit_seqs, fit_seqs_newonly, costs):
    thr = tune_threshold(fit_seqs, costs)
    thr_new = tune_threshold(fit_seqs_newonly, costs)
    thr_new.name = "threshold_new_only"
    rule = tune_rule(fit_seqs, costs, thr)
    cum = tune_threshold(fit_seqs, costs, key="r_max")
    cum.name = "cumulative_threshold"
    mdp_pol, mdp, V, iters = tune_mdp(fit_seqs, costs)
    return {"thr": thr, "thr_new": thr_new, "rule": rule, "cum": cum, "mdp": mdp_pol}, (mdp, V, iters)


# --- policy experiments -------------------------------------------------------

SEQ_TYPES = ("one_shot", "slow_split", "slow_decomposed", "mixed", "benign", "benign_real")
N_BOOT = 200 if QUICK else 1000


def build_scored(emb, train, val, test, det=None, det_new=None) -> dict:
    """Detector scores for the policy-fit set (out-of-fold train + val) and for test."""
    yt = np.array([r["step_label"] for r in train])
    det = det or DualDetector(emb, **DETECTOR_KW).fit(train)
    det_new = det_new or ChangeDetector(emb, new_only=True).fit(train, yt)
    oof_step, oof_cum = out_of_fold(lambda: DualDetector(emb, **DETECTOR_KW), train)
    oof_new = np.zeros(len(train))
    for tr_i, te_i in GroupKFold(n_splits=5).split(train, yt, [r["server"] for r in train]):
        oof_new[te_i] = ChangeDetector(emb, new_only=True).fit(
            [train[i] for i in tr_i], yt[tr_i]).predict_proba([train[i] for i in te_i])
    val_step, val_cum = det.predict(val)
    val_new = det_new.predict_proba(val)
    test_step, test_cum = det.predict(test)
    test_new = det_new.predict_proba(test)
    fit_rows = train + val
    return {"fit_rows": fit_rows, "fit_step": np.r_[oof_step, val_step], "fit_new_scores": np.r_[oof_new, val_new],
            "fit": to_sequences(fit_rows, np.r_[oof_step, val_step], np.r_[oof_cum, val_cum]),
            "fit_new": to_sequences(fit_rows, np.r_[oof_new, val_new], np.r_[oof_new, val_new]),
            "test": to_sequences(test, test_step, test_cum), "test_new": to_sequences(test, test_new, test_new)}


def sequence_level(scored: dict) -> dict:
    """Does a whole history look like an attack? Per-step view vs cumulative view vs new text only."""
    def auc(seqs, score):
        labels = [int(any(st["label"] for st in s["steps"])) for s in seqs]
        return round(float(roc_auc_score(labels, [score(s) for s in seqs])), 4) if len(set(labels)) == 2 else None
    out = {}
    for t in ("all", "one_shot", "slow_split", "slow_decomposed", "mixed"):
        keep = lambda s: t == "all" or s["seq_type"] in (t, "benign")  # noqa: E731
        sub, sub_new = [s for s in scored["test"] if keep(s)], [s for s in scored["test_new"] if keep(s)]
        out[t] = {"n_attack": sum(s["seq_type"] != "benign" for s in sub),
                  "max_step_risk": auc(sub, lambda s: max(st["r_step"] for st in s["steps"])),
                  "final_cumulative_risk": auc(sub, lambda s: s["steps"][-1]["r_cum"]),
                  "new_only_final": auc(sub_new, lambda s: s["steps"][-1]["r_step"])}
    return out


def bootstrap(policies_and_seqs: dict, costs, n=N_BOOT, seed=0) -> dict:
    """95% CIs by resampling test sequences; also paired differences against the MDP."""
    rng = np.random.default_rng(seed)
    n_seq = len(next(iter(policies_and_seqs.values()))[1])
    keys = ("asr", "fbr", "rb", "cost_per_update")
    draws = {name: {k: [] for k in keys} for name in policies_and_seqs}
    for b in range(n):
        idx = rng.integers(0, n_seq, n_seq)
        for name, (pol, seqs) in policies_and_seqs.items():
            r = simulate(pol, [seqs[i] for i in idx], costs, seed=b)
            for k in keys:
                draws[name][k].append(getattr(r, k))
    ci = lambda v: [round(float(np.percentile(v, 2.5)), 4), round(float(np.percentile(v, 97.5)), 4)]  # noqa: E731
    out = {name: {k: ci(v) for k, v in d.items()} for name, d in draws.items()}
    for other in ("threshold", "history_rule", "cumulative_threshold", "threshold_new_only"):
        if other in draws and "mdp" in draws:
            diff = {k: np.array(draws["mdp"][k]) - np.array(draws[other][k]) for k in keys}
            out[f"mdp_minus_{other}"] = {k: ci(v) + [round(float(np.mean(v < 0)), 3)] for k, v in diff.items()}
    return out


SPLIT_SEEDS = (42, 1, 2) if QUICK else (42, 1, 2, 3, 4)


def resplit(rows: list[dict], seed: int) -> list[dict]:
    """Re-draw the server-grouped train/val/test split with another seed."""
    seqs: dict[str, dict] = {}
    for r in rows:
        seqs.setdefault(r["seq_id"], {"server": r["server"]})
    assign_splits(list(seqs.values()), seed)
    return [dict(r, split=seqs[r["seq_id"]]["split"]) for r in rows]


def multi_split(rows: list[dict], emb, costs, real_dev: list[dict] = (), community: list[dict] = ()) -> dict:
    """Main comparisons repeated over several server splits: mean, std and wins per policy."""
    slow_ids = {r["seq_id"] for r in rows if r["change_type"].startswith("malicious_slow")}
    runs = {"seen": [], "unseen_slow": [], "unseen_slow_augmented": []}
    for seed in SPLIT_SEEDS:
        rs = resplit(rows, seed)
        part = {k: [r for r in rs if r["split"] == k] for k in ("train", "val", "test")}
        part["train"] = part["train"] + real_for_training(list(real_dev), part["train"]) + list(community)
        tr_u = [r for r in part["train"] if r["seq_id"] not in slow_ids]
        va_u = [r for r in part["val"] if r["seq_id"] not in slow_ids]
        settings = {"seen": (part["train"], part["val"]), "unseen_slow": (tr_u, va_u),
                    "unseen_slow_augmented": (tr_u + augment_slow(tr_u, seed), va_u + augment_slow(va_u, seed + 1))}
        for name, (tr, va) in settings.items():
            res, _, _ = compare_policies(build_scored(emb, tr, va, part["test"]), costs, boot=False)
            runs[name].append({"seed": seed, "results": {r["name"]: r for r in res["results"]},
                               "slow_decomposed_asr": {k: v["asr"] for k, v in res["by_seq_type"]["slow_decomposed"].items()
                                                       if k != "n"}})
        emb.save()
        print(f"   split seed {seed} done")
    out = {}
    for name, rr in runs.items():
        policies = list(rr[0]["results"])
        summary = {}
        for p in policies:
            vals = {k: [run["results"][p][k] for run in rr] for k in ("asr", "fbr", "rb", "cost_per_update")}
            summary[p] = {k: [round(float(np.mean(v)), 4), round(float(np.std(v)), 4)] for k, v in vals.items()}
            sd = [run["slow_decomposed_asr"].get(p) for run in rr if p in run["slow_decomposed_asr"]]
            if sd:
                summary[p]["slow_decomposed_asr"] = [round(float(np.mean(sd)), 4), round(float(np.std(sd)), 4)]
            summary[p]["lowest_cost_splits"] = sum(
                min((q for q in policies if q not in ("no_protection",)),
                    key=lambda q: run["results"][q]["cost_per_update"]) == p for run in rr)
        out[name] = {"splits": list(SPLIT_SEEDS), "summary": summary}
    return out


def compare_policies(scored: dict, costs, boot: bool = True) -> tuple[dict, dict, MDP]:
    pols, (mdp, V, iters) = fit_policies(scored["fit"], scored["fit_new"], costs)
    test, test_new = scored["test"], scored["test_new"]
    entries = {"no_protection": (AllowAll(), test), "hash_pinning": (HashPin(), test),
               "threshold_new_only": (pols["thr_new"], test_new), "threshold": (pols["thr"], test),
               "history_rule": (pols["rule"], test), "cumulative_threshold": (pols["cum"], test),
               "mdp": (pols["mdp"], test)}
    results = [simulate_avg(pol, seqs, costs, SEEDS).as_dict() for pol, seqs in entries.values()]
    by_type = {}
    for t in SEQ_TYPES:
        by_type[t] = {"n": sum(s["seq_type"] == t for s in test)}
        for name, (pol, seqs) in entries.items():
            if name == "no_protection":
                continue
            r = simulate_avg(pol, [s for s in seqs if s["seq_type"] == t], costs, SEEDS)
            by_type[t][name] = {"asr": round(r.asr, 4), "rb": round(r.rb, 4), "fbr": round(r.fbr, 4), "dd": round(r.dd, 3)}
    out = {"results": results, "by_seq_type": by_type,
           "bootstrap": bootstrap({k: v for k, v in entries.items() if k != "no_protection"}, costs) if boot else {},
           "tuned": {"threshold": [pols["thr"].t_low, pols["thr"].t_high],
                     "threshold_new_only": [pols["thr_new"].t_low, pols["thr_new"].t_high],
                     "history_rule_theta": pols["rule"].theta, "mdp_risk_bins": list(pols["mdp"].space.risk_bins),
                     "cumulative_threshold": [pols["cum"].t_low, pols["cum"].t_high]},
           "mdp_value_iterations": iters}
    return out, pols, mdp


# --- main ---------------------------------------------------------------------

def main() -> int:
    t0 = time.time()
    RESULTS.mkdir(exist_ok=True)
    rows = load_rows()
    by_split = defaultdict(list)
    for r in rows:
        by_split[r["split"]].append(r)
    train, val, test = by_split["train"], by_split["val"], by_split["test"]
    y = {k: np.array([r["step_label"] for r in v]) for k, v in by_split.items()}
    emb = SentenceEmbedder(DATA / "cache" / "embeddings.npz")
    out: dict = {"data": {k: {"updates": len(v), "attack_updates": int(y[k].sum())} for k, v in by_split.items()}}

    real = load_real_rows()                  # development set 1: official servers' git history
    community = [dict(r, weight=COMMUNITY_WEIGHT) for r in load_real_rows(COMMUNITY)]  # development set 2
    held = load_real_rows(FINAL)             # final held-out set: fresh community repos, never used to fit or tune
    train_bench = train
    # Community repos are disjoint from every benchmark server, so they can join training without leaking.
    train = train_bench + real_for_training(real, train_bench) + community
    y["train"] = np.array([r["step_label"] for r in train])
    out["data"]["train"]["real_changes_added"] = len(train) - len(train_bench)

    def ours():
        return DualDetector(emb, **DETECTOR_KW)

    def step_only():
        return ChangeDetector(emb, DETECTOR_KW["config"], C=DETECTOR_KW["step_C"], text=DETECTOR_KW["step_text"],
                              tfidf_scale=DETECTOR_KW["step_scale"])

    def new_only():
        return ChangeDetector(emb, new_only=True)

    print("1/7 selecting detector settings on validation, training detectors")
    out["head_selection"] = select_heads(emb, train, val)
    det = ours().fit(train)
    det.save(MODELS / "detector.joblib")
    det_new = new_only().fit(train, y["train"])
    tfidf = {mode: TfidfDetector(mode).fit(train, y["train"]) for mode in ("new", "added")}
    emb.save()

    print("2/7 detector metrics")
    test_step, test_cum = score_rows(det, test)
    test_new = det_new.predict_proba(test)
    test_tfidf = {mode: d.predict_proba(test) for mode, d in tfidf.items()}
    det_out = {"change_pair": detector_metrics(y["test"], test_step), "new_only": detector_metrics(y["test"], test_new),
               "tfidf_new": detector_metrics(y["test"], test_tfidf["new"]),
               "tfidf_added": detector_metrics(y["test"], test_tfidf["added"]),
               "cumulative_head": detector_metrics([r["cum_label"] for r in test], test_cum)}
    det_out["pr_curves"] = {"change_pair": pr_points(y["test"], test_step), "new_only": pr_points(y["test"], test_new),
                            "tfidf_new": pr_points(y["test"], test_tfidf["new"]),
                            "tfidf_added": pr_points(y["test"], test_tfidf["added"])}

    if held:
        # Final held-out real-world false positives (fresh community repos, never used to fit or tune).
        # Thresholds: 0.5, and the one giving FPR <= 5% on validation. The ablations show what the
        # text model and the real training data each contribute.
        embed_cfg, _, _ = HEAD_CANDIDATES["embed_pooled"]
        embed_real = ChangeDetector(emb, embed_cfg, C=0.1).fit(train, y["train"])
        chosen_no_real = step_only().fit(train_bench, [r["step_label"] for r in train_bench])
        models = {"change_pair": det.step, "new_only": det_new, "tfidf_new": tfidf["new"], "tfidf_added": tfidf["added"],
                  "ablation_embeddings_with_real": embed_real, "ablation_chosen_no_real": chosen_no_real}
        y_val = [r["step_label"] for r in val]
        repos = sorted({r["server"] for r in held})
        out["real_world"] = {"changes": len(held), "tools": len({r["tool_id"] for r in held}), "servers": len(repos),
                             "source": "fresh community MCP repos (git history)", "detectors": {}}
        attacks = [r for r in test if r["step_label"] == 1]
        reworded = [(a, b) for a, b in ((r, reword_update(r)) for r in attacks) if b["new"] != a["new"]]
        softened = [r for r in attacks if r["style"] == "softened"]
        test_benign = [r for r in test if r["step_label"] == 0]
        out["robustness"] = {"reworded_n": len(reworded), "softened_n": len(softened), "detectors": {}}
        for name, m in models.items():
            p, thr5 = m.predict_proba(held), recall_at_fpr(y_val, m.predict_proba(val), 0.05)[1]
            per_repo = [float(np.mean([pi >= thr5 for pi, r in zip(p, held) if r["server"] == s])) for s in repos]
            out["real_world"]["detectors"][name] = {
                "fpr_at_0.5": round(float(np.mean(p >= 0.5)), 4),
                "fpr_at_val_fpr5_threshold": round(float(np.mean(p >= thr5)), 4),
                "fpr_at_val_fpr5_threshold_repo_avg": round(float(np.mean(per_repo)), 4),
                "val_fpr5_threshold": round(thr5, 4), "mean_score": round(float(np.mean(p)), 4)}
            # Same threshold on the test servers: attacks caught as written, softened and reworded.
            caught = lambda rs: round(float(np.mean(m.predict_proba(rs) >= thr5)), 4) if rs else None  # noqa: E731
            out["robustness"]["detectors"][name] = {
                "recall": caught(attacks), "fpr": caught(test_benign), "softened_recall": caught(softened),
                "reworded_recall_original": caught([a for a, _ in reworded]),
                "reworded_recall": caught([b for _, b in reworded])}
    if real:
        # Development set, scored by grouped cross-validation (it is part of training).
        groups = [r["server"] for r in real]
        cv_p = np.zeros(len(real))
        n_folds = min(5, len(set(groups)))
        for tr_i, te_i in GroupKFold(n_splits=n_folds).split(real, groups=groups):
            extra = [dict(real[i], weight=REAL_WEIGHT) for i in tr_i]
            d = step_only().fit(train_bench + extra, [r["step_label"] for r in train_bench + extra])
            cv_p[te_i] = d.predict_proba([real[i] for i in te_i])
        out.setdefault("real_world", {})["development_set_cv"] = {
            "changes": len(real), "fpr_at_0.5": round(float(np.mean(cv_p >= 0.5)), 4),
            "mean_score": round(float(np.mean(cv_p)), 4), "folds": n_folds,
            "note": "official servers' history; train + real changes of the other server groups (weight 20)"}
    for group_key in ("style", "seq_type", "change_type"):
        det_out[f"by_{group_key}"] = {}
        for value in sorted({str(r[group_key]) for r in test}):
            idx = [i for i, r in enumerate(test) if str(r[group_key]) == value]
            det_out[f"by_{group_key}"][value] = {
                "change_pair": detector_metrics(y["test"][idx], test_step[idx]),
                "new_only": detector_metrics(y["test"][idx], test_new[idx])}
    hn = [i for i, r in enumerate(test) if r["hard_negative"] and not r["step_label"]]
    det_out["hard_negative_fpr"] = {"n": len(hn), "change_pair": float(np.mean(test_step[hn] >= 0.5)) if hn else None,
                                    "new_only": float(np.mean(test_new[hn] >= 0.5)) if hn else None}
    det_out["top_weights"] = det.step.top_weights(15)
    out["detector"] = det_out

    print("3/7 ablations")
    ablations = {"full": FeatureConfig(), "no_embed_added": FeatureConfig(embed_added=False),
                 "no_embed_diff": FeatureConfig(embed_diff=False), "no_drift": FeatureConfig(drift=False),
                 "no_scope": FeatureConfig(scope=False), "no_flags": FeatureConfig(flags=False),
                 "flags_and_numeric_only": FeatureConfig(embed_added=False, embed_diff=False)}
    out["ablations"] = {}
    for name, cfg in ablations.items():
        d = ChangeDetector(emb, cfg).fit(train, y["train"])
        out["ablations"][name] = detector_metrics(y["test"], d.predict_proba(test))

    print("4/7 generalization: unseen paradigm and unseen phrasing")
    out["leave_one_paradigm_out"] = {}
    for paradigm in ("Template-1", "Template-2", "Template-3"):
        tr = [r for r in train + val if r["paradigm"] != paradigm]
        te = [r for r in test if r["paradigm"] in (paradigm, None)] + \
             [r for r in train + val if r["paradigm"] == paradigm]
        d = step_only().fit(tr, [r["step_label"] for r in tr])
        out["leave_one_paradigm_out"][paradigm] = detector_metrics([r["step_label"] for r in te], d.predict_proba(te))

    def variant(row):
        tid = row["template_id"]
        return int(tid.rsplit(":", 1)[1]) % 2 if tid.rsplit(":", 1)[-1].isdigit() and not tid.startswith("mcptox") else None
    tr = [r for r in train if variant(r) in (0, None)]
    te = [r for r in test if variant(r) in (1, None)]
    d = step_only().fit(tr, [r["step_label"] for r in tr])
    out["template_holdout"] = detector_metrics([r["step_label"] for r in te], d.predict_proba(te))

    print("5/7 policy-fit set (out-of-fold train + val)")
    scored = build_scored(emb, train, val, test, det, det_new)
    emb.save()
    # None of the flagged hard-negative tools' servers is in test, so measure them out-of-fold.
    fit_rows, fit_step, fit_newp = scored["fit_rows"], scored["fit_step"], scored["fit_new_scores"]
    hn = [i for i, r in enumerate(fit_rows) if r["hard_negative"] and not r["step_label"]]
    out["detector"]["hard_negative_fpr_out_of_fold"] = {
        "n": len(hn), "tools": sorted({fit_rows[i]["tool_id"] for i in hn}),
        "change_pair": round(float(np.mean(fit_step[hn] >= 0.5)), 4) if hn else None,
        "new_only": round(float(np.mean(fit_newp[hn] >= 0.5)), 4) if hn else None}
    out["sequence_level_auc"] = sequence_level(scored)
    fit_seqs, fit_new, test_seqs = scored["fit"], scored["fit_new"], scored["test"]

    print("6/7 policy comparison: all strategies known, and slow strategies unseen in training")
    costs = Costs()
    out["policies"], pols, mdp = compare_policies(scored, costs)
    out["policies"]["costs"] = costs.__dict__
    if held:
        r_step, r_cum = det.predict(held)
        real_seqs, real_new = to_sequences(held, r_step, r_cum), to_sequences(held, *[det_new.predict_proba(held)] * 2)
        out["real_world"]["policies"] = {}
        for name, pol, seqs in (("hash_pinning", HashPin(), real_seqs), ("threshold_new_only", pols["thr_new"], real_new),
                                ("threshold", pols["thr"], real_seqs), ("history_rule", pols["rule"], real_seqs),
                                ("cumulative_threshold", pols["cum"], real_seqs), ("mdp", pols["mdp"], real_seqs)):
            r = simulate_avg(pol, seqs, costs, SEEDS)
            out["real_world"]["policies"][name] = {"fbr": round(r.fbr, 4), "rb": round(r.rb, 4)}
    slow_ids = {r["seq_id"] for r in rows if r["change_type"].startswith("malicious_slow")}
    tr_u, va_u = [r for r in train if r["seq_id"] not in slow_ids], [r for r in val if r["seq_id"] not in slow_ids]
    scored_u = build_scored(emb, tr_u, va_u, test)
    emb.save()
    out["unseen_slow"], _, _ = compare_policies(scored_u, costs)
    out["unseen_slow"].update(train_updates=len(tr_u), sequence_level_auc=sequence_level(scored_u))
    # Same setting, but the defender splits its own known one-shot poisons into synthetic slow histories.
    aug_tr, aug_va = augment_slow(tr_u, 0), augment_slow(va_u, 1)
    scored_a = build_scored(emb, tr_u + aug_tr, va_u + aug_va, test)
    emb.save()
    out["unseen_slow_augmented"], _, _ = compare_policies(scored_a, costs)
    out["unseen_slow_augmented"].update(train_updates=len(tr_u) + len(aug_tr), augmented_updates=len(aug_tr),
                                        sequence_level_auc=sequence_level(scored_a))
    print(f"   repeating both comparisons over {len(SPLIT_SEEDS)} server splits")
    out["multi_split"] = multi_split(rows, emb, costs, real, community)
    space = pols["mdp"].space
    out["mdp_policy_table"] = [
        {"state": dict(zip(("step_risk", "cum_risk", "updates", "prior_max"), st)), "visits": int(mdp.counts[i]),
         "p_attack": round(float(mdp.p_attack[i]), 3), "action": ACTIONS[int(pols["mdp"].table[i])]}
        for i, st in enumerate(space.states)]

    print("7/7 sensitivity and trade-off curves")
    sens = []
    for c_miss in (20, 50, 100, 200, 500):
        for eps in (0.0, 0.05, 0.1, 0.2):
            c = Costs(c_miss=c_miss, eps=eps)
            p, _ = fit_policies(fit_seqs, fit_new, c)
            row = {"c_miss": c_miss, "eps": eps}
            for name in ("thr", "rule", "cum", "mdp"):
                r = simulate_avg(p[name], test_seqs, c, SEEDS)
                row[name] = {"cost": round(r.cost_per_update, 4), "asr": round(r.asr, 4), "rb": round(r.rb, 4), "fbr": round(r.fbr, 4)}
            sens.append(row)
    out["sensitivity"] = sens
    curves = {"threshold": [], "history_rule": [], "cumulative_threshold": [], "mdp": []}
    for c_rev in (0.5, 1, 2, 4, 8, 16, 32):
        c = Costs(c_rev=c_rev)
        p, _ = fit_policies(fit_seqs, fit_new, c)
        for key, name in (("thr", "threshold"), ("rule", "history_rule"), ("cum", "cumulative_threshold"), ("mdp", "mdp")):
            r = simulate_avg(p[key], test_seqs, c, SEEDS)
            curves[name].append({"c_rev": c_rev, "asr": r.asr, "rb": r.rb, "fbr": r.fbr})
    out["tradeoff_curves"] = curves
    out["runtime_seconds"] = round(time.time() - t0, 1)

    (RESULTS / "results.json").write_text(json.dumps(out, indent=2, default=float), encoding="utf-8")
    (MODELS / "mdp_policy.json").write_text(json.dumps(
        {"risk_bins": space.risk_bins, "max_count": space.max_count, "table": pols["mdp"].table.tolist(),
         "costs": costs.__dict__}, indent=2), encoding="utf-8")
    from experiments.report import write_report
    write_report(out, RESULTS)
    print(f"done in {out['runtime_seconds']}s -> results/")
    return 0


if __name__ == "__main__":
    sys.exit(main())
