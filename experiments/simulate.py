"""Replay version sequences through a policy and measure outcomes.

Gateway semantics per update:
    ALLOW       the new version becomes the approved baseline; continue.
    QUARANTINE  a reviewer inspects it. Attack -> caught (sequence stops) unless
                the reviewer errs (prob eps) and approves it. Benign -> approved
                unless the reviewer errs and rejects it (counts as a false block).
    BLOCK       the tool is blocked; the sequence stops.

Metrics:
    ASR   attack sequences whose payload-complete update was allowed / attack sequences
    FBR   legitimate updates blocked (incl. wrong rejections) / legitimate updates seen
    RB    quarantines / updates seen
    DD    mean steps from the first attack update to the stop, over stopped attacks
    cost  total cost under the same Costs the MDP optimizes (lower is better):
          c_miss per completed attack, c_fb per blocked legitimate update, c_rev per review
"""

import random
from dataclasses import dataclass

import numpy as np

from gateway.policy_engine import Observation
from mdp.model import Costs


@dataclass
class Result:
    name: str
    asr: float
    fbr: float
    rb: float
    dd: float
    cost_per_update: float
    attacks_stopped_early: float
    fbr_hard_negative: float

    def as_dict(self) -> dict:
        return {k: (round(v, 4) if isinstance(v, float) else v) for k, v in self.__dict__.items()}


def simulate(policy, sequences: list[dict], costs: Costs, seed: int = 0) -> Result:
    """sequences: dicts with 'steps' = [{r_step, r_cum, label, payload_complete}], 'hard_negative'."""
    rng = random.Random(seed)
    attacks = succeeded = stopped_early = 0
    benign_seen = benign_blocked = hn_seen = hn_blocked = 0
    updates = quarantines = 0
    delays, cost = [], 0.0
    for seq in sequences:
        is_attack = any(st["label"] for st in seq["steps"])
        attacks += is_attack
        first_attack = next((k for k, st in enumerate(seq["steps"]) if st["label"]), None)
        prev_max = None
        for k, st in enumerate(seq["steps"]):
            obs = Observation(st["r_step"], st["r_cum"], k + 1, prev_max)
            action, _ = policy.decide(obs)
            updates += 1
            y = st["label"]
            if not y:
                benign_seen += 1
                hn_seen += seq.get("hard_negative", False)
            stop = False
            if action == "QUARANTINE":
                quarantines += 1
                cost += costs.c_rev
                wrong = rng.random() < costs.eps
                if y and not wrong:
                    stop = True
                elif y and wrong:
                    action = "ALLOW"            # reviewer approved an attack
                elif not y and wrong:
                    action = "BLOCK"            # reviewer rejected a legitimate update
                else:
                    action = "ALLOW"
            if action == "BLOCK":
                stop = True
                if not y:
                    benign_blocked += 1
                    hn_blocked += seq.get("hard_negative", False)
                    cost += costs.c_fb
            if action == "ALLOW" and y and st["payload_complete"]:
                cost += costs.c_miss
                succeeded += 1
            if stop:
                if y:
                    delays.append(k - first_attack)
                    stopped_early += not st["payload_complete"]
                break
            prev_max = st["r_step"] if prev_max is None else max(prev_max, st["r_step"])
    return Result(
        name=getattr(policy, "name", type(policy).__name__),
        asr=succeeded / max(attacks, 1),
        fbr=benign_blocked / max(benign_seen, 1),
        rb=quarantines / max(updates, 1),
        dd=float(np.mean(delays)) if delays else float("nan"),
        cost_per_update=cost / max(updates, 1),
        attacks_stopped_early=stopped_early / max(attacks, 1),
        fbr_hard_negative=hn_blocked / max(hn_seen, 1),
    )


def simulate_avg(policy, sequences: list[dict], costs: Costs, seeds=range(5)) -> Result:
    runs = [simulate(policy, sequences, costs, seed) for seed in seeds]
    fields = [f for f in Result.__dataclass_fields__ if f != "name"]
    return Result(runs[0].name, **{f: float(np.nanmean([getattr(r, f) for r in runs])) for f in fields})
