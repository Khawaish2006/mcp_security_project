"""Decision policies: ALLOW / QUARANTINE / BLOCK for one update.

Every policy sees the same observation:
    r_step   detector risk of this update (prev -> new)
    r_cum    detector risk of all drift since approval (d0 -> new)
    n        number of updates since the original approval (1, 2, ...)
    prev_max highest r_step earlier in this tool's history (None if first)

Hard rules run before any policy and cannot be overridden by a low score:
    hidden unicode in the added text  -> BLOCK
    detector unavailable / failed     -> QUARANTINE (never ALLOW)
"""

from dataclasses import dataclass

import numpy as np

from mdp.model import ACTIONS, StateSpace


@dataclass
class Observation:
    r_step: float
    r_cum: float
    n: int
    prev_max: float | None
    hash_changed: bool = True

    @property
    def r_max(self) -> float:
        """Treat the whole drift since approval like one update: the worse of step and cumulative risk."""
        return max(self.r_step, self.r_cum)


class AllowAll:
    name = "no_protection"

    def decide(self, obs: Observation) -> tuple[str, str]:
        return "ALLOW", "no protection"


class HashPin:
    name = "hash_pinning"

    def decide(self, obs: Observation) -> tuple[str, str]:
        if obs.hash_changed:
            return "QUARANTINE", "description hash changed since approval"
        return "ALLOW", "unchanged"


@dataclass
class Threshold:
    t_low: float
    t_high: float
    key: str = "r_step"
    name: str = "threshold"

    def decide(self, obs: Observation) -> tuple[str, str]:
        r = getattr(obs, self.key)
        if r >= self.t_high:
            return "BLOCK", f"{self.key}={r:.2f} >= {self.t_high:.2f}"
        if r >= self.t_low:
            return "QUARANTINE", f"{self.key}={r:.2f} >= {self.t_low:.2f}"
        return "ALLOW", f"{self.key}={r:.2f} below {self.t_low:.2f}"


@dataclass
class CumulativeRule:
    """Hand-written history rule: per-step thresholds, plus review if total drift looks risky."""
    step: Threshold
    theta: float
    name: str = "history_rule"

    def decide(self, obs: Observation) -> tuple[str, str]:
        action, reason = self.step.decide(obs)
        if action == "ALLOW" and obs.r_cum >= self.theta:
            return "QUARANTINE", f"r_cum={obs.r_cum:.2f} >= {self.theta:.2f} (drift since approval)"
        return action, reason


@dataclass
class MDPPolicy:
    space: StateSpace
    table: np.ndarray        # action index per state
    name: str = "mdp"

    def decide(self, obs: Observation) -> tuple[str, str]:
        s = self.space.index(obs.r_step, obs.r_cum, obs.n, obs.prev_max)
        rb, cb, n, m = self.space.states[s]
        labels = ("low", "med", "high")
        action = ACTIONS[int(self.table[s])]
        return action, (f"state(step={labels[rb]}, cumulative={labels[cb]}, updates={n + 1}"
                        f"{'+' if n + 1 == self.space.max_count else ''}, prior_max={labels[m]}) -> {action}")


def apply_hard_rules(flags: list[str], detector_ok: bool) -> tuple[str, str] | None:
    if "hidden_unicode" in flags:
        return "BLOCK", "hard rule: hidden unicode characters in added text"
    if not detector_ok:
        return "QUARANTINE", "hard rule: detector unavailable, holding for review"
    return None
