"""Layer 2: the history-aware decision MDP  M = (S, A, P, R, gamma).

State s_k = (bin(r_step), bin(r_cum), n_k, m_k)
    bin(r)  in {low, med, high}   detector risk of this update / of all drift since d0
    n_k     in {1, 2, 3+}         how many updates this tool has had since approval
    m_k     in {low, med, high}   highest step risk seen earlier in this history
    |S| = 3 * 3 * 3 * 3 = 81 (plus absorbing terminal states)

Actions: ALLOW, QUARANTINE (human review), BLOCK.

The true label (is this update part of an attack?) is hidden, so this is
really a POMDP; the state summarizes the evidence. Two probabilities are
estimated from (out-of-fold) training data:
    p_s = P(this update belongs to an attack | s)
    q_s = P(this update completes an attack's payload | s)    (q_s <= p_s)
The miss cost is charged only when a payload-completing update is allowed:
allowing an innocuous-looking early fragment costs nothing by itself, but it
moves the history towards states where completion becomes likely, which the
value function accounts for.

Transitions are estimated by counting consecutive updates in the training
sequences, separately for attack and benign histories:
    P(s'|s, ALLOW)      = p_s P_mal(s'|s) + (1 - p_s) P_ben(s'|s)
    P(s'|s, QUARANTINE) = reviewer catches an attack (absorbing) or approves it and the history continues
    P(s'|s, BLOCK)      = absorbing
with Laplace smoothing; "end of sequence" is an absorbing successor.

Expected rewards with costs C_miss, C_fb, C_rev, reviewer error eps:
    R(s, ALLOW)      = -C_miss q_s + r_ok (1 - p_s)
    R(s, BLOCK)      = r_catch p_s - C_fb (1 - p_s)
    R(s, QUARANTINE) = -C_rev + p_s (1-eps) r_catch - eps q_s C_miss + (1-p_s) [(1-eps) r_ok - eps C_fb]

Solved by value iteration on the Bellman optimality equation.
"""

from dataclasses import dataclass, field
from itertools import product

import numpy as np

ACTIONS = ("ALLOW", "QUARANTINE", "BLOCK")
ALLOW, QUARANTINE, BLOCK = range(3)


@dataclass
class Costs:
    c_miss: float = 100.0   # allowing an attack update
    c_fb: float = 10.0      # blocking a legitimate update
    c_rev: float = 2.0      # one human review
    r_ok: float = 1.0       # correct allow
    r_catch: float = 1.0    # correct stop
    eps: float = 0.05       # reviewer error rate
    gamma: float = 0.9


@dataclass
class StateSpace:
    risk_bins: tuple[float, float] = (0.3, 0.7)
    max_count: int = 3

    def bin(self, r: float) -> int:
        return int(r >= self.risk_bins[0]) + int(r >= self.risk_bins[1])

    @property
    def states(self) -> list[tuple[int, int, int, int]]:
        return list(product(range(3), range(3), range(self.max_count), range(3)))

    def index(self, r_step: float, r_cum: float, n: int, prev_max_step_risk: float | None) -> int:
        m = 0 if prev_max_step_risk is None else self.bin(prev_max_step_risk)
        s = (self.bin(r_step), self.bin(r_cum), min(n, self.max_count) - 1, m)
        return self.states.index(s)


@dataclass
class MDP:
    space: StateSpace
    costs: Costs
    p_attack: np.ndarray = field(default=None)       # (S,) P(update belongs to an attack | s)
    P_mal: np.ndarray = field(default=None)          # (S, S+1) last column = end of sequence
    P_ben: np.ndarray = field(default=None)
    counts: np.ndarray = field(default=None)         # visits per state (for reporting)
    p_complete: np.ndarray = field(default=None)     # (S,) P(update completes an attack payload | s)

    @classmethod
    def estimate(cls, sequences: list[list[dict]], space: StateSpace, costs: Costs, alpha: float = 1.0) -> "MDP":
        """sequences: per sequence, a list of {state, label, complete} for consecutive updates.

        `complete` defaults to `label` (every attack update completes an attack).
        """
        n = len(space.states)
        mal, done, tot = np.zeros(n), np.zeros(n), np.zeros(n)
        T = {0: np.zeros((n, n + 1)), 1: np.zeros((n, n + 1))}
        for seq in sequences:
            for k, step in enumerate(seq):
                s, y = step["state"], step["label"]
                tot[s] += 1
                mal[s] += y
                done[s] += step.get("complete", y)
                nxt = seq[k + 1]["state"] if k + 1 < len(seq) else n
                T[y][s, nxt] += 1
        # Beta priors centred on the overall rates keep rarely seen states sensible.
        def smoothed(hits):
            base = hits.sum() / max(tot.sum(), 1)
            return np.divide(hits + alpha * base, tot + alpha, out=np.full(n, base), where=(tot + alpha) > 0)
        P = {}
        for y in (0, 1):
            num, den = T[y] + alpha / (n + 1), T[y].sum(1, keepdims=True) + alpha
            # States never seen with this label: assume the sequence ends.
            P[y] = np.divide(num, den, out=np.eye(n + 1)[[n] * n], where=den > 0)
        return cls(space, costs, smoothed(mal), P[1], P[0], tot, smoothed(done))

    def rewards(self) -> np.ndarray:
        c, p = self.costs, self.p_attack
        q = self.p_complete if self.p_complete is not None else p
        R = np.zeros((len(p), 3))
        R[:, ALLOW] = -c.c_miss * q + c.r_ok * (1 - p)
        R[:, BLOCK] = c.r_catch * p - c.c_fb * (1 - p)
        R[:, QUARANTINE] = (-c.c_rev + p * (1 - c.eps) * c.r_catch - c.eps * q * c.c_miss
                            + (1 - p) * ((1 - c.eps) * c.r_ok - c.eps * c.c_fb))
        return R

    def continuation(self) -> np.ndarray:
        """(S, A, S) probability of moving to each non-terminal next state."""
        p, eps = self.p_attack[:, None], self.costs.eps
        n = len(self.p_attack)
        C = np.zeros((n, 3, n))
        C[:, ALLOW] = p * self.P_mal[:, :n] + (1 - p) * self.P_ben[:, :n]
        # Under review an attack continues only if the reviewer misses it; benign continues unless wrongly rejected.
        C[:, QUARANTINE] = p * eps * self.P_mal[:, :n] + (1 - p) * (1 - eps) * self.P_ben[:, :n]
        return C

    def solve(self, tol: float = 1e-8, max_iter: int = 10_000) -> tuple[np.ndarray, np.ndarray, int]:
        """Value iteration. Returns (V, policy, iterations)."""
        R, C, g = self.rewards(), self.continuation(), self.costs.gamma
        V = np.zeros(len(R))
        for it in range(1, max_iter + 1):
            Q = R + g * C @ V
            V_new = Q.max(1)
            if np.max(np.abs(V_new - V)) < tol:
                V = V_new
                break
            V = V_new
        Q = R + g * C @ V
        return V, Q.argmax(1), it
