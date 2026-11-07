import numpy as np
import pytest

from experiments.simulate import simulate
from gateway.policy_engine import AllowAll, CumulativeRule, HashPin, MDPPolicy, Observation, Threshold, apply_hard_rules
from mdp.model import ALLOW, BLOCK, MDP, QUARANTINE, Costs, StateSpace


def test_state_space_size_and_binning():
    space = StateSpace()
    assert len(space.states) == 81
    assert [space.bin(r) for r in (0.1, 0.3, 0.69, 0.7, 0.99)] == [0, 1, 1, 2, 2]
    assert space.states[space.index(0.9, 0.1, 5, None)] == (2, 0, 2, 0)


def _mdp_with(p_attack: float, costs=Costs()) -> MDP:
    """One-state MDP where every sequence ends after one update."""
    space = StateSpace()
    n = len(space.states)
    P = np.zeros((n, n + 1))
    P[:, n] = 1.0
    return MDP(space, costs, np.full(n, p_attack), P.copy(), P.copy(), np.ones(n))


def test_value_iteration_matches_hand_computed_myopic_answer():
    # With no continuation the optimal action is argmax of the expected reward.
    for p, expected in ((0.001, ALLOW), (0.3, QUARANTINE), (0.999, BLOCK)):
        mdp = _mdp_with(p)
        V, policy, iters = mdp.solve()
        assert set(policy) == {expected}, p
        assert np.allclose(V, mdp.rewards().max(1))


def test_value_iteration_converges_with_continuation():
    mdp = _mdp_with(0.2)
    n = len(mdp.p_attack)
    mdp.P_ben = np.full((n, n + 1), 1.0 / (n + 1))
    mdp.P_mal = mdp.P_ben.copy()
    V, policy, iters = mdp.solve()
    R, C = mdp.rewards(), mdp.continuation()
    assert np.allclose(V, (R + mdp.costs.gamma * C @ V).max(1), atol=1e-6)
    assert iters < 10_000


def test_estimate_counts_attack_rate_and_transitions():
    space = StateSpace()
    episodes = [[{"state": 0, "label": 0}, {"state": 1, "label": 0}], [{"state": 0, "label": 1}]]
    mdp = MDP.estimate(episodes, space, Costs(), alpha=0.0)
    assert mdp.p_attack[0] == pytest.approx(0.5)
    assert mdp.P_ben[0, 1] == pytest.approx(1.0)
    assert mdp.P_mal[0, len(space.states)] == pytest.approx(1.0)


def test_policies_are_deterministic_and_explain_themselves():
    obs = Observation(r_step=0.5, r_cum=0.8, n=2, prev_max=0.4)
    thr = Threshold(0.6, 0.9)
    rule = CumulativeRule(thr, theta=0.7)
    assert thr.decide(obs)[0] == "ALLOW"
    assert rule.decide(obs)[0] == "QUARANTINE" and "r_cum" in rule.decide(obs)[1]
    assert HashPin().decide(obs)[0] == "QUARANTINE"
    assert AllowAll().decide(obs)[0] == "ALLOW"
    space = StateSpace()
    table = np.full(len(space.states), BLOCK)
    assert MDPPolicy(space, table).decide(obs) == MDPPolicy(space, table).decide(obs)


def test_hard_rules():
    assert apply_hard_rules(["hidden_unicode"], True)[0] == "BLOCK"
    assert apply_hard_rules([], False)[0] == "QUARANTINE"
    assert apply_hard_rules(["sensitive_target"], True) is None


SLOW = {"hard_negative": False, "steps": [
    {"r_step": 0.2, "r_cum": 0.2, "label": 1, "payload_complete": False},
    {"r_step": 0.25, "r_cum": 0.5, "label": 1, "payload_complete": False},
    {"r_step": 0.2, "r_cum": 0.9, "label": 1, "payload_complete": True}]}
BENIGN = {"hard_negative": True, "steps": [
    {"r_step": 0.1, "r_cum": 0.1, "label": 0, "payload_complete": False},
    {"r_step": 0.1, "r_cum": 0.15, "label": 0, "payload_complete": False}]}


def test_simulator_slow_attack_beats_step_threshold_but_not_cumulative_rule():
    costs = Costs(eps=0.0)
    thr = Threshold(0.5, 0.9)
    assert simulate(thr, [SLOW], costs).asr == 1.0
    res = simulate(CumulativeRule(thr, theta=0.8), [SLOW, BENIGN], costs)
    assert res.asr == 0.0 and res.fbr == 0.0 and res.dd == 2


def test_simulator_hash_pinning_reviews_everything():
    res = simulate(HashPin(), [SLOW, BENIGN], Costs(eps=0.0))
    assert res.asr == 0.0 and res.dd == 0
    assert res.rb == 1.0


def test_reviewer_error_can_let_attacks_through():
    res = simulate(HashPin(), [SLOW] * 200, Costs(eps=0.5), seed=1)
    assert 0 < res.asr < 1
