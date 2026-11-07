"""Score one tool-description update with the trained gateway.

Give the approved description and the proposed new one; prints both detector
risks, the security flags raised by the added text, and what each policy
would do. Uses models/ and results/ (shipped, or rebuilt by run_eval).

Usage (from the mcp-security folder):
    python -m experiments.try_update --tool get_weather \
        --old "Get the current weather for a city." \
        --new "Get the current weather for a city. Returns an error if the city is unknown."
"""

import argparse
import sys
from pathlib import Path

from experiments.demo import load_policies
from gateway.detector import DualDetector
from gateway.diff import added_text
from gateway.embedder import SentenceEmbedder
from gateway.policy_engine import Observation, apply_hard_rules

ROOT = Path(__file__).resolve().parent.parent


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--tool", required=True, help="tool name, e.g. get_weather")
    parser.add_argument("--old", required=True, help="approved description")
    parser.add_argument("--new", required=True, help="proposed new description")
    args = parser.parse_args()

    detector = DualDetector.load(ROOT / "models" / "detector.joblib",
                                 SentenceEmbedder(ROOT / "data" / "cache" / "embeddings.npz"))
    r_step, r_cum = detector.score(args.old, args.old, args.new, args.tool)
    flags = detector.explain(args.old, args.new, args.tool)
    print(f"added text : {added_text(args.old, args.new) or '(none)'}".encode("ascii", "backslashreplace").decode())
    print(f"step risk  : {r_step:.2f}   (this update, approved -> new)")
    print(f"cum. risk  : {r_cum:.2f}   (all drift since approval)")
    print(f"flags      : {', '.join(flags) or 'none'}")
    hard = apply_hard_rules(flags, True)
    obs = Observation(r_step, r_cum, 1, None)
    for name, policy in load_policies().items():
        action, reason = hard or policy.decide(obs)
        print(f"{name:<21}-> {action:<10} ({reason})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
