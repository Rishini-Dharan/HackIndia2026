"""
Pass/fail gate for the scheduled planner eval (.github/workflows/planner-eval.yml).

Fails when the planner regresses, not on noise: an occasional malformed tool call
(a `//` comment in the JSON, rejected by Groq) is expected about once per run, so
the thresholds leave room for one or two misses.

    python eval/check_results.py results-gpt-oss-120b.json:17 results-gpt-oss-120b-holdout.json:10
"""

import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
MAX_FALLBACKS = 3  # more than this means the provider or model is broken, not the planner


def main(specs: list[str]) -> int:
    failed = False
    for spec in specs:
        name, minimum = spec.rsplit(":", 1)
        path = HERE / name
        if not path.exists():
            print(f"FAIL {name}: missing (the eval did not finish)")
            failed = True
            continue
        summary = json.loads(path.read_text())["summary"]
        ok = summary["passed"] >= int(minimum) and summary["fallback_cases"] <= MAX_FALLBACKS
        print(f"{'PASS' if ok else 'FAIL'} {name}: {summary['passed']}/{summary['cases']} "
              f"(need {minimum}), fallbacks {summary['fallback_cases']} (max {MAX_FALLBACKS}), "
              f"model {summary['model']}")
        failed |= not ok
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
