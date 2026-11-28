"""
Planner evaluation: does the agent mount the right widgets for a request?

Each case lists the widget components a good answer mounts (empty = just talk).
A case passes when the set of mounted components equals the expected set.

    cd backend
    python eval/run_eval.py                       # uses whatever provider is configured
    GROQ_API_KEY=... python eval/run_eval.py      # real LLM

Writes eval/results-<mode>-<provider>.json.
"""

import argparse
import asyncio
import json
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

# Same .env the backend uses (repo root), loaded before the orchestrator reads its keys.
from dotenv import load_dotenv  # noqa: E402

load_dotenv(HERE.parent.parent / ".env")

import llm_orchestrator as llm  # noqa: E402


async def plan_with_retry(prompt: str, retries: int):
    """Retry rate-limited calls so a fallback reply is never scored as the model's."""
    for attempt in range(retries + 1):
        t0 = time.perf_counter()
        msgs = await llm.plan_investigation(prompt)
        latency = time.perf_counter() - t0
        reason = llm.LAST_MODE.get("reason", "")
        # Groq 429s and our own shared-budget cap are both "wait and retry", not failures.
        if not any(marker in reason for marker in ("429", "HTTPStatusError", "budget busy")):
            return msgs, latency
        if attempt < retries:
            print(f"      rate limited, waiting 20s (retry {attempt + 1}/{retries})")
            await asyncio.sleep(20)
    return msgs, latency


async def run(delay: float, retries: int, case_file: str):
    cases = json.loads((HERE / case_file).read_text())
    rows, passed = [], 0
    for i, case in enumerate(cases):
        if i and delay:
            await asyncio.sleep(delay)  # stay under free-tier tokens-per-minute limits
        msgs, latency = await plan_with_retry(case["prompt"], retries)
        got = sorted({m["component"] for m in msgs if m.get("type") == "widget"})
        ok = got == sorted(case["expect"])
        passed += ok
        rows.append({**case, "got": got, "pass": ok, "latency_s": round(latency, 2), "mode": dict(llm.LAST_MODE)})
        print(f"{'PASS' if ok else 'FAIL'}  {case['prompt'][:55]:<55} expected={case['expect']} got={got}")

    modes = {r["mode"]["mode"] for r in rows}
    fallbacks = sum(1 for r in rows if r["mode"]["mode"] == "scripted" and llm.LLM_PROVIDER != "mock")
    mode = {"mode": modes.pop() if len(modes) == 1 else "mixed", "provider": llm.LLM_PROVIDER}
    summary = {
        "mode": mode["mode"],
        "provider": mode["provider"],
        "model": {"groq": llm.GROQ_MODEL, "openai": llm.OPENAI_MODEL, "ollama": llm.OLLAMA_MODEL}.get(mode["provider"], "scripted"),
        "fallback_cases": fallbacks,
        "valid": fallbacks == 0,
        "cases": len(cases),
        "passed": passed,
        "accuracy": round(passed / len(cases), 3),
        "median_latency_s": sorted(r["latency_s"] for r in rows)[len(rows) // 2],
    }
    suffix = "" if case_file == "cases.json" else "-" + Path(case_file).stem
    model_slug = summary["model"].split("/")[-1] if summary["mode"] != "scripted" else "scripted"
    out = HERE / f"results-{model_slug}{suffix}.json"
    out.write_text(json.dumps({"summary": summary, "cases": rows}, indent=2))
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--delay", type=float, default=0.0, help="seconds between cases (free tiers: ~10)")
    ap.add_argument("--retries", type=int, default=3)
    ap.add_argument("--cases", default="cases.json", help="cases.json (tuned on) or holdout.json (never tuned on)")
    a = ap.parse_args()
    asyncio.run(run(a.delay, a.retries, a.cases))
