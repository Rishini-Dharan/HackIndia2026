"""
Planner evaluation: does the agent mount the right widgets for a request?

Each case lists the widget components a good answer mounts (empty = just talk).
A case passes when the set of mounted components equals the expected set.

    cd backend
    python eval/run_eval.py                       # uses whatever provider is configured
    GROQ_API_KEY=... python eval/run_eval.py      # real LLM

Writes eval/results-<mode>-<provider>.json.
"""

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


async def run():
    cases = json.loads((HERE / "cases.json").read_text())
    rows, passed = [], 0
    for case in cases:
        t0 = time.perf_counter()
        msgs = await llm.plan_investigation(case["prompt"])
        latency = time.perf_counter() - t0
        got = sorted({m["component"] for m in msgs if m.get("type") == "widget"})
        ok = got == sorted(case["expect"])
        passed += ok
        rows.append({**case, "got": got, "pass": ok, "latency_s": round(latency, 2), "mode": dict(llm.LAST_MODE)})
        print(f"{'PASS' if ok else 'FAIL'}  {case['prompt'][:55]:<55} expected={case['expect']} got={got}")

    mode = llm.LAST_MODE
    summary = {
        "mode": mode["mode"],
        "provider": mode["provider"],
        "model": {"groq": llm.GROQ_MODEL, "openai": llm.OPENAI_MODEL, "ollama": llm.OLLAMA_MODEL}.get(mode["provider"], "scripted"),
        "cases": len(cases),
        "passed": passed,
        "accuracy": round(passed / len(cases), 3),
        "median_latency_s": sorted(r["latency_s"] for r in rows)[len(rows) // 2],
    }
    out = HERE / f"results-{mode['mode']}-{mode['provider']}.json"
    out.write_text(json.dumps({"summary": summary, "cases": rows}, indent=2))
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    asyncio.run(run())
