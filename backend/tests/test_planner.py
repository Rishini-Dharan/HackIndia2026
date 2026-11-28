import asyncio
import json

import pytest

import llm_orchestrator as llm


def test_valid_widget_call_parses():
    call = llm.parse_widget_call(json.dumps({"component": "ThreatTopology", "title": "Blast radius"}))
    assert call.component == "ThreatTopology"
    assert call.props == {}


@pytest.mark.parametrize("raw", [
    "not json",
    json.dumps({"component": "MadeUpWidget", "title": "x"}),
    json.dumps({"component": "LiveTrafficChart"}),
    json.dumps({"component": "LiveTrafficChart", "title": ""}),
])
def test_invalid_widget_calls_are_rejected(raw):
    with pytest.raises(ValueError):
        llm.parse_widget_call(raw)


def test_without_keys_planner_reports_scripted_mode():
    msgs = asyncio.run(llm.plan_investigation("show me live traffic"))
    assert msgs
    assert llm.LAST_MODE["mode"] == "scripted"


def test_provider_failure_falls_back_visibly(monkeypatch):
    monkeypatch.setattr(llm, "GROQ_FALLBACK_MODEL", "")
    async def boom(_, model=None):
        raise RuntimeError("down")

    monkeypatch.setattr(llm, "LLM_PROVIDER", "groq")
    monkeypatch.setattr(llm, "GROQ_API_KEY", "test-key")
    monkeypatch.setattr(llm, "_groq_route", boom)
    msgs = asyncio.run(llm.plan_investigation("hello"))
    assert msgs
    assert llm.LAST_MODE["mode"] == "scripted"
    assert "groq request failed" in llm.LAST_MODE["reason"]


def test_fallback_reason_names_status_and_error_code(monkeypatch):
    monkeypatch.setattr(llm, "GROQ_FALLBACK_MODEL", "")
    import httpx

    async def not_found(_, model=None):
        req = httpx.Request("POST", "https://api.groq.com/openai/v1/chat/completions")
        resp = httpx.Response(404, request=req, json={"error": {"code": "model_not_found", "message": "secret-free"}})
        raise httpx.HTTPStatusError("404", request=req, response=resp)

    monkeypatch.setattr(llm, "LLM_PROVIDER", "groq")
    monkeypatch.setattr(llm, "GROQ_API_KEY", "test-key")
    monkeypatch.setattr(llm, "_groq_route", not_found)
    asyncio.run(llm.plan_investigation("hello"))
    assert "HTTP 404 model_not_found" in llm.LAST_MODE["reason"]
    assert "test-key" not in llm.LAST_MODE["reason"]


def test_batch_call_mounts_every_widget_in_order():
    calls = llm.parse_widget_batch(json.dumps({"widgets": [
        {"component": "LiveTrafficChart", "title": "Traffic"},
        {"component": "ThreatTopology", "title": "Topology"},
    ]}))
    assert [c.component for c in calls] == ["LiveTrafficChart", "ThreatTopology"]


def test_legacy_single_widget_call_still_accepted():
    calls = llm.parse_widget_batch(json.dumps({"component": "MitigationAction", "title": "Contain"}))
    assert [c.component for c in calls] == ["MitigationAction"]


@pytest.mark.parametrize("payload", [
    {"widgets": []},
    {"widgets": [{"component": "LiveTrafficChart", "title": "t"}] * 5},
    {"widgets": [{"component": "LiveTrafficChart", "title": "ok"}, {"component": "Nope", "title": "bad"}]},
])
def test_invalid_batches_are_rejected_whole(payload):
    with pytest.raises(ValueError):
        llm.parse_widget_batch(json.dumps(payload))


def test_tool_schema_is_a_widget_list():
    params = llm.RENDER_WIDGET_TOOL["function"]["parameters"]
    assert llm.RENDER_WIDGET_TOOL["function"]["name"] == "render_security_widgets"
    assert params["properties"]["widgets"]["maxItems"] == 4


def test_global_llm_budget_falls_back_visibly(monkeypatch):
    monkeypatch.setattr(llm, "GROQ_FALLBACK_MODEL", "")
    calls = []

    async def fake_groq(text, model=None):
        calls.append(text)
        return [{"type": "chat", "role": "agent", "content": "llm"}]

    monkeypatch.setattr(llm, "LLM_PROVIDER", "groq")
    monkeypatch.setattr(llm, "GROQ_API_KEY", "test-key")
    monkeypatch.setattr(llm, "_groq_route", fake_groq)
    monkeypatch.setattr(llm, "GLOBAL_LLM_CALLS_PER_MINUTE", 3)
    llm._llm_call_times.clear()
    for _ in range(3):
        asyncio.run(llm.plan_investigation("hello"))
        assert llm.LAST_MODE["mode"] == "llm"
    asyncio.run(llm.plan_investigation("hello"))
    assert len(calls) == 3
    assert llm.LAST_MODE["mode"] == "scripted"
    assert "budget" in llm.LAST_MODE["reason"]
    llm._llm_call_times.clear()


def test_budget_window_slides():
    llm._llm_call_times.clear()
    for i in range(llm.GLOBAL_LLM_CALLS_PER_MINUTE):
        assert llm._llm_budget_available(now=1000.0 + i * 0.01)
    assert not llm._llm_budget_available(now=1001.0)
    assert llm._llm_budget_available(now=1061.0)  # oldest calls aged out
    llm._llm_call_times.clear()


@pytest.mark.parametrize("text,seconds", [
    ("7.66s", 7.66), ("2m59.56s", 179.56), ("1h2m3s", 3723.0), ("850ms", 0.85), ("12", 12.0), ("", None),
])
def test_parse_groq_durations(text, seconds):
    got = llm._parse_duration(text)
    assert got == pytest.approx(seconds) if seconds is not None else got is None


def test_token_budget_gates_calls_until_reset():
    llm._token_budget.update(remaining=None, reset_at=0.0)
    assert llm._tokens_available(now=100.0)  # unknown budget: allowed
    llm.record_rate_limit_headers({"x-ratelimit-remaining-tokens": "900", "x-ratelimit-reset-tokens": "7.5s"}, now=100.0)
    assert not llm._tokens_available(now=101.0)  # too few tokens left
    assert llm._tokens_available(now=108.0)  # window reset
    llm.record_rate_limit_headers({"x-ratelimit-remaining-tokens": "6000", "x-ratelimit-reset-tokens": "5s"}, now=200.0)
    assert llm._tokens_available(now=201.0)
    llm._token_budget.update(remaining=None, reset_at=0.0)


def test_429_blocks_until_retry_after():
    llm._token_budget.update(remaining=None, reset_at=0.0)
    llm.record_rate_limit_headers({"retry-after": "4"}, now=50.0)
    assert not llm._tokens_available(now=52.0)
    assert llm._tokens_available(now=54.5)
    llm._token_budget.update(remaining=None, reset_at=0.0)


def test_low_token_budget_falls_back_without_calling_provider(monkeypatch):
    calls = []

    async def fake_groq(text, model=None):
        calls.append(text)
        return [{"type": "chat", "role": "agent", "content": "llm"}]

    monkeypatch.setattr(llm, "LLM_PROVIDER", "groq")
    monkeypatch.setattr(llm, "GROQ_API_KEY", "test-key")
    monkeypatch.setattr(llm, "_groq_route", fake_groq)
    import time as _time
    monkeypatch.setattr(llm, "GROQ_FALLBACK_MODEL", "")
    llm._token_budget.update(remaining=500, reset_at=_time.time() + 30)
    asyncio.run(llm.plan_investigation("hello"))
    assert calls == []
    assert "budget" in llm.LAST_MODE["reason"]
    llm._token_budget.update(remaining=None, reset_at=0.0)


def test_spent_primary_model_falls_back_to_second_model(monkeypatch):
    import time as _time
    used = []

    async def fake_groq(text, model=None):
        used.append(model)
        return [{"type": "chat", "role": "agent", "content": "ok"}]

    monkeypatch.setattr(llm, "LLM_PROVIDER", "groq")
    monkeypatch.setattr(llm, "GROQ_API_KEY", "test-key")
    monkeypatch.setattr(llm, "_groq_route", fake_groq)
    monkeypatch.setattr(llm, "GROQ_FALLBACK_MODEL", "openai/gpt-oss-20b")
    llm._llm_call_times.clear()
    llm._budget_for(llm.GROQ_MODEL).update(remaining=100, reset_at=_time.time() + 30)
    llm._budget_for("openai/gpt-oss-20b").update(remaining=None, reset_at=0.0)
    asyncio.run(llm.plan_investigation("hello"))
    assert used == ["openai/gpt-oss-20b"]
    assert llm.LAST_MODE["mode"] == "llm" and llm.LAST_MODE["model"] == "openai/gpt-oss-20b"
    llm._token_budgets.clear()
    llm._token_budget = llm._budget_for(llm.GROQ_MODEL)
