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
    async def boom(_):
        raise RuntimeError("down")

    monkeypatch.setattr(llm, "LLM_PROVIDER", "groq")
    monkeypatch.setattr(llm, "GROQ_API_KEY", "test-key")
    monkeypatch.setattr(llm, "_groq_route", boom)
    msgs = asyncio.run(llm.plan_investigation("hello"))
    assert msgs
    assert llm.LAST_MODE["mode"] == "scripted"
    assert "groq request failed" in llm.LAST_MODE["reason"]
