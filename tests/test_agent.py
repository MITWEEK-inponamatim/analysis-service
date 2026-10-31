import asyncio

import pytest

from app import agent
from app.llm import LLMAnalysis, LLMFinding
from app.tools import ToolContext


class StubMessage:
    def __init__(self, tool_calls=None):
        self.tool_calls = tool_calls or []
        self.content = ""
        self.usage_metadata = {"input_tokens": 5, "output_tokens": 2}


class StubBound:
    def __init__(self, rounds):
        self.rounds = rounds
        self.calls = 0

    async def ainvoke(self, _messages):
        self.calls += 1
        responses = self.rounds.pop(0) if self.rounds else []
        return StubMessage(responses)


class StubModel:
    def __init__(self, rounds):
        self.bound = StubBound(rounds)
        self.bound_tools = None

    def bind_tools(self, tools):
        self.bound_tools = tools
        return self.bound


class StubAnalyzer:
    def __init__(self, parsed="default"):
        self.parsed = parsed if parsed != "default" else LLMAnalysis(findings=[LLMFinding(indicator="evidence based", severity="medium", confidence="medium")])
        self.calls = 0

    async def ainvoke(self, _messages):
        self.calls += 1
        if self.parsed is None:
            return {"parsed": None, "raw": None}
        return {"parsed": self.parsed, "raw": StubMessage()}


def _context():
    return ToolContext(scan_id="scan-1", user_id="user-1", kind="message", message="kirim OTP")


def _patch(monkeypatch, model, analyzer):
    monkeypatch.setattr(agent, "chat_model", lambda: model)
    monkeypatch.setattr(agent, "message_analyzer", lambda: analyzer)


def test_agent_returns_structured_findings(monkeypatch):
    model = StubModel([[]])
    analyzer = StubAnalyzer()
    _patch(monkeypatch, model, analyzer)

    result = asyncio.run(agent.run_agent(_context(), system_prompt="analyze", payload="kirim OTP"))
    assert result is not None
    assert [item.indicator for item in result.findings] == ["evidence based"]
    assert result.usage["status"] == "completed"
    assert result.tool_calls == 0
    assert analyzer.calls == 1


def test_agent_executes_whitelisted_tool_calls(monkeypatch):
    rounds = [
        [{"name": "analyze_message", "args": {"text": "kirim OTP"}, "id": "call_1"}],
        [],
    ]
    model = StubModel(rounds)
    _patch(monkeypatch, model, StubAnalyzer())

    result = asyncio.run(agent.run_agent(_context(), system_prompt="analyze", payload="kirim OTP"))
    assert result.tool_calls == 1
    assert result.rounds == 2
    assert len(model.bound_tools) == 9


def test_agent_stops_at_the_iteration_limit(monkeypatch):
    endless = [[{"name": "analyze_message", "args": {"text": "x"}, "id": "c1"}], [{"name": "analyze_message", "args": {"text": "y"}, "id": "c2"}], [{"name": "analyze_message", "args": {"text": "z"}, "id": "c3"}]]
    model = StubModel(list(endless))
    _patch(monkeypatch, model, StubAnalyzer())

    result = asyncio.run(agent.run_agent(_context(), system_prompt="analyze", payload="x"))
    assert result.rounds == 2
    assert model.bound.calls == 2


def test_agent_caps_total_tool_calls(monkeypatch):
    many = [{"name": "analyze_message", "args": {"text": f"m{index}"}, "id": f"c{index}"} for index in range(10)]
    model = StubModel([many, many])
    monkeypatch.setenv("AGENT_MAX_TOOL_CALLS", "6")
    _patch(monkeypatch, model, StubAnalyzer())

    result = asyncio.run(agent.run_agent(_context(), system_prompt="analyze", payload="x"))
    assert result.tool_calls == 6


def test_unknown_tool_name_does_not_crash(monkeypatch):
    rounds = [[{"name": "run_shell", "args": {"cmd": "id"}, "id": "call_1"}], []]
    model = StubModel(rounds)
    _patch(monkeypatch, model, StubAnalyzer())

    result = asyncio.run(agent.run_agent(_context(), system_prompt="analyze", payload="x"))
    assert result.tool_calls == 1
    assert result.usage["status"] == "completed"


def test_invalid_structured_output_is_reported_as_unavailable(monkeypatch):
    _patch(monkeypatch, StubModel([[]]), StubAnalyzer(parsed=None))
    result = asyncio.run(agent.run_agent(_context(), system_prompt="analyze", payload="x"))
    assert result.unavailable == ["llm_analysis"]
    assert result.usage["status"] == "invalid_output"


def test_agent_without_model_returns_none(monkeypatch):
    monkeypatch.setattr(agent, "chat_model", lambda: None)
    assert asyncio.run(agent.run_agent(_context(), system_prompt="analyze", payload="x")) is None


@pytest.mark.parametrize("rounds", ["0"])
def test_zero_rounds_skips_tool_phase(monkeypatch, rounds):
    monkeypatch.setenv("AGENT_TOOL_ROUNDS", rounds)
    model = StubModel([[]])
    _patch(monkeypatch, model, StubAnalyzer())
    result = asyncio.run(agent.run_agent(_context(), system_prompt="analyze", payload="x"))
    assert model.bound.calls == 0
    assert result.usage["status"] == "completed"
