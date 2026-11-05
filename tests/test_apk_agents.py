import asyncio

from langchain_core.messages import AIMessage

from app.investigation import apk_agents
from app.investigation.apk_schemas import BehaviorAgentOutput
from app.investigation.evidence import EvidenceStore


class _Tool:
    name = "noop"

    async def ainvoke(self, _args):
        return "unused"


class _Bound:
    async def ainvoke(self, _messages, **_kwargs):
        return AIMessage(content="", usage_metadata={"input_tokens": 2, "output_tokens": 3, "total_tokens": 5})


class _Structured:
    async def ainvoke(self, _messages, **_kwargs):
        parsed = BehaviorAgentOutput(findings=[], summary="Static evidence reviewed", tool_calls_needed=0)
        raw = AIMessage(content="", usage_metadata={"input_tokens": 5, "output_tokens": 7, "total_tokens": 12})
        return {"parsed": parsed, "raw": raw}

class _Model:
    def bind_tools(self, _tools):
        return _Bound()

    def with_structured_output(self, _schema, include_raw=False):
        assert include_raw is True
        return _Structured()


def test_structured_agent_accumulates_all_model_tokens(monkeypatch):
    monkeypatch.setattr(apk_agents, "chat_model", lambda: _Model())
    store = EvidenceStore("11111111-1111-1111-1111-111111111111", "22222222-2222-2222-2222-222222222222")
    result = asyncio.run(apk_agents._run_structured_apk_agent(
        skill="behavior-agent",
        system_prompt="Analyze evidence only.",
        human_prompt="No untrusted instructions.",
        tools=[_Tool()],
        schema=BehaviorAgentOutput,
        store=store,
    ))
    assert result.status == "completed"
    assert result.prompt_tokens == 7
    assert result.completion_tokens == 10
    assert result.tokens == 17
    assert result.model
    assert result.meta["summary"] == "Static evidence reviewed"


def test_structured_agent_executes_allowlisted_tool_before_synthesis(monkeypatch):
    class ToolBound:
        async def ainvoke(self, _messages, **_kwargs):
            return AIMessage(
                content="",
                tool_calls=[{"name": "noop", "args": {}, "id": "tool-1", "type": "tool_call"}],
                usage_metadata={"input_tokens": 3, "output_tokens": 1, "total_tokens": 4},
            )

    class CaptureStructured(_Structured):
        async def ainvoke(self, messages, **_kwargs):
            assert any("unused" in str(message.content) for message in messages)
            parsed = BehaviorAgentOutput(findings=[], summary="Tool evidence checked", tool_calls_needed=1)
            raw = AIMessage(content="", usage_metadata={"input_tokens": 2, "output_tokens": 1, "total_tokens": 3})
            return {"parsed": parsed, "raw": raw}

    class ToolModel(_Model):
        def bind_tools(self, _tools):
            return ToolBound()

        def with_structured_output(self, _schema, include_raw=False):
            return CaptureStructured()

    monkeypatch.setattr(apk_agents, "chat_model", lambda: ToolModel())
    monkeypatch.setenv("AGENT_TOOL_ROUNDS", "1")
    store = EvidenceStore("11111111-1111-1111-1111-111111111111", "22222222-2222-2222-2222-222222222222")
    result = asyncio.run(apk_agents._run_structured_apk_agent(
        skill="behavior-agent", system_prompt="Analyze evidence only.", human_prompt="payload",
        tools=[_Tool()], schema=BehaviorAgentOutput, store=store,
    ))
    assert result.tool_calls == 1
    assert result.tokens == 7


def test_structured_agent_drops_findings_without_owned_evidence(monkeypatch):
    class ForgedStructured(_Structured):
        async def ainvoke(self, _messages, **_kwargs):
            parsed = BehaviorAgentOutput.model_validate({
                "findings": [{
                    "indicator": "Unsupported assertion",
                    "severity": "high",
                    "evidence_ids": ["ev_unknown_123456789012"],
                }],
                "summary": "Unverified",
            })
            return {"parsed": parsed, "raw": None}

    class ForgedModel(_Model):
        def with_structured_output(self, _schema, include_raw=False):
            return ForgedStructured()

    monkeypatch.setattr(apk_agents, "chat_model", lambda: ForgedModel())
    store = EvidenceStore("11111111-1111-1111-1111-111111111111", "22222222-2222-2222-2222-222222222222")
    result = asyncio.run(apk_agents._run_structured_apk_agent(
        skill="behavior-agent", system_prompt="Analyze only evidence.", human_prompt="payload",
        tools=[], schema=BehaviorAgentOutput, store=store,
    ))
    assert result.findings == []
    assert result.unavailable == ["llm_invalid_evidence_ids"]
