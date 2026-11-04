import os

from langchain_core.language_models.chat_models import BaseChatModel
from langchain_openai import ChatOpenAI
from pydantic import BaseModel, Field


class LLMFinding(BaseModel):
    indicator: str
    severity: str = Field(pattern="^(info|low|medium|high|critical)$")
    confidence: str = Field(pattern="^(low|medium|high)$")


class LLMAnalysis(BaseModel):
    findings: list[LLMFinding]


def _options(model: str) -> dict:
    options = {
        "model": model,
        "api_key": os.environ["OPENAI_API_KEY"],
        "timeout": float(os.getenv("OPENAI_TIMEOUT", "30")),
        "max_retries": int(os.getenv("OPENAI_MAX_RETRIES", "2")),
    }
    if os.getenv("OPENAI_BASE_URL"):
        options["base_url"] = os.environ["OPENAI_BASE_URL"]
    return options


def chat_model() -> BaseChatModel | None:
    """Plain chat model used for tool calling. None when no API key is configured."""
    if not os.getenv("OPENAI_API_KEY"):
        return None
    return ChatOpenAI(**_options(os.getenv("OPENAI_MODEL", "gpt-6-luna")))


def message_analyzer():
    """Structured-output analyzer; also used for the final pass of every agent."""
    model = chat_model()
    if model is None:
        return None
    return model.with_structured_output(LLMAnalysis, include_raw=True)


def url_analyzer():
    return message_analyzer()
