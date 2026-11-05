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

def token_usage(message) -> dict[str, int]:
    """Normalize usage metadata across supported LangChain/OpenAI response shapes."""
    if message is None:
        return {"prompt_tokens": 0, "completion_tokens": 0}
    metadata = getattr(message, "usage_metadata", None) or {}
    if metadata:
        return {
            "prompt_tokens": int(metadata.get("input_tokens", metadata.get("prompt_tokens", 0)) or 0),
            "completion_tokens": int(metadata.get("output_tokens", metadata.get("completion_tokens", 0)) or 0),
        }
    response = getattr(message, "response_metadata", None) or {}
    metadata = response.get("token_usage") or response.get("usage") or {}
    return {
        "prompt_tokens": int(metadata.get("prompt_tokens", metadata.get("input_tokens", 0)) or 0),
        "completion_tokens": int(metadata.get("completion_tokens", metadata.get("output_tokens", 0)) or 0),
    }
