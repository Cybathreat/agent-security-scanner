"""
LLM client for the Singularity agent, backed by litellm.

Abstracts away provider differences so the agent loop works identically
whether targeting Anthropic, OpenAI, Ollama, OpenRouter, or any
OpenAI-compatible endpoint (KIMI / Moonshot, local vLLM, etc.).
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

import litellm
from litellm import ModelResponse
from loguru import logger


class LLMClientError(Exception):
    """Raised when the LLM call fails after all retries."""


class LLMClient:
    """
    Thin litellm wrapper.  One instance per agent run.

    Parameters
    ----------
    model : str
        litellm model string.  Examples:
          - "anthropic/claude-sonnet-4-6"     (Anthropic via SDK)
          - "openai/gpt-4o"                   (OpenAI)
          - "ollama/llama3"                   (local Ollama)
          - "openrouter/meta-llama/llama-3-8b-instruct"
          - "moonshot/moonshot-v1-8k"         (KIMI / Moonshot AI)
          - "openai/my-model"  + base_url     (any OpenAI-compat endpoint)
    api_key : str
        API key for the provider.  Passed to litellm as the api_key kwarg
        so it never touches environment variables already set by the user.
    base_url : Optional[str]
        Override the base URL.  Required for Ollama ("http://localhost:11434")
        and for any custom OpenAI-compatible gateway.
        Ignored when None.

    Usage
    -----
        client = LLMClient(
            model="anthropic/claude-sonnet-4-6",
            api_key=os.environ["ANTHROPIC_API_KEY"],
        )
        resp = client.complete(messages, tools=TOOL_DEFINITIONS)
        tool_calls = client.extract_tool_calls(resp)
        text = client.extract_text(resp)

    Design notes
    ------------
    - litellm normalises provider differences; we never branch on provider name.
    - We do NOT set litellm.api_key / litellm.openai_key globally to avoid
      polluting other threads.
    - Retries (up to 3) with exponential backoff are delegated to litellm's
      built-in retry mechanism via num_retries=3.
    - All exceptions are caught and re-raised as LLMClientError so callers
      have a single exception type to handle.
    """

    def __init__(
        self,
        model: str,
        api_key: str,
        base_url: Optional[str] = None,
        ssl_verify: bool = True,
        extra_headers: Optional[Dict[str, str]] = None,
    ) -> None:
        self.model = model
        self._api_key = api_key
        self._base_url = base_url
        self._extra_headers = extra_headers or {}
        litellm.ssl_verify = ssl_verify

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def complete(
        self,
        messages: List[Dict[str, Any]],
        tools: Optional[List[Dict[str, Any]]] = None,
    ) -> ModelResponse:
        """
        Call the LLM and return the raw litellm ModelResponse.

        Parameters
        ----------
        messages : list[dict]
            OpenAI-format message list, e.g.:
              [{"role": "system", "content": "..."},
               {"role": "user",   "content": "..."}]
        tools : list[dict] | None
            OpenAI-format tool definitions.  When provided the model may
            respond with tool_calls instead of (or in addition to) content.
            Pass None for plain text completion.

        Returns
        -------
        ModelResponse
            litellm's unified response object.

        Raises
        ------
        LLMClientError
            On any provider error, connection error, or timeout after retries.
        """
        kwargs: Dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "api_key": self._api_key,
            "num_retries": 3,
        }

        if self._base_url is not None:
            kwargs["base_url"] = self._base_url

        if self._extra_headers:
            kwargs["extra_headers"] = self._extra_headers

        if tools is not None:
            kwargs["tools"] = tools
            kwargs["tool_choice"] = "auto"

        try:
            response: ModelResponse = litellm.completion(**kwargs)
            logger.debug(
                "LLM call ok | model={} prompt_tokens={} completion_tokens={}",
                self.model,
                response.usage.prompt_tokens,
                response.usage.completion_tokens,
            )
            return response

        except litellm.exceptions.RateLimitError as exc:
            logger.error(
                "LLM rate limit error | model={} error={}",
                self.model,
                str(exc),
            )
            raise LLMClientError(f"Rate limit error for model '{self.model}': {exc}") from exc

        except litellm.exceptions.Timeout as exc:
            logger.error(
                "LLM timeout | model={} error={}",
                self.model,
                str(exc),
            )
            raise LLMClientError(f"Timeout calling model '{self.model}': {exc}") from exc

        except litellm.exceptions.APIError as exc:
            logger.error(
                "LLM API error | model={} status={} error={}",
                self.model,
                getattr(exc, "status_code", "unknown"),
                str(exc),
            )
            raise LLMClientError(f"API error for model '{self.model}': {exc}") from exc

        except Exception as exc:  # noqa: BLE001
            logger.error(
                "LLM unexpected error | model={} type={} error={}",
                self.model,
                type(exc).__name__,
                str(exc),
            )
            raise LLMClientError(
                f"Unexpected error calling model '{self.model}': {exc}"
            ) from exc

    def extract_tool_calls(
        self,
        response: ModelResponse,
    ) -> List[Dict[str, Any]]:
        """
        Extract tool calls from a ModelResponse.

        Returns a list of dicts, one per tool call:
          [{"id": str, "name": str, "arguments": dict}, ...]

        The "arguments" value is always a parsed dict (JSON-decoded from the
        string that litellm / the provider returns).

        Returns [] (not raises) on any AttributeError / IndexError so the
        agent loop can treat an empty list as "no tool call requested".
        """
        try:
            choice = response.choices[0]
            if choice.finish_reason not in ("tool_calls", "stop"):
                return []

            raw_calls = getattr(choice.message, "tool_calls", None) or []

            result: List[Dict[str, Any]] = []
            for tc in raw_calls:
                name: str = tc.function.name
                args_str: str = tc.function.arguments or "{}"
                try:
                    arguments: Dict[str, Any] = json.loads(args_str)
                except json.JSONDecodeError:
                    logger.warning(
                        "Failed to JSON-decode tool call arguments for '{}', "
                        "falling back to raw string. args={}",
                        name,
                        args_str,
                    )
                    arguments = {"raw": args_str}

                result.append(
                    {
                        "id": tc.id,
                        "name": name,
                        "arguments": arguments,
                    }
                )

            return result

        except (AttributeError, IndexError) as exc:
            logger.debug(
                "extract_tool_calls: no tool calls in response ({})", str(exc)
            )
            return []

    def extract_text(self, response: ModelResponse) -> str:
        """
        Extract the assistant's text content from a ModelResponse.

        Returns the string content of choices[0].message.content, or ""
        if the message has no text content (e.g. pure tool-call response).

        Never raises; returns "" on any AttributeError / IndexError / TypeError.
        """
        try:
            content = response.choices[0].message.content
            if content is None:
                return ""
            return str(content)
        except (AttributeError, IndexError, TypeError) as exc:
            logger.debug(
                "extract_text: could not extract text from response ({})", str(exc)
            )
            return ""
