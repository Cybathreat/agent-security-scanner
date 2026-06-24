# singularity/agent/loop.py
"""
Agent control loop for the Singularity security scanner.

Implements a ReAct-style (Reason + Act) loop:
  1. Append user/tool messages to the conversation.
  2. Call the LLM.
  3. If the response contains tool calls, dispatch them, append results,
     continue.
  4. If the text contains "SCAN COMPLETE" or max_iterations is reached,
     stop and return collected findings.

The loop is fully async; run it with asyncio.run(loop.run(...)).
"""

from __future__ import annotations

import asyncio
import json
from typing import Any, Dict, List, Optional

from loguru import logger

from .findings import AgentFinding, GLOBAL_STORE
from .llm_client import LLMClient, LLMClientError
from .system_prompt import SYSTEM_PROMPT as FALLBACK_SYSTEM_PROMPT
from .tools import TOOL_DEFINITIONS, dispatch


SYSTEM_PROMPT_PATH = "singularity/agent/system_prompt.txt"


class AgentLoop:
    """
    Orchestrates the agent's think-act-observe cycle.

    Parameters
    ----------
    llm_client    : Configured LLMClient instance.
    max_iterations: Hard cap on LLM turns (default 50).  Prevents runaway
                    cost on stuck agents.

    Attributes
    ----------
    _messages : List[Dict[str, Any]]
        Growing conversation history in OpenAI format.  Each LLM turn
        appends the assistant message; each tool result appends a "tool"
        role message.
    """

    def __init__(
        self,
        llm_client: LLMClient,
        max_iterations: int = 50,
    ) -> None:
        self.llm = llm_client
        self.max_iterations = max_iterations
        self._messages: List[Dict[str, Any]] = []

    async def run(
        self,
        target: str,
        bearer_token: Optional[str] = None,
    ) -> List[AgentFinding]:
        """
        Execute the full agent scan against `target`.

        Parameters
        ----------
        target       : Target URL (LLM gateway endpoint or base API URL).
        bearer_token : Optional auth token forwarded to every tool call
                       that accepts one.

        Returns
        -------
        List[AgentFinding]
            All findings recorded via save_finding() during this run.
            The list is a snapshot of GLOBAL_STORE at the time the loop
            terminates.
        """
        # Step 1: Clear the global findings store for this run
        GLOBAL_STORE.clear()

        # Step 2: Load system prompt from file, fall back to inline constant
        system_prompt = FALLBACK_SYSTEM_PROMPT
        try:
            with open(SYSTEM_PROMPT_PATH, "r", encoding="utf-8") as fh:
                system_prompt = fh.read()
            logger.debug("Loaded system prompt from {}", SYSTEM_PROMPT_PATH)
        except OSError as exc:
            logger.warning(
                "Could not read system prompt from {}: {}. Using fallback.",
                SYSTEM_PROMPT_PATH,
                exc,
            )

        # Step 3: Initialise conversation history
        self._messages = [
            {"role": "system", "content": system_prompt},
            {
                "role": "user",
                "content": (
                    f"Begin security assessment of: {target}\n"
                    f"Bearer token available: {'yes' if bearer_token else 'no'}\n"
                    f"Start with gateway discovery using http_request, then "
                    f"proceed systematically through all test categories."
                ),
            },
        ]

        # Step 4: Main agent loop
        scan_complete = False
        for i in range(self.max_iterations):
            logger.info("Agent iteration {}/{}", i + 1, self.max_iterations)

            try:
                # 4b. Call the LLM
                response = self.llm.complete(
                    self._messages,
                    tools=TOOL_DEFINITIONS,
                )

                # 4c. Extract assistant text
                text = self.llm.extract_text(response)
                logger.debug(
                    "LLM text (first 200 chars): {}",
                    (text or "")[:200],
                )

                # 4d. Append assistant message (only include tool_calls key when present)
                raw_tool_calls = None
                try:
                    raw_tool_calls = response.choices[0].message.tool_calls  # type: ignore[attr-defined]
                except (AttributeError, IndexError, TypeError):
                    raw_tool_calls = None

                assistant_msg: Dict[str, Any] = {
                    "role": "assistant",
                    "content": text or None,
                }
                if raw_tool_calls:
                    assistant_msg["tool_calls"] = raw_tool_calls
                self._messages.append(assistant_msg)

                # 4e. Check termination signal
                if "SCAN COMPLETE" in (text or ""):
                    logger.info(
                        "Agent signalled SCAN COMPLETE at iteration {}", i + 1
                    )
                    scan_complete = True
                    break

                # 4f. Extract structured tool calls
                calls = self.llm.extract_tool_calls(response)

                # 4g. No tool calls and no SCAN COMPLETE — nudge the agent
                if not calls:
                    logger.warning(
                        "No tool calls and no SCAN COMPLETE at iteration {}",
                        i + 1,
                    )
                    self._messages.append(
                        {
                            "role": "user",
                            "content": (
                                "Continue the assessment. Use the available tools "
                                "to probe the target further, or signal SCAN COMPLETE "
                                "if all tests are done."
                            ),
                        }
                    )
                    continue

                # 4h. Dispatch all tool calls from this turn concurrently
                logger.debug(
                    "Dispatching {} tool(s): {}",
                    len(calls),
                    [tc["name"] for tc in calls],
                )

                async def _safe_dispatch(tc: Dict[str, Any]) -> Dict[str, Any]:
                    """Wrap dispatch so a single failing tool doesn't abort the turn."""
                    try:
                        return await dispatch(tc["name"], tc["arguments"])
                    except Exception as dispatch_exc:  # noqa: BLE001
                        logger.error(
                            "Tool {} raised outside its own guard: {}",
                            tc["name"],
                            dispatch_exc,
                        )
                        return {"error": str(dispatch_exc)}

                results = await asyncio.gather(
                    *[_safe_dispatch(tc) for tc in calls]
                )

                # Append tool result messages in call order (preserves tool_call_id alignment)
                for tc, result_dict in zip(calls, results):
                    result_str = json.dumps(result_dict, default=str)
                    self._messages.append(
                        {
                            "role": "tool",
                            "tool_call_id": tc["id"],
                            "name": tc["name"],
                            "content": result_str,
                        }
                    )
                    logger.debug(
                        "tool {} returned {} chars", tc["name"], len(result_str)
                    )

            except LLMClientError as exc:
                logger.error("LLM error: {}", exc)
                break

        else:
            # Loop exhausted without a break — max_iterations reached
            logger.warning(
                "Agent hit max_iterations={} without SCAN COMPLETE",
                self.max_iterations,
            )

        findings = list(GLOBAL_STORE.findings)
        logger.info("Scan finished. {} finding(s) recorded.", len(findings))
        return findings
