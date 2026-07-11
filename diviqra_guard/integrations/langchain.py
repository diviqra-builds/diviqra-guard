# MIT License — Copyright (c) 2026 Diviqra Technologies
"""
Diviqra Guard — LangChain integration.

Usage:
    from diviqra_guard.integrations.langchain import GuardCallback
    from langchain_openai import ChatOpenAI

    guard = GuardCallback(api_key="dg_dev_...")
    llm = ChatOpenAI(callbacks=[guard])
    response = llm.invoke("Hello")
"""
from __future__ import annotations
from typing import Any, Dict, List, Optional
from uuid import UUID

from diviqra_guard.client import Guard
from diviqra_guard.exceptions import GuardBlockedError

try:
    from langchain_core.callbacks.base import BaseCallbackHandler
    from langchain_core.messages import BaseMessage
    from langchain_core.outputs import LLMResult
except ImportError:
    raise ImportError(
        "LangChain is required.\n"
        "Install with: pip install langchain-core"
    )


class GuardCallback(BaseCallbackHandler):
    """
    LangChain callback that scans all LLM inputs and outputs.

    Args:
        api_key:        Diviqra Guard API key
        base_url:       Guard API URL (default: https://api.guard.diviqra.com)
        agent_type:     Agent type for context-aware rules
        scan_outputs:   Whether to scan LLM outputs (default: True)
        raise_on_block: Raise GuardBlockedError on block (default: True)

    Example:
        guard = GuardCallback(api_key="dg_dev_...", agent_type="customer_service")
        llm = ChatOpenAI(callbacks=[guard])
    """

    def __init__(
        self,
        api_key: str,
        base_url: str = "https://api.guard.diviqra.com",
        agent_type: str = "default",
        scan_outputs: bool = True,
        raise_on_block: bool = True,
    ):
        self._guard = Guard(api_key=api_key, base_url=base_url)
        self._agent_type = agent_type
        self._scan_outputs = scan_outputs
        self._raise_on_block = raise_on_block

    def on_llm_start(
        self,
        serialized: Dict[str, Any],
        prompts: List[str],
        *,
        run_id: UUID,
        **kwargs: Any,
    ) -> None:
        for prompt in prompts:
            if prompt and prompt.strip():
                self._scan(prompt, "ingress")

    def on_chat_model_start(
        self,
        serialized: Dict[str, Any],
        messages: List[List[BaseMessage]],
        *,
        run_id: UUID,
        **kwargs: Any,
    ) -> None:
        for message_list in messages:
            for message in message_list:
                content = message.content
                if isinstance(content, str) and content.strip():
                    self._scan(content, "ingress")

    def on_llm_end(
        self,
        response: LLMResult,
        *,
        run_id: UUID,
        **kwargs: Any,
    ) -> None:
        if not self._scan_outputs:
            return
        for generations in response.generations:
            for generation in generations:
                text = getattr(generation, "text", None)
                if not text:
                    msg = getattr(generation, "message", None)
                    text = getattr(msg, "content", None) if msg else None
                if text and isinstance(text, str) and text.strip():
                    self._scan(text, "egress")

    def _scan(self, text: str, direction: str) -> None:
        try:
            result = self._guard.scan(
                text=text,
                direction=direction,
                agent_type=self._agent_type,
            )
        except Exception:
            return  # Fail open — Guard never breaks your app

        if result.blocked and self._raise_on_block:
            raise GuardBlockedError(
                f"Guard blocked {direction}: {result.reason}"
            )


# Alias for clarity
AsyncGuardCallback = GuardCallback
