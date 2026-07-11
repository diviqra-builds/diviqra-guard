# MIT License — Copyright (c) 2026 Diviqra Technologies
"""
Diviqra Guard — OpenAI SDK integration.

Usage:
    from diviqra_guard.integrations.openai import wrap_openai
    from openai import OpenAI

    client = wrap_openai(OpenAI(), api_key="dg_dev_...")
    response = client.chat.completions.create(
        model="gpt-4o",
        messages=[{"role": "user", "content": "Hello"}]
    )
"""
from __future__ import annotations
from typing import Any, Dict, List, Optional
from functools import wraps

from diviqra_guard.client import Guard
from diviqra_guard.exceptions import GuardBlockedError

try:
    from openai import OpenAI, AsyncOpenAI
except ImportError:
    raise ImportError(
        "OpenAI SDK is required.\n"
        "Install with: pip install openai"
    )


def wrap_openai(
    client: OpenAI,
    api_key: str,
    base_url: str = "https://api.guard.diviqra.com",
    agent_type: str = "default",
    scan_responses: bool = True,
    raise_on_block: bool = True,
) -> OpenAI:
    """
    Wrap an OpenAI client with Diviqra Guard scanning.

    Drop-in replacement — works exactly like the normal client.
    All messages scanned before reaching OpenAI.
    All responses scanned before returning to your code.

    Args:
        client:         OpenAI() instance
        api_key:        Diviqra Guard API key
        agent_type:     Agent type for context-aware rules
        scan_responses: Scan LLM responses (default: True)
        raise_on_block: Raise on block (default: True)

    Example:
        client = wrap_openai(OpenAI(), api_key="dg_dev_...")
        response = client.chat.completions.create(
            model="gpt-4o",
            messages=[{"role": "user", "content": "Hello"}]
        )
    """
    guard = Guard(api_key=api_key, base_url=base_url)
    original_create = client.chat.completions.create

    @wraps(original_create)
    def guarded_create(*args, **kwargs):
        messages: List[Dict] = kwargs.get("messages", [])

        # Scan all messages (ingress)
        for msg in messages:
            content = msg.get("content", "")
            if content and isinstance(content, str):
                _scan(guard, content, "ingress", agent_type, raise_on_block)

        # Call OpenAI
        response = original_create(*args, **kwargs)

        # Scan response (egress)
        if scan_responses:
            for choice in response.choices:
                content = choice.message.content
                if content and isinstance(content, str):
                    _scan(guard, content, "egress", agent_type, raise_on_block)

        return response

    client.chat.completions.create = guarded_create
    return client


def wrap_async_openai(
    client: AsyncOpenAI,
    api_key: str,
    base_url: str = "https://api.guard.diviqra.com",
    agent_type: str = "default",
    scan_responses: bool = True,
    raise_on_block: bool = True,
) -> AsyncOpenAI:
    """Async version of wrap_openai."""
    guard = Guard(api_key=api_key, base_url=base_url)
    original_create = client.chat.completions.create

    @wraps(original_create)
    async def guarded_create(*args, **kwargs):
        messages: List[Dict] = kwargs.get("messages", [])
        for msg in messages:
            content = msg.get("content", "")
            if content and isinstance(content, str):
                _scan(guard, content, "ingress", agent_type, raise_on_block)

        response = await original_create(*args, **kwargs)

        if scan_responses:
            for choice in response.choices:
                content = choice.message.content
                if content and isinstance(content, str):
                    _scan(guard, content, "egress", agent_type, raise_on_block)

        return response

    client.chat.completions.create = guarded_create
    return client


def _scan(
    guard: Guard,
    text: str,
    direction: str,
    agent_type: str,
    raise_on_block: bool,
) -> None:
    try:
        result = guard.scan(text=text, direction=direction, agent_type=agent_type)
    except Exception:
        return  # Fail open

    if result.blocked and raise_on_block:
        raise GuardBlockedError(f"Guard blocked {direction}: {result.reason}")
