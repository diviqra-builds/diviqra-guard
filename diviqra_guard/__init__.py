# MIT License — Copyright (c) 2026 Diviqra
"""
Diviqra Guard — LLM firewall for AI agents.
Built by intelligence. Secured by Guard.
"""
import os

from .async_client import AsyncGuard
from .client import Guard
from .exceptions import GuardBlockedError, GuardConnectionError, GuardTimeoutError
from .models import ScanResult

__version__ = "1.0.1"
__all__ = [
    "Guard",
    "AsyncGuard",
    "ScanResult",
    "GuardBlockedError",
    "GuardTimeoutError",
    "GuardConnectionError",
    "scan",
]


def scan(text: str, **kwargs) -> ScanResult:
    """Convenience function — reads GUARD_API_KEY from environment."""
    return Guard(api_key=os.environ.get("GUARD_API_KEY", "")).scan(text, **kwargs)
