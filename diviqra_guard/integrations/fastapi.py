# MIT License — Copyright (c) 2026 Diviqra Technologies
"""
Diviqra Guard — FastAPI middleware integration.

Usage:
    from fastapi import FastAPI
    from diviqra_guard.integrations.fastapi import GuardMiddleware

    app = FastAPI()
    app.add_middleware(GuardMiddleware, api_key="dg_dev_...")
"""
from __future__ import annotations
import json
from typing import Callable, List, Optional, Set

from diviqra_guard.client import Guard

try:
    from starlette.middleware.base import BaseHTTPMiddleware
    from starlette.requests import Request
    from starlette.responses import JSONResponse, Response
    from starlette.types import ASGIApp
except ImportError:
    raise ImportError(
        "FastAPI/Starlette is required.\n"
        "Install with: pip install fastapi"
    )


class GuardMiddleware(BaseHTTPMiddleware):
    """
    FastAPI middleware that scans JSON request bodies for LLM threats.

    Args:
        api_key:      Diviqra Guard API key
        scan_paths:   Only scan these paths (default: all)
        skip_paths:   Skip these paths (default: /health, /docs, /openapi.json)
        text_fields:  JSON fields to scan (default: message, text, prompt, query, input)
        agent_type:   Agent type for context-aware rules

    Example:
        app.add_middleware(
            GuardMiddleware,
            api_key="dg_dev_...",
            scan_paths=["/chat", "/agent"],
        )
    """

    SKIP_PATHS: Set[str] = {
        "/health", "/healthz", "/ready",
        "/docs", "/redoc", "/openapi.json",
        "/metrics", "/ping",
    }

    TEXT_FIELDS: Set[str] = {
        "message", "text", "prompt", "query",
        "input", "content", "user_message",
        "question", "instruction",
    }

    def __init__(
        self,
        app: ASGIApp,
        api_key: str,
        base_url: str = "https://api.guard.diviqra.com",
        scan_paths: Optional[List[str]] = None,
        skip_paths: Optional[List[str]] = None,
        text_fields: Optional[List[str]] = None,
        agent_type: str = "default",
    ):
        super().__init__(app)
        self._guard = Guard(api_key=api_key, base_url=base_url)
        self._scan_paths = set(scan_paths) if scan_paths else None
        self._skip_paths = set(skip_paths) if skip_paths else self.SKIP_PATHS
        self._text_fields = set(text_fields) if text_fields else self.TEXT_FIELDS
        self._agent_type = agent_type

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        path = request.url.path

        if path in self._skip_paths:
            return await call_next(request)

        if self._scan_paths and path not in self._scan_paths:
            return await call_next(request)

        if request.method not in ("POST", "PUT", "PATCH"):
            return await call_next(request)

        content_type = request.headers.get("content-type", "")
        if "application/json" not in content_type:
            return await call_next(request)

        try:
            body = await request.body()
            data = json.loads(body)
        except Exception:
            return await call_next(request)

        for text in self._extract_texts(data):
            try:
                result = self._guard.scan(
                    text=text,
                    direction="ingress",
                    agent_type=self._agent_type,
                )
                if result.blocked:
                    return JSONResponse(
                        status_code=400,
                        content={
                            "error": "blocked",
                            "message": "Request blocked by Diviqra Guard",
                            "reason": result.reason,
                        },
                    )
            except Exception:
                pass  # Fail open

        async def receive():
            return {"type": "http.request", "body": body}

        request._receive = receive
        return await call_next(request)

    def _extract_texts(self, data: dict) -> List[str]:
        texts = []
        if not isinstance(data, dict):
            return texts
        for key, value in data.items():
            if key.lower() in self._text_fields:
                if isinstance(value, str) and value.strip():
                    texts.append(value)
                elif isinstance(value, list):
                    for item in value:
                        if isinstance(item, dict):
                            content = item.get("content", "")
                            if isinstance(content, str) and content.strip():
                                texts.append(content)
            elif isinstance(value, dict):
                texts.extend(self._extract_texts(value))
        return texts
