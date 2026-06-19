# MIT License — Copyright (c) 2026 Diviqra
import os

import httpx

from .exceptions import GuardBlockedError, GuardConnectionError, GuardTimeoutError
from .models import ScanResult


class Guard:
    def __init__(
        self,
        api_key: str | None = None,
        base_url: str = "https://api.guard.diviqra.com",
        timeout: float = 5.0,
    ):
        self._api_key = api_key or os.environ.get("GUARD_API_KEY", "")
        self._base_url = base_url.rstrip("/")
        self._timeout = timeout

    def scan(
        self,
        text: str,
        direction: str = "ingress",
        agent_type: str = "default",
        company_id: str = "",
        profile: str = "balanced",
        language: str = "en",
    ) -> ScanResult:
        payload = {
            "text": text,
            "direction": direction,
            "agent_type": agent_type,
            "company_id": company_id,
            "profile": profile,
            "language": language,
        }
        try:
            with httpx.Client(timeout=self._timeout) as client:
                resp = client.post(
                    f"{self._base_url}/v1/scan",
                    json=payload,
                    headers={"Authorization": f"Bearer {self._api_key}"},
                )
                resp.raise_for_status()
                return _parse(resp.json())
        except httpx.TimeoutException as exc:
            raise GuardTimeoutError("Guard service timed out") from exc
        except httpx.ConnectError as exc:
            raise GuardConnectionError("Cannot connect to Guard service") from exc

    def scan_or_raise(self, text: str, **kwargs) -> ScanResult:
        """Scan and raise GuardBlockedError if the result is blocked."""
        result = self.scan(text, **kwargs)
        if result.blocked:
            raise GuardBlockedError(result.reason)
        return result


def _parse(data: dict) -> ScanResult:
    return ScanResult(
        action=data["action"],
        score=data["score"],
        threats=data.get("threats", []),
        reason=data.get("reason", ""),
        latency_ms=data.get("latency_ms", 0),
        scan_id=data.get("scan_id", ""),
    )
