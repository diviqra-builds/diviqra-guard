# MIT License — Copyright (c) 2026 Diviqra
"""
Celery Beat integration for scheduled red team runs.

Add to Diviqra backend's celery_app.py:

    from redteam.scheduler import setup_guard_redteam
    # then call setup_guard_redteam(celery_app) after app creation
"""
import httpx
import structlog

log = structlog.get_logger()


def setup_guard_redteam(celery_app, guard_url: str, guard_api_key: str) -> None:
    """Register periodic red team tasks on an existing Celery app."""
    from celery.schedules import crontab

    @celery_app.task(name="guard.redteam.nightly_broad")
    def run_guard_redteam_broad():
        _trigger_redteam(guard_url, guard_api_key, mode="broad")

    @celery_app.task(name="guard.redteam.weekly_deep")
    def run_guard_redteam_deep():
        _trigger_redteam(guard_url, guard_api_key, mode="deep")

    celery_app.conf.beat_schedule.update({
        "guard_redteam_nightly": {
            "task": "guard.redteam.nightly_broad",
            "schedule": crontab(hour=20, minute=30),  # 2am IST = 8:30pm UTC
        },
        "guard_redteam_weekly": {
            "task": "guard.redteam.weekly_deep",
            "schedule": crontab(hour=21, minute=30, day_of_week=0),  # Sunday 3am IST
        },
    })


def _trigger_redteam(guard_url: str, api_key: str, mode: str) -> None:
    try:
        resp = httpx.post(
            f"{guard_url}/v1/redteam/run",
            json={"mode": mode},
            headers={"Authorization": f"Bearer {api_key}"},
            timeout=10.0,
        )
        resp.raise_for_status()
        log.info("redteam.triggered", mode=mode, run_id=resp.json().get("run_id"))
    except Exception as exc:
        log.error("redteam.trigger_failed", mode=mode, error=str(exc))
