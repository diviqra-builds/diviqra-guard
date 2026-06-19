# MIT License — Copyright (c) 2026 Diviqra
from service.models import ScanRequest, WallResult
from service.walls.wall2 import llm_judge


async def scan(request: ScanRequest) -> WallResult:
    return await llm_judge.judge(request)
