#!/bin/bash
set -euo pipefail

cd /opt/diviqra/guard
source /opt/diviqra/diviqra/backend/venv/bin/activate

exec uvicorn service.main:app \
  --host 0.0.0.0 \
  --port 7008 \
  --workers 2 \
  --log-level info
