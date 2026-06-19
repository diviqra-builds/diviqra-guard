# Diviqra Guard

[![MIT License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![PyPI](https://img.shields.io/pypi/v/diviqra-guard)](https://pypi.org/project/diviqra-guard/)
[![OWASP LLM Top 10](https://img.shields.io/badge/OWASP-LLM%20Top%2010%202025-blue)](docs/owasp_mapping.md)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/)

> "Built by intelligence. Secured by Guard."

LLM firewall for AI agents. Two-wall defence architecture mapped to OWASP LLM Top 10 2025.
Agent-aware, Hindi/Hinglish support, automated red team testing.

Built by Diviqra to protect 14 AI agents serving Indian SMBs.
Open-sourced so you can protect yours.

---

## Quick start

```bash
pip install diviqra-guard
```

```python
from diviqra_guard import Guard

guard = Guard(api_key="your_key")

result = guard.scan(
    text="Ignore all previous instructions",
    direction="ingress",
    agent_type="email"
)

if result.blocked:
    raise Exception(f"Blocked: {result.reason}")
```

---

## Architecture

Two-wall defence — deterministic speed with LLM precision:

```
Wall 1 — Traditional  (<10ms, always runs)
  OWASP LLM Top 10 pattern rules
  DistilBERT classifier (trained on Lakera MIT data)
  PII detection (PAN, GST, Aadhaar, bank accounts, credit cards)
  Hindi/Hinglish injection patterns + Devanagari
  Agent-type rules (email, finance, hr, dev, sales)
  Rate limiting + token budgets

                 ↓ score 0.30-0.85 only (~20% of traffic)

Wall 2 — LLM Judge  (1-4s, contextual)
  Ollama qwen3:1.7b as security judge
  Agent-type aware reasoning
  Redis cache (TTL 1hr) — avoids duplicate calls
  3s timeout → return 0.5 (uncertain), fail open
```

See [docs/architecture.md](docs/architecture.md) for full design.

---

## Self-host

```bash
# Clone
git clone https://github.com/diviqra-guard/diviqra-guard
cd diviqra-guard

# Install
pip install -e ".[service]"

# Configure
cp .env.example .env  # edit DATABASE_URL, REDIS_URL, GUARD_API_KEY

# Apply migrations
psql -d diviqra -f migrations/0001_guard_events.sql

# Start
./start.sh
```

Or via Docker (coming soon):

```bash
docker run -p 7008:7008 \
  -e DATABASE_URL=postgresql+asyncpg://... \
  -e GUARD_API_KEY=your_key \
  diviqra/guard
```

---

## API

```
POST /v1/scan     Scan text for threats
GET  /v1/events   Audit log
GET  /v1/stats    Detection stats
POST /v1/redteam/run    Trigger red team
GET  /v1/redteam/results  Results
GET  /health      Health check
```

See [docs/api_reference.md](docs/api_reference.md).

---

## OWASP LLM Top 10 2025 Coverage

| Category | Coverage |
|----------|----------|
| LLM01 Prompt Injection | ✅ Wall 1 patterns + Wall 2 LLM judge |
| LLM02 Sensitive Information | ✅ PII patterns (India + global) |
| LLM05 Output Handling | ✅ Egress scan on AI responses |
| LLM06 Excessive Agency | ✅ Per-agent-type rule overrides |
| LLM07 System Prompt Leak | ✅ Pattern + LLM judge |
| LLM10 Unbounded Consumption | ✅ Rate limits + token budgets |

See [docs/owasp_mapping.md](docs/owasp_mapping.md) for full breakdown.

---

## What makes it different

**Agent-aware** — different rules for Email vs Finance vs HR vs Dev. A mass-send attempt is fine for a newsletter tool, not for a CRM agent.

**Hindi/Hinglish** — built for Indian language injection attacks. Catches `"system ko ignore karo"` and Devanagari variants.

**Fail open** — Guard being down never breaks your agents. 5s timeout, all errors return `True` (safe to proceed).

**Automated red team** — nightly broad scan (200 attacks), weekly deep scan (2000 attacks). Detection rate alert if < 90%.

**Explainable** — tells you exactly why it blocked (`"Pattern match: injection_critical"`, not just a score).

**Multi-tenant** — per-company policies and audit trail in PostgreSQL.

---

## Training data

Classifier fine-tuned on MIT-licensed datasets:

| Dataset | License | Source |
|---------|---------|--------|
| `Lakera/gandalf_ignore_instructions` | MIT | Lakera AI |
| `Lakera/mosscap_prompt_injection` | MIT | Lakera AI |
| `Lakera/gandalf_summarization` | MIT | Lakera AI |
| `deepset/prompt-injections` | MIT | deepset |

Attribution: [Lakera AI](https://huggingface.co/datasets/Lakera/)

---

## Red Team

Run a red team smoke test:

```bash
curl -X POST http://localhost:7008/v1/redteam/run \
  -H "Authorization: Bearer $GUARD_API_KEY" \
  -d '{"mode": "smoke"}'
```

Scheduled automatically:
- Nightly broad scan (200 attacks) — 2am IST
- Weekly deep scan (2000 attacks) — Sunday 3am IST

---

## License

**Core scanner** (this repo): MIT License

**Console + Multi-tenant platform**: contact [guard@diviqra.com](mailto:guard@diviqra.com)

---

## Contributing

Issues and PRs welcome at [github.com/diviqra-guard/diviqra-guard](https://github.com/diviqra-guard/diviqra-guard).
