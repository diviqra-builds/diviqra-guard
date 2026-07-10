# Diviqra Guard — Architecture

## Two-Wall Defence

```
User Input / Agent Output
         │
         ▼
    ┌─────────────────────────────────────────┐
    │            WALL 1 (always runs, <10ms)   │
    │                                          │
    │  ┌──────────┐  ┌─────┐  ┌──────┐  ┌───┐│
    │  │ OWASP    │  │ PII │  │Hindi │  │Rate││
    │  │ Patterns │  │ Det.│  │/Hin. │  │Lim.││
    │  └──────────┘  └─────┘  └──────┘  └───┘│
    │        +  DistilBERT ONNX Classifier     │
    └──────────────────┬──────────────────────┘
                       │
           ┌───────────┴────────────┐
           │                        │
      score >= 0.85           score < 0.30
           │                        │
        BLOCK                  allow/warn
      (fast path)             (fast path)
           │
    0.30 ≤ score < 0.85
    (~20% of traffic)
           │
           ▼
    ┌─────────────────────────────────────────┐
    │         WALL 2 (uncertain zone, 1-4s)   │
    │                                          │
    │       Ollama qwen3:1.7b LLM Judge       │
    │       Agent-aware contextual reasoning   │
    │       Redis cache (TTL 1hr)              │
    └──────────────────┬──────────────────────┘
                       │
              Combined score:
          w1×0.4 + w2×0.6
                       │
           Profile threshold
         strict / balanced / permissive
                       │
              allow / warn / block
                       │
               guard_events (DB)
```

## Component Map

```
./
├── diviqra_guard/      PyPI SDK (httpx client)
├── service/            FastAPI service :7008
│   ├── main.py         API endpoints
│   ├── scanner.py      Two-wall orchestrator
│   ├── walls/
│   │   ├── wall1/      Deterministic layer
│   │   └── wall2/      LLM judge layer
│   ├── agent_rules.py  Per-agent-type overrides
│   └── events.py       DB writer
├── redteam/            Automated red team
├── classifier/         DistilBERT training pipeline
├── migrations/         PostgreSQL schema
└── tests/              Pytest suite
```

## Data Flow

1. Diviqra backend agent calls `_guard_scan(text, direction)`
2. HTTP POST to Guard service `/v1/scan`
3. Wall 1 runs all checks in parallel (asyncio.gather)
4. Score >= 0.85 → immediate block, no Wall 2
5. Score < 0.30 → immediate allow/warn
6. Score 0.30-0.85 → Wall 2 (LLM judge)
7. Wall 2 checks Redis cache (sha256 key)
8. If miss → Ollama API call (3s timeout)
9. Combined score → profile threshold → action
10. Event written to guard_events table
11. Response returned to agent

## Fail-Open Design

- Guard service down → agents continue (5s HTTP timeout, return True)
- Wall 2 timeout (3s) → score 0.5 (uncertain), escalates to balanced profile
- DistilBERT model missing → classifier skipped, other Wall 1 checks run
- Redis down → Wall 2 cache miss, calls Ollama directly

## Shared Infrastructure

Uses Diviqra's existing infrastructure (no additional containers):
- PostgreSQL: `guard_events`, `guard_redteam_results` tables
- Redis: port 7379, Wall 2 cache + rate limiting
- Ollama: port 11434, qwen3:1.7b model
