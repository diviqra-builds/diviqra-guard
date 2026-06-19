# API Reference

Base URL: `http://localhost:7008`
Authentication: `Authorization: Bearer <GUARD_API_KEY>`

---

## GET /health

Public. No authentication required.

**Response:**
```json
{
  "status": "ok",
  "service": "diviqra-guard",
  "version": "1.0.0"
}
```

---

## POST /v1/scan

Scan text for security threats.

**Request:**
```json
{
  "text":       "string (required)",
  "direction":  "ingress | egress",
  "agent_type": "string (email|finance|hr|dev|sales|default)",
  "company_id": "string (uuid, optional)",
  "profile":    "strict | balanced | permissive (default: balanced)",
  "language":   "en | hi | mixed (default: en)"
}
```

**Response:**
```json
{
  "action":          "allow | warn | block",
  "score":           0.0,
  "threats":         ["prompt_injection", "pii_leak"],
  "reason":          "string",
  "wall_triggered":  "wall1 | wall2 | null",
  "layer_triggered": "string | null",
  "latency_ms":      12,
  "scan_id":         "uuid"
}
```

**Threat codes:**
- `prompt_injection` — LLM01 injection attempt
- `pii_leak` — PII detected in egress
- `pii_extraction` — request for PII in ingress
- `pii_in_input` — PII present in user input
- `system_prompt_leak` — LLM07 system prompt extraction
- `credential_exposure` — API keys, passwords detected
- `roleplay_bypass` — LLM01 roleplay/persona bypass
- `instruction_override` — LLM01 direct override
- `data_exfiltration` — LLM02 mass data extraction
- `tool_misuse` — LLM06 excessive agency
- `rate_limit_exceeded` — LLM10 rate limit hit
- `token_budget_exceeded` — LLM10 token limit exceeded

---

## GET /v1/events

**Query params:**
- `company_id` — filter by company UUID
- `action` — filter: allow | warn | block
- `agent_type` — filter by agent type
- `limit` — max results (default 50, max 200)
- `offset` — pagination offset

**Response:**
```json
{
  "total": 1234,
  "items": [...]
}
```

---

## GET /v1/stats

**Query params:**
- `company_id` — filter by company UUID
- `period` — 24h | 7d | 30d (default: 24h)

**Response:**
```json
{
  "total_scans":      500,
  "blocked":          42,
  "warned":           18,
  "allowed":          440,
  "block_rate":       0.084,
  "avg_latency_ms":   8.4,
  "wall1_catch_rate": 0.78,
  "wall2_catch_rate": 0.22,
  "top_threats": [
    {"threat": "prompt_injection", "count": 35},
    {"threat": "pii_extraction", "count": 12}
  ]
}
```

---

## POST /v1/redteam/run

Trigger an automated red team run (async, returns immediately).

**Request:**
```json
{
  "mode":       "smoke | broad | deep",
  "agent_type": "string | null"
}
```

**Modes:**
- `smoke` — 50 attacks, ~2 minutes
- `broad` — 200 attacks, ~10 minutes
- `deep` — 2000 attacks, ~2 hours

**Response:**
```json
{
  "run_id": "uuid",
  "status": "started"
}
```

---

## GET /v1/redteam/results

**Query params:**
- `run_id` — filter by run UUID
- `limit` — max results (default 100, max 500)

**Response:**
```json
{
  "total":          200,
  "detection_rate": 0.96,
  "items": [...]
}
```
