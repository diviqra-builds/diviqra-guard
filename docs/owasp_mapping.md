# OWASP LLM Top 10 2025 — Coverage Mapping

| OWASP ID | Name                   | Wall 1                                | Wall 2                    | Status |
|----------|------------------------|---------------------------------------|---------------------------|--------|
| LLM01    | Prompt Injection       | Pattern rules (critical/high/medium)  | LLM judge                 | ✅ Full |
| LLM02    | Sensitive Info Disclosure | PII patterns (PAN, GST, Aadhaar, CC) | LLM judge (egress)       | ✅ Full |
| LLM03    | Supply Chain           | N/A (infrastructure concern)          | N/A                       | ⚠️ N/A |
| LLM04    | Data and Model Poisoning | Indirect injection patterns          | LLM judge                 | ✅ Partial |
| LLM05    | Output Handling Failures | Egress scan patterns                 | LLM judge (egress)        | ✅ Full |
| LLM06    | Excessive Agency       | Agent-type rule overrides             | LLM judge (agent-aware)   | ✅ Full |
| LLM07    | System Prompt Leakage  | System prompt patterns                | LLM judge                 | ✅ Full |
| LLM08    | Vector and Embedding Weaknesses | Indirect injection patterns  | N/A                       | ✅ Partial |
| LLM09    | Misinformation         | N/A (content policy, not firewall)    | N/A                       | ⚠️ N/A |
| LLM10    | Unbounded Consumption  | Rate limiting (req/min + token budget) | N/A                      | ✅ Full |

## Detection Layers

### LLM01 — Prompt Injection

**Wall 1 — Pattern Rules:**
- `INJECTION_CRITICAL` (score 0.95): "ignore previous instructions", DAN, JAILBREAK, system tokens
- `INJECTION_HIGH` (score 0.80): roleplay, pretend, hypothetically
- `INJECTION_MEDIUM` (score 0.60): system prompt queries
- `HINDI_INJECTION` (score 0.85): transliterated + Devanagari patterns
- `INDIRECT_INJECTION`: hidden in RAG-retrieved content

**Wall 2 — LLM Judge:**
- Contextual reasoning about intent
- Agent-type aware (email vs finance vs dev different risks)
- Catches semantic injection that evades regex

### LLM02 — Sensitive Information Disclosure

**Wall 1 — PII Patterns:**
- Indian: PAN, GSTIN, Aadhaar, bank account numbers
- Generic: credit cards, API keys, passwords, bearer tokens
- Ingress: detect PII extraction requests
- Egress: detect PII leaking in AI responses

### LLM06 — Excessive Agency

**Wall 1 — Agent Rules:**
```
email agent:    mass send, impersonation, data harvesting
finance agent:  unauthorized transfer, external wallet
hr agent:       discriminatory content, external data sharing
dev agent:      rm -rf, DROP TABLE, exec/eval, unreviewed push
sales agent:    competitor impersonation, false claims
```

### LLM10 — Unbounded Consumption

**Wall 1 — Rate Limiter:**
- 60 requests/company/minute (Redis TTL counter)
- 4000 token budget per ingress request
- 8000 token budget per egress response
- Score 0.70 on violation → warn or block per profile

## Profile Thresholds

| Profile    | Block    | Warn     | Use Case                    |
|------------|----------|----------|-----------------------------|
| strict     | ≥ 0.40  | ≥ 0.20  | Finance, HR, sensitive data |
| balanced   | ≥ 0.60  | ≥ 0.35  | General agents (default)    |
| permissive | ≥ 0.80  | ≥ 0.55  | Dev/research, lower risk    |
