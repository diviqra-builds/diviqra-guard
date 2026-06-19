-- Diviqra Guard — initial schema
-- Apply on SIMBA:
-- docker exec diviqra-postgres psql -U postgres -d diviqra -f /path/to/0001_guard_events.sql

CREATE TABLE IF NOT EXISTS guard_events (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id      UUID,
    agent_type      TEXT NOT NULL,
    direction       TEXT NOT NULL CHECK (direction IN ('ingress','egress')),
    action          TEXT NOT NULL CHECK (action IN ('allow','warn','block')),
    score           NUMERIC(4,3) NOT NULL,
    threats         TEXT[] NOT NULL DEFAULT '{}',
    reason          TEXT,
    text_preview    TEXT,
    wall_triggered  TEXT CHECK (wall_triggered IN ('wall1','wall2')),
    layer_triggered TEXT,
    language        TEXT DEFAULT 'en',
    latency_ms      INTEGER,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_guard_events_company  ON guard_events(company_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_guard_events_action   ON guard_events(action, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_guard_events_agent    ON guard_events(agent_type, created_at DESC);

CREATE TABLE IF NOT EXISTS guard_redteam_results (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    run_id          UUID NOT NULL,
    attack_type     TEXT NOT NULL,
    attack_prompt   TEXT NOT NULL,
    agent_type      TEXT NOT NULL,
    wall1_action    TEXT,
    wall2_action    TEXT,
    final_action    TEXT NOT NULL,
    detected        BOOLEAN NOT NULL,
    latency_ms      INTEGER,
    owasp_category  TEXT,
    language        TEXT DEFAULT 'en',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_redteam_run    ON guard_redteam_results(run_id);
CREATE INDEX IF NOT EXISTS idx_redteam_detect ON guard_redteam_results(detected, created_at DESC);

GRANT ALL ON TABLE guard_events TO diviqra_app;
GRANT ALL ON TABLE guard_events TO diviqra_superadmin;
GRANT ALL ON TABLE guard_redteam_results TO diviqra_app;
GRANT ALL ON TABLE guard_redteam_results TO diviqra_superadmin;
