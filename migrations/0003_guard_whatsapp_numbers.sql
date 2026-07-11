-- Guard WhatsApp middleware: per-number registration + monthly counters.
-- Run as postgres on SIMBA:
--   docker exec -i diviqra-postgres psql -U postgres -d diviqra < 0003_guard_whatsapp_numbers.sql

CREATE TABLE IF NOT EXISTS guard_whatsapp_numbers (
    id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    customer_id          UUID NOT NULL REFERENCES guard_customers(id),
    phone_number_id      TEXT NOT NULL UNIQUE,  -- Meta phone number ID
    display_name         TEXT,
    webhook_verify_token TEXT NOT NULL,
    is_active            BOOLEAN NOT NULL DEFAULT true,
    scans_this_month     INTEGER NOT NULL DEFAULT 0,
    threats_this_month   INTEGER NOT NULL DEFAULT 0,
    razorpay_payment_id  TEXT,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_guard_whatsapp_numbers_customer ON guard_whatsapp_numbers(customer_id);

GRANT ALL ON TABLE guard_whatsapp_numbers TO diviqra_app;
GRANT ALL ON TABLE guard_whatsapp_numbers TO diviqra_superadmin;
