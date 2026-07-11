-- Stripe USD billing: record the subscription/session id from the last
-- completed Stripe checkout, mirroring razorpay_payment_id.
ALTER TABLE guard_customers ADD COLUMN IF NOT EXISTS stripe_payment_id TEXT;
