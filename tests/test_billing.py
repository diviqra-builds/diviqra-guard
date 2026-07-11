# MIT License — Copyright (c) 2026 Diviqra
import hashlib
import hmac
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import respx
import stripe as stripe_sdk
from fastapi import FastAPI
from fastapi.testclient import TestClient
from httpx import Response

from routers import billing
from service.config import settings

# Mount only the billing router rather than importing service.main — keeps
# these tests independent of unrelated routes/dependencies on the full app.
app = FastAPI()
app.include_router(billing.router)

_CUSTOMER = {"sub": "11111111-1111-1111-1111-111111111111", "email": "buyer@example.com", "type": "guard", "plan": "free"}

# A throwaway RSA keypair — lets _get_customer's real RS256 verification
# path run end-to-end in tests without touching the real Guard signing key.
from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: E402

_TEST_PRIVATE_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_TEST_PRIVATE_PEM = _TEST_PRIVATE_KEY.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption(),
).decode()
_TEST_PUBLIC_PEM = _TEST_PRIVATE_KEY.public_key().public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
).decode()


@pytest.fixture
def client():
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()


@pytest.fixture(autouse=True)
def override_customer():
    app.dependency_overrides[billing._get_customer] = lambda: _CUSTOMER
    yield
    app.dependency_overrides.pop(billing._get_customer, None)


class _FakeResult:
    def __init__(self, row=None):
        self._row = row

    def fetchone(self):
        return self._row


class _FakeSession:
    """Records every execute() call so tests can assert on the SQL/params sent."""

    def __init__(self, first_row=None):
        self.first_row = first_row
        self.executed: list[tuple[str, dict]] = []
        self.committed = False

    async def execute(self, stmt, params=None):
        self.executed.append((str(stmt), params or {}))
        if len(self.executed) == 1:
            return _FakeResult(self.first_row)
        return _FakeResult(None)

    async def commit(self):
        self.committed = True

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False


class TestGenerateApiKey:
    def test_prefix_matches_plan(self):
        for plan_id, prefix in [("pro", "dg_pro_"), ("enterprise", "dg_ent_"), ("free", "dg_dev_")]:
            full_key, key_prefix, key_hash = billing._generate_api_key(plan_id)
            assert full_key.startswith(prefix)
            assert key_prefix.startswith(prefix)
            assert full_key.startswith(key_prefix)
            assert len(key_hash) == 64  # sha256 hex digest

    def test_unknown_plan_falls_back_to_dev_prefix(self):
        full_key, _, _ = billing._generate_api_key("nonexistent")
        assert full_key.startswith("dg_dev_")


class TestScanLimitSentinel:
    def test_pro_resolves_to_fixed_limit(self):
        assert billing._resolved_scan_limit(billing.PLANS["pro"]) == 500_000

    def test_enterprise_resolves_to_unlimited_sentinel(self):
        assert billing._resolved_scan_limit(billing.PLANS["enterprise"]) == billing.UNLIMITED_SCAN_LIMIT

    def test_display_hides_sentinel_as_none(self):
        assert billing._display_scan_limit(billing.UNLIMITED_SCAN_LIMIT) is None
        assert billing._display_scan_limit(None) is None

    def test_display_passes_through_normal_limit(self):
        assert billing._display_scan_limit(500_000) == 500_000


class TestStripeCreateCheckout:
    def test_creates_session_for_pro_plan(self, client):
        fake_session = SimpleNamespace(id="cs_test_123", url="https://checkout.stripe.com/pay/cs_test_123")
        with patch.object(billing.stripe.checkout.Session, "create", return_value=fake_session) as mock_create:
            with patch.dict(billing._STRIPE_PRICE_IDS, {"pro": "price_pro_test"}):
                resp = client.post("/v1/billing/stripe/create-checkout", json={"plan": "pro"})

        assert resp.status_code == 200
        body = resp.json()
        assert body["checkout_url"] == fake_session.url
        assert body["session_id"] == "cs_test_123"

        _, kwargs = mock_create.call_args
        assert kwargs["mode"] == "subscription"
        assert kwargs["line_items"] == [{"price": "price_pro_test", "quantity": 1}]
        assert kwargs["client_reference_id"] == _CUSTOMER["sub"]
        assert kwargs["metadata"] == {"guard_customer_id": _CUSTOMER["sub"], "plan": "pro"}

    def test_unknown_plan_rejected(self, client):
        resp = client.post("/v1/billing/stripe/create-checkout", json={"plan": "ultra"})
        assert resp.status_code == 400

    def test_missing_price_id_returns_500(self, client):
        with patch.dict(billing._STRIPE_PRICE_IDS, {"pro": ""}):
            resp = client.post("/v1/billing/stripe/create-checkout", json={"plan": "pro"})
        assert resp.status_code == 500

    def test_stripe_error_returns_502(self, client):
        with patch.object(billing.stripe.checkout.Session, "create", side_effect=stripe_sdk.error.StripeError("boom")):
            with patch.dict(billing._STRIPE_PRICE_IDS, {"pro": "price_pro_test"}):
                resp = client.post("/v1/billing/stripe/create-checkout", json={"plan": "pro"})
        assert resp.status_code == 502

    def test_requires_auth(self):
        app.dependency_overrides.pop(billing._get_customer, None)
        with TestClient(app) as c:
            resp = c.post("/v1/billing/stripe/create-checkout", json={"plan": "pro"})
        assert resp.status_code == 401


class TestStripeWebhookSignature:
    def test_invalid_signature_rejected(self, client):
        with patch.object(
            billing.stripe.Webhook, "construct_event",
            side_effect=stripe_sdk.error.SignatureVerificationError("bad sig", "sig_header"),
        ):
            resp = client.post("/v1/billing/stripe/webhook", content=b"{}", headers={"Stripe-Signature": "bad"})
        assert resp.status_code == 400

    def test_malformed_payload_rejected(self, client):
        with patch.object(billing.stripe.Webhook, "construct_event", side_effect=ValueError("bad payload")):
            resp = client.post("/v1/billing/stripe/webhook", content=b"not-json", headers={"Stripe-Signature": "x"})
        assert resp.status_code == 400

    def test_valid_signature_ignores_unhandled_events(self, client):
        fake_event = {"type": "invoice.paid", "data": {"object": {}}}
        with patch.object(billing.stripe.Webhook, "construct_event", return_value=fake_event):
            with patch.object(billing, "_upgrade_customer_from_stripe", new_callable=AsyncMock) as mock_upgrade:
                resp = client.post("/v1/billing/stripe/webhook", content=b"{}", headers={"Stripe-Signature": "good"})
        assert resp.status_code == 200
        mock_upgrade.assert_not_called()


class TestStripeWebhookUpgrade:
    def _completed_event(self, customer_id="cust-42", plan="pro"):
        return {
            "type": "checkout.session.completed",
            "data": {"object": {
                "id": "cs_test_999",
                "subscription": "sub_test_999",
                "client_reference_id": customer_id,
                "metadata": {"guard_customer_id": customer_id, "plan": plan},
            }},
        }

    def test_completed_checkout_triggers_upgrade(self, client):
        event = self._completed_event()
        with patch.object(billing.stripe.Webhook, "construct_event", return_value=event):
            with patch.object(billing, "_upgrade_customer_from_stripe", new_callable=AsyncMock) as mock_upgrade:
                resp = client.post("/v1/billing/stripe/webhook", content=b"{}", headers={"Stripe-Signature": "good"})

        assert resp.status_code == 200
        assert resp.json() == {"status": "ok"}
        mock_upgrade.assert_awaited_once_with("cust-42", "pro", "sub_test_999")

    def test_missing_customer_id_is_ignored(self, client):
        event = self._completed_event(customer_id="")
        event["data"]["object"]["client_reference_id"] = None
        event["data"]["object"]["metadata"] = {"plan": "pro"}
        with patch.object(billing.stripe.Webhook, "construct_event", return_value=event):
            with patch.object(billing, "_upgrade_customer_from_stripe", new_callable=AsyncMock) as mock_upgrade:
                resp = client.post("/v1/billing/stripe/webhook", content=b"{}", headers={"Stripe-Signature": "good"})

        assert resp.status_code == 200
        assert resp.json() == {"status": "ignored"}
        mock_upgrade.assert_not_called()

    @pytest.mark.parametrize("plan_id,expected_limit", [("pro", 500_000), ("enterprise", billing.UNLIMITED_SCAN_LIMIT)])
    @pytest.mark.asyncio
    async def test_upgrade_writes_both_scan_limit_columns_and_rotates_key(self, plan_id, expected_limit):
        fake_row = SimpleNamespace(email="buyer@example.com", full_name="Buyer Person")
        fake_session = _FakeSession(first_row=fake_row)

        with patch.object(billing, "_session_factory", return_value=fake_session):
            with patch.object(billing, "_send_upgrade_email", new_callable=AsyncMock) as mock_email:
                await billing._upgrade_customer_from_stripe("cust-1", plan_id, "sub_abc")

        assert fake_session.committed is True
        assert len(fake_session.executed) == 4  # select + update customers + deactivate key + insert key

        update_sql, update_params = fake_session.executed[1]
        assert "scan_limit" in update_sql and "scans_limit" in update_sql
        assert update_params["limit"] == expected_limit
        assert update_params["plan"] == plan_id
        assert update_params["payment_id"] == "sub_abc"

        insert_sql, insert_params = fake_session.executed[3]
        assert "guard_api_keys" in insert_sql and "INSERT" in insert_sql
        assert insert_params["limit"] == expected_limit
        assert insert_params["prefix"].startswith(billing._PLAN_KEY_PREFIX[plan_id])

        mock_email.assert_awaited_once()
        email_args = mock_email.await_args.args
        assert email_args[0] == "buyer@example.com"
        assert email_args[3].startswith(billing._PLAN_KEY_PREFIX[plan_id])

    @pytest.mark.asyncio
    async def test_upgrade_noop_for_unknown_customer(self):
        fake_session = _FakeSession(first_row=None)
        with patch.object(billing, "_session_factory", return_value=fake_session):
            with patch.object(billing, "_send_upgrade_email", new_callable=AsyncMock) as mock_email:
                await billing._upgrade_customer_from_stripe("ghost", "pro", "sub_x")

        assert fake_session.committed is False
        mock_email.assert_not_called()


class TestRazorpayVerifyWritesBothColumns:
    """Regression test: guard_customers has two usage-limit column pairs
    (scan_limit/scan_count written historically, scans_limit/scans_used_month
    actually read by quota enforcement). verify_payment must keep both in
    sync or a paid upgrade silently fails to raise the enforced limit."""

    def test_verify_updates_scan_limit_and_scans_limit(self, client):
        fake_session = _FakeSession()

        async def _override_get_session():
            yield fake_session

        app.dependency_overrides[billing._get_session] = _override_get_session

        with patch.object(billing, "_verify_signature", return_value=True):
            resp = client.post("/v1/billing/verify", json={
                "razorpay_order_id": "order_1",
                "razorpay_payment_id": "pay_1",
                "razorpay_signature": "sig_1",
                "plan": "pro",
            })

        app.dependency_overrides.pop(billing._get_session, None)
        assert resp.status_code == 200
        assert fake_session.committed is True
        update_sql, update_params = fake_session.executed[0]
        assert "scan_limit" in update_sql and "scans_limit" in update_sql
        assert update_params["limit"] == 500_000

    def test_invalid_signature_rejected(self, client):
        with patch.object(billing, "_verify_signature", return_value=False):
            resp = client.post("/v1/billing/verify", json={
                "razorpay_order_id": "order_1",
                "razorpay_payment_id": "pay_1",
                "razorpay_signature": "bad",
                "plan": "pro",
            })
        assert resp.status_code == 400

    def test_unknown_plan_rejected(self, client):
        with patch.object(billing, "_verify_signature", return_value=True):
            resp = client.post("/v1/billing/verify", json={
                "razorpay_order_id": "order_1",
                "razorpay_payment_id": "pay_1",
                "razorpay_signature": "sig_1",
                "plan": "ultra",
            })
        assert resp.status_code == 400


class TestGetCustomer:
    def test_missing_credentials_raises_401(self):
        with pytest.raises(billing.HTTPException) as exc_info:
            billing._get_customer(credentials=None)
        assert exc_info.value.status_code == 401

    def test_wrongly_signed_token_raises_401(self):
        from jose import jwt as jose_jwt

        # Signed with an unrelated key/algorithm — decode() against the
        # configured RS256 public key fails before "type" is even checked.
        bogus = jose_jwt.encode({"type": "guard"}, "not-the-real-key", algorithm="HS256")
        creds = SimpleNamespace(credentials=bogus)
        with pytest.raises(billing.HTTPException) as exc_info:
            billing._get_customer(credentials=creds)
        assert exc_info.value.status_code == 401

    def test_malformed_token_raises_401(self):
        creds = SimpleNamespace(credentials="not-a-jwt")
        with pytest.raises(billing.HTTPException) as exc_info:
            billing._get_customer(credentials=creds)
        assert exc_info.value.status_code == 401

    def test_non_guard_type_rejected_with_valid_signature(self):
        from jose import jwt as jose_jwt

        token = jose_jwt.encode({"type": "platform", "sub": "x"}, _TEST_PRIVATE_PEM, algorithm="RS256")
        with patch.object(billing.settings, "GUARD_JWT_PUBLIC_KEY", _TEST_PUBLIC_PEM):
            with pytest.raises(billing.HTTPException) as exc_info:
                billing._get_customer(credentials=SimpleNamespace(credentials=token))
        assert exc_info.value.status_code == 401

    def test_valid_guard_token_returns_payload(self):
        from jose import jwt as jose_jwt

        token = jose_jwt.encode({"type": "guard", "sub": "cust-1"}, _TEST_PRIVATE_PEM, algorithm="RS256")
        with patch.object(billing.settings, "GUARD_JWT_PUBLIC_KEY", _TEST_PUBLIC_PEM):
            payload = billing._get_customer(credentials=SimpleNamespace(credentials=token))
        assert payload["sub"] == "cust-1"


class TestVerifySignatureHelper:
    def test_matches_expected_hmac(self):
        body = "order_1|pay_1"
        sig = hmac.new(settings.RAZORPAY_KEY_SECRET.encode(), body.encode(), hashlib.sha256).hexdigest()
        assert billing._verify_signature("order_1", "pay_1", sig) is True

    def test_rejects_wrong_signature(self):
        assert billing._verify_signature("order_1", "pay_1", "wrong") is False


class TestCreateRazorpayOrder:
    @respx.mock
    def test_create_order_success(self, client):
        respx.post("https://api.razorpay.com/v1/orders").mock(
            return_value=Response(200, json={"id": "order_abc123"})
        )
        resp = client.post("/v1/billing/create-order", json={"plan": "pro"})
        assert resp.status_code == 200
        body = resp.json()
        assert body["order_id"] == "order_abc123"
        assert body["amount"] == billing.PLANS["pro"]["price_inr_paise"]
        assert body["currency"] == "INR"

    @respx.mock
    def test_create_order_gateway_error(self, client):
        respx.post("https://api.razorpay.com/v1/orders").mock(return_value=Response(500, json={}))
        resp = client.post("/v1/billing/create-order", json={"plan": "pro"})
        assert resp.status_code == 502

    def test_create_order_unknown_plan(self, client):
        resp = client.post("/v1/billing/create-order", json={"plan": "ultra"})
        assert resp.status_code == 400

    @respx.mock
    def test_create_order_enterprise_plan(self, client):
        respx.post("https://api.razorpay.com/v1/orders").mock(
            return_value=Response(200, json={"id": "order_ent"})
        )
        resp = client.post("/v1/billing/create-order", json={"plan": "enterprise"})
        assert resp.status_code == 200
        assert resp.json()["amount"] == billing.PLANS["enterprise"]["price_inr_paise"]


class TestBillingStatus:
    def test_returns_plan_and_catalog(self, client):
        fake_row = SimpleNamespace(plan="pro", scan_limit=500_000, scan_count=1_234, razorpay_payment_id="pay_1")
        fake_session = _FakeSession(first_row=fake_row)

        async def _override_get_session():
            yield fake_session

        app.dependency_overrides[billing._get_session] = _override_get_session
        try:
            resp = client.get("/v1/billing/status")
        finally:
            app.dependency_overrides.pop(billing._get_session, None)

        assert resp.status_code == 200
        body = resp.json()
        assert body["plan"] == "pro"
        assert body["scan_limit"] == 500_000
        assert body["scan_count"] == 1_234
        assert any(p["id"] == "enterprise" and p["scan_limit"] is None for p in body["available_plans"])

    def test_unknown_customer_returns_404(self, client):
        fake_session = _FakeSession(first_row=None)

        async def _override_get_session():
            yield fake_session

        app.dependency_overrides[billing._get_session] = _override_get_session
        try:
            resp = client.get("/v1/billing/status")
        finally:
            app.dependency_overrides.pop(billing._get_session, None)

        assert resp.status_code == 404


class TestRazorpayWebhook:
    def _sign(self, body: bytes) -> str:
        return hmac.new(settings.RAZORPAY_WEBHOOK_SECRET.encode(), body, hashlib.sha256).hexdigest()

    def test_valid_signature_payment_captured(self, client):
        body = b'{"event": "payment.captured", "payload": {"payment": {"entity": {"id": "pay_999"}}}}'
        resp = client.post(
            "/v1/billing/webhook", content=body,
            headers={"X-Razorpay-Signature": self._sign(body), "Content-Type": "application/json"},
        )
        assert resp.status_code == 200
        assert resp.json() == {"status": "ok"}

    def test_invalid_signature_rejected(self, client):
        body = b'{"event": "payment.captured"}'
        resp = client.post(
            "/v1/billing/webhook", content=body,
            headers={"X-Razorpay-Signature": "bad-signature", "Content-Type": "application/json"},
        )
        assert resp.status_code == 400


class TestSendUpgradeEmail:
    @pytest.mark.asyncio
    async def test_skips_when_no_api_key_configured(self):
        with patch.object(settings, "RESEND_API_KEY", ""):
            with respx.mock:
                route = respx.post("https://api.resend.com/emails")
                await billing._send_upgrade_email("a@b.com", "A B", "Guard Pro", "dg_pro_xxx")
                assert route.call_count == 0

    @pytest.mark.asyncio
    async def test_sends_via_resend_when_configured(self):
        with patch.object(settings, "RESEND_API_KEY", "re_test_key"):
            with respx.mock:
                route = respx.post("https://api.resend.com/emails").mock(
                    return_value=Response(200, json={"id": "email_123"})
                )
                await billing._send_upgrade_email("a@b.com", "A B", "Guard Pro", "dg_pro_xxx")
                assert route.call_count == 1
                sent_json = route.calls[0].request.content
                assert b"dg_pro_xxx" in sent_json

    @pytest.mark.asyncio
    async def test_swallows_resend_failure(self):
        with patch.object(settings, "RESEND_API_KEY", "re_test_key"):
            with respx.mock:
                respx.post("https://api.resend.com/emails").mock(return_value=Response(500, json={}))
                # Must not raise — upgrade already succeeded, email is best-effort.
                await billing._send_upgrade_email("a@b.com", "A B", "Guard Pro", "dg_pro_xxx")
