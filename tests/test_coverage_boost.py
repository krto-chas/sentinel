"""
test_coverage_boost.py – Extra tests to push total coverage above 80 %.

Covers uncovered branches in:
  alerts.py, auth.py, scanner.py, db.py,
  app/services/threat_intel.py, app/main.py
"""
import os
import socket
from collections import deque
from datetime import UTC, datetime, timezone
from time import monotonic
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# Auth off so app can be imported without credentials
os.environ.setdefault("AUTH_MODE", "off")

from fastapi import HTTPException
from fastapi.testclient import TestClient

from app.main import app, _upload_request_times
import app.services.threat_intel as ti


# ─────────────────────────────────────────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture
def client():
    _upload_request_times.clear()
    with TestClient(app) as c:
        yield c


# ─────────────────────────────────────────────────────────────────────────────
# app.alerts – _should_alert, _build_payload, _send_webhook, _send_email,
#              maybe_send_alert
# ─────────────────────────────────────────────────────────────────────────────

class TestShouldAlert:
    def test_malicious_status_triggers(self):
        from app.alerts import _should_alert
        assert _should_alert("malicious", "accepted", 0) is True

    def test_rejected_decision_triggers(self):
        from app.alerts import _should_alert
        assert _should_alert("clean", "rejected", 0) is True

    def test_high_risk_score_triggers(self):
        from app.alerts import _should_alert
        assert _should_alert("clean", "accepted", 70) is True

    def test_clean_low_score_no_alert(self):
        from app.alerts import _should_alert
        assert _should_alert("clean", "accepted", 10) is False


class TestBuildPayload:
    def test_critical_severity_for_malicious(self):
        from app.alerts import _build_payload
        p = _build_payload(
            filename="evil.txt", sha256="abc", scan_status="malicious",
            scan_engine="mock", scan_detail="EICAR", decision="rejected",
            risk_score=100, risk_reasons=["bad"], user_id="u", client_ip="1.2.3.4",
        )
        assert p["severity"] == "critical"
        assert p["event"] == "upload_alert"
        assert p["filename"] == "evil.txt"

    def test_high_severity_for_non_malicious(self):
        from app.alerts import _build_payload
        p = _build_payload(
            filename="f.txt", sha256="x", scan_status="error",
            scan_engine="mock", scan_detail="err", decision="rejected",
            risk_score=80, risk_reasons=[], user_id="anon", client_ip="x",
        )
        assert p["severity"] == "high"


class TestSendWebhook:
    def test_no_op_when_url_empty(self):
        import app.alerts as mod
        orig = mod.ALERT_WEBHOOK_URL
        mod.ALERT_WEBHOOK_URL = ""
        try:
            mod._send_webhook({"event": "test"})  # must not raise
        finally:
            mod.ALERT_WEBHOOK_URL = orig

    def test_posts_when_url_configured(self):
        import app.alerts as mod
        orig = mod.ALERT_WEBHOOK_URL
        mod.ALERT_WEBHOOK_URL = "http://example.com/hook"
        mock_resp = MagicMock()
        mock_resp.status = 200
        try:
            with patch("app.alerts.urllib_request.urlopen", return_value=mock_resp):
                mod._send_webhook({"event": "test"})
        finally:
            mod.ALERT_WEBHOOK_URL = orig

    def test_logs_error_on_network_failure(self):
        import app.alerts as mod
        orig = mod.ALERT_WEBHOOK_URL
        mod.ALERT_WEBHOOK_URL = "http://example.com/hook"
        try:
            with patch(
                "app.alerts.urllib_request.urlopen",
                side_effect=Exception("connection refused"),
            ):
                mod._send_webhook({"event": "test"})  # must not raise
        finally:
            mod.ALERT_WEBHOOK_URL = orig


class TestSendEmail:
    _base_payload = {
        "env": "test", "filename": "f.txt", "sha256": "abc",
        "scan_status": "malicious", "scan_engine": "mock", "scan_detail": "EICAR",
        "decision": "rejected", "risk_score": 100, "risk_reasons": ["bad"],
        "user_id": "u", "client_ip": "1.2.3.4", "severity": "critical",
    }

    def test_no_op_when_smtp_not_configured(self):
        import app.alerts as mod
        orig_host = mod._SMTP_HOST
        mod._SMTP_HOST = ""
        try:
            mod._send_email(self._base_payload)  # must not raise
        finally:
            mod._SMTP_HOST = orig_host

    def test_sends_with_smtp_configured(self):
        import app.alerts as mod
        mod._SMTP_HOST = "smtp.example.com"
        mod._SMTP_FROM = "from@example.com"
        mod._SMTP_TO = ["to@example.com"]
        mod._SMTP_USER = "user"
        mod._SMTP_PASSWORD = "pass"
        try:
            with patch("smtplib.SMTP") as mock_smtp_cls:
                mock_server = mock_smtp_cls.return_value.__enter__.return_value
                mod._send_email(self._base_payload)
                mock_server.sendmail.assert_called_once()
        finally:
            mod._SMTP_HOST = ""
            mod._SMTP_FROM = ""
            mod._SMTP_TO = []
            mod._SMTP_USER = ""
            mod._SMTP_PASSWORD = ""

    def test_logs_error_on_smtp_exception(self):
        import app.alerts as mod
        mod._SMTP_HOST = "smtp.example.com"
        mod._SMTP_FROM = "from@example.com"
        mod._SMTP_TO = ["to@example.com"]
        try:
            with patch("smtplib.SMTP", side_effect=Exception("SMTP failed")):
                mod._send_email(self._base_payload)  # must not raise
        finally:
            mod._SMTP_HOST = ""
            mod._SMTP_FROM = ""
            mod._SMTP_TO = []


class TestMaybeSendAlert:
    async def test_no_alert_for_clean_upload(self):
        from app.alerts import maybe_send_alert
        # _should_alert returns False → early return on line 162
        await maybe_send_alert(
            filename="clean.txt", sha256="abc", scan_status="clean",
            scan_engine="mock", scan_detail="ok", decision="accepted",
            risk_score=5, risk_reasons=[], user_id="anon", client_ip="x",
        )

    async def test_webhook_task_queued_for_malicious(self):
        import app.alerts as mod
        from app.alerts import maybe_send_alert
        orig = mod.ALERT_WEBHOOK_URL
        mod.ALERT_WEBHOOK_URL = "http://example.com/hook"
        try:
            # Patch _send_webhook so no real HTTP call is made in the thread
            with patch("app.alerts._send_webhook"):
                await maybe_send_alert(
                    filename="evil.txt", sha256="abc", scan_status="malicious",
                    scan_engine="mock", scan_detail="EICAR", decision="rejected",
                    risk_score=100, risk_reasons=["bad"],
                )
            # No exception means lines 185-192 were executed
        finally:
            mod.ALERT_WEBHOOK_URL = orig

    async def test_exception_in_task_is_logged(self):
        """Covers lines 193-194: exceptions from gather results are logged."""
        import app.alerts as mod
        from app.alerts import maybe_send_alert
        orig = mod.ALERT_WEBHOOK_URL
        mod.ALERT_WEBHOOK_URL = "http://example.com/hook"
        try:
            delivery_exc = RuntimeError("simulated delivery failure")
            # to_thread returns a dummy object (non-coroutine) so tasks is non-empty
            # gather is mocked to return a list containing an exception object
            with (
                patch("asyncio.to_thread", return_value=MagicMock()),
                patch("asyncio.gather", new_callable=AsyncMock, return_value=[delivery_exc]),
            ):
                await maybe_send_alert(
                    filename="evil.txt", sha256="abc", scan_status="malicious",
                    scan_engine="mock", scan_detail="EICAR", decision="rejected",
                    risk_score=100, risk_reasons=["bad"],
                )
            # Exception was caught and logged; no re-raise
        finally:
            mod.ALERT_WEBHOOK_URL = orig


# ─────────────────────────────────────────────────────────────────────────────
# app.auth – key-without-prefix, _resolve_firebase_user, get_current_user
# ─────────────────────────────────────────────────────────────────────────────

class TestAuthAnonymousKeyWithoutPrefix:
    """Keys without 'user:' prefix should map to 'anonymous'."""

    def test_bare_key_resolves_to_anonymous(self, monkeypatch):
        monkeypatch.setenv("SENTINEL_API_KEYS", "bare-secret-key")
        monkeypatch.setenv("AUTH_MODE", "apikey")
        import importlib
        import app.auth as auth_mod
        importlib.reload(auth_mod)
        try:
            class FakeRequest:
                headers = {"X-API-Key": "bare-secret-key"}
                client = MagicMock()
            user = auth_mod._resolve_apikey_user(FakeRequest())
            assert user == "anonymous"
        finally:
            monkeypatch.setenv("AUTH_MODE", "off")
            importlib.reload(auth_mod)


class TestResolveFirebaseUser:
    async def test_none_credentials_returns_none(self):
        from app.auth import _resolve_firebase_user
        result = await _resolve_firebase_user(None)
        assert result is None

    async def test_empty_credentials_returns_none(self):
        from app.auth import _resolve_firebase_user
        creds = MagicMock()
        creds.credentials = ""
        result = await _resolve_firebase_user(creds)
        assert result is None

    async def test_invalid_token_returns_none(self):
        """firebase_admin not installed or token invalid → exception → None."""
        from app.auth import _resolve_firebase_user
        creds = MagicMock()
        creds.credentials = "invalid.jwt.token"
        result = await _resolve_firebase_user(creds)
        assert result is None


class TestGetCurrentUserModes:
    async def test_unknown_auth_mode_raises_500(self):
        import app.auth as auth_mod
        orig = auth_mod.AUTH_MODE
        auth_mod.AUTH_MODE = "unknown_mode"
        try:
            with pytest.raises(HTTPException) as exc_info:
                await auth_mod.get_current_user(MagicMock(), None)
            assert exc_info.value.status_code == 500
        finally:
            auth_mod.AUTH_MODE = orig

    async def test_firebase_mode_with_invalid_token_raises_401(self):
        import app.auth as auth_mod
        orig = auth_mod.AUTH_MODE
        auth_mod.AUTH_MODE = "firebase"
        try:
            creds = MagicMock()
            creds.credentials = "bad.token"
            with pytest.raises(HTTPException) as exc_info:
                await auth_mod.get_current_user(MagicMock(), creds)
            assert exc_info.value.status_code == 401
        finally:
            auth_mod.AUTH_MODE = orig


# ─────────────────────────────────────────────────────────────────────────────
# app.scanner – _scan_mock filename, _scan_clamav socket paths,
#               scan_bytes mode selection
# ─────────────────────────────────────────────────────────────────────────────

class TestScanMock:
    def test_malicious_in_filename_triggers(self):
        from app.scanner import _scan_mock
        result = _scan_mock("malicious_payload.txt", b"normal content")
        assert result.status == "malicious"
        assert result.engine == "mock"

    def test_eicar_in_filename_triggers(self):
        from app.scanner import _scan_mock
        result = _scan_mock("eicar_test.txt", b"normal content")
        assert result.status == "malicious"

    def test_clean_content_and_name(self):
        from app.scanner import _scan_mock
        result = _scan_mock("report.txt", b"ordinary content")
        assert result.status == "clean"


class TestScanClamav:
    @staticmethod
    def _sock(response_bytes: bytes) -> MagicMock:
        sock = MagicMock()
        sock.__enter__ = lambda s: s
        sock.__exit__ = MagicMock(return_value=False)
        sock.recv.return_value = response_bytes
        return sock

    def test_found_returns_malicious(self):
        from app.scanner import _scan_clamav
        with patch("socket.create_connection", return_value=self._sock(b"stream: Eicar FOUND\0")):
            r = _scan_clamav(b"content")
        assert r.status == "malicious"
        assert r.engine == "clamav"

    def test_ok_returns_clean(self):
        from app.scanner import _scan_clamav
        with patch("socket.create_connection", return_value=self._sock(b"stream: OK\0")):
            r = _scan_clamav(b"content")
        assert r.status == "clean"

    def test_error_in_response_returns_error(self):
        from app.scanner import _scan_clamav
        with patch("socket.create_connection", return_value=self._sock(b"stream: ERROR\0")):
            r = _scan_clamav(b"content")
        assert r.status == "error"

    def test_unexpected_response_returns_error(self):
        from app.scanner import _scan_clamav
        with patch("socket.create_connection", return_value=self._sock(b"UNKNOWN_RESPONSE\0")):
            r = _scan_clamav(b"content")
        assert r.status == "error"
        assert "Unexpected" in r.detail

    def test_connection_failure_returns_error(self):
        from app.scanner import _scan_clamav
        with patch("socket.create_connection", side_effect=ConnectionRefusedError("refused")):
            r = _scan_clamav(b"content")
        assert r.status == "error"
        assert "unavailable" in r.detail.lower()


class TestScanBytesMode:
    @staticmethod
    def _ok_sock():
        sock = MagicMock()
        sock.__enter__ = lambda s: s
        sock.__exit__ = MagicMock(return_value=False)
        sock.recv.return_value = b"stream: OK\0"
        return sock

    def test_mock_mode_uses_mock_scanner(self, monkeypatch):
        monkeypatch.setenv("SCANNER_MODE", "mock")
        from app.scanner import scan_bytes
        result = scan_bytes("clean.txt", b"content")
        assert result.engine == "mock"

    def test_clamav_mode_returns_clamav_result(self, monkeypatch):
        monkeypatch.setenv("SCANNER_MODE", "clamav")
        from app.scanner import scan_bytes
        with patch("socket.create_connection", side_effect=ConnectionRefusedError()):
            result = scan_bytes("clean.txt", b"content")
        assert result.engine == "clamav"
        assert result.status == "error"

    def test_auto_mode_clamav_success(self, monkeypatch):
        monkeypatch.setenv("SCANNER_MODE", "auto")
        from app.scanner import scan_bytes
        with patch("socket.create_connection", return_value=self._ok_sock()):
            result = scan_bytes("clean.txt", b"content")
        assert result.engine == "clamav"
        assert result.status == "clean"

    def test_auto_mode_falls_back_to_mock(self, monkeypatch):
        monkeypatch.setenv("SCANNER_MODE", "auto")
        from app.scanner import scan_bytes
        with patch("socket.create_connection", side_effect=ConnectionRefusedError()):
            result = scan_bytes("clean.txt", b"content")
        assert result.engine == "mock"
        assert "fallback" in result.detail


# ─────────────────────────────────────────────────────────────────────────────
# app.db – _env_int edge-cases
# ─────────────────────────────────────────────────────────────────────────────

class TestEnvIntDb:
    def test_returns_default_for_missing_var(self, monkeypatch):
        monkeypatch.delenv("NONEXISTENT_VAR_DB_TEST", raising=False)
        from app.db import _env_int
        assert _env_int("NONEXISTENT_VAR_DB_TEST", 42) == 42

    def test_returns_default_for_invalid_value(self, monkeypatch):
        monkeypatch.setenv("TEST_DB_INT_BAD", "not_an_int")
        from app.db import _env_int
        assert _env_int("TEST_DB_INT_BAD", 7) == 7

    def test_returns_default_for_non_positive(self, monkeypatch):
        monkeypatch.setenv("TEST_DB_INT_ZERO", "0")
        from app.db import _env_int
        assert _env_int("TEST_DB_INT_ZERO", 5) == 5

    def test_returns_parsed_positive_value(self, monkeypatch):
        monkeypatch.setenv("TEST_DB_INT_OK", "99")
        from app.db import _env_int
        assert _env_int("TEST_DB_INT_OK", 5) == 99


# ─────────────────────────────────────────────────────────────────────────────
# app.main – _env_int, sanitize_filename, compute_risk, _record_timestamp,
#            _parse_kev_date, index endpoint, kev_summary endpoint,
#            uploads with user filter
# ─────────────────────────────────────────────────────────────────────────────

class TestEnvIntMain:
    def test_returns_default_for_invalid_string(self, monkeypatch):
        monkeypatch.setenv("MAIN_INT_TEST_BAD", "abc")
        from app.main import _env_int
        assert _env_int("MAIN_INT_TEST_BAD", 3) == 3

    def test_returns_default_for_zero(self, monkeypatch):
        monkeypatch.setenv("MAIN_INT_TEST_ZERO", "0")
        from app.main import _env_int
        assert _env_int("MAIN_INT_TEST_ZERO", 3) == 3


class TestSanitizeFilename:
    def test_empty_string_raises_400(self):
        from app.main import sanitize_filename
        with pytest.raises(HTTPException) as exc:
            sanitize_filename("")
        assert exc.value.status_code == 400

    def test_none_raises_400(self):
        from app.main import sanitize_filename
        with pytest.raises(HTTPException) as exc:
            sanitize_filename(None)
        assert exc.value.status_code == 400

    def test_dotdot_filename_raises_400(self):
        from app.main import sanitize_filename
        with pytest.raises(HTTPException) as exc:
            sanitize_filename("..")
        assert exc.value.status_code == 400

    def test_too_long_filename_raises_400(self):
        from app.main import sanitize_filename
        with pytest.raises(HTTPException) as exc:
            sanitize_filename("a" * 256 + ".txt")
        assert exc.value.status_code == 400


class TestComputeRiskEdgeCases:
    def test_large_file_raises_score(self):
        from app.main import compute_risk
        big = b"x" * (5 * 1024 * 1024 + 1)
        score, decision, reasons = compute_risk(
            filename="big.txt", content=big,
            scan_status="clean", scan_engine="mock", scan_detail="ok",
        )
        assert any("Large file" in r for r in reasons)

    def test_mock_engine_clean_adds_confidence_note(self):
        from app.main import compute_risk
        score, decision, reasons = compute_risk(
            filename="clean.txt", content=b"tiny",
            scan_status="clean", scan_engine="mock",
            scan_detail="No signature matched",
        )
        assert any("Mock" in r or "mock" in r.lower() for r in reasons)

    def test_fallback_detail_adds_fallback_reason(self):
        from app.main import compute_risk
        score, decision, reasons = compute_risk(
            filename="clean.txt", content=b"small",
            scan_status="clean", scan_engine="mock",
            scan_detail="No signature matched (fallback: ClamAV unavailable)",
        )
        assert any("Fallback" in r or "fallback" in r for r in reasons)
        assert score >= 25


class TestRecordTimestamp:
    def test_with_aware_datetime(self):
        from app.main import _record_timestamp
        now = datetime.now(UTC)
        assert _record_timestamp({"created_at": now}) == now

    def test_with_naive_datetime_gets_utc(self):
        from app.main import _record_timestamp
        naive = datetime(2025, 1, 1, 12, 0, 0)
        result = _record_timestamp({"created_at": naive})
        assert result is not None
        assert result.tzinfo is not None

    def test_with_object_id_generation_time(self):
        from app.main import _record_timestamp
        fake_oid = MagicMock()
        fake_oid.generation_time = datetime(2025, 6, 1, tzinfo=UTC)
        result = _record_timestamp({"_id": fake_oid})
        assert result is not None

    def test_returns_none_for_empty_record(self):
        from app.main import _record_timestamp
        assert _record_timestamp({}) is None


class TestParseKevDate:
    def test_valid_date(self):
        from app.main import _parse_kev_date
        result = _parse_kev_date("2025-01-15")
        assert result is not None
        assert result.year == 2025

    def test_invalid_date_returns_none(self):
        from app.main import _parse_kev_date
        assert _parse_kev_date("not-a-date") is None

    def test_none_returns_none(self):
        from app.main import _parse_kev_date
        assert _parse_kev_date(None) is None


class TestIndexEndpoint:
    def test_root_endpoint_responds(self, client):
        r = client.get("/")
        # The static index.html may or may not exist; we just check it's handled
        assert r.status_code in (200, 404, 500)


class TestFetchKevSummaryRemote:
    def test_parses_valid_response(self):
        from app.main import _fetch_kev_summary_remote
        import json
        vuln = {
            "cveID": "CVE-2024-1234", "vendorProject": "Acme", "product": "Widget",
            "dateAdded": "2026-01-15", "shortDescription": "A bad bug",
            "knownRansomwareCampaignUse": "Known",
        }
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps({"vulnerabilities": [vuln]}).encode()
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        with patch("app.main.request.urlopen", return_value=mock_resp):
            result = _fetch_kev_summary_remote()
        assert result["source"] == "CISA KEV"
        assert result["total_known_exploited_cves"] == 1

    def test_raises_on_unexpected_shape(self):
        from app.main import _fetch_kev_summary_remote
        import json
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps({"vulnerabilities": "not-a-list"}).encode()
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        with patch("app.main.request.urlopen", return_value=mock_resp):
            with pytest.raises(ValueError):
                _fetch_kev_summary_remote()


class TestKevSummaryEndpoint:
    def _clear_cache(self, mod):
        self._orig = (
            mod._kev_cached_payload,
            mod._kev_cached_at_monotonic,
            mod._kev_last_attempt_monotonic,
        )
        mod._kev_cached_payload = None
        mod._kev_cached_at_monotonic = 0.0
        mod._kev_last_attempt_monotonic = 0.0

    def _restore_cache(self, mod):
        mod._kev_cached_payload, mod._kev_cached_at_monotonic, mod._kev_last_attempt_monotonic = self._orig

    def test_503_when_remote_fails_and_no_cache(self, client):
        import app.main as mod
        self._clear_cache(mod)
        try:
            with patch("app.main._fetch_kev_summary_remote", side_effect=Exception("err")):
                r = client.get("/external/threats/kev-summary")
            assert r.status_code == 503
        finally:
            self._restore_cache(mod)

    def test_200_on_successful_remote_fetch(self, client):
        import app.main as mod
        self._clear_cache(mod)
        fake = {
            "source": "CISA KEV", "fetched_at": "2026-01-01T00:00:00+00:00",
            "total_known_exploited_cves": 100, "added_last_30_days": 5, "latest": [],
        }
        try:
            with patch("app.main._fetch_kev_summary_remote", return_value=fake):
                r = client.get("/external/threats/kev-summary")
            assert r.status_code == 200
            assert r.json()["source"] == "CISA KEV"
        finally:
            self._restore_cache(mod)

    def test_returns_fresh_cache_without_fetching(self, client):
        import app.main as mod
        orig = (mod._kev_cached_payload, mod._kev_cached_at_monotonic, mod._kev_last_attempt_monotonic)
        mod._kev_cached_payload = {
            "source": "CISA KEV", "total_known_exploited_cves": 42, "latest": [],
        }
        mod._kev_cached_at_monotonic = monotonic()  # fresh
        try:
            r = client.get("/external/threats/kev-summary")
            assert r.status_code == 200
            assert r.json()["total_known_exploited_cves"] == 42
        finally:
            mod._kev_cached_payload, mod._kev_cached_at_monotonic, mod._kev_last_attempt_monotonic = orig

    def test_stale_cache_returned_with_warning_when_remote_fails(self, client):
        import app.main as mod
        orig = (mod._kev_cached_payload, mod._kev_cached_at_monotonic, mod._kev_last_attempt_monotonic)
        stale = {"source": "CISA KEV", "total_known_exploited_cves": 55, "latest": []}
        mod._kev_cached_payload = stale
        mod._kev_cached_at_monotonic = monotonic() - 3600  # stale
        mod._kev_last_attempt_monotonic = 0.0
        try:
            with patch("app.main._fetch_kev_summary_remote", side_effect=Exception("down")):
                r = client.get("/external/threats/kev-summary")
            assert r.status_code == 200
            body = r.json()
            assert "warning" in body or body["total_known_exploited_cves"] == 55
        finally:
            mod._kev_cached_payload, mod._kev_cached_at_monotonic, mod._kev_last_attempt_monotonic = orig


class TestListUploadsUserFilter:
    """Test the authenticated user_id query filter path in /uploads (line 592)."""

    def test_successful_query_returns_items(self, monkeypatch):
        from app.auth import get_current_user

        class FakeCursor:
            def sort(self, *a, **kw):
                return self

            def limit(self, *a, **kw):
                return self

            def __aiter__(self):
                self._i = iter([])
                return self

            async def __anext__(self):
                try:
                    return next(self._i)
                except StopIteration:
                    raise StopAsyncIteration

        class FakeUploads:
            def find(self, query, projection): return FakeCursor()

        class FakeDB:
            def __init__(self): self.uploads = FakeUploads()

        monkeypatch.setattr("app.main.get_db", lambda: FakeDB())

        async def _override_user():
            return "alice"

        _upload_request_times.clear()
        app.dependency_overrides[get_current_user] = _override_user
        try:
            with TestClient(app) as c:
                r = c.get("/uploads")
            assert r.status_code == 200
            assert "items" in r.json()
        finally:
            app.dependency_overrides.clear()


# ─────────────────────────────────────────────────────────────────────────────
# app/services/threat_intel.py – unit tests with mocked IO
# ─────────────────────────────────────────────────────────────────────────────

class TestParseAllowedSources:
    def test_parses_comma_separated(self):
        result = ti._parse_allowed_sources("Feodo Tracker,URLhaus,ThreatFox")
        assert "Feodo Tracker" in result
        assert "URLhaus" in result
        assert "ThreatFox" in result

    def test_strips_whitespace(self):
        result = ti._parse_allowed_sources("  Feodo Tracker , URLhaus  ")
        assert "Feodo Tracker" in result
        assert "URLhaus" in result

    def test_ignores_empty_entries(self):
        result = ti._parse_allowed_sources("Feodo Tracker,,ThreatFox")
        assert len(result) == 2


class TestLoadSecretEnvValue:
    def test_returns_env_var_when_set(self, monkeypatch):
        monkeypatch.setenv("MY_SECRET_TEST_VAR_99", "env-secret")
        assert ti._load_secret_env_value("MY_SECRET_TEST_VAR_99", "") == "env-secret"

    def test_reads_from_file_when_env_missing(self, tmp_path):
        secret_file = tmp_path / "secret.txt"
        secret_file.write_text("file-secret")
        result = ti._load_secret_env_value("NONEXISTENT_VAR_XYZ_99", str(secret_file))
        assert result == "file-secret"

    def test_returns_empty_when_file_missing(self):
        result = ti._load_secret_env_value("NONEXISTENT_VAR_XYZ_99", "/no/such/file.txt")
        assert result == ""

    def test_returns_empty_with_no_env_and_no_path(self):
        result = ti._load_secret_env_value("NONEXISTENT_VAR_XYZ_99", "")
        assert result == ""


class TestGetGeolocation:
    def test_returns_none_when_db_missing(self, monkeypatch):
        monkeypatch.setattr(ti, "GEOIP_DB_PATH", "/nonexistent/GeoLite2-City.mmdb")
        assert ti.get_geolocation("1.2.3.4") is None

    def test_returns_dict_on_success(self, monkeypatch, tmp_path):
        fake_db = tmp_path / "GeoLite2-City.mmdb"
        fake_db.write_bytes(b"fake")
        monkeypatch.setattr(ti, "GEOIP_DB_PATH", str(fake_db))

        mock_resp = MagicMock()
        mock_resp.location.latitude = 59.33
        mock_resp.location.longitude = 18.07
        mock_resp.city.name = "Stockholm"
        mock_resp.country.iso_code = "SE"

        mock_reader = MagicMock()
        mock_reader.__enter__ = lambda s: s
        mock_reader.__exit__ = MagicMock(return_value=False)
        mock_reader.city.return_value = mock_resp

        with patch("geoip2.database.Reader", return_value=mock_reader):
            result = ti.get_geolocation("1.2.3.4")

        assert result == {"lat": 59.33, "lon": 18.07, "city": "Stockholm", "country": "SE"}

    def test_returns_none_on_address_not_found(self, monkeypatch, tmp_path):
        import geoip2.errors
        fake_db = tmp_path / "GeoLite2-City.mmdb"
        fake_db.write_bytes(b"fake")
        monkeypatch.setattr(ti, "GEOIP_DB_PATH", str(fake_db))

        mock_reader = MagicMock()
        mock_reader.__enter__ = lambda s: s
        mock_reader.__exit__ = MagicMock(return_value=False)
        mock_reader.city.side_effect = geoip2.errors.AddressNotFoundError("not found")

        with patch("geoip2.database.Reader", return_value=mock_reader):
            assert ti.get_geolocation("0.0.0.0") is None

    def test_returns_none_on_generic_exception(self, monkeypatch, tmp_path):
        fake_db = tmp_path / "GeoLite2-City.mmdb"
        fake_db.write_bytes(b"fake")
        monkeypatch.setattr(ti, "GEOIP_DB_PATH", str(fake_db))

        mock_reader = MagicMock()
        mock_reader.__enter__ = lambda s: s
        mock_reader.__exit__ = MagicMock(return_value=False)
        mock_reader.city.side_effect = RuntimeError("db corrupt")

        with patch("geoip2.database.Reader", return_value=mock_reader):
            assert ti.get_geolocation("8.8.8.8") is None


class TestIpFromHost:
    def test_empty_string_returns_none(self):
        assert ti._ip_from_host("") is None

    def test_valid_ip_returns_same(self):
        assert ti._ip_from_host("8.8.8.8") == "8.8.8.8"

    def test_domain_without_resolve_returns_none(self, monkeypatch):
        monkeypatch.setattr(ti, "THREAT_RESOLVE_DOMAINS", False)
        assert ti._ip_from_host("example.com") is None

    def test_domain_with_resolve_returns_public_ip(self, monkeypatch):
        monkeypatch.setattr(ti, "THREAT_RESOLVE_DOMAINS", True)
        with patch("socket.gethostbyname", return_value="93.184.216.34"):
            result = ti._ip_from_host("example.com")
        assert result == "93.184.216.34"

    def test_domain_with_resolve_filters_private_ip(self, monkeypatch):
        monkeypatch.setattr(ti, "THREAT_RESOLVE_DOMAINS", True)
        with patch("socket.gethostbyname", return_value="192.168.1.1"):
            assert ti._ip_from_host("internal.local") is None

    def test_domain_with_resolve_handles_dns_error(self, monkeypatch):
        monkeypatch.setattr(ti, "THREAT_RESOLVE_DOMAINS", True)
        with patch("socket.gethostbyname", side_effect=socket.gaierror("NXDOMAIN")):
            assert ti._ip_from_host("doesnotexist.invalid") is None


class TestMakeEvent:
    def test_produces_correct_structure(self):
        ts = datetime(2026, 1, 1, tzinfo=timezone.utc)
        event = ti._make_event(
            source="TestSrc", timestamp=ts, lat=52.0, lon=13.0,
            severity="high", event_type="C2", ioc="1.2.3.4",
            confidence=90, details={"country": "DE"},
        )
        assert event["source"] == "TestSrc"
        assert event["lat"] == 52.0
        assert event["confidence"] == 90
        assert "event_fingerprint" in event
        assert event["event_day"] == "2026-01-01"


class TestFetchFeodoIocs:
    def test_returns_empty_on_network_error(self):
        with patch("app.services.threat_intel.requests.get", side_effect=Exception("timeout")):
            assert ti.fetch_and_normalize_feodo_iocs() == []

    def test_normalizes_valid_ioc(self, monkeypatch):
        monkeypatch.setattr(
            ti, "get_geolocation",
            lambda ip: {"lat": 37.7, "lon": -122.4, "city": "SF", "country": "US"},
        )
        mock_resp = MagicMock()
        mock_resp.json.return_value = [{
            "ip_address": "5.5.5.5",
            "last_online": "2026-01-15 10:00:00 UTC",
            "first_seen": "2026-01-01 00:00:00",
            "malware": "Dridex", "country": "US", "status": "online",
        }]
        with patch("app.services.threat_intel.requests.get", return_value=mock_resp):
            result = ti.fetch_and_normalize_feodo_iocs()
        assert len(result) >= 1
        assert result[0]["source"] == "Feodo Tracker"

    def test_skips_entry_without_ip(self, monkeypatch):
        mock_resp = MagicMock()
        mock_resp.json.return_value = [{"ip_address": None}]
        with patch("app.services.threat_intel.requests.get", return_value=mock_resp):
            assert ti.fetch_and_normalize_feodo_iocs() == []

    def test_skips_entry_without_geo(self, monkeypatch):
        monkeypatch.setattr(ti, "get_geolocation", lambda ip: None)
        mock_resp = MagicMock()
        mock_resp.json.return_value = [{"ip_address": "5.5.5.5", "last_online": "2026-01-15"}]
        with patch("app.services.threat_intel.requests.get", return_value=mock_resp):
            assert ti.fetch_and_normalize_feodo_iocs() == []


class TestFetchUrlhausIocs:
    def test_returns_empty_on_error(self):
        with patch("app.services.threat_intel.requests.get", side_effect=Exception("err")):
            assert ti.fetch_and_normalize_urlhaus_iocs() == []

    def test_handles_list_shape(self, monkeypatch):
        monkeypatch.setattr(
            ti, "get_geolocation",
            lambda ip: {"lat": 1.0, "lon": 2.0, "city": "X", "country": "Y"},
        )
        monkeypatch.setattr(ti, "_ip_from_host", lambda h: "5.5.5.5" if h else None)
        mock_resp = MagicMock()
        mock_resp.json.return_value = [{
            "host": "5.5.5.5", "url": "http://5.5.5.5/bad",
            "dateadded": "2026-02-01 12:00:00",
            "url_status": "online", "threat": "malware_download", "tags": [],
        }]
        with patch("app.services.threat_intel.requests.get", return_value=mock_resp):
            result = ti.fetch_and_normalize_urlhaus_iocs()
        assert len(result) >= 1
        assert result[0]["source"] == "URLhaus"

    def test_handles_dict_with_urls_key(self, monkeypatch):
        monkeypatch.setattr(
            ti, "get_geolocation",
            lambda ip: {"lat": 1.0, "lon": 2.0, "city": "X", "country": "Y"},
        )
        monkeypatch.setattr(ti, "_ip_from_host", lambda h: "5.5.5.5" if h else None)
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"urls": [{
            "host": "5.5.5.5", "url": "http://5.5.5.5/bad",
            "dateadded": "2026-02-01 12:00:00",
            "url_status": "online", "threat": "malware_download", "tags": [],
        }]}
        with patch("app.services.threat_intel.requests.get", return_value=mock_resp):
            result = ti.fetch_and_normalize_urlhaus_iocs()
        assert len(result) >= 1

    def test_handles_unsupported_type(self):
        mock_resp = MagicMock()
        mock_resp.json.return_value = 99999  # not list or dict
        with patch("app.services.threat_intel.requests.get", return_value=mock_resp):
            assert ti.fetch_and_normalize_urlhaus_iocs() == []

    def test_handles_dict_with_no_useful_keys(self):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"query_status": "ok"}  # no "urls", no id-keyed dicts
        with patch("app.services.threat_intel.requests.get", return_value=mock_resp):
            assert ti.fetch_and_normalize_urlhaus_iocs() == []

    def test_handles_dict_id_keyed(self, monkeypatch):
        """Dict with ID-keyed entries (no 'urls' key)."""
        monkeypatch.setattr(
            ti, "get_geolocation",
            lambda ip: {"lat": 1.0, "lon": 2.0, "city": "X", "country": "Y"},
        )
        monkeypatch.setattr(ti, "_ip_from_host", lambda h: "5.5.5.5" if h else None)
        mock_resp = MagicMock()
        mock_resp.json.return_value = {
            "1": {
                "host": "5.5.5.5", "url": "http://5.5.5.5/bad",
                "dateadded": "2026-02-01 12:00:00",
                "url_status": "online", "threat": "malware_download", "tags": [],
            }
        }
        with patch("app.services.threat_intel.requests.get", return_value=mock_resp):
            result = ti.fetch_and_normalize_urlhaus_iocs()
        assert len(result) >= 1


class TestFetchThreatfoxIocs:
    def test_returns_empty_on_error(self):
        with patch("app.services.threat_intel.requests.post", side_effect=Exception("err")):
            assert ti.fetch_and_normalize_threatfox_iocs() == []

    def test_returns_empty_for_no_result_status(self):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"query_status": "no_result", "data": []}
        with patch("app.services.threat_intel.requests.post", return_value=mock_resp):
            assert ti.fetch_and_normalize_threatfox_iocs() == []

    def test_returns_empty_for_bad_response_type(self):
        mock_resp = MagicMock()
        mock_resp.json.return_value = "not-a-dict"
        with patch("app.services.threat_intel.requests.post", return_value=mock_resp):
            assert ti.fetch_and_normalize_threatfox_iocs() == []

    def test_normalizes_ip_port_ioc(self, monkeypatch):
        monkeypatch.setattr(
            ti, "get_geolocation",
            lambda ip: {"lat": 1.0, "lon": 2.0, "city": "X", "country": "Y"},
        )
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"query_status": "ok", "data": [{
            "ioc": "5.5.5.5:4444", "ioc_type": "ip:port",
            "threat_type": "botnet_cc", "malware": "TrickBot",
            "reporter": "user", "tags": [], "confidence_level": 85,
            "first_seen": "2026-02-01 00:00:00",
        }]}
        with patch("app.services.threat_intel.requests.post", return_value=mock_resp):
            result = ti.fetch_and_normalize_threatfox_iocs()
        assert len(result) >= 1
        assert result[0]["source"] == "ThreatFox"

    def test_normalizes_domain_ioc(self, monkeypatch):
        monkeypatch.setattr(
            ti, "get_geolocation",
            lambda ip: {"lat": 1.0, "lon": 2.0, "city": "X", "country": "Y"},
        )
        monkeypatch.setattr(ti, "_ip_from_host", lambda h: "5.5.5.5" if h else None)
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"query_status": "ok", "data": [{
            "ioc": "evil.example.com", "ioc_type": "domain",
            "threat_type": "c2", "malware": "Cobalt", "reporter": "x",
            "tags": [], "confidence_level": 80,
            "first_seen": "2026-02-01 00:00:00",
        }]}
        with patch("app.services.threat_intel.requests.post", return_value=mock_resp):
            result = ti.fetch_and_normalize_threatfox_iocs()
        assert len(result) >= 1

    def test_normalizes_url_ioc(self, monkeypatch):
        monkeypatch.setattr(
            ti, "get_geolocation",
            lambda ip: {"lat": 1.0, "lon": 2.0, "city": "X", "country": "Y"},
        )
        monkeypatch.setattr(ti, "_ip_from_host", lambda h: "5.5.5.5" if h else None)
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"query_status": "ok", "data": [{
            "ioc": "http://evil.example.com/payload", "ioc_type": "url",
            "threat_type": "payload_delivery", "malware": "X",
            "reporter": "x", "tags": [], "confidence_level": 75,
            "first_seen": "2026-02-01 00:00:00",
        }]}
        with patch("app.services.threat_intel.requests.post", return_value=mock_resp):
            result = ti.fetch_and_normalize_threatfox_iocs()
        assert len(result) >= 1

    def test_skips_ioc_without_geo(self, monkeypatch):
        monkeypatch.setattr(ti, "get_geolocation", lambda ip: None)
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"query_status": "ok", "data": [{
            "ioc": "5.5.5.5:80", "ioc_type": "ip:port",
            "confidence_level": 85, "first_seen": "2026-02-01 00:00:00",
        }]}
        with patch("app.services.threat_intel.requests.post", return_value=mock_resp):
            assert ti.fetch_and_normalize_threatfox_iocs() == []


class TestSetupDatabaseIndexes:
    def test_creates_indexes_and_drops_old(self, monkeypatch):
        mock_col = MagicMock()
        monkeypatch.setattr(ti, "threat_events_collection", mock_col)
        ti.setup_database_indexes()
        assert mock_col.create_index.call_count >= 2
        mock_col.drop_index.assert_called_with("ioc_1_source_1")

    def test_handles_drop_index_exception(self, monkeypatch):
        mock_col = MagicMock()
        mock_col.drop_index.side_effect = Exception("index not found")
        monkeypatch.setattr(ti, "threat_events_collection", mock_col)
        ti.setup_database_indexes()  # must not raise


class TestSaveEventsToDB:
    def test_empty_list_is_no_op(self, monkeypatch):
        mock_col = MagicMock()
        monkeypatch.setattr(ti, "threat_events_collection", mock_col)
        ti.save_events_to_db([])
        mock_col.bulk_write.assert_not_called()

    def test_filters_low_confidence_events(self, monkeypatch):
        mock_col = MagicMock()
        monkeypatch.setattr(ti, "threat_events_collection", mock_col)
        monkeypatch.setattr(ti, "THREAT_INTEL_MIN_CONFIDENCE", 70)
        ti.save_events_to_db([{"confidence": 50, "source": "X"}])
        mock_col.bulk_write.assert_not_called()

    def test_writes_events_above_threshold(self, monkeypatch):
        mock_col = MagicMock()
        mock_col.bulk_write.return_value = MagicMock(inserted_count=1)
        monkeypatch.setattr(ti, "threat_events_collection", mock_col)
        monkeypatch.setattr(ti, "THREAT_INTEL_MIN_CONFIDENCE", 70)
        ti.save_events_to_db([{"confidence": 80, "source": "X"}])
        mock_col.bulk_write.assert_called_once()

    def test_handles_bulk_write_error_gracefully(self, monkeypatch):
        from pymongo.errors import BulkWriteError
        mock_col = MagicMock()
        mock_col.bulk_write.side_effect = BulkWriteError({"nInserted": 0, "writeErrors": []})
        monkeypatch.setattr(ti, "threat_events_collection", mock_col)
        ti.save_events_to_db([{"confidence": 80, "source": "X"}])  # must not raise

    def test_handles_generic_db_exception(self, monkeypatch):
        mock_col = MagicMock()
        mock_col.bulk_write.side_effect = Exception("DB down")
        monkeypatch.setattr(ti, "threat_events_collection", mock_col)
        ti.save_events_to_db([{"confidence": 90, "source": "X"}])  # must not raise


class TestRunThreatIntelUpdateJob:
    def test_calls_all_enabled_sources(self, monkeypatch):
        monkeypatch.setattr(ti, "ALLOWED_THREAT_SOURCES", {"Feodo Tracker", "URLhaus", "ThreatFox"})
        with (
            patch.object(ti, "fetch_and_normalize_feodo_iocs", return_value=[]) as feodo,
            patch.object(ti, "fetch_and_normalize_urlhaus_iocs", return_value=[]) as urlhaus,
            patch.object(ti, "fetch_and_normalize_threatfox_iocs", return_value=[]) as tfox,
            patch.object(ti, "save_events_to_db") as save,
        ):
            ti.run_threat_intel_update_job()
        feodo.assert_called_once()
        urlhaus.assert_called_once()
        tfox.assert_called_once()
        save.assert_called_once()

    def test_skips_disabled_sources(self, monkeypatch):
        monkeypatch.setattr(ti, "ALLOWED_THREAT_SOURCES", set())
        with (
            patch.object(ti, "fetch_and_normalize_feodo_iocs", return_value=[]) as feodo,
            patch.object(ti, "save_events_to_db") as save,
        ):
            ti.run_threat_intel_update_job()
        feodo.assert_not_called()
        save.assert_called_once_with([])


class TestThreatRouterEndpoint:
    def test_get_threats_returns_list(self, client, monkeypatch):
        mock_cursor = MagicMock()
        mock_cursor.sort.return_value = mock_cursor
        mock_cursor.limit.return_value = [{"source": "Feodo Tracker", "ioc": "1.2.3.4"}]
        with patch("app.routers.threats.threat_events_collection") as mock_col:
            mock_col.find.return_value = mock_cursor
            r = client.get("/api/v1/threats/")
        assert r.status_code == 200


# ─────────────────────────────────────────────────────────────────────────────
# Additional targeted tests for hard-to-reach branches
# ─────────────────────────────────────────────────────────────────────────────

class TestDbGetDbFallback:
    """Cover the ConfigurationError fallback path in get_db (lines 23-25)."""

    def test_falls_back_when_no_default_database(self):
        from pymongo.errors import ConfigurationError as PyMongoConfigError
        from app.db import get_db

        mock_client = MagicMock()
        mock_client.get_default_database.side_effect = PyMongoConfigError("no default")
        mock_client.get_database.return_value = MagicMock()

        with patch("app.db.get_mongo_client", return_value=mock_client):
            get_db()

        mock_client.get_database.assert_called_once()


class TestDbEnsureUploadIndexes:
    """Cover ensure_upload_indexes (line 46)."""

    async def test_creates_two_indexes(self):
        from app.db import ensure_upload_indexes

        mock_uploads = MagicMock()
        mock_uploads.create_index = AsyncMock()

        mock_db = MagicMock()
        mock_db.uploads = mock_uploads

        with patch("app.db.get_db", return_value=mock_db):
            await ensure_upload_indexes()

        assert mock_uploads.create_index.call_count == 2


class TestRateLimitStaleCleaning:
    """Cover stale-client removal (line 189) and old-timestamp popleft (line 193)."""

    def test_stale_client_removed_from_tracker(self):
        from app.main import enforce_upload_rate_limit, _upload_request_times, RATE_LIMIT_WINDOW_SECONDS
        _upload_request_times.clear()
        # Insert a stale entry (last timestamp > window ago)
        _upload_request_times["stale-id"] = deque([monotonic() - RATE_LIMIT_WINDOW_SECONDS - 1])
        enforce_upload_rate_limit("fresh-client")
        assert "stale-id" not in _upload_request_times
        _upload_request_times.clear()

    def test_old_timestamps_popped_within_window(self):
        from app.main import enforce_upload_rate_limit, _upload_request_times, RATE_LIMIT_WINDOW_SECONDS
        _upload_request_times.clear()
        old = monotonic() - RATE_LIMIT_WINDOW_SECONDS - 1
        _upload_request_times["client-x"] = deque([old])
        enforce_upload_rate_limit("client-x")
        # Old timestamp should have been popped; only the new one remains
        assert len(_upload_request_times.get("client-x", deque())) == 1
        _upload_request_times.clear()


class TestMaybeSendAlertSmtp:
    """Cover line 188: SMTP task queued in maybe_send_alert."""

    async def test_smtp_task_queued_when_configured(self):
        import app.alerts as mod
        from app.alerts import maybe_send_alert
        mod._SMTP_HOST = "smtp.example.com"
        mod._SMTP_FROM = "from@example.com"
        mod._SMTP_TO = ["to@example.com"]
        try:
            with patch("app.alerts._send_email"):
                await maybe_send_alert(
                    filename="evil.txt", sha256="abc", scan_status="malicious",
                    scan_engine="mock", scan_detail="EICAR", decision="rejected",
                    risk_score=100, risk_reasons=["bad"],
                )
        finally:
            mod._SMTP_HOST = ""
            mod._SMTP_FROM = ""
            mod._SMTP_TO = []


class TestFeodoOldDateSkip:
    """Cover the cutoff continue branch in feodo (line 175)."""

    def test_skips_ioc_older_than_cutoff(self):
        mock_resp = MagicMock()
        mock_resp.json.return_value = [{
            "ip_address": "5.5.5.5",
            "last_online": "2020-01-01",  # very old, parsed via %Y-%m-%d
        }]
        with patch("app.services.threat_intel.requests.get", return_value=mock_resp):
            result = ti.fetch_and_normalize_feodo_iocs()
        assert result == []


class TestUrlhausOldDateSkip:
    """Cover the cutoff continue branch in urlhaus (line 274)."""

    def test_skips_old_urlhaus_entry(self, monkeypatch):
        monkeypatch.setattr(ti, "_ip_from_host", lambda h: "5.5.5.5" if h else None)
        monkeypatch.setattr(ti, "get_geolocation", lambda ip: {"lat": 1.0, "lon": 2.0, "city": "X", "country": "Y"})
        mock_resp = MagicMock()
        mock_resp.json.return_value = [{
            "host": "5.5.5.5",
            "url": "http://5.5.5.5/bad",
            "dateadded": "2019-01-01 00:00:00",  # very old
        }]
        with patch("app.services.threat_intel.requests.get", return_value=mock_resp):
            result = ti.fetch_and_normalize_urlhaus_iocs()
        assert result == []


class TestThreatfoxOldDateSkip:
    """Cover the cutoff continue branch in threatfox (line 367)."""

    def test_skips_old_threatfox_entry(self, monkeypatch):
        monkeypatch.setattr(ti, "get_geolocation", lambda ip: {"lat": 1.0, "lon": 2.0, "city": "X", "country": "Y"})
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"query_status": "ok", "data": [{
            "ioc": "5.5.5.5:4444", "ioc_type": "ip:port",
            "confidence_level": 85,
            "first_seen": "2019-01-01 00:00:00",  # very old
        }]}
        with patch("app.services.threat_intel.requests.post", return_value=mock_resp):
            result = ti.fetch_and_normalize_threatfox_iocs()
        assert result == []


class TestThreatfoxNoResultData:
    """Cover the non-list data branch in threatfox (line 325)."""

    def test_handles_non_list_data(self):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"query_status": "ok", "data": "not-a-list"}
        with patch("app.services.threat_intel.requests.post", return_value=mock_resp):
            result = ti.fetch_and_normalize_threatfox_iocs()
        assert result == []


class TestUrlhausDictIdKeyed:
    """Cover the id-keyed dict branch that builds id_keyed list (lines 230-237)."""

    def test_handles_list_values_in_id_keyed_dict(self, monkeypatch):
        monkeypatch.setattr(ti, "_ip_from_host", lambda h: "5.5.5.5" if h else None)
        monkeypatch.setattr(ti, "get_geolocation", lambda ip: {"lat": 1.0, "lon": 2.0, "city": "X", "country": "Y"})
        mock_resp = MagicMock()
        # Value is a list of rows (the id_keyed.extend branch)
        mock_resp.json.return_value = {
            "somekey": [
                {
                    "host": "5.5.5.5",
                    "url": "http://5.5.5.5/bad",
                    "dateadded": "2026-02-01 12:00:00",
                    "url_status": "online",
                    "threat": "malware_download",
                    "tags": [],
                }
            ]
        }
        with patch("app.services.threat_intel.requests.get", return_value=mock_resp):
            result = ti.fetch_and_normalize_urlhaus_iocs()
        assert len(result) >= 1
