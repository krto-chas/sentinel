import pytest
from datetime import UTC, datetime, timedelta
from fastapi import HTTPException
from app.main import _upload_request_times
from app.main import enforce_upload_rate_limit
from app.scanner import ScanResult


def test_upload_accepts_allowed_type(client):
    files = {"file": ("hello.txt", b"hello", "text/plain")}
    r = client.post("/upload", files=files)
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "accepted"
    assert body["decision"] == "accepted"
    assert body["risk_score"] < 30
    assert body["deduplicated"] is False
    assert body["content_type"] == "text/plain"
    assert body["scan_status"] == "clean"


def test_upload_accepts_markdown_type(client):
    files = {"file": ("README.md", b"# hello", "text/markdown")}
    r = client.post("/upload", files=files)
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "accepted"
    assert body["content_type"] == "text/markdown"
    assert body["scan_status"] == "clean"


def test_upload_blocks_disallowed_type(client):
    files = {"file": ("evil.exe", b"MZ...", "application/octet-stream")}
    r = client.post("/upload", files=files)
    assert r.status_code == 415


def test_upload_rejects_malicious_signature(client):
    eicar = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    files = {"file": ("eicar.txt", eicar, "text/plain")}
    r = client.post("/upload", files=files)
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "rejected"
    assert body["decision"] == "rejected"
    assert body["risk_score"] >= 70
    assert body["scan_status"] == "malicious"


def test_upload_rejects_when_scanner_errors(client, monkeypatch):
    def fake_scan_bytes(_filename, _content):
        return ScanResult(status="error", engine="clamav", detail="ClamAV unavailable")

    monkeypatch.setattr("app.main.scan_bytes", fake_scan_bytes)
    files = {"file": ("hello.txt", b"hello", "text/plain")}
    r = client.post("/upload", files=files)
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "rejected"
    assert body["decision"] in {"review", "rejected"}
    assert body["scan_status"] == "error"


def test_upload_rejects_path_traversal_filename(client):
    files = {"file": ("../../etc/passwd", b"root:x:0:0", "text/plain")}
    r = client.post("/upload", files=files)
    # Path components stripped, "passwd" has no allowed extension
    assert r.status_code == 415


def test_upload_rejects_mismatched_extension(client):
    files = {"file": ("evil.exe", b"MZ...", "text/plain")}
    r = client.post("/upload", files=files)
    assert r.status_code == 415
    assert "does not match" in r.json()["detail"]


def test_upload_rejects_invalid_characters_in_filename(client):
    files = {"file": ("<script>alert(1)</script>.txt", b"hi", "text/plain")}
    r = client.post("/upload", files=files)
    assert r.status_code == 400
    assert "invalid characters" in r.json()["detail"]


def test_upload_sanitizes_path_and_accepts_valid_file(client):
    files = {"file": ("subdir/hello.txt", b"hello", "text/plain")}
    r = client.post("/upload", files=files)
    assert r.status_code == 200
    assert r.json()["filename"] == "hello.txt"
    assert r.json()["sha256"]


def test_upload_deduplicates_by_sha256(client, monkeypatch):
    class FakeUploads:
        def __init__(self):
            self.items = []

        async def find_one(self, query, projection):
            target_hash = query.get("sha256")
            for item in self.items:
                if item.get("sha256") == target_hash:
                    return {
                        key: value for key, value in item.items()
                        if key in projection and key != "_id"
                    }
            return None

        async def insert_one(self, doc):
            self.items.append(doc)
            return object()

    class FakeDB:
        def __init__(self):
            self.uploads = FakeUploads()

    fake_db = FakeDB()
    monkeypatch.setattr("app.main.get_db", lambda: fake_db)

    files = {"file": ("hello.txt", b"hello", "text/plain")}
    first = client.post("/upload", files=files)
    assert first.status_code == 200
    second = client.post("/upload", files=files)
    assert second.status_code == 200
    second_body = second.json()
    assert second_body["deduplicated"] is True
    assert second_body["sha256"] == first.json()["sha256"]


def test_upload_rejects_oversized_file(client, monkeypatch):
    monkeypatch.setattr("app.main.MAX_FILE_SIZE_BYTES", 100)
    files = {"file": ("big.txt", b"x" * 101, "text/plain")}
    r = client.post("/upload", files=files)
    assert r.status_code == 413
    assert "too large" in r.json()["detail"]


def test_uploads_list_returns_503_when_db_unavailable(client):
    r = client.get("/uploads")
    assert r.status_code == 503
    assert "Database unavailable" in r.json()["detail"]


def test_metrics_summary_returns_503_when_db_unavailable(client):
    r = client.get("/metrics/summary")
    assert r.status_code == 503
    assert "Database unavailable" in r.json()["detail"]


def test_metrics_summary_returns_expected_counts(client, monkeypatch):
    now = datetime.now(UTC)
    records = [
        {
            "created_at": now - timedelta(hours=1),
            "status": "accepted",
            "decision": "accepted",
            "deduplicated": False,
            "risk_score": 10,
            "content_type": "text/plain",
        },
        {
            "created_at": now - timedelta(hours=2),
            "status": "rejected",
            "decision": "rejected",
            "deduplicated": True,
            "risk_score": 95,
            "content_type": "text/plain",
        },
        {
            "created_at": now - timedelta(days=3),
            "status": "accepted",
            "decision": "review",
            "deduplicated": False,
            "risk_score": 45,
            "content_type": "image/jpeg",
        },
        {
            "created_at": now - timedelta(days=10),
            "status": "accepted",
            "decision": "accepted",
            "deduplicated": False,
            "risk_score": 15,
            "content_type": "text/markdown",
        },
    ]

    class FakeCursor:
        def __init__(self, items):
            self.items = items

        def sort(self, *_args, **_kwargs):
            return self

        def limit(self, *_args, **_kwargs):
            return self

        def __aiter__(self):
            self._iter = iter(self.items)
            return self

        async def __anext__(self):
            try:
                return next(self._iter)
            except StopIteration:
                raise StopAsyncIteration

    class FakeUploads:
        def find(self, *_args, **_kwargs):
            return FakeCursor(records)

    class FakeDB:
        def __init__(self):
            self.uploads = FakeUploads()

    monkeypatch.setattr("app.main.get_db", lambda: FakeDB())

    r = client.get("/metrics/summary")
    assert r.status_code == 200
    body = r.json()
    assert body["last_24h"]["total_uploads"] == 2
    assert body["last_24h"]["rejected"] == 1
    assert body["last_7d"]["total_uploads"] == 3
    assert body["last_7d"]["review"] == 1
    assert body["all_time"]["total_uploads"] == 4
    assert body["top_content_types_7d"][0]["content_type"] == "text/plain"
    assert body["top_content_types_7d"][0]["count"] == 2


def test_upload_rate_limit_returns_429_when_exceeded(monkeypatch):
    monkeypatch.setattr("app.main.RATE_LIMIT_UPLOADS_PER_MINUTE", 3)
    monkeypatch.setattr("app.main.RATE_LIMIT_WINDOW_SECONDS", 60)
    _upload_request_times.clear()

    for _ in range(3):
        enforce_upload_rate_limit("ci-test-client")

    with pytest.raises(HTTPException) as exc:
        enforce_upload_rate_limit("ci-test-client")

    assert exc.value.status_code == 429


# ─── Auth-tester ─────────────────────────────────────────────────────────────

def test_upload_without_apikey_returns_401_when_auth_enabled(authed_client):
    """Uppladdning utan API-nyckel ska returnera 401 när AUTH_MODE=apikey."""
    files = {"file": ("hello.txt", b"hello", "text/plain")}
    r = authed_client.post("/upload", files=files)
    assert r.status_code == 401


def test_upload_with_valid_apikey_returns_200(authed_client):
    """Uppladdning med giltig API-nyckel ska accepteras."""
    files = {"file": ("hello.txt", b"hello", "text/plain")}
    r = authed_client.post(
        "/upload",
        files=files,
        headers={"X-API-Key": "test-secret-key"},
    )
    assert r.status_code == 200
    assert r.json()["user_id"] == "testuser"


def test_upload_with_invalid_apikey_returns_401(authed_client):
    """Uppladdning med fel API-nyckel ska returnera 401."""
    files = {"file": ("hello.txt", b"hello", "text/plain")}
    r = authed_client.post(
        "/upload",
        files=files,
        headers={"X-API-Key": "wrong-key"},
    )
    assert r.status_code == 401


def test_upload_user_id_stored_in_response(client):
    """user_id ska alltid returneras i svaret (anonymous när AUTH_MODE=off)."""
    files = {"file": ("hello.txt", b"hello", "text/plain")}
    r = client.post("/upload", files=files)
    assert r.status_code == 200
    assert r.json()["user_id"] == "anonymous"


# ─── Alert-tester ─────────────────────────────────────────────────────────────

def test_alert_triggered_on_malicious_upload(client, monkeypatch):
    """maybe_send_alert ska anropas vid malicious-scan."""
    alert_calls = []

    async def fake_alert(**kwargs):
        alert_calls.append(kwargs)

    monkeypatch.setattr("app.main.maybe_send_alert", fake_alert)

    from app.scanner import ScanResult
    monkeypatch.setattr(
        "app.main.scan_bytes",
        lambda _f, _c: ScanResult(status="malicious", engine="mock", detail="EICAR"),
    )

    files = {"file": ("eicar.txt", b"X5O!P%", "text/plain")}
    r = client.post("/upload", files=files)
    assert r.status_code == 200
    assert len(alert_calls) == 1
    assert alert_calls[0]["scan_status"] == "malicious"
    assert alert_calls[0]["decision"] == "rejected"


def test_alert_not_triggered_on_clean_upload(client, monkeypatch):
    """maybe_send_alert ska INTE anropas vid ren uppladdning."""
    alert_calls = []

    async def fake_alert(**kwargs):
        alert_calls.append(kwargs)

    monkeypatch.setattr("app.main.maybe_send_alert", fake_alert)

    files = {"file": ("hello.txt", b"hello world", "text/plain")}
    r = client.post("/upload", files=files)
    assert r.status_code == 200
    assert len(alert_calls) == 0