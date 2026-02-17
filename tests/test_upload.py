import pytest
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


def test_upload_rate_limit_returns_429_when_exceeded(monkeypatch):
    monkeypatch.setattr("app.main.RATE_LIMIT_UPLOADS_PER_MINUTE", 3)
    monkeypatch.setattr("app.main.RATE_LIMIT_WINDOW_SECONDS", 60)
    _upload_request_times.clear()

    for _ in range(3):
        enforce_upload_rate_limit("ci-test-client")

    with pytest.raises(HTTPException) as exc:
        enforce_upload_rate_limit("ci-test-client")

    assert exc.value.status_code == 429
