"""
Integrationstester för Sentinel mot riktig MongoDB-instans.

Kräver att MongoDB körs lokalt på mongodb://localhost:27017
(eller via MONGODB_TEST_URI-miljövariabeln).

Kör med:
    pytest -m integration
    pytest -m integration -v --tb=short

Hoppas över automatiskt i CI om MongoDB inte är tillgänglig.
"""

import os
import pytest
import pytest_asyncio
from datetime import datetime
from app.scanner import ScanResult
from motor.motor_asyncio import AsyncIOMotorClient
from fastapi.testclient import TestClient

# ─── Konfiguration ────────────────────────────────────────────────────────────

MONGODB_TEST_URI = os.getenv("MONGODB_TEST_URI", "mongodb://localhost:27017")
TEST_DB_NAME = "sentinel_test"

# ─── Marker ───────────────────────────────────────────────────────────────────

pytestmark = pytest.mark.integration


# ─── Fixtures ─────────────────────────────────────────────────────────────────

@pytest.fixture(scope="session")
def mongo_client():
    """Motor-klient som delas över hela testsessionen."""
    client = AsyncIOMotorClient(MONGODB_TEST_URI, serverSelectionTimeoutMS=2000)
    yield client
    client.close()


@pytest_asyncio.fixture
async def test_db(mongo_client):
    """
    Ger en ren test-databas för varje test.
    Rensar uploads-kollektionen före och efter testet.
    """
    db = mongo_client[TEST_DB_NAME]
    await db.uploads.delete_many({})
    yield db
    await db.uploads.delete_many({})


@pytest.fixture
def integration_client(test_db, monkeypatch):
    """
    TestClient kopplad till riktig MongoDB.
    Sätter AUTH_MODE=off och pekar get_db mot test-databasen.
    """
    os.environ.setdefault("AUTH_MODE", "off")
    monkeypatch.setenv("MONGODB_TEST_URI", MONGODB_TEST_URI)

    # Importera app efter att env är satt
    from app.main import app, _upload_request_times
    _upload_request_times.clear()

    # Monkeypatcha get_db att returnera test-databasen
    monkeypatch.setattr("app.main.get_db", lambda: test_db)

    with TestClient(app) as client:
        yield client


# ─── Hjälpfunktioner ──────────────────────────────────────────────────────────

def upload_txt(client, content: bytes = b"hello world", filename: str = "test.txt"):
    """Skickar en enkel text/plain-uppladdning."""
    return client.post("/upload", files={"file": (filename, content, "text/plain")})


# ─── Tester ───────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_upload_stores_record_in_mongodb(integration_client, test_db):
    """Uppladdning ska spara ett dokument i MongoDB."""
    r = upload_txt(integration_client)
    assert r.status_code == 200
    body = r.json()

    doc = await test_db.uploads.find_one({"sha256": body["sha256"]})
    assert doc is not None
    assert doc["filename"] == "test.txt"
    assert doc["content_type"] == "text/plain"
    assert doc["status"] == "accepted"
    assert doc["scan_status"] == "clean"
    assert "created_at" in doc
    assert "user_id" in doc


@pytest.mark.asyncio
async def test_upload_deduplication_uses_real_db(integration_client, test_db):
    """Andra uppladdning av samma fil ska markeras som deduplicated i MongoDB."""
    r1 = upload_txt(integration_client, b"dedup-content")
    assert r1.status_code == 200
    assert r1.json()["deduplicated"] is False

    r2 = upload_txt(integration_client, b"dedup-content")
    assert r2.status_code == 200
    assert r2.json()["deduplicated"] is True

    # Båda dokumenten ska finnas i databasen
    docs = await test_db.uploads.find({"sha256": r1.json()["sha256"]}).to_list(10)
    assert len(docs) == 2
    assert any(d["deduplicated"] is False for d in docs)
    assert any(d["deduplicated"] is True for d in docs)


@pytest.mark.asyncio
async def test_uploads_list_returns_stored_records(integration_client, test_db):
    """GET /uploads ska returnera dokument från MongoDB."""
    upload_txt(integration_client, b"file-one", "one.txt")
    upload_txt(integration_client, b"file-two", "two.txt")

    r = integration_client.get("/uploads")
    assert r.status_code == 200
    items = r.json()["items"]
    assert len(items) == 2
    filenames = {item["filename"] for item in items}
    assert "one.txt" in filenames
    assert "two.txt" in filenames


@pytest.mark.asyncio
async def test_uploads_list_respects_limit(integration_client, test_db):
    """GET /uploads?limit=1 ska bara returnera ett dokument."""
    for i in range(3):
        upload_txt(integration_client, f"content-{i}".encode(), f"file{i}.txt")

    r = integration_client.get("/uploads?limit=1")
    assert r.status_code == 200
    assert len(r.json()["items"]) == 1


@pytest.mark.asyncio
async def test_metrics_summary_reflects_real_data(integration_client, test_db):
    """GET /metrics/summary ska räkna rätt på riktiga dokument."""
    upload_txt(integration_client, b"clean-file", "clean.txt")


    r = integration_client.get("/metrics/summary")
    assert r.status_code == 200
    body = r.json()
    assert body["all_time"]["total_uploads"] >= 1
    assert body["last_24h"]["total_uploads"] >= 1


@pytest.mark.asyncio
async def test_upload_record_has_correct_schema(integration_client, test_db):
    """Sparad post ska innehålla alla förväntade fält med rätt typer."""
    r = upload_txt(integration_client, b"schema-check")
    assert r.status_code == 200
    sha = r.json()["sha256"]

    doc = await test_db.uploads.find_one({"sha256": sha}, {"_id": 0})
    assert doc is not None

    expected_fields = {
        "filename", "sha256", "content_type", "status", "decision",
        "risk_score", "risk_reasons", "scan_status", "scan_engine",
        "scan_detail", "deduplicated", "user_id", "created_at",
    }
    assert expected_fields.issubset(doc.keys()), (
        f"Saknade fält: {expected_fields - doc.keys()}"
    )
    assert isinstance(doc["risk_score"], int)
    assert isinstance(doc["risk_reasons"], list)
    assert isinstance(doc["deduplicated"], bool)
    assert isinstance(doc["created_at"], datetime)


@pytest.mark.asyncio
async def test_ensure_upload_indexes_creates_indexes(test_db, monkeypatch):
    """ensure_upload_indexes ska skapa sha256- och TTL-index."""
    monkeypatch.setattr("app.db.get_db", lambda: test_db)

    from app.db import ensure_upload_indexes
    await ensure_upload_indexes()

    indexes = await test_db.uploads.index_information()
    index_keys = [
        list(v["key"].keys())[0]
        for v in indexes.values()
        if list(v["key"].keys())[0] != "_id"
    ]
    assert "sha256" in index_keys, "sha256-index saknas"
    assert "created_at" in index_keys, "TTL-index på created_at saknas"


@pytest.mark.asyncio
async def test_malicious_upload_stored_as_rejected(integration_client, test_db, monkeypatch):
    """Malicious-scan ska sparas med status=rejected och risk_score>=70."""
    monkeypatch.setattr(
        "app.main.scan_bytes",
        lambda _f, _c: ScanResult(status="malicious", engine="mock", detail="EICAR"),
    )

    r = upload_txt(integration_client, b"X5O!EICAR", "eicar.txt")
    assert r.status_code == 200

    doc = await test_db.uploads.find_one({"filename": "eicar.txt"})
    assert doc is not None
    assert doc["status"] == "rejected"
    assert doc["scan_status"] == "malicious"
    assert doc["risk_score"] >= 70
