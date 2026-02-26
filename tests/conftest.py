import os
import pytest
from fastapi.testclient import TestClient

# Sätt AUTH_MODE=off innan app importeras så testerna inte kräver API-nyckel
os.environ.setdefault("AUTH_MODE", "off")

from app.main import app, _upload_request_times


@pytest.fixture
def client():
    _upload_request_times.clear()
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def authed_client():
    """Klient med API-nyckelautentisering aktiverad."""
    os.environ["AUTH_MODE"] = "apikey"
    os.environ["SENTINEL_API_KEYS"] = "testuser:test-secret-key"
    # Importera om auth-modulen så den plockar upp de nya env-variablerna
    import importlib
    import app.auth as auth_module
    importlib.reload(auth_module)

    _upload_request_times.clear()
    with TestClient(app) as test_client:
        yield test_client

    # Återställ
    os.environ["AUTH_MODE"] = "off"
    importlib.reload(auth_module)