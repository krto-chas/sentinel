import pytest
from fastapi.testclient import TestClient
from app.main import app, _upload_request_times


@pytest.fixture
def client():
    _upload_request_times.clear()
    with TestClient(app) as test_client:
        yield test_client
