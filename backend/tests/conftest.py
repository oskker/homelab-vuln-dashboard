import os
from datetime import datetime
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text

from app.config import Settings
from app.db import Base, make_engine
from app.main import create_app
from app.parsers import ParsedFinding, ParsedHost, ParsedScan

SAMPLES = Path(__file__).resolve().parents[2] / "sample-data"
FIXTURES = Path(__file__).resolve().parent / "fixtures"
OPENVAS_DEMOS = sorted(SAMPLES.glob("openvas-demo-*.xml"))
DEMO_SCANS = sorted((FIXTURES / "nessus").glob("demo-scan-*.nessus"))  # Nessus fixtures
WRITE = {"X-Requested-With": "vulndash"}


# Tests use in-memory SQLite by default. Set TEST_DATABASE_URL to run the same suite
# against PostgreSQL, for example:
#   TEST_DATABASE_URL=postgresql+psycopg://user:pass@127.0.0.1:5432/vulndash_test pytest
TEST_DATABASE_URL = os.environ.get("TEST_DATABASE_URL", "sqlite:///:memory:")


def make_settings(**overrides) -> Settings:
    values = {"database_url": TEST_DATABASE_URL, "allowed_hosts": "testserver"}
    values.update(overrides)
    return Settings(**values)


@pytest.fixture(autouse=True)
def clean_database():
    """Each test starts from an empty schema, whichever database is in use."""
    yield
    if not TEST_DATABASE_URL.startswith("sqlite"):
        engine = make_engine(TEST_DATABASE_URL)
        Base.metadata.drop_all(engine)
        with engine.begin() as connection:
            connection.execute(text("DROP TABLE IF EXISTS alembic_version"))
        engine.dispose()


@pytest.fixture
def app():
    return create_app(make_settings())


@pytest.fixture
def client(app):
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def db(app, client):
    session = app.state.session_factory()
    try:
        yield session
    finally:
        session.close()


def upload(client: TestClient, path: Path):
    with path.open("rb") as handle:
        return client.post("/api/scans", files={"file": (path.name, handle)}, headers=WRITE)


def upload_bytes(client: TestClient, data: bytes, name: str = "scan.nessus"):
    return client.post("/api/scans", files={"file": (name, data)}, headers=WRITE)


@pytest.fixture
def loaded(client):
    """A client with the three Nessus fixture scans imported, oldest first."""
    for path in DEMO_SCANS:
        response = upload(client, path)
        assert response.status_code == 201, response.text
    return client


@pytest.fixture
def openvas_loaded(client):
    """A client with the eight OpenVAS demo reports imported, oldest first."""
    for path in OPENVAS_DEMOS:
        response = upload(client, path)
        assert response.status_code == 201, response.text
    return client


def one_host_scan(when: datetime, *plugin_ids: str, ip: str = "10.0.0.5") -> ParsedScan:
    findings = [
        ParsedFinding(
            plugin_id=pid, plugin_name=f"Plugin {pid}", severity=3, port=443, protocol="tcp"
        )
        for pid in plugin_ids
    ]
    return ParsedScan(source="nessus", hosts=[ParsedHost(ip=ip, scan_end=when, findings=findings)])
