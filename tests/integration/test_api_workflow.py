"""Authenticated API workflow tests with scanners fully mocked."""

from datetime import date, timedelta

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database import Base, get_db
from app.main import app


def test_authorized_scan_api_enforces_scope_and_never_runs_external_scanner(
    tmp_path, monkeypatch
):
    engine = create_engine(f"sqlite:///{tmp_path / 'integration.db'}")
    session_local = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    Base.metadata.create_all(bind=engine)

    def override_db():
        with session_local() as session:
            yield session

    app.dependency_overrides[get_db] = override_db
    monkeypatch.setattr("app.api.scans.scan_orchestrator.start", lambda scan_id: None)
    client = TestClient(app)
    try:
        setup = client.post(
            "/api/auth/setup",
            json={
                "username": "integration-admin",
                "email": "integration.admin@example.com",
                "password": "a-strong-test-password",
                "role": "admin",
            },
        )
        assert setup.status_code == 201
        token = client.post(
            "/api/auth/token",
            data={"username": "integration-admin", "password": "a-strong-test-password"},
        ).json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}
        engagement = client.post(
            "/api/engagements",
            headers=headers,
            json={
                "name": "Integration authorization",
                "customer": "Example owner",
                "authorization_reference": "TEST-ONLY",
                "start_date": str(date.today()),
                "expiry_date": str(date.today() + timedelta(days=1)),
                "approved_targets": ["8.8.8.8/32"],
                "exclusions": [],
            },
        )
        assert engagement.status_code == 201
        engagement_id = engagement.json()["public_id"]
        accepted = client.post(
            "/api/scans",
            headers=headers,
            json={
                "engagement_id": engagement_id,
                "targets": ["8.8.8.8"],
                "profile": "quick",
                "authorized": True,
                "initiated_by": "integration-admin",
            },
        )
        assert accepted.status_code == 202
        rejected = client.post(
            "/api/scans",
            headers=headers,
            json={
                "engagement_id": engagement_id,
                "targets": ["10.0.0.1"],
                "profile": "quick",
                "authorized": True,
                "initiated_by": "integration-admin",
            },
        )
        assert rejected.status_code == 422
    finally:
        app.dependency_overrides.clear()
        engine.dispose()
