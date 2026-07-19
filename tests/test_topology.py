"""Tests for Phase 3 network topology persistence and aggregation."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from flask_login import login_user

from app import create_app
from app.analytics.dashboard import DashboardService
from app.extensions import db
from app.models import ScanSession, TracerouteHop, User
from app.repositories import (
    ScanSessionRepository,
    TracerouteHopRepository,
)


@pytest.fixture
def app():
    """Create a Flask app instance for testing."""
    app = create_app("testing")
    with app.app_context():
        db.drop_all()
        db.create_all()
        # Create test user
        from app.extensions import bcrypt
        hashed_password = bcrypt.generate_password_hash("testpass123").decode("utf-8")
        user = User(
            username="testuser",
            email="test@example.com",
            password_hash=hashed_password,
        )
        db.session.add(user)
        db.session.commit()
        user = db.session.get(User, user.id)
        yield app, user


@pytest.fixture
def client(app):
    """Create a test client for the Flask app."""
    app_instance, user = app
    with app_instance.test_client() as client:
        # Log in the test user
        client.post(
            "/login",
            data={"email": user.email, "password": "testpass123"},
            follow_redirects=False,
        )
        yield client


def test_traceroute_hop_repository_save_and_get(app) -> None:
    """TracerouteHopRepository should persist and retrieve hops for a session."""
    app_instance, test_user = app
    with app_instance.app_context():
        with app_instance.test_request_context():
            login_user(test_user)

            session = ScanSessionRepository().create(
                target_host="8.8.8.8",
                scan_type="tcp",
                protocol="tcp",
            )
            hop_repo = TracerouteHopRepository()
            saved = hop_repo.save_hops(
                session.id,
                [
                    {
                        "hop_number": 1,
                        "ip_address": "192.168.1.1",
                        "hostname": "gateway.local",
                        "round_trip_time_ms": 1.5,
                    },
                    {
                        "hop_number": 2,
                        "ip_address": "8.8.8.8",
                        "hostname": None,
                        "round_trip_time_ms": 12.0,
                    },
                ],
            )

            assert len(saved) == 2
            assert all(isinstance(hop, TracerouteHop) for hop in saved)

            loaded = hop_repo.get_hops_for_session(session.id)
            assert len(loaded) == 2
            assert loaded[0].hop_number == 1
            assert loaded[0].ip_address == "192.168.1.1"
            assert loaded[0].hostname == "gateway.local"
            assert loaded[0].round_trip_time_ms == 1.5
            assert loaded[1].ip_address == "8.8.8.8"


def test_network_topology_deduplicates_ips_and_averages_latency() -> None:
    """Topology aggregation should merge hops by IP and average edge latency."""
    sessions = [
        ScanSession(
            id=1,
            target_host="10.0.0.5",
            scan_type="tcp",
            protocol="tcp",
            status="completed",
            os_guess="Linux (likely)",
            created_at=datetime(2024, 1, 2, 10, 0, tzinfo=timezone.utc),
        ),
        ScanSession(
            id=2,
            target_host="10.0.0.5",
            scan_type="tcp",
            protocol="tcp",
            status="completed",
            os_guess="Linux (likely)",
            created_at=datetime(2024, 1, 3, 10, 0, tzinfo=timezone.utc),
        ),
    ]
    hops = [
        TracerouteHop(
            id=1,
            scan_session_id=1,
            hop_number=1,
            ip_address="192.168.0.1",
            hostname=None,
            round_trip_time_ms=2.0,
        ),
        TracerouteHop(
            id=2,
            scan_session_id=1,
            hop_number=2,
            ip_address="10.0.0.5",
            hostname=None,
            round_trip_time_ms=10.0,
        ),
        TracerouteHop(
            id=3,
            scan_session_id=2,
            hop_number=1,
            ip_address="192.168.0.1",
            hostname=None,
            round_trip_time_ms=4.0,
        ),
        TracerouteHop(
            id=4,
            scan_session_id=2,
            hop_number=2,
            ip_address="10.0.0.5",
            hostname=None,
            round_trip_time_ms=14.0,
        ),
    ]

    class FakeSessionRepository(ScanSessionRepository):
        def list_all(self) -> list[ScanSession]:
            return list(sessions)

    class FakeHopRepository(TracerouteHopRepository):
        def list_all(self) -> list[TracerouteHop]:
            return list(hops)

        def get_hops_for_session(self, scan_session_id: int) -> list[TracerouteHop]:
            return [hop for hop in hops if hop.scan_session_id == scan_session_id]

    service = DashboardService(
        session_repo=FakeSessionRepository(),
        hop_repo=FakeHopRepository(),
    )
    topology = service.get_network_topology()

    assert topology["empty"] is False
    node_ids = {node["id"] for node in topology["nodes"]}
    assert "source" in node_ids
    assert "hop:192.168.0.1" in node_ids
    assert "target:10.0.0.5" in node_ids
    # Duplicate IP across sessions collapses to a single hop node
    assert sum(1 for node in topology["nodes"] if node["id"] == "hop:192.168.0.1") == 1

    target = next(node for node in topology["nodes"] if node["id"] == "target:10.0.0.5")
    assert target["type"] == "target"
    assert target["os_guess"] == "Linux (likely)"
    assert "Linux (likely)" in target["label"]

    edge_map = {(edge["from"], edge["to"]): edge["avg_latency_ms"] for edge in topology["edges"]}
    assert edge_map[("source", "hop:192.168.0.1")] == 3.0  # avg of 2.0 and 4.0
    assert edge_map[("hop:192.168.0.1", "target:10.0.0.5")] == 12.0  # avg of 10.0 and 14.0


def test_network_topology_empty_when_no_hops() -> None:
    """Topology should report an empty state when no hops are stored."""

    class FakeSessionRepository(ScanSessionRepository):
        def list_all(self) -> list[ScanSession]:
            return []

    class FakeHopRepository(TracerouteHopRepository):
        def list_all(self) -> list[TracerouteHop]:
            return []

    service = DashboardService(
        session_repo=FakeSessionRepository(),
        hop_repo=FakeHopRepository(),
    )
    topology = service.get_network_topology()
    assert topology["empty"] is True
    assert topology["nodes"] == []
    assert topology["edges"] == []


def test_topology_route_returns_seeded_graph(app, client) -> None:
    """The /topology route should render with graph data from seeded hops."""
    app_instance, test_user = app
    with app_instance.app_context():
        with app_instance.test_request_context():
            login_user(test_user)

            session_repo = ScanSessionRepository()
            hop_repo = TracerouteHopRepository()
            session = session_repo.create(
                target_host="203.0.113.10",
                scan_type="tcp",
                protocol="tcp",
            )
            session.os_guess = "Windows (likely)"
            session.status = "completed"
            session_repo.update(session)

            hop_repo.save_hops(
                session.id,
                [
                    {
                        "hop_number": 1,
                        "ip_address": "198.51.100.1",
                        "hostname": None,
                        "round_trip_time_ms": 5.0,
                    },
                    {
                        "hop_number": 2,
                        "ip_address": "203.0.113.10",
                        "hostname": None,
                        "round_trip_time_ms": 20.0,
                    },
                ],
            )

        with app_instance.test_client() as client:
            # Log in
            client.post(
                "/login",
                data={"email": test_user.email, "password": "testpass123"},
                follow_redirects=False,
            )
            response = client.get("/topology")
            assert response.status_code == 200
            body = response.data.decode("utf-8")
            assert "Network Topology" in body
            assert "topology-network" in body
            assert "203.0.113.10" in body
            assert "198.51.100.1" in body
            assert "vis-network" in body


def test_topology_route_empty_state(app, client) -> None:
    """The /topology route should show a friendly empty state with no hops."""
    response = client.get("/topology")
    assert response.status_code == 200
    body = response.data.decode("utf-8")
    assert "No topology data yet" in body
    assert "topology builds up" in body.lower()
    assert "topology-network" not in body
