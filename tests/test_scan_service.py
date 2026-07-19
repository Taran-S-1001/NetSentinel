"""Tests for the scan orchestration service."""

from __future__ import annotations

from flask_login import login_user

from app import create_app
from app.extensions import db
from app.repositories import PortResultRepository, ScanSessionRepository
from app.services import ScanService, ScanSessionService


def test_scan_service_orchestrates_scan_workflow(authenticated_app_context) -> None:
    """The scan service should create, execute, persist, and finalize a scan session."""
    app, test_user = authenticated_app_context

    with app.test_request_context():
        login_user(test_user)

        session_service = ScanSessionService(
            session_repo=ScanSessionRepository(),
            result_repo=PortResultRepository(),
        )
        service = ScanService(
            session_service=session_service,
            scanner=None,
        )

        result = service.start_scan(
            target_host="127.0.0.1",
            ports=[80, 443],
            scan_type="tcp",
            protocol="tcp",
        )

        assert result.target_host == "127.0.0.1"
        assert result.total_ports == 2
        assert result.open_ports >= 0
        assert result.closed_ports >= 0
        assert result.filtered_ports >= 0
        assert result.duration is not None
        assert result.scan_speed >= 0
        assert result.first_open_port is None or isinstance(result.first_open_port, int)
        assert result.last_open_port is None or isinstance(result.last_open_port, int)
        assert isinstance(result.most_common_service, str)
