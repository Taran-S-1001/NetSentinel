"""Tests for the scan session persistence layer."""

from __future__ import annotations

from flask_login import login_user

from app import create_app
from app.extensions import db
from app.models import PortResult, ScanSession, User
from app.repositories import PortResultRepository, ScanSessionRepository
from app.services import ScanSessionService


def test_session_and_results_can_be_created_and_retrieved(authenticated_app_context) -> None:
    """The persistence layer should create sessions and related port results."""
    app, test_user = authenticated_app_context

    with app.test_request_context():
        login_user(test_user)

        session_repo = ScanSessionRepository()
        result_repo = PortResultRepository()
        service = ScanSessionService(session_repo=session_repo, result_repo=result_repo)

        session = service.create_session(target_host="127.0.0.1", scan_type="tcp", protocol="tcp")
        assert isinstance(session, ScanSession)
        assert session.target_host == "127.0.0.1"

        result = service.save_result(
            session_id=session.id,
            port=80,
            protocol="tcp",
            service_name="http",
            status="OPEN",
            response_time=0.12,
            error_message=None,
        )

        assert isinstance(result, PortResult)
        assert result.scan_session_id == session.id
        assert result.port == 80

        finished = service.finish_session(session.id, status="completed")
        assert finished.status == "completed"
