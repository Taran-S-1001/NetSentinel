"""Tests for scheduled scan persistence, execution, and deletion."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from app.extensions import db
from app.models import ScanSession, ScheduledScan, User
from app.repositories import ScanSessionRepository, ScheduledScanRepository
from app.services.scheduled_scan import ScheduledScanManager


def _create_schedule(
    repository: ScheduledScanRepository,
    *,
    user_id: int,
    enabled: bool = True,
) -> ScheduledScan:
    """Create a representative recurring scan configuration."""
    return repository.create(
        user_id=user_id,
        target_host="127.0.0.1",
        scan_type="tcp",
        protocol="tcp",
        start_port=80,
        end_port=81,
        interval_seconds=60,
        enabled=enabled,
    )


def test_scheduled_scan_repository_crud(app) -> None:
    """Schedules can be created, listed, updated, and deleted."""
    with app.app_context():
        repository = ScheduledScanRepository()
        user = User(username="scheduler", email="scheduler@example.com", password_hash="hash")
        db.session.add(user)
        db.session.commit()
        enabled_schedule = _create_schedule(repository, user_id=user.id)
        disabled_schedule = _create_schedule(repository, user_id=user.id, enabled=False)

        assert [item.id for item in repository.list_all()] == [disabled_schedule.id, enabled_schedule.id]
        assert [item.id for item in repository.list_active()] == [enabled_schedule.id]

        enabled_schedule.interval_seconds = 120
        assert repository.update(enabled_schedule).interval_seconds == 120

        repository.delete(disabled_schedule)
        assert repository.get_by_id(disabled_schedule.id) is None


def test_list_by_host_returns_newest_sessions_first(app) -> None:
    """Host filtering supports schedule comparisons without request auth."""
    with app.app_context():
        user = User(username="scanner", email="scanner@example.com", password_hash="hash")
        db.session.add(user)
        db.session.flush()
        older = ScanSession(
            user_id=user.id,
            target_host="127.0.0.1",
            scan_type="tcp",
            protocol="tcp",
            created_at=datetime.now(timezone.utc) - timedelta(minutes=1),
        )
        newer = ScanSession(
            user_id=user.id,
            target_host="127.0.0.1",
            scan_type="tcp",
            protocol="tcp",
            created_at=datetime.now(timezone.utc),
        )
        other_host = ScanSession(
            user_id=user.id,
            target_host="example.com",
            scan_type="tcp",
            protocol="tcp",
        )
        db.session.add_all([older, newer, other_host])
        db.session.commit()

        assert [item.id for item in ScanSessionRepository().list_by_host("127.0.0.1")] == [newer.id, older.id]


@pytest.mark.parametrize("should_fail, expected_status", [(False, "completed"), (True, "failed")])
def test_run_job_records_status(app, should_fail: bool, expected_status: str) -> None:
    """Each scheduled run persists a completed or failed status."""
    with app.app_context():
        user = User(username="runner", email="runner@example.com", password_hash="hash")
        db.session.add(user)
        db.session.commit()
        schedule = _create_schedule(ScheduledScanRepository(), user_id=user.id)
        session = ScanSession(
            user_id=user.id,
            target_host=schedule.target_host,
            scan_type="tcp",
            protocol="tcp",
        )
        db.session.add(session)
        db.session.commit()

        scan_service = Mock()
        if should_fail:
            scan_service.start_scan.side_effect = RuntimeError("scanner unavailable")
        else:
            scan_service.start_scan.return_value = SimpleNamespace(scan_id=session.id)
            scan_service.get_scan_by_id.return_value = session

        manager = ScheduledScanManager(app, scan_service=scan_service)
        manager._run_job(schedule.id)

        db.session.expire_all()
        refreshed = ScheduledScanRepository().get_by_id(schedule.id)
        assert refreshed is not None
        assert refreshed.last_run_at is not None
        assert refreshed.last_status == expected_status
        if not should_fail:
            assert scan_service.start_scan.call_args.kwargs["user_id"] == schedule.user_id
            assert scan_service.get_scan_by_id.call_args.kwargs["user_id"] == schedule.user_id


def test_delete_schedule_route_removes_schedule_and_job(authenticated_client, app) -> None:
    """Deleting a schedule also asks the active scheduler to remove its job."""
    with app.app_context():
        user = User.query.filter_by(email="test@example.com").one()
        schedule = _create_schedule(ScheduledScanRepository(), user_id=user.id)
        manager = Mock()
        app.scheduled_scan_manager = manager
        app.config["SCHEDULER_ENABLED"] = True
        schedule_id = schedule.id

    response = authenticated_client.post(
        f"/schedules/{schedule_id}/delete",
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert b"Scheduled scan deleted successfully." in response.data
    with app.app_context():
        assert ScheduledScanRepository().get_by_id(schedule_id) is None
    manager.remove_schedule.assert_called_once_with(schedule_id)
