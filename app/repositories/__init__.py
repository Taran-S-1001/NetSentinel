"""Repository layer for SQLAlchemy data access."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from app.extensions import db
from app.models import PortResult, ScanSession


class ScanRepository:
    """Repository responsible for legacy scan-related database operations."""

    def count_scans(self) -> int:
        """Return the number of stored scan results."""
        return db.session.query(PortResult).count()


class ScanSessionRepository:
    """Repository for session-level persistence operations."""

    def create(self, *, target_host: str, scan_type: str, protocol: str) -> ScanSession:
        """Create and persist a new scan session."""
        session = ScanSession(
            target_host=target_host,
            scan_type=scan_type,
            protocol=protocol,
            status="running",
            start_time=datetime.now(timezone.utc),
        )
        db.session.add(session)
        db.session.commit()
        return session

    def get_by_id(self, session_id: int) -> Optional[ScanSession]:
        """Retrieve a scan session by its identifier."""
        return db.session.get(ScanSession, session_id)

    def update(self, session: ScanSession) -> ScanSession:
        """Persist updates to an existing scan session."""
        db.session.add(session)
        db.session.commit()
        return session

    def list_all(self) -> list[ScanSession]:
        """Return all persisted scan sessions."""
        return db.session.query(ScanSession).order_by(ScanSession.created_at.desc()).all()

    def delete(self, session: ScanSession) -> None:
        """Delete a scan session and its associated port results."""
        db.session.delete(session)
        db.session.commit()


class ScheduledScanRepository:
    """Repository for recurring scan schedule persistence."""

    def create(
        self,
        *,
        target_host: str,
        scan_type: str,
        protocol: str,
        start_port: int,
        end_port: int,
        interval_seconds: int,
        enabled: bool = True,
        alert_email: Optional[str] = None,
        alert_webhook: Optional[str] = None,
    ) -> "ScheduledScan":
        from app.models import ScheduledScan

        schedule = ScheduledScan(
            target_host=target_host,
            scan_type=scan_type,
            protocol=protocol,
            start_port=start_port,
            end_port=end_port,
            interval_seconds=interval_seconds,
            enabled=enabled,
            alert_email=alert_email,
            alert_webhook=alert_webhook,
        )
        db.session.add(schedule)
        db.session.commit()
        return schedule

    def get_by_id(self, schedule_id: int) -> Optional["ScheduledScan"]:
        from app.models import ScheduledScan

        return db.session.get(ScheduledScan, schedule_id)

    def list_all(self) -> list["ScheduledScan"]:
        from app.models import ScheduledScan

        return db.session.query(ScheduledScan).order_by(ScheduledScan.created_at.desc()).all()

    def list_active(self) -> list["ScheduledScan"]:
        from app.models import ScheduledScan

        return (
            db.session.query(ScheduledScan)
            .filter(ScheduledScan.enabled.is_(True))
            .order_by(ScheduledScan.created_at.desc())
            .all()
        )

    def update(self, schedule: "ScheduledScan") -> "ScheduledScan":
        db.session.add(schedule)
        db.session.commit()
        return schedule

    def delete(self, schedule: "ScheduledScan") -> None:
        db.session.delete(schedule)
        db.session.commit()


class PortResultRepository:
    """Repository for persisting individual port scan results."""

    def create(
        self,
        *,
        scan_session_id: int,
        port: int,
        protocol: str,
        service_name: Optional[str],
        status: str,
        response_time: Optional[float],
        error_message: Optional[str],
    ) -> PortResult:
        """Create and persist a new port result entry."""
        result = PortResult(
            scan_session_id=scan_session_id,
            port=port,
            protocol=protocol,
            service_name=service_name,
            status=status,
            response_time=response_time,
            error_message=error_message,
        )
        db.session.add(result)
        db.session.commit()
        return result

    def list_for_session(self, session_id: int) -> list[PortResult]:
        """Return all port results associated with a session."""
        return (
            db.session.query(PortResult)
            .filter(PortResult.scan_session_id == session_id)
            .order_by(PortResult.port)
            .all()
        )
