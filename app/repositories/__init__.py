"""Repository layer for SQLAlchemy data access."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from app.extensions import db
from app.models import PortResult, ScanSession
from flask_login import current_user

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
            user_id=current_user.id,
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
        """Retrieve a scan session belonging to the current user."""
        return (
            db.session.query(ScanSession)
            .filter(
            ScanSession.id == session_id,
            ScanSession.user_id == current_user.id,
        )
        .first()
    )

    def update(self, session: ScanSession) -> ScanSession:
        """Persist updates to an existing scan session."""
        db.session.add(session)
        db.session.commit()
        return session

    def list_all(self) -> list[ScanSession]:
        """Return scan sessions for the current user only."""
        return (
        db.session.query(ScanSession)
        .filter(ScanSession.user_id == current_user.id)
        .order_by(ScanSession.created_at.desc())
        .all()
        )

    def delete(self, session: ScanSession) -> None:
        """Delete a scan session and its associated port results."""
        db.session.delete(session)
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
