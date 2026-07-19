"""Repository layer for SQLAlchemy data access."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional, Sequence

from app.extensions import db
from app.models import PortResult, ScanSession, TracerouteHop


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


class TracerouteHopRepository:
    """Repository for persisting traceroute hop observations."""

    def save_hops(
        self,
        scan_session_id: int,
        hops: Sequence[Any],
    ) -> list[TracerouteHop]:
        """Persist a sequence of traceroute hops for a scan session.

        Each hop may be a mapping or an object with ``hop_number``,
        ``ip_address``, ``hostname``, and ``round_trip_time_ms`` attributes.
        """
        persisted: list[TracerouteHop] = []
        for hop in hops:
            hop_number = self._hop_field(hop, "hop_number")
            if hop_number is None:
                continue
            row = TracerouteHop(
                scan_session_id=scan_session_id,
                hop_number=int(hop_number),
                ip_address=self._hop_field(hop, "ip_address"),
                hostname=self._hop_field(hop, "hostname"),
                round_trip_time_ms=self._hop_field(hop, "round_trip_time_ms"),
            )
            db.session.add(row)
            persisted.append(row)
        db.session.commit()
        return persisted

    def get_hops_for_session(self, scan_session_id: int) -> list[TracerouteHop]:
        """Return traceroute hops for a session ordered by hop number."""
        return (
            db.session.query(TracerouteHop)
            .filter(TracerouteHop.scan_session_id == scan_session_id)
            .order_by(TracerouteHop.hop_number)
            .all()
        )

    def list_all(self) -> list[TracerouteHop]:
        """Return all persisted traceroute hops across sessions."""
        return (
            db.session.query(TracerouteHop)
            .order_by(TracerouteHop.scan_session_id, TracerouteHop.hop_number)
            .all()
        )

    @staticmethod
    def _hop_field(hop: Any, name: str) -> Any:
        """Read a hop field from a mapping or attribute-bearing object."""
        if isinstance(hop, dict):
            return hop.get(name)
        return getattr(hop, name, None)
