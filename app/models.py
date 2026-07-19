"""SQLAlchemy models for persistent scan sessions and port results."""

from __future__ import annotations

from datetime import datetime, timezone
from flask_login import UserMixin
from app.extensions import db

class User(UserMixin, db.Model):
    """Represents an authenticated user."""

    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)

    username = db.Column(
        db.String(80),
        unique=True,
        nullable=False,
    )

    email = db.Column(
        db.String(120),
        unique=True,
        nullable=False,
    )

    password_hash = db.Column(
        db.String(255),
        nullable=False,
    )

    role = db.Column(
        db.String(20),
        default="viewer",
        nullable=False,
    )

    created_at = db.Column(
        db.DateTime,
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    scan_sessions = db.relationship(
        "ScanSession",
        back_populates="user",
        cascade="all, delete-orphan",
        lazy="select",
    )

class ScanSession(db.Model):  # type: ignore[name-defined]
    """Represents a single scan session executed by the scanner."""

    __tablename__ = "scan_sessions"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(
    db.Integer,
    db.ForeignKey("users.id", ondelete="CASCADE"),
    nullable=False,
    )
    target_host = db.Column(db.String(255), nullable=False)
    scan_type = db.Column(db.String(50), nullable=False)
    protocol = db.Column(db.String(20), nullable=False)
    start_time = db.Column(db.DateTime, nullable=True)
    end_time = db.Column(db.DateTime, nullable=True)
    duration = db.Column(db.Float, nullable=True)
    total_ports = db.Column(db.Integer, nullable=True, default=0)
    open_ports = db.Column(db.Integer, nullable=True, default=0)
    closed_ports = db.Column(db.Integer, nullable=True, default=0)
    filtered_ports = db.Column(db.Integer, nullable=True, default=0)
    status = db.Column(db.String(50), nullable=False, default="running")
    # OS fingerprint guess from TTL heuristics (Phase 3 persistence).
    # Note: adding this column to an existing SQLite DB requires deleting
    # netsentinel.db (or a raw ALTER TABLE) — db.create_all() will not alter
    # already-created tables.
    os_guess = db.Column(db.String(100), nullable=True)
    created_at = db.Column(
        db.DateTime,
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    user = db.relationship(
    "User",
    back_populates="scan_sessions",
    )   
    
    port_results = db.relationship(
        "PortResult",
        back_populates="scan_session",
        cascade="all, delete-orphan",
        lazy="select",
    )
    traceroute_hops = db.relationship(
        "TracerouteHop",
        back_populates="scan_session",
        cascade="all, delete-orphan",
        lazy="select",
    )


class PortResult(db.Model):  # type: ignore[name-defined]
    """Represents the outcome of a single scanned port within a session."""

    __tablename__ = "port_results"

    id = db.Column(db.Integer, primary_key=True)
    scan_session_id = db.Column(
        db.Integer,
        db.ForeignKey("scan_sessions.id", ondelete="CASCADE"),
        nullable=False,
    )
    port = db.Column(db.Integer, nullable=False)
    protocol = db.Column(db.String(20), nullable=False)
    service_name = db.Column(db.String(100), nullable=True)
    status = db.Column(db.String(50), nullable=False, default="pending")
    response_time = db.Column(db.Float, nullable=True)
    error_message = db.Column(db.Text, nullable=True)

    scan_session = db.relationship("ScanSession", back_populates="port_results")


<<<<<<< HEAD
class Vulnerability(db.Model):  # type: ignore[name-defined]
    """Represents a vulnerability instance (CVE) discovered or recorded in the system."""

    __tablename__ = "vulnerabilities"

    id = db.Column(db.Integer, primary_key=True)
    cve_id = db.Column(db.String(50), nullable=False, index=True)
    summary = db.Column(db.Text, nullable=True)
    cvss = db.Column(db.Float, nullable=True)
    references = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))

    vulnerable_ports = db.relationship(
        "VulnerablePort",
        back_populates="vulnerability",
        cascade="all, delete-orphan",
        lazy="select",
    )


class VulnerablePort(db.Model):  # type: ignore[name-defined]
    """Join table linking a `PortResult` to discovered `Vulnerability` entries."""

    __tablename__ = "vulnerable_ports"

    id = db.Column(db.Integer, primary_key=True)
    port_result_id = db.Column(
        db.Integer, db.ForeignKey("port_results.id", ondelete="CASCADE"), nullable=False
    )
    vulnerability_id = db.Column(
        db.Integer, db.ForeignKey("vulnerabilities.id", ondelete="CASCADE"), nullable=False
    )
    
    port_result = db.relationship("PortResult", backref="vulnerable_links")
    vulnerability = db.relationship("Vulnerability", back_populates="vulnerable_ports")
=======
class TracerouteHop(db.Model):  # type: ignore[name-defined]
    """Persisted traceroute hop observed during a scan session.

    Distinct from the in-memory ``app.scanner.models.TracerouteHop`` dataclass,
    which remains the transient shape used during a live scan.
    """

    __tablename__ = "traceroute_hops"

    id = db.Column(db.Integer, primary_key=True)
    scan_session_id = db.Column(
        db.Integer,
        db.ForeignKey("scan_sessions.id", ondelete="CASCADE"),
        nullable=False,
    )
    hop_number = db.Column(db.Integer, nullable=False)
    ip_address = db.Column(db.String(255), nullable=True)
    hostname = db.Column(db.String(255), nullable=True)
    round_trip_time_ms = db.Column(db.Float, nullable=True)

    scan_session = db.relationship("ScanSession", back_populates="traceroute_hops")
>>>>>>> origin/feature/realtime-progress-fingerprinting
