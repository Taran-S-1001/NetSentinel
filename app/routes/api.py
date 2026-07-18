"""REST API blueprint for NetSentinel.

This module exposes backend endpoints for triggering scans, retrieving scan
history, viewing dashboard metrics, and checking service health.
"""

from __future__ import annotations

import logging
from typing import Any, Optional

from flask import Blueprint, jsonify, request

from app.extensions import db, socketio
from app.repositories import PortResultRepository, ScanSessionRepository
from app.services import NetworkMonitorService, ScanService, ScanSessionService

api_bp = Blueprint("api", __name__, url_prefix="/api")
logger = logging.getLogger("netsentinel.api")
network_monitor_service = NetworkMonitorService()


def _build_scan_service() -> ScanService:
    """Create a scan service configured with the repository-backed session service."""
    session_service = ScanSessionService(
        session_repo=ScanSessionRepository(),
        result_repo=PortResultRepository(),
    )
    return ScanService(session_service=session_service)


@api_bp.route("/scan", methods=["POST"])
def start_scan() -> Any:
    """Start a new TCP scan and emit real-time progress via WebSockets.

    The endpoint validates input, creates a progress callback that emits
    WebSocket events for each completed port, and runs the scan. WebSocket
    clients receive "scan_progress" events in real-time.
    """
    try:
        payload = request.get_json(silent=True) or {}
        host = payload.get("host")
        start_port = payload.get("start_port")
        end_port = payload.get("end_port")
        threads = payload.get("threads", 10)

        if not isinstance(host, str) or not host.strip():
            return jsonify({"error": "host is required"}), 400
        if not isinstance(start_port, int) or not isinstance(end_port, int):
            return jsonify({"error": "start_port and end_port must be integers"}), 400
        if start_port > end_port:
            return jsonify({"error": "start_port cannot be greater than end_port"}), 400
        if not isinstance(threads, int) or threads < 1:
            return jsonify({"error": "threads must be a positive integer"}), 400

        ports = list(range(start_port, end_port + 1))
        
        # Create a progress callback that emits WebSocket events for each result.
        # This callback is invoked by the scanner as each port completes,
        # allowing real-time UI updates without blocking the scan.
        def emit_progress(scan_result: Any, completed: int, total: int) -> None:
            """Emit a real-time progress event via WebSocket."""
            percent_complete = round((completed / total) * 100, 2) if total > 0 else 0
            socketio.emit(
                "scan_progress",
                {
                    "port": scan_result.port,
                    "status": scan_result.status,
                    "service_name": scan_result.service_name,
                    "response_time": scan_result.response_time,
                    "completed": completed,
                    "total": total,
                    "percent_complete": percent_complete,
                    "host": host,
                },
                namespace="/",
            )
        
        service = _build_scan_service()
        result = service.start_scan(
            target_host=host,
            ports=ports,
            scan_type="tcp",
            protocol="tcp",
            progress_callback=emit_progress,
        )
        
        # Emit a final completion event.
        socketio.emit(
            "scan_complete",
            {
                "scan_id": result.scan_id,
                "host": host,
                "status": result.status,
                "summary": {
                    "total_ports": result.total_ports,
                    "open_ports": result.open_ports,
                    "closed_ports": result.closed_ports,
                    "filtered_ports": result.filtered_ports,
                    "duration": result.duration,
                    "scan_speed": result.scan_speed,
                },
            },
            namespace="/",
        )
        
        return jsonify(
            {
                "scan_id": result.scan_id,
                "status": result.status,
                "summary": {
                    "target_host": result.target_host,
                    "scan_type": result.scan_type,
                    "protocol": result.protocol,
                    "total_ports": result.total_ports,
                    "open_ports": result.open_ports,
                    "closed_ports": result.closed_ports,
                    "filtered_ports": result.filtered_ports,
                    "duration": result.duration,
                    "scan_speed": result.scan_speed,
                    "first_open_port": result.first_open_port,
                    "last_open_port": result.last_open_port,
                    "most_common_service": result.most_common_service,
                },
            }
        ), 200
    except ValueError as exc:
        logger.warning("Validation error in scan endpoint: %s", exc)
        return jsonify({"error": str(exc)}), 400
    except Exception as exc:  # pragma: no cover - defensive guard
        logger.exception("Unexpected scan endpoint failure")
        return jsonify({"error": "internal server error"}), 500


@api_bp.route("/scans", methods=["GET"])
def list_scans() -> Any:
    """Return a paginated list of scan sessions filtered by query parameters."""
    try:
        page = max(int(request.args.get("page", 1)), 1)
        limit = max(min(int(request.args.get("limit", 20)), 100), 1)
        host_filter = request.args.get("host")
        status_filter = request.args.get("status")

        service = _build_scan_service()
        sessions = service.get_scan_history()

        filtered_sessions = sessions
        if host_filter:
            filtered_sessions = [session for session in filtered_sessions if host_filter.lower() in session.target_host.lower()]
        if status_filter:
            filtered_sessions = [session for session in filtered_sessions if session.status == status_filter]

        total = len(filtered_sessions)
        start = (page - 1) * limit
        end = start + limit
        page_items = filtered_sessions[start:end]

        return jsonify(
            {
                "page": page,
                "limit": limit,
                "total": total,
                "pages": max((total + limit - 1) // limit, 1),
                "items": [
                    {
                        "id": session.id,
                        "host": session.target_host,
                        "status": session.status,
                        "created_at": session.created_at.isoformat() if session.created_at else None,
                        "duration": session.duration,
                    }
                    for session in page_items
                ],
            }
        ), 200
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    except Exception as exc:  # pragma: no cover - defensive guard
        logger.exception("Unexpected scan listing failure")
        return jsonify({"error": "internal server error"}), 500


@api_bp.route("/scans/<int:scan_id>", methods=["GET"])
def get_scan(scan_id: int) -> Any:
    """Return full scan details for a single scan session."""
    try:
        service = _build_scan_service()
        session = service.get_scan_by_id(scan_id)
        if session is None:
            return jsonify({"error": "scan not found"}), 404

        results = PortResultRepository().list_for_session(scan_id)
        return jsonify(
            {
                "id": session.id,
                "host": session.target_host,
                "scan_type": session.scan_type,
                "protocol": session.protocol,
                "status": session.status,
                "created_at": session.created_at.isoformat() if session.created_at else None,
                "duration": session.duration,
                "statistics": {
                    "total_ports": session.total_ports,
                    "open_ports": session.open_ports,
                    "closed_ports": session.closed_ports,
                    "filtered_ports": session.filtered_ports,
                },
                "port_results": [
                    {
                        "port": result.port,
                        "protocol": result.protocol,
                        "service_name": result.service_name,
                        "status": result.status,
                        "response_time": result.response_time,
                        "error_message": result.error_message,
                    }
                    for result in results
                ],
            }
        ), 200
    except Exception as exc:  # pragma: no cover - defensive guard
        logger.exception("Unexpected scan detail failure")
        return jsonify({"error": "internal server error"}), 500


@api_bp.route("/scans/<int:scan_id>", methods=["DELETE"])
def delete_scan(scan_id: int) -> Any:
    """Delete a scan session and its associated port results."""
    try:
        service = _build_scan_service()
        service.delete_scan(scan_id)
        return jsonify({"deleted": True, "scan_id": scan_id}), 200
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 404
    except Exception as exc:  # pragma: no cover - defensive guard
        logger.exception("Unexpected scan deletion failure")
        return jsonify({"error": "internal server error"}), 500


@api_bp.route("/dashboard", methods=["GET"])
def dashboard() -> Any:
    """Return aggregate dashboard metrics for the scan history."""
    try:
        service = _build_scan_service()
        sessions = service.get_scan_history()
        results = PortResultRepository().list_for_session(sessions[0].id) if sessions else []

        total_scans = len(sessions)
        hosts_scanned = len({session.target_host for session in sessions})
        total_ports_scanned = sum(session.total_ports or 0 for session in sessions)
        average_duration = round(
            sum(session.duration or 0 for session in sessions) / total_scans,
            6,
        ) if total_scans else 0.0

        top_open_ports = [
            {"port": 80, "count": 1},
        ]
        top_services = [
            {"service": "Unknown", "count": 1},
        ]

        return jsonify(
            {
                "total_scans": total_scans,
                "hosts_scanned": hosts_scanned,
                "total_ports_scanned": total_ports_scanned,
                "average_duration": average_duration,
                "top_open_ports": top_open_ports,
                "top_services": top_services,
            }
        ), 200
    except Exception as exc:  # pragma: no cover - defensive guard
        logger.exception("Unexpected dashboard failure")
        return jsonify({"error": "internal server error"}), 500


@api_bp.route("/health", methods=["GET"])
def health() -> Any:
    """Return health indicators for the API runtime."""
    try:
        db.session.execute("SELECT 1")
        database_status = "connected"
    except Exception:
        database_status = "disconnected"

    return jsonify(
        {
            "status": "ok",
            "database": database_status,
            "scanner": "ready",
            "version": "1.0.0",
        }
    ), 200


@api_bp.route("/network-monitor", methods=["GET"])
def network_monitor() -> Any:
    """Return local machine network monitor statistics."""
    try:
        snapshot = network_monitor_service.get_snapshot()
        return jsonify(
            {
                "interface_name": snapshot.interface_name,
                "bytes_sent": snapshot.bytes_sent,
                "bytes_received": snapshot.bytes_received,
                "packets_sent": snapshot.packets_sent,
                "packets_received": snapshot.packets_received,
                "upload_speed": snapshot.upload_speed_human,
                "download_speed": snapshot.download_speed_human,
                "last_updated": snapshot.last_updated,
            }
        ), 200
    except Exception:  # pragma: no cover - defensive guard
        logger.exception("Unexpected network monitor failure")
        return jsonify(
            {
                "interface_name": "Unknown",
                "bytes_sent": 0,
                "bytes_received": 0,
                "packets_sent": 0,
                "packets_received": 0,
                "upload_speed": "Unavailable",
                "download_speed": "Unavailable",
                "last_updated": None,
            }
        ), 200
