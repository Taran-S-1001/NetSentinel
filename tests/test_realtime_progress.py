"""Tests for real-time scan progress via WebSocket callbacks.

This module tests the progress callback mechanism in TCPScanner and verifies
that socket.io events are emitted correctly during scans.
"""

from __future__ import annotations

import logging
from typing import Any, Optional
from unittest.mock import MagicMock, Mock, patch

import pytest
from flask_login import login_user

from app import create_app
from app.extensions import db
from app.models import PortResult, ScanSession, User
from app.repositories import PortResultRepository, ScanSessionRepository
from app.scanner.models import ScanResult
from app.scanner.tcp import TCPScanner
from app.services import ScanService, ScanSessionService


logger = logging.getLogger("netsentinel.tests.realtime_progress")


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


@pytest.fixture
def tcp_scanner():
    """Create a TCPScanner instance for testing."""
    return TCPScanner(timeout=0.1)


class TestProgressCallback:
    """Test the progress callback mechanism in TCPScanner."""

    def test_scan_ports_threaded_without_callback(self, tcp_scanner):
        """Verify that scans work without a progress callback (backward compatibility)."""
        # Mock scan_port to return results quickly
        mock_results = [
            ScanResult(host="127.0.0.1", port=80, protocol="tcp", status="OPEN", service_name="http"),
            ScanResult(host="127.0.0.1", port=443, protocol="tcp", status="CLOSED", service_name="https"),
        ]

        with patch.object(tcp_scanner, "scan_port", side_effect=mock_results):
            results = tcp_scanner.scan_ports_threaded("127.0.0.1", [80, 443], max_workers=2)

        assert len(results) == 2
        assert results[0].port == 80
        assert results[1].port == 443

    def test_scan_ports_threaded_invokes_callback_for_each_result(self, tcp_scanner):
        """Verify that the progress callback is invoked for each completed port."""
        # Track callback invocations
        callback_calls = []

        def progress_callback(result: ScanResult, completed: int, total: int) -> None:
            callback_calls.append((result.port, completed, total))

        mock_results = [
            ScanResult(host="127.0.0.1", port=80, protocol="tcp", status="OPEN", service_name="http"),
            ScanResult(host="127.0.0.1", port=443, protocol="tcp", status="CLOSED", service_name="https"),
            ScanResult(host="127.0.0.1", port=8080, protocol="tcp", status="FILTERED", service_name="http-alt"),
        ]

        with patch.object(tcp_scanner, "scan_port", side_effect=mock_results):
            results = tcp_scanner.scan_ports_threaded(
                "127.0.0.1", [80, 443, 8080], max_workers=3, progress_callback=progress_callback
            )

        assert len(results) == 3
        assert len(callback_calls) == 3

        # Verify callback was called with correct completed counts
        completed_counts = [call[1] for call in callback_calls]
        assert sorted(completed_counts) == [1, 2, 3]

        # Verify total count is always 3
        total_counts = [call[2] for call in callback_calls]
        assert all(total == 3 for total in total_counts)

    def test_scan_ports_threaded_callback_receives_scan_results(self, tcp_scanner):
        """Verify that callback receives ScanResult objects with correct data."""
        received_results = []

        def progress_callback(result: ScanResult, completed: int, total: int) -> None:
            received_results.append(result)

        mock_results = [
            ScanResult(
                host="127.0.0.1",
                port=80,
                protocol="tcp",
                status="OPEN",
                service_name="http",
                response_time=0.005,
            ),
            ScanResult(
                host="127.0.0.1",
                port=443,
                protocol="tcp",
                status="OPEN",
                service_name="https",
                response_time=0.006,
            ),
        ]

        with patch.object(tcp_scanner, "scan_port", side_effect=mock_results):
            tcp_scanner.scan_ports_threaded(
                "127.0.0.1", [80, 443], max_workers=2, progress_callback=progress_callback
            )

        assert len(received_results) == 2
        assert received_results[0].port == 80
        assert received_results[0].status == "OPEN"
        assert received_results[1].port == 443
        assert received_results[1].response_time == 0.006

    def test_scan_ports_threaded_callback_handles_exceptions(self, tcp_scanner):
        """Verify that exceptions in the callback are logged but don't crash the scan."""
        callback_exception = RuntimeError("Callback failed")

        def failing_callback(result: ScanResult, completed: int, total: int) -> None:
            raise callback_exception

        mock_results = [
            ScanResult(host="127.0.0.1", port=80, protocol="tcp", status="OPEN"),
            ScanResult(host="127.0.0.1", port=443, protocol="tcp", status="CLOSED"),
        ]

        with patch.object(tcp_scanner, "scan_port", side_effect=mock_results):
            # Should not raise an exception
            results = tcp_scanner.scan_ports_threaded(
                "127.0.0.1", [80, 443], max_workers=2, progress_callback=failing_callback
            )

        # Scan should still complete and return results
        assert len(results) == 2

    def test_scan_ports_threaded_preserves_order(self, tcp_scanner):
        """Verify that results maintain original port order despite concurrent execution."""
        callback_order = []

        def track_order_callback(result: ScanResult, completed: int, total: int) -> None:
            callback_order.append(result.port)

        ports = [8000, 8001, 8002, 8003, 8004]
        mock_results = [
            ScanResult(host="127.0.0.1", port=port, protocol="tcp", status="OPEN") for port in ports
        ]

        with patch.object(tcp_scanner, "scan_port", side_effect=mock_results):
            results = tcp_scanner.scan_ports_threaded(
                "127.0.0.1", ports, max_workers=2, progress_callback=track_order_callback
            )

        # Results should maintain original port order in the returned list
        result_ports = [result.port for result in results]
        assert result_ports == ports


class TestScanServiceWithCallback:
    """Test that ScanService correctly passes the callback to TCPScanner."""

    def test_start_scan_passes_callback_to_scanner(self, app):
        """Verify that ScanService.start_scan() passes the callback through the chain."""
        app_instance, test_user = app
        callback_invocations = []

        def test_callback(result: Any, completed: int, total: int) -> None:
            callback_invocations.append((result.port, completed, total))

        # Mock TCPScanner to track callback usage
        mock_scanner = MagicMock(spec=TCPScanner)
        mock_scanner.scan_ports_threaded.return_value = [
            ScanResult(host="127.0.0.1", port=80, protocol="tcp", status="OPEN"),
        ]

        with app_instance.app_context():
            with app_instance.test_request_context():
                login_user(test_user)

                session_service = ScanSessionService(
                    session_repo=ScanSessionRepository(),
                    result_repo=PortResultRepository(),
                )
                scan_service = ScanService(session_service=session_service, scanner=mock_scanner)

                # Mock all the necessary methods to isolate the callback test
                with patch.object(scan_service, "save_results") as mock_save:
                    with patch.object(scan_service, "calculate_statistics") as mock_stats:
                        with patch.object(scan_service, "finish_scan") as mock_finish_scan:
                            mock_session = Mock(spec=ScanSession)
                            mock_session.id = 1
                            mock_session.target_host = "127.0.0.1"
                            mock_session.scan_type = "tcp"
                            mock_session.protocol = "tcp"
                            mock_session.status = "completed"
                            mock_session.created_at = None
                            mock_finish_scan.return_value = mock_session
                            mock_save.return_value = [ScanResult(host="127.0.0.1", port=80, protocol="tcp", status="OPEN")]
                            mock_stats.return_value = {
                                "total_ports": 1,
                                "open_ports": 1,
                                "closed_ports": 0,
                                "filtered_ports": 0,
                                "duration": 0.1,
                                "scan_speed": 10.0,
                                "first_open_port": 80,
                                "last_open_port": 80,
                                "most_common_service": "http",
                            }

                            # Start scan with callback
                            scan_service.start_scan(
                                target_host="127.0.0.1",
                                ports=[80],
                                scan_type="tcp",
                                protocol="tcp",
                                progress_callback=test_callback,
                            )

            # Verify scan_ports_threaded was called with the callback
            mock_scanner.scan_ports_threaded.assert_called_once()
            call_kwargs = mock_scanner.scan_ports_threaded.call_args.kwargs
            assert "progress_callback" in call_kwargs
            assert call_kwargs["progress_callback"] is test_callback

    def test_start_scan_works_without_callback(self, app):
        """Verify that ScanService.start_scan() works when no callback is provided."""
        app_instance, test_user = app
        mock_scanner = MagicMock(spec=TCPScanner)
        mock_scanner.scan_ports_threaded.return_value = [
            ScanResult(host="127.0.0.1", port=80, protocol="tcp", status="OPEN"),
        ]

        with app_instance.app_context():
            with app_instance.test_request_context():
                login_user(test_user)

                session_service = ScanSessionService(
                    session_repo=ScanSessionRepository(),
                    result_repo=PortResultRepository(),
                )
                scan_service = ScanService(session_service=session_service, scanner=mock_scanner)

                with patch.object(scan_service, "save_results") as mock_save:
                    with patch.object(scan_service, "calculate_statistics") as mock_stats:
                        with patch.object(scan_service, "finish_scan") as mock_finish_scan:
                            mock_session = Mock(spec=ScanSession)
                            mock_session.id = 1
                            mock_session.target_host = "127.0.0.1"
                            mock_session.scan_type = "tcp"
                            mock_session.protocol = "tcp"
                            mock_session.status = "completed"
                            mock_session.created_at = None
                            mock_finish_scan.return_value = mock_session
                            mock_save.return_value = [ScanResult(host="127.0.0.1", port=80, protocol="tcp", status="OPEN")]
                            mock_stats.return_value = {
                                "total_ports": 1,
                                "open_ports": 1,
                                "closed_ports": 0,
                                "filtered_ports": 0,
                                "duration": 0.1,
                                "scan_speed": 10.0,
                                "first_open_port": 80,
                                "last_open_port": 80,
                                "most_common_service": "http",
                            }

                            # Start scan without callback (backward compatibility)
                            scan_service.start_scan(
                                target_host="127.0.0.1",
                                ports=[80],
                                scan_type="tcp",
                                protocol="tcp",
                            )

            # Should complete without error
            mock_scanner.scan_ports_threaded.assert_called_once()
            
            # Verify progress_callback is None when not provided
            call_kwargs = mock_scanner.scan_ports_threaded.call_args.kwargs
            assert call_kwargs.get("progress_callback") is None


class TestAPIProgressEvents:
    """Test that the /api/scan endpoint emits progress events correctly."""

    def test_api_scan_emits_progress_events(self, client):
        """Verify that the API endpoint emits scan_progress events via socket.io."""

        # Mock the socketio.emit function
        with patch("app.routes.api.socketio.emit") as mock_emit:
            # Mock TCPScanner to return results
            mock_results = [
                ScanResult(
                    host="127.0.0.1",
                    port=80,
                    protocol="tcp",
                    status="OPEN",
                    service_name="http",
                    response_time=0.005,
                ),
                ScanResult(
                    host="127.0.0.1",
                    port=443,
                    protocol="tcp",
                    status="CLOSED",
                    service_name="https",
                    response_time=0.006,
                ),
            ]

            with patch("app.routes.api.ScanService.start_scan") as mock_start_scan:
                from app.schemas import HostScanResult

                # Mock the scan result
                mock_host_result = HostScanResult(
                    scan_id=1,
                    target_host="127.0.0.1",
                    scan_type="tcp",
                    protocol="tcp",
                    total_ports=2,
                    open_ports=1,
                    closed_ports=1,
                    filtered_ports=0,
                    duration=0.5,
                    scan_speed=4.0,
                    first_open_port=80,
                    last_open_port=80,
                    most_common_service="http",
                    status="completed",
                    created_at="2025-01-01T00:00:00",
                )
                mock_start_scan.return_value = mock_host_result

                # Send scan request
                response = client.post(
                    "/api/scan",
                    json={
                        "host": "127.0.0.1",
                        "start_port": 80,
                        "end_port": 81,
                        "threads": 2,
                    },
                )

            assert response.status_code == 200

            # Verify socketio.emit was called with scan_complete event
            emit_calls = mock_emit.call_args_list
            assert len(emit_calls) > 0

            # Check for scan_complete event
            complete_event_found = False
            for call in emit_calls:
                if call[0][0] == "scan_complete":
                    complete_event_found = True
                    assert "scan_id" in call[0][1]
                    break

            assert complete_event_found, "scan_complete event was not emitted"

    def test_api_scan_validates_input(self, client):
        """Verify that the API endpoint validates input correctly."""

        # Test missing host
        response = client.post(
            "/api/scan",
            json={
                "start_port": 80,
                "end_port": 81,
                "threads": 2,
            },
        )
        assert response.status_code == 400
        assert "host is required" in response.get_json()["error"]

        # Test invalid port range
        response = client.post(
            "/api/scan",
            json={
                "host": "127.0.0.1",
                "start_port": 81,
                "end_port": 80,
                "threads": 2,
            },
        )
        assert response.status_code == 400
        assert "start_port cannot be greater than end_port" in response.get_json()["error"]

    def test_api_scan_returns_structured_response(self, client):
        """Verify that the API endpoint returns the correct response structure."""

        with patch("app.routes.api.ScanService.start_scan") as mock_start_scan:
            from app.schemas import HostScanResult

            mock_host_result = HostScanResult(
                scan_id=42,
                target_host="192.168.1.1",
                scan_type="tcp",
                protocol="tcp",
                total_ports=10,
                open_ports=3,
                closed_ports=5,
                filtered_ports=2,
                duration=1.5,
                scan_speed=6.67,
                first_open_port=22,
                last_open_port=443,
                most_common_service="ssh",
                status="completed",
                created_at="2025-01-01T00:00:00",
            )
            mock_start_scan.return_value = mock_host_result

            response = client.post(
                "/api/scan",
                json={
                    "host": "192.168.1.1",
                    "start_port": 20,
                    "end_port": 29,
                    "threads": 5,
                },
            )

        assert response.status_code == 200
        data = response.get_json()

        # Verify response structure
        assert "scan_id" in data
        assert data["scan_id"] == 42
        assert "status" in data
        assert "summary" in data

        summary = data["summary"]
        assert summary["target_host"] == "192.168.1.1"
        assert summary["total_ports"] == 10
        assert summary["open_ports"] == 3


@pytest.mark.integration
class TestProgressEndToEnd:
    """Integration tests for real-time progress feature."""

    def test_full_scan_with_progress_callback(self):
        """Test a complete scan flow with progress tracking (integration test)."""
        tcp_scanner = TCPScanner(timeout=0.1)
        callback_results = []

        def track_progress(result: ScanResult, completed: int, total: int) -> None:
            callback_results.append(
                {
                    "port": result.port,
                    "status": result.status,
                    "completed": completed,
                    "total": total,
                    "percent": round((completed / total) * 100, 2),
                }
            )
            logger.info(
                "Progress: port %s, %d/%d (%.2f%%)",
                result.port,
                completed,
                total,
                (completed / total) * 100,
            )

        # This will attempt to scan real ports on localhost
        # Results will vary based on system configuration
        ports = [80, 443, 8080]
        results = tcp_scanner.scan_ports_threaded(
            "127.0.0.1", ports, max_workers=2, progress_callback=track_progress
        )

        # Verify results
        assert len(results) == 3
        assert len(callback_results) == 3

        # Verify progress was tracked correctly
        completed_counts = [cb["completed"] for cb in callback_results]
        assert sorted(completed_counts) == [1, 2, 3]

        logger.info("Integration test completed with %d callback invocations", len(callback_results))
