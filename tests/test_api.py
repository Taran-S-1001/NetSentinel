"""Tests for the NetSentinel REST API."""

from __future__ import annotations

from flask.testing import FlaskClient

from app import create_app
from app.extensions import db


def test_api_health_and_scan_workflow(authenticated_client: FlaskClient) -> None:
    """The API should expose health and scan endpoints."""
    health = authenticated_client.get("/api/health")
    assert health.status_code == 200
    assert health.get_json()["status"] == "ok"

    scan_response = authenticated_client.post(
        "/api/scan",
        json={"host": "127.0.0.1", "start_port": 1, "end_port": 3, "threads": 2},
    )
    assert scan_response.status_code == 200
    assert scan_response.get_json()["status"] == "completed"

    scans = authenticated_client.get("/api/scans")
    assert scans.status_code == 200
    assert scans.get_json()["items"]

    scan_detail = authenticated_client.get(f"/api/scans/{scan_response.get_json()['scan_id']}")
    assert scan_detail.status_code == 200

    dashboard = authenticated_client.get("/api/dashboard")
    assert dashboard.status_code == 200
    assert dashboard.get_json()["total_scans"] >= 1

    network_monitor = authenticated_client.get("/api/network-monitor")
    assert network_monitor.status_code == 200
    network_payload = network_monitor.get_json()
    assert "interface_name" in network_payload
    assert "upload_speed" in network_payload
    assert "download_speed" in network_payload

    delete_response = authenticated_client.delete(f"/api/scans/{scan_response.get_json()['scan_id']}")
    assert delete_response.status_code == 200
