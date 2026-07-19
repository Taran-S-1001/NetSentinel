"""Smoke tests for the NetSentinel Flask application skeleton."""

from flask.testing import FlaskClient

from app import create_app


def test_home_page_renders(authenticated_client: FlaskClient) -> None:
    """The application factory should create a working Flask app."""
    response = authenticated_client.get("/")

    assert response.status_code == 200
    assert b"NetSentinel" in response.data
