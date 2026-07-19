from flask.testing import FlaskClient

from app import create_app


def test_dashboard_and_pages_render(authenticated_client: FlaskClient) -> None:
    assert authenticated_client.get("/", follow_redirects=True).status_code == 200
    assert authenticated_client.get("/scan").status_code == 200
    assert authenticated_client.get("/history").status_code == 200
    assert authenticated_client.get("/analytics").status_code == 200


def test_scan_form_validation(authenticated_client: FlaskClient) -> None:
    response = authenticated_client.post(
        "/scan",
        data={"host": "", "start_port": "1", "end_port": "0", "threads": "2"},
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert b"Host/IP is required" in response.data


def test_not_found_page(authenticated_client: FlaskClient) -> None:
    response = authenticated_client.get("/missing")
    assert response.status_code == 404
