from flask.testing import FlaskClient

from app import create_app


def test_enterprise_pages_render(authenticated_client: FlaskClient) -> None:
    assert authenticated_client.get("/reports").status_code == 200
    assert authenticated_client.get("/settings").status_code == 200
    assert authenticated_client.get("/about").status_code == 200
