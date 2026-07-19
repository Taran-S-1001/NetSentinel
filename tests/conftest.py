"""Shared pytest fixtures for NetSentinel tests."""

import pytest
from flask import Flask
from flask.testing import FlaskClient
from flask_login import login_user

from app import create_app
from app.extensions import db, bcrypt
from app.models import User


@pytest.fixture
def app() -> Flask:
    """Create and configure a test application instance."""
    app = create_app("testing")
    app.config.update(TESTING=True)
    
    with app.app_context():
        db.drop_all()
        db.create_all()
    
    yield app
    
    with app.app_context():
        db.drop_all()


@pytest.fixture
def authenticated_client(app: Flask) -> FlaskClient:
    """Create a test client with an authenticated user session."""
    with app.app_context():
        # Create test user
        hashed_password = bcrypt.generate_password_hash("testpass123").decode("utf-8")
        user = User(
            username="testuser",
            email="test@example.com",
            password_hash=hashed_password,
        )
        db.session.add(user)
        db.session.commit()
        user_id = user.id  # Store ID before potential detach
        
        with app.test_client() as client:
            # Log in the test user via the login endpoint
            client.post(
                "/login",
                data={"email": user.email, "password": "testpass123"},
                follow_redirects=False,
            )
            yield client


@pytest.fixture
def authenticated_app_context(app: Flask):
    """Create an app context with a test user for service/repository tests.
    
    Tests should use this with a request context and login_user:
        with app.test_request_context():
            login_user(test_user)
            # ... call service methods
    """
    with app.app_context():
        # Create test user
        hashed_password = bcrypt.generate_password_hash("testpass123").decode("utf-8")
        user = User(
            username="testuser",
            email="test@example.com",
            password_hash=hashed_password,
        )
        db.session.add(user)
        db.session.commit()
        # Re-query to ensure we have a fresh instance attached to session
        user = db.session.get(User, user.id)
        yield app, user
