"""Extension initialization for the Flask application.

This module keeps third-party integrations centralized so the app factory
can initialize them in a consistent and modular way.
"""

from __future__ import annotations

from flask_socketio import SocketIO
from flask_sqlalchemy import SQLAlchemy

# SQLAlchemy instance used throughout the application.
db = SQLAlchemy()

# Flask-SocketIO instance for real-time WebSocket communication.
socketio = SocketIO(cors_allowed_origins="*", async_mode="threading")
