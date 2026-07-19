"""Entry point for running the NetSentinel Flask application."""

from __future__ import annotations

from app import create_app
from app.extensions import socketio

app = create_app()


if __name__ == "__main__":
    socketio.run(app, debug=True, host="0.0.0.0", port=5000)
