"""Entry point for the NetSentinel development server (``python run.py``).

This runs the Werkzeug development server. It is NOT a production server.
Defaults: debug off, listening on 127.0.0.1 only. Configure with environment
variables or a local .env file:

    NETSENTINEL_DEBUG=1                  Flask debug mode (development only)
    NETSENTINEL_HOST=127.0.0.1           listen address
    NETSENTINEL_PORT=5000                listen port
    NETSENTINEL_SECRET_KEY=...           session signing key
    NETSENTINEL_ALLOW_UNSAFE_WERKZEUG=1  required to listen on a non-loopback host
"""

from __future__ import annotations

from app import create_app
from app.config import dev_server_options
from app.extensions import socketio

app = create_app()  # importing app also loads .env


if __name__ == "__main__":
    socketio.run(app, **dev_server_options())
