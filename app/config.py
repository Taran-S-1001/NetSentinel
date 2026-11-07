"""Configuration settings for the Flask application.

This module centralizes environment-specific settings for development,
testing, and production deployments.
"""

from __future__ import annotations

import os
import secrets


class Config:
    """Base configuration shared across all environments."""

    # Resolved at app creation by ``resolve_secret_key`` (never hard-coded).
    SECRET_KEY: str | None = None
    # Database URI is set dynamically in create_app() to ensure instance path exists
    SQLALCHEMY_DATABASE_URI: str = None  # type: ignore
    SQLALCHEMY_TRACK_MODIFICATIONS: bool = False
    DEBUG: bool = False
    TESTING: bool = False
    SCHEDULER_ENABLED = True


def env_flag(name: str, default: bool = False) -> bool:
    """Read a boolean environment variable (1/true/yes/on)."""
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def resolve_secret_key(configured: str | None) -> str:
    """Return the session signing key.

    Order: ``NETSENTINEL_SECRET_KEY`` / ``SECRET_KEY`` env var, then a value
    already set on the config class (only ``TestingConfig`` sets one), else a
    random per-process key, so no known default key is used at runtime.
    Sessions then reset on restart; set the env var for stable sessions.
    """
    key = (
        os.environ.get("NETSENTINEL_SECRET_KEY")
        or os.environ.get("SECRET_KEY")
        or configured
    )
    if key:
        return key
    return secrets.token_hex(32)


class TestingConfig(Config):
    """Configuration used by the automated test suite."""

    TESTING: bool = True
    # Fixed key for tests only; the runtime Config never uses it.
    SECRET_KEY: str | None = "test-only-secret-key"
    SQLALCHEMY_DATABASE_URI: str = "sqlite:///:memory:"
    SCHEDULER_ENABLED = False


LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}


def dev_server_options(environ=None) -> dict:
    """Build the options for the local development server (``python run.py``).

    Debug is off and the host is loopback unless overridden. This is the
    Werkzeug development server, not a production server. Listening on a
    non-loopback host exposes it to the network, so that requires an explicit
    ``NETSENTINEL_ALLOW_UNSAFE_WERKZEUG=1``; otherwise startup is refused.
    """
    env = os.environ if environ is None else environ

    def flag(name: str) -> bool:
        return env.get(name, "").strip().lower() in {"1", "true", "yes", "on"}

    host = env.get("NETSENTINEL_HOST", "127.0.0.1")
    exposed = host not in LOOPBACK_HOSTS
    if exposed and not flag("NETSENTINEL_ALLOW_UNSAFE_WERKZEUG"):
        raise SystemExit(
            f"Refusing to serve the development server on {host!r}: it would be "
            "reachable from the network. Use a production WSGI server for "
            "deployment, or set NETSENTINEL_ALLOW_UNSAFE_WERKZEUG=1 to accept "
            "the risk on a trusted network."
        )
    return {
        "debug": flag("NETSENTINEL_DEBUG"),
        "host": host,
        "port": int(env.get("NETSENTINEL_PORT", "5000")),
        "allow_unsafe_werkzeug": True,
    }
