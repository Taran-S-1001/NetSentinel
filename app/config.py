"""Configuration settings for the Flask application.

This module centralizes environment-specific settings for development,
testing, and production deployments.
"""

from __future__ import annotations


class Config:
    """Base configuration shared across all environments."""

    SECRET_KEY: str = "dev-secret-key"
    # Database URI is set dynamically in create_app() to ensure instance path exists
    SQLALCHEMY_DATABASE_URI: str = None  # type: ignore
    SQLALCHEMY_TRACK_MODIFICATIONS: bool = False
    DEBUG: bool = False
    TESTING: bool = False
    SCHEDULER_ENABLED = True


class TestingConfig(Config):
    """Configuration used by the automated test suite."""

    TESTING: bool = True
    SQLALCHEMY_DATABASE_URI: str = "sqlite:///:memory:"
    SCHEDULER_ENABLED = False
