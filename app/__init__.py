"""Application package for NetSentinel.

This module exposes the Flask application factory used to create
application instances for development, testing, and production.
"""

from __future__ import annotations

import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Optional

from flask import Flask, render_template
from dotenv import load_dotenv

from app.config import Config, TestingConfig
from app.extensions import db, login_manager, bcrypt, socketio
from sqlalchemy.exc import OperationalError
from app.routes.api import api_bp
from app.routes.main import main_bp
from app.routes.ui import ui_bp
from app.routes.auth import auth_bp

from app.models import User
from app.extensions import login_manager


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

load_dotenv()


def create_app(config_name: Optional[str] = None) -> Flask:
    """Create and configure a Flask application instance."""
    app = Flask(
        __name__,
        instance_relative_config=True,
        template_folder="../templates",
        static_folder="../static",
    )

    config_obj = resolve_config(config_name)
    app.config.from_object(config_obj)

    # Ensure instance directory exists BEFORE initializing database
    Path(app.instance_path).mkdir(parents=True, exist_ok=True)

    # Set database URI based on config or use default SQLite path
    if app.config.get("SQLALCHEMY_DATABASE_URI") is None:
        if app.config.get("TESTING"):
            app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
        else:
            db_path = Path(app.instance_path) / "netsentinel.db"
            app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{db_path.as_posix()}"

    initialize_extensions(app)
    register_blueprints(app)
    if app.config.get("SCHEDULER_ENABLED"):
        from app.services.scheduled_scan import ScheduledScanManager
        app.scheduled_scan_manager = ScheduledScanManager(app)
        app.scheduled_scan_manager.start()
    configure_logging(app)
    register_shell_context(app)
    register_error_handlers(app)

    return app


def resolve_config(config_name: Optional[str]) -> type[Config]:
    """Resolve the active configuration class from the provided name."""
    if config_name == "testing":
        return TestingConfig
    return Config


def initialize_extensions(app: Flask) -> None:
    """Initialize third-party extensions for the Flask app."""

    db.init_app(app)
    socketio.init_app(app)

    login_manager.init_app(app)
    bcrypt.init_app(app)

    login_manager.login_view = "auth.login"
    login_manager.login_message = "Please log in to continue."
    login_manager.login_message_category = "info"

    with app.app_context():
        # Import models so SQLAlchemy metadata includes all tables (including
        # traceroute_hops / ScanSession.os_guess from Phase 3).
        # db.create_all() only creates *missing* tables — it will not ALTER an
        # existing scan_sessions table to add os_guess. Anyone with an existing
        # netsentinel.db must delete/recreate it, or run a raw:
        #   ALTER TABLE scan_sessions ADD COLUMN os_guess VARCHAR(100);
        import app.models  # noqa: F401

        db.create_all()




def register_blueprints(app: Flask) -> None:
    """Register all Flask blueprints with the application."""
    app.register_blueprint(main_bp)
    app.register_blueprint(api_bp)
    app.register_blueprint(ui_bp)
    app.register_blueprint(auth_bp)


def configure_logging(app: Flask) -> None:
    """Configure application logging for console and file output."""
    # Instance directory already exists from create_app()
    if not app.logger.handlers:
        handler = RotatingFileHandler(
            Path(app.instance_path) / "netsentinel.log",
            maxBytes=1024 * 1024,
            backupCount=5,
        )
        handler.setLevel(logging.INFO)
        handler.setFormatter(
            logging.Formatter(
                "%(asctime)s %(levelname)s %(name)s: %(message)s"
            )
        )
        app.logger.addHandler(handler)

    app.logger.setLevel(logging.INFO)
    app.logger.info("NetSentinel application initialized")


def register_shell_context(app: Flask) -> None:
    """Register shell context helpers for Flask CLI usage."""
    @app.shell_context_processor
    def make_shell_context() -> dict[str, object]:
        return {"db": db}


def register_error_handlers(app: Flask) -> None:
    """Register friendly error pages for the UI."""

    @app.errorhandler(404)
    def handle_not_found(_error: Exception) -> tuple[str, int]:
        return render_template("errors/404.html"), 404

    @app.errorhandler(500)
    def handle_server_error(_error: Exception) -> tuple[str, int]:
        return render_template("errors/500.html"), 500
