"""Extension initialization for the Flask application.

This module keeps third-party integrations centralized so the app factory
can initialize them in a consistent and modular way.
"""

from __future__ import annotations

from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_bcrypt import Bcrypt

# Database
db = SQLAlchemy()

# Authentication
login_manager = LoginManager()

# Password hashing
bcrypt = Bcrypt()