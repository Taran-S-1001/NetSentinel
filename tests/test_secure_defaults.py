"""Tests for secret-key resolution and safe startup defaults."""

import pytest

from app import create_app
from app.config import dev_server_options, env_flag, resolve_secret_key


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    for name in ("NETSENTINEL_SECRET_KEY", "SECRET_KEY", "NETSENTINEL_DEBUG",
                 "NETSENTINEL_HOST", "NETSENTINEL_PORT",
                 "NETSENTINEL_ALLOW_UNSAFE_WERKZEUG"):
        monkeypatch.delenv(name, raising=False)


def test_no_hardcoded_default_key():
    assert resolve_secret_key(None) != "dev-secret-key"


def test_generated_key_is_random_and_long():
    first, second = resolve_secret_key(None), resolve_secret_key(None)
    assert first != second
    assert len(first) >= 32


def test_env_var_wins(monkeypatch):
    monkeypatch.setenv("NETSENTINEL_SECRET_KEY", "from-env")
    assert resolve_secret_key("configured") == "from-env"


def test_generic_secret_key_env_var(monkeypatch):
    monkeypatch.setenv("SECRET_KEY", "generic")
    assert resolve_secret_key(None) == "generic"


def test_configured_value_used_when_no_env():
    assert resolve_secret_key("configured") == "configured"


def test_testing_config_uses_fixed_key():
    app = create_app("testing")
    assert app.config["SECRET_KEY"] == "test-only-secret-key"


def test_runtime_config_never_uses_test_key():
    app = create_app()
    assert app.config["SECRET_KEY"] != "test-only-secret-key"
    assert app.config["SECRET_KEY"] != "dev-secret-key"
    assert len(app.config["SECRET_KEY"]) >= 32


def test_runtime_key_from_env(monkeypatch):
    monkeypatch.setenv("NETSENTINEL_SECRET_KEY", "abc123")
    assert create_app()
    assert create_app().config["SECRET_KEY"] == "abc123"


@pytest.mark.parametrize("value,expected", [
    ("1", True), ("true", True), ("YES", True), ("on", True),
    ("0", False), ("false", False), ("", False), ("nope", False),
])
def test_env_flag_values(monkeypatch, value, expected):
    monkeypatch.setenv("NETSENTINEL_DEBUG", value)
    assert env_flag("NETSENTINEL_DEBUG") is expected


def test_env_flag_default_off():
    assert env_flag("NETSENTINEL_DEBUG") is False


def test_dev_server_defaults():
    opts = dev_server_options({})
    assert opts["debug"] is False
    assert opts["host"] == "127.0.0.1"
    assert opts["port"] == 5000


def test_dev_server_debug_and_port_overrides():
    opts = dev_server_options({"NETSENTINEL_DEBUG": "1", "NETSENTINEL_PORT": "8080"})
    assert opts["debug"] is True
    assert opts["host"] == "127.0.0.1"
    assert opts["port"] == 8080


@pytest.mark.parametrize("host", ["127.0.0.1", "localhost", "::1"])
def test_dev_server_loopback_hosts_allowed(host):
    assert dev_server_options({"NETSENTINEL_HOST": host})["host"] == host


@pytest.mark.parametrize("host", ["0.0.0.0", "192.168.1.5", "::"])
def test_dev_server_refuses_exposed_host_without_opt_in(host):
    with pytest.raises(SystemExit):
        dev_server_options({"NETSENTINEL_HOST": host})
    with pytest.raises(SystemExit):
        dev_server_options({"NETSENTINEL_HOST": host, "NETSENTINEL_DEBUG": "1"})


def test_dev_server_exposed_host_with_explicit_opt_in():
    opts = dev_server_options({
        "NETSENTINEL_HOST": "0.0.0.0",
        "NETSENTINEL_ALLOW_UNSAFE_WERKZEUG": "1",
    })
    assert opts["host"] == "0.0.0.0"


def test_run_module_uses_dev_server_options(monkeypatch):
    captured = {}
    import runpy
    import app.extensions as ext

    monkeypatch.setattr(ext.socketio, "run", lambda *a, **kw: captured.update(kw))
    monkeypatch.setenv("NETSENTINEL_PORT", "8081")
    runpy.run_path("run.py", run_name="__main__")
    assert captured["host"] == "127.0.0.1"
    assert captured["debug"] is False
    assert captured["port"] == 8081
