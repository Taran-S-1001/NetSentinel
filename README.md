# NetSentinel

**Intelligent Network Port Scanner & Service Analysis Dashboard**

Flask, SQLite, Bootstrap and Chart.js. Features: port scanning, service
detection, OS fingerprinting, traceroute, scan history and comparison,
scheduled scans, dashboard analytics, security recommendations, PDF and CSV
reports, user accounts.

> Only scan hosts and networks you own or have permission to test.

## Setup

```bash
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

## Run (development server)

```bash
python run.py
```

This starts Flask's **development server, not a production server**. It opens on
http://127.0.0.1:5000 with debug off and is reachable from your machine only.
For deployment, use a production WSGI server instead.

Configure with environment variables or a local `.env` file in the project
folder (git-ignored; `python run.py` loads it):

| Variable | Default | Purpose |
| --- | --- | --- |
| `NETSENTINEL_SECRET_KEY` (or `SECRET_KEY`) | random per start | Session signing key. Set it for sessions that survive restarts. |
| `NETSENTINEL_DEBUG` | off | `1` enables Flask debug mode. Development only. |
| `NETSENTINEL_HOST` | `127.0.0.1` | Listen address. |
| `NETSENTINEL_PORT` | `5000` | Listen port. |
| `NETSENTINEL_ALLOW_UNSAFE_WERKZEUG` | off | Must be `1` to listen on a non-loopback host such as `0.0.0.0`. That exposes the development server to your network; trusted networks only. |

Generate a key with `python -c "import secrets; print(secrets.token_hex(32))"`.

## Test

```bash
pytest
```
