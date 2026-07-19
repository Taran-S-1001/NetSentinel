\# NetSentinel



\*\*Intelligent Network Port Scanner \& Service Analysis Dashboard\*\*



\## Tech Stack



\- Flask

\- Python

\- SQLite

\- Bootstrap

\- Chart.js



\## Features



\- Port Scanning

\- Service Detection

\- Scan History

\- Dashboard Analytics

\- PDF Reports

\- CSV Export

\## Setup Notes



If you already have a local \`instance/netsentinel.db\` from before the

realtime-progress-fingerprinting branch, delete it before running the app.

Phase 3 added new columns/tables (e.g. \`os_guess\` on \`ScanSession\`), and

\`db.create_all()\` only creates brand-new tables, it will not alter ones

that already exist. A stale database will cause a database schema error

on startup.

\## Status



🚧 Under Development

