# CyberGuard

CyberGuard is a responsive dark SOC-style cybersecurity website built with Flask and SQLite. It combines public awareness content with a protected operations console for incident triage.

## Features

- Flask application with SQLite initialization and seeded demo data
- Werkzeug password hashing, cookie sessions, registration, login, and logout
- Analyst/admin RBAC with protected dashboard and user role management
- Incident creation, filtering, status/severity updates, and admin deletion
- Local heuristic threat scanner with scan history
- Browser-only password strength checker (passwords are not submitted)
- Phishing scenario, 10-question knowledge quiz, field guides, attack library, and tools pages
- Chart.js dashboard data endpoint with severity, status, incident timeline, and login activity
- Admin audit log, threat telemetry, incident queue, and role management
- CSRF protection, security headers, HttpOnly/SameSite session cookies, and parameterized SQL

## Run locally

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
python init_db.py
flask --app app run --debug
```

The app also initializes the database automatically on first import. The default database is `cyberguard.db`; set `CYBERGUARD_DB` to use another path.

### Main routes

- Public: `/`, `/learn`, `/attacks`, `/tools`, `/password-checker`, `/phishing-quiz`, `/quiz`
- Protected console: `/dashboard`, `/threat-demo`, `/incidents`, `/incident-reports`
- Admin-only: `/admin`

The aliases `/threats`, `/password`, `/phishing`, `/learning`, `/cyber-attacks`, `/security-tools`, and `/security-quiz` are also available for navigation integrations.

### Demo accounts

- Admin: `admin` / `Admin123!`
- Analyst: `analyst` / `Analyst123!`

Change demo credentials before deploying. Set a strong random `SECRET_KEY` in production, run behind HTTPS, and use a production WSGI server.
