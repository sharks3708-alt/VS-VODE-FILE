"""CyberGuard - a small, production-minded Flask security operations portal."""
from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import secrets
import smtplib
import socket
import sqlite3
import ssl
import tempfile
from email.message import EmailMessage
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path

from flask import (
    Flask,
    abort,
    flash,
    g,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash
from dotenv import load_dotenv

load_dotenv()
BASE_DIR = Path(__file__).resolve().parent
DATABASE = os.environ.get("CYBERGUARD_DB", str(BASE_DIR / "cyberguard.db"))

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get("SECRET_KEY", "cyberguard-local-development-key"),
    DATABASE=DATABASE,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("SESSION_COOKIE_SECURE", "0") == "1",
    MAX_CONTENT_LENGTH=8 * 1024 * 1024,
)


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def get_db() -> sqlite3.Connection:
    if "db" not in g:
        g.db = sqlite3.connect(app.config["DATABASE"])
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def close_db(_error: BaseException | None = None) -> None:
    db = g.pop("db", None)
    if db is not None:
        db.close()


@app.after_request
def add_security_headers(response):
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "SAMEORIGIN")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; img-src 'self' data:; "
        "connect-src 'self'; frame-ancestors 'self'",
    )
    return response


def init_db() -> None:
    db = get_db()
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            full_name TEXT NOT NULL DEFAULT '',
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'analyst' CHECK(role IN ('admin', 'analyst')),
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS pending_registrations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            full_name TEXT NOT NULL,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            otp_hash TEXT NOT NULL,
            attempts INTEGER NOT NULL DEFAULT 0,
            expires_at INTEGER NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS incidents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            severity TEXT NOT NULL DEFAULT 'medium'
                CHECK(severity IN ('low', 'medium', 'high', 'critical')),
            status TEXT NOT NULL DEFAULT 'open'
                CHECK(status IN ('open', 'investigating', 'contained', 'resolved')),
            source TEXT NOT NULL DEFAULT 'manual',
            assigned_to INTEGER REFERENCES users(id) ON DELETE SET NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS threat_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT NOT NULL,
            verdict TEXT NOT NULL,
            score INTEGER NOT NULL,
            indicators TEXT NOT NULL,
            scanned_at TEXT NOT NULL,
            scanned_by INTEGER REFERENCES users(id) ON DELETE SET NULL
        );
        CREATE TABLE IF NOT EXISTS activity_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
            action TEXT NOT NULL,
            detail TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS quiz_questions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            prompt TEXT NOT NULL,
            option_a TEXT NOT NULL,
            option_b TEXT NOT NULL,
            option_c TEXT NOT NULL,
            option_d TEXT NOT NULL,
            answer TEXT NOT NULL,
            explanation TEXT NOT NULL
        );
        """
    )
    user_columns = {row["name"] for row in db.execute("PRAGMA table_info(users)")}
    if "full_name" not in user_columns:
        db.execute("ALTER TABLE users ADD COLUMN full_name TEXT NOT NULL DEFAULT ''")
    seed_db(db)
    db.commit()


def seed_db(db: sqlite3.Connection) -> None:
    if db.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
        db.executemany(
            """INSERT INTO users
            (full_name, username, email, password_hash, role, created_at)
            VALUES (?, ?, ?, ?, ?, ?)""",
            [
                (
                    "Mohammed Abrar Khan",
                    "admin",
                    "admin@cyberguard.local",
                    generate_password_hash("Abrar123", method="pbkdf2:sha256"),
                    "admin",
                    utc_now(),
                ),
                (
                    "Security Analyst",
                    "analyst",
                    "analyst@cyberguard.local",
                    generate_password_hash("Analyst123!", method="pbkdf2:sha256"),
                    "analyst",
                    utc_now(),
                ),
            ],
        )
    else:
        db.execute(
            """UPDATE users
            SET full_name = ?, password_hash = ?, role = 'admin'
            WHERE username = 'admin'""",
            (
                "Mohammed Abrar Khan",
                generate_password_hash("Abrar123", method="pbkdf2:sha256"),
            ),
        )
    if db.execute("SELECT COUNT(*) FROM incidents").fetchone()[0] == 0:
        admin_id = db.execute("SELECT id FROM users WHERE username = 'admin'").fetchone()[0]
        db.executemany(
            """INSERT INTO incidents
            (title, description, severity, status, source, assigned_to, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            [
                (
                    "Suspicious OAuth consent grant",
                    "Unusual consent grant detected for a newly registered application.",
                    "high",
                    "investigating",
                    "identity-monitor",
                    admin_id,
                    utc_now(),
                    utc_now(),
                ),
                (
                    "Endpoint malware quarantine",
                    "EDR isolated a workstation after a known loader signature fired.",
                    "critical",
                    "contained",
                    "edr",
                    admin_id,
                    utc_now(),
                    utc_now(),
                ),
                (
                    "Excessive failed logins",
                    "Multiple failed logins against a finance account from an unfamiliar ASN.",
                    "medium",
                    "open",
                    "siem",
                    None,
                    utc_now(),
                    utc_now(),
                ),
            ],
        )
    if db.execute("SELECT COUNT(*) FROM quiz_questions").fetchone()[0] == 0:
        questions = [
            ("What does MFA add to an account?", "A second verification factor", "A faster login", "A backup email", "An antivirus scan", "a", "MFA combines two or more independent factors."),
            ("Which is a strong password practice?", "Reuse one password", "Use a long unique passphrase", "Share it with IT", "Store it in notes", "b", "Length and uniqueness make guessing and reuse attacks harder."),
            ("What is phishing?", "A network cable issue", "A deceptive attempt to steal information", "A backup method", "A software update", "b", "Phishing uses social engineering, often through messages or fake sites."),
            ("What does HTTPS primarily protect?", "Data in transit", "Your battery", "Your keyboard", "Printer ink", "a", "HTTPS encrypts traffic between a browser and the web server."),
            ("What is the safest response to an unexpected attachment?", "Open it quickly", "Forward it", "Verify through a trusted channel", "Disable security tools", "c", "Independent verification prevents malicious attachment execution."),
            ("What does least privilege mean?", "Everyone is an admin", "Only necessary access is granted", "No passwords are needed", "Access never expires", "b", "Least privilege limits the blast radius of compromised accounts."),
            ("What is ransomware?", "A weather alert", "Malware that encrypts data for payment", "A password manager", "A firewall rule", "b", "Ransomware extorts victims by denying access to files or systems."),
            ("Why are software updates important?", "They add vulnerabilities", "They patch known weaknesses", "They remove backups", "They weaken encryption", "b", "Security updates close vulnerabilities attackers may already know."),
            ("Which is a useful incident response first step?", "Delete all logs", "Preserve evidence and scope the event", "Post publicly", "Ignore the alert", "b", "Preserving evidence supports accurate containment and recovery."),
            ("What is a secure way to use public Wi-Fi?", "Disable encryption", "Use a trusted VPN and HTTPS", "Share files openly", "Turn off MFA", "b", "A VPN and HTTPS reduce exposure on untrusted networks."),
        ]
        db.executemany(
            """INSERT INTO quiz_questions
            (prompt, option_a, option_b, option_c, option_d, answer, explanation)
            VALUES (?, ?, ?, ?, ?, ?, ?)""",
            questions,
        )


def log_activity(action: str, detail: str, user_id: int | None = None) -> None:
    db = get_db()
    db.execute(
        "INSERT INTO activity_logs (user_id, action, detail, created_at) VALUES (?, ?, ?, ?)",
        (user_id, action, detail, utc_now()),
    )
    db.commit()


@app.before_request
def load_logged_in_user() -> None:
    user_id = session.get("user_id")
    g.user = None
    if user_id is not None:
        g.user = get_db().execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()


@app.before_request
def validate_csrf() -> None:
    if request.method == "POST":
        expected = session.get("_csrf_token")
        supplied = request.form.get("_csrf_token", "")
        if not expected or not secrets.compare_digest(expected, supplied):
            abort(400, description="The security token is missing or invalid.")


@app.context_processor
def inject_globals():
    token = session.setdefault("_csrf_token", secrets.token_urlsafe(32))
    return {"app_name": "CyberGuard", "year": datetime.now().year, "csrf_token": token}


def login_required(view):
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if g.user is None:
            flash("Sign in to access the security console.", "info")
            return redirect(url_for("login", next=request.path))
        return view(*args, **kwargs)

    return wrapped_view


def admin_required(view):
    @wraps(view)
    @login_required
    def wrapped_view(*args, **kwargs):
        if g.user["role"] != "admin":
            abort(403)
        return view(*args, **kwargs)

    return wrapped_view


@app.route("/")
def index():
    if g.user:
        return redirect(url_for("dashboard"))
    return render_template("landing.html")


def username_from_full_name(full_name: str) -> str:
    base = re.sub(r"[^a-z0-9]+", "_", full_name.casefold()).strip("_") or "user"
    username = base[:40]
    suffix = 2
    db = get_db()
    while db.execute(
        "SELECT 1 FROM users WHERE username = ? UNION SELECT 1 FROM pending_registrations WHERE username = ?",
        (username, username),
    ).fetchone():
        suffix_text = f"_{suffix}"
        username = f"{base[:40 - len(suffix_text)]}{suffix_text}"
        suffix += 1
    return username


def send_verification_email(recipient: str, full_name: str, otp: str) -> bool:
    host = os.environ.get("SMTP_HOST", "").strip()
    username = os.environ.get("SMTP_USERNAME", "").strip()
    password = os.environ.get("SMTP_PASSWORD", "")
    sender = os.environ.get("SMTP_FROM", username).strip()
    if not host or not sender:
        return False
    message = EmailMessage()
    message["Subject"] = "Your CyberGuard verification code"
    message["From"] = sender
    message["To"] = recipient
    message.set_content(
        f"Hello {full_name},\n\nYour CyberGuard verification code is: {otp}\n\n"
        "This code expires in 10 minutes. If you did not request an account, ignore this email."
    )
    try:
        port = int(os.environ.get("SMTP_PORT", "587"))
        if os.environ.get("SMTP_USE_TLS", "1") == "1":
            with smtplib.SMTP(host, port, timeout=10) as connection:
                connection.starttls(context=ssl.create_default_context())
                if username:
                    connection.login(username, password)
                connection.send_message(message)
        else:
            with smtplib.SMTP_SSL(host, port, timeout=10, context=ssl.create_default_context()) as connection:
                if username:
                    connection.login(username, password)
                connection.send_message(message)
    except (OSError, smtplib.SMTPException, ValueError):
        return False
    return True


@app.route("/register", methods=("GET", "POST"))
def register():
    if g.user:
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        full_name = request.form.get("full_name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirmation = request.form.get("confirmation", "")
        if not full_name or not email or len(password) < 8:
            flash("Name, valid email, and an 8+ character password are required.", "error")
        elif password != confirmation:
            flash("Passwords do not match.", "error")
        elif not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email):
            flash("Enter a valid email address.", "error")
        else:
            try:
                db = get_db()
                username = username_from_full_name(full_name)
                otp = f"{secrets.randbelow(1_000_000):06d}"
                db.execute("DELETE FROM pending_registrations WHERE email = ?", (email,))
                db.execute(
                    """INSERT INTO pending_registrations
                    (full_name, username, email, password_hash, otp_hash, expires_at, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?)""",
                    (full_name, username, email, generate_password_hash(password, method="pbkdf2:sha256"), generate_password_hash(otp, method="pbkdf2:sha256"), int(datetime.now(timezone.utc).timestamp()) + 600, utc_now()),
                )
                db.commit()
                if not send_verification_email(email, full_name, otp):
                    db.execute("DELETE FROM pending_registrations WHERE email = ?", (email,))
                    db.commit()
                    flash("Email verification is not configured. Add SMTP settings before registering users.", "error")
                    return render_template("auth/register.html")
                session["pending_verification_email"] = email
                flash("A verification code was sent to your email.", "success")
                return redirect(url_for("verify_email"))
            except sqlite3.IntegrityError:
                flash("That email is already registered or awaiting verification.", "error")
    return render_template("auth/register.html")


@app.route("/verify-email", methods=("GET", "POST"))
def verify_email():
    email = session.get("pending_verification_email")
    if not email:
        return redirect(url_for("register"))
    pending = get_db().execute("SELECT * FROM pending_registrations WHERE email = ?", (email,)).fetchone()
    if pending is None:
        session.pop("pending_verification_email", None)
        flash("That verification request has expired. Please register again.", "error")
        return redirect(url_for("register"))
    if request.method == "POST":
        if int(datetime.now(timezone.utc).timestamp()) > pending["expires_at"]:
            get_db().execute("DELETE FROM pending_registrations WHERE id = ?", (pending["id"],))
            get_db().commit()
            session.pop("pending_verification_email", None)
            flash("That verification code has expired. Please register again.", "error")
            return redirect(url_for("register"))
        if pending["attempts"] >= 5:
            flash("Too many incorrect codes. Please register again.", "error")
        else:
            code = request.form.get("otp", "").strip()
            if check_password_hash(pending["otp_hash"], code):
                db = get_db()
                db.execute("INSERT INTO users (full_name, username, email, password_hash, created_at) VALUES (?, ?, ?, ?, ?)", (pending["full_name"], pending["username"], pending["email"], pending["password_hash"], utc_now()))
                db.execute("DELETE FROM pending_registrations WHERE id = ?", (pending["id"],))
                db.commit()
                session.pop("pending_verification_email", None)
                log_activity("account.verified", f"Email verified for {pending['username']}")
                flash("Email verified. You can now sign in.", "success")
                return redirect(url_for("login"))
            db = get_db()
            db.execute("UPDATE pending_registrations SET attempts = attempts + 1 WHERE id = ?", (pending["id"],))
            db.commit()
            flash("That verification code is incorrect.", "error")
    return render_template("auth/verify_email.html", email=email)


@app.route("/login", methods=("GET", "POST"))
def login():
    if g.user:
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        identity = request.form.get("identity", "").strip()
        password = request.form.get("password", "")
        user = get_db().execute(
            "SELECT * FROM users WHERE username = ? OR email = ?", (identity, identity.lower())
        ).fetchone()
        if user is None or not check_password_hash(user["password_hash"], password):
            log_activity("auth.failed", f"Failed sign-in attempt for {identity[:80]}")
            flash("Invalid credentials. Try again.", "error")
        else:
            session.clear()
            session["user_id"] = user["id"]
            log_activity("auth.login", f"Successful sign-in: {user['username']}", user["id"])
            next_page = request.args.get("next", "")
            if not next_page.startswith("/") or next_page.startswith("//"):
                next_page = url_for("dashboard")
            return redirect(next_page)
    return render_template("auth/login.html")


@app.route("/logout")
def logout():
    if g.user:
        log_activity("auth.logout", f"Signed out: {g.user['username']}", g.user["id"])
    session.clear()
    flash("You have been signed out.", "info")
    return redirect(url_for("index"))


@app.route("/dashboard")
@login_required
def dashboard():
    db = get_db()
    total_incidents = db.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]
    open_incidents = db.execute(
        "SELECT COUNT(*) FROM incidents WHERE status != 'resolved'"
    ).fetchone()[0]
    suspicious_scans = db.execute(
        "SELECT COUNT(*) FROM threat_logs WHERE verdict != 'likely safe'"
    ).fetchone()[0]
    critical_open = db.execute(
        "SELECT COUNT(*) FROM incidents WHERE severity = 'critical' AND status != 'resolved'"
    ).fetchone()[0]
    failed_logins = db.execute(
        "SELECT COUNT(*) FROM activity_logs WHERE action = 'auth.failed'"
    ).fetchone()[0]
    security_score = max(0, min(100, 100 - critical_open * 8 - open_incidents * 3 - suspicious_scans * 2))
    stats = {
        "open": db.execute("SELECT COUNT(*) FROM incidents WHERE status = 'open'").fetchone()[0],
        "investigating": db.execute("SELECT COUNT(*) FROM incidents WHERE status = 'investigating'").fetchone()[0],
        "contained": db.execute("SELECT COUNT(*) FROM incidents WHERE status = 'contained'").fetchone()[0],
        "resolved": db.execute("SELECT COUNT(*) FROM incidents WHERE status = 'resolved'").fetchone()[0],
        "critical": db.execute("SELECT COUNT(*) FROM incidents WHERE severity = 'critical' AND status != 'resolved'").fetchone()[0],
        "active_alerts": open_incidents,
        "suspicious": suspicious_scans,
        "failed_logins": failed_logins,
        "security_score": security_score,
        "threat_level": "CRITICAL" if critical_open >= 2 else "HIGH" if critical_open or open_incidents >= 4 else "LOW",
        "total_incidents": total_incidents,
    }
    incidents = db.execute(
        """SELECT incidents.*, users.username AS assignee FROM incidents
        LEFT JOIN users ON users.id = incidents.assigned_to
        ORDER BY incidents.updated_at DESC LIMIT 6"""
    ).fetchall()
    return render_template("dashboard.html", stats=stats, incidents=incidents)


@app.get("/api/dashboard-data")
@login_required
def dashboard_data():
    db = get_db()
    severity = db.execute("SELECT severity, COUNT(*) AS total FROM incidents GROUP BY severity").fetchall()
    status = db.execute("SELECT status, COUNT(*) AS total FROM incidents GROUP BY status").fetchall()
    categories = db.execute(
        "SELECT source, COUNT(*) AS total FROM incidents GROUP BY source ORDER BY total DESC"
    ).fetchall()
    activity = db.execute(
        """SELECT substr(created_at, 1, 10) AS day, COUNT(*) AS total
        FROM activity_logs WHERE action IN ('auth.login', 'auth.failed')
        GROUP BY day ORDER BY day DESC LIMIT 14"""
    ).fetchall()
    threat_timeline = db.execute(
        """SELECT substr(created_at, 1, 10) AS day, COUNT(*) AS total
        FROM incidents GROUP BY day ORDER BY day DESC LIMIT 14"""
    ).fetchall()
    return jsonify(
        severity={row["severity"]: row["total"] for row in severity},
        status={row["status"]: row["total"] for row in status},
        categories={row["source"]: row["total"] for row in categories},
        login_activity=list(reversed([dict(row) for row in activity])),
        threat_timeline=list(reversed([dict(row) for row in threat_timeline])),
    )


@app.route("/incidents", methods=("GET", "POST"))
@login_required
def incidents():
    db = get_db()
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        description = request.form.get("description", "").strip()
        severity = request.form.get("severity", "medium")
        source = request.form.get("source", "manual").strip() or "manual"
        if title and description and severity in {"low", "medium", "high", "critical"}:
            now = utc_now()
            db.execute(
                """INSERT INTO incidents
                (title, description, severity, status, source, created_at, updated_at)
                VALUES (?, ?, ?, 'open', ?, ?, ?)""",
                (title, description, severity, source, now, now),
            )
            db.commit()
            log_activity("incident.created", f"Created incident: {title}", g.user["id"])
            flash("Incident created and added to the queue.", "success")
            return redirect(url_for("incidents"))
        flash("Title and description are required.", "error")
    severity_filter = request.args.get("severity", "")
    status_filter = request.args.get("status", "")
    query = """SELECT incidents.*, users.username AS assignee FROM incidents
        LEFT JOIN users ON users.id = incidents.assigned_to WHERE 1=1"""
    params: list[str] = []
    if severity_filter in {"low", "medium", "high", "critical"}:
        query += " AND incidents.severity = ?"
        params.append(severity_filter)
    if status_filter in {"open", "investigating", "contained", "resolved"}:
        query += " AND incidents.status = ?"
        params.append(status_filter)
    query += " ORDER BY incidents.updated_at DESC"
    rows = db.execute(query, params).fetchall()
    return render_template("incidents.html", incidents=rows, severity_filter=severity_filter, status_filter=status_filter)


@app.route("/incidents/<int:incident_id>", methods=("GET", "POST"))
@login_required
def incident_detail(incident_id: int):
    db = get_db()
    incident = db.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,)).fetchone()
    if incident is None:
        abort(404)
    if request.method == "POST":
        status = request.form.get("status", "")
        severity = request.form.get("severity", "")
        if status in {"open", "investigating", "contained", "resolved"} and severity in {"low", "medium", "high", "critical"}:
            db.execute(
                "UPDATE incidents SET status = ?, severity = ?, updated_at = ? WHERE id = ?",
                (status, severity, utc_now(), incident_id),
            )
            db.commit()
            log_activity("incident.updated", f"Updated incident #{incident_id}", g.user["id"])
            flash("Incident updated.", "success")
            return redirect(url_for("incident_detail", incident_id=incident_id))
        flash("Choose a valid status and severity.", "error")
    return render_template("incident_detail.html", incident=incident)


@app.post("/incidents/<int:incident_id>/delete")
@admin_required
def delete_incident(incident_id: int):
    db = get_db()
    db.execute("DELETE FROM incidents WHERE id = ?", (incident_id,))
    db.commit()
    log_activity("incident.deleted", f"Deleted incident #{incident_id}", g.user["id"])
    flash("Incident deleted.", "success")
    return redirect(url_for("incidents"))


@app.get("/admin")
@admin_required
def admin():
    db = get_db()
    users = db.execute("SELECT id, username, email, role, created_at FROM users ORDER BY created_at DESC").fetchall()
    incidents = db.execute(
        "SELECT * FROM incidents ORDER BY updated_at DESC LIMIT 8"
    ).fetchall()
    activity_logs = db.execute(
        """SELECT activity_logs.*, users.username
        FROM activity_logs LEFT JOIN users ON users.id = activity_logs.user_id
        ORDER BY activity_logs.created_at DESC LIMIT 12"""
    ).fetchall()
    threat_stats = db.execute(
        "SELECT verdict, COUNT(*) AS total FROM threat_logs GROUP BY verdict ORDER BY total DESC"
    ).fetchall()
    return render_template(
        "admin.html",
        users=users,
        incidents=incidents,
        activity_logs=activity_logs,
        threat_stats=threat_stats,
    )


@app.post("/admin/users/<int:user_id>/role")
@admin_required
def update_role(user_id: int):
    role = request.form.get("role")
    if role in {"admin", "analyst"} and user_id != g.user["id"]:
        db = get_db()
        db.execute("UPDATE users SET role = ? WHERE id = ?", (role, user_id))
        db.commit()
        log_activity("access.role_changed", f"Changed user #{user_id} role to {role}", g.user["id"])
        flash("User role updated.", "success")
    return redirect(url_for("admin"))


@app.route("/threat-demo", methods=("GET", "POST"))
@login_required
def threat_demo():
    result = None
    if request.method == "POST":
        target = request.form.get("target", "").strip()
        if target:
            lower = target.lower()
            indicators = []
            patterns = [
                ("punycode domain", "xn--" in lower),
                ("credential keyword", any(x in lower for x in ("login", "verify", "password", "wallet"))),
                ("raw IP address", bool(re.search(r"https?://\d{1,3}(?:\.\d{1,3}){3}", lower))),
                ("suspicious file extension", any(x in lower for x in (".zip", ".scr", ".exe", ".js"))),
                ("insecure transport", lower.startswith("http://")),
            ]
            indicators = [label for label, found in patterns if found]
            score = min(99, len(indicators) * 21 + (9 if target.count("/") > 3 else 0))
            verdict = "high risk" if score >= 60 else "review" if score >= 20 else "likely safe"
            db = get_db()
            db.execute(
                "INSERT INTO threat_logs (target, verdict, score, indicators, scanned_at, scanned_by) VALUES (?, ?, ?, ?, ?, ?)",
                (target, verdict, score, json.dumps(indicators), utc_now(), g.user["id"]),
            )
            db.commit()
            log_activity("threat.scan", f"Scanned target with verdict: {verdict}", g.user["id"])
            result = {"target": target, "verdict": verdict, "score": score, "indicators": indicators}
        else:
            flash("Enter a URL, domain, IP, or file name to scan.", "error")
    recent = get_db().execute(
        "SELECT * FROM threat_logs ORDER BY scanned_at DESC LIMIT 8"
    ).fetchall()
    return render_template("threat_demo.html", result=result, recent=recent)


@app.route("/threats", methods=("GET", "POST"))
@login_required
def threats():
    return threat_demo()


@app.get("/password-checker")
@login_required
def password_checker():
    return render_template("password_checker.html")


@app.get("/password")
def password():
    return password_checker()


@app.route("/hash-generator", methods=("GET", "POST"))
@login_required
def hash_generator():
    result = None
    if request.method == "POST":
        uploaded = request.files.get("file")
        if uploaded is None or not uploaded.filename:
            flash("Choose a file to hash.", "error")
        else:
            try:
                with tempfile.NamedTemporaryFile(prefix="cyberguard-hash-", delete=True) as temporary:
                    uploaded.save(temporary.name)
                    temporary.flush()
                    digests = {"sha256": hashlib.sha256(), "sha512": hashlib.sha512(), "md5": hashlib.md5()}
                    size = 0
                    with open(temporary.name, "rb") as source:
                        for chunk in iter(lambda: source.read(1024 * 1024), b""):
                            size += len(chunk)
                            for digest in digests.values():
                                digest.update(chunk)
                result = {"name": uploaded.filename, "size": size, "sha256": digests["sha256"].hexdigest(), "sha512": digests["sha512"].hexdigest(), "md5": digests["md5"].hexdigest()}
                log_activity("tool.hash", "Generated file hashes", g.user["id"])
            except OSError:
                flash("The file could not be processed. Try again.", "error")
    return render_template("hash_generator.html", result=result)


def _safe_analysis_target(target: str) -> tuple[bool, str]:
    parsed = urllib.parse.urlsplit(target)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
        return False, "Use a valid http:// or https:// URL without embedded credentials."
    try:
        addresses = socket.getaddrinfo(parsed.hostname, parsed.port or (443 if parsed.scheme == "https" else 80), type=socket.SOCK_STREAM)
    except (OSError, ValueError):
        return False, "The hostname could not be resolved."
    for address in {item[4][0] for item in addresses}:
        ip = ipaddress.ip_address(address)
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast or ip.is_unspecified:
            return False, "Private, local, and reserved network targets are not allowed."
    return True, ""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, _request, _file, _code, _message, _headers, _newurl):
        return None


@app.route("/security-headers", methods=("GET", "POST"))
@login_required
def security_headers():
    result = None
    if request.method == "POST":
        target = request.form.get("target", "").strip()
        valid, message = _safe_analysis_target(target)
        if not valid:
            flash(message, "error")
        else:
            try:
                request_object = urllib.request.Request(target, headers={"User-Agent": "CyberGuard educational analyzer"}, method="GET")
                opener = urllib.request.build_opener(_NoRedirect)
                with opener.open(request_object, timeout=6) as response:
                    headers = {key.lower(): value for key, value in response.headers.items()}
                definitions = {"content-security-policy": "Content-Security-Policy", "strict-transport-security": "Strict-Transport-Security", "x-content-type-options": "X-Content-Type-Options", "x-frame-options": "X-Frame-Options", "referrer-policy": "Referrer-Policy", "permissions-policy": "Permissions-Policy"}
                checks = []
                recommendations = []
                for key, label in definitions.items():
                    value = headers.get(key, "").strip()
                    status = "present" if value else "missing"
                    if value and ((key == "strict-transport-security" and not target.startswith("https://")) or (key == "content-security-policy" and "unsafe-inline" in value.lower())):
                        status = "weak"
                    if status != "present":
                        recommendations.append(f"Add or strengthen {label}.")
                    checks.append({"name": label, "value": value, "status": status})
                score = min(100, sum({"present": 17, "weak": 10, "missing": 0}[item["status"]] for item in checks))
                result = {"target": target, "checks": checks, "score": score, "recommendations": recommendations}
                log_activity("tool.headers", "Analyzed security headers", g.user["id"])
            except (OSError, urllib.error.URLError, ValueError):
                flash("The target could not be reached within the safety limits.", "error")
    return render_template("security_headers.html", result=result)


@app.get("/cvss-calculator")
@login_required
def cvss_calculator():
    return render_template("cvss_calculator.html")


@app.route("/log-analyzer", methods=("GET", "POST"))
@login_required
def log_analyzer():
    result = None
    if request.method == "POST":
        raw_logs = request.form.get("logs", "")[:1_000_000]
        lines = [line.strip() for line in raw_logs.splitlines() if line.strip()][:10_000]
        failure_pattern = r"failed login|authentication failure|login failed|auth failed"
        failed = sum(bool(re.search(failure_pattern, line, re.I)) for line in lines)
        successful = sum(bool(re.search(r"successful login|login successful|logged in", line, re.I)) for line in lines)
        ips = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", raw_logs)
        counts = {}
        for ip in ips:
            counts[ip] = counts.get(ip, 0) + 1
        findings = []
        for line in lines:
            ip_match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", line)
            lower = line.lower()
            severity = None
            reason = ""
            if re.search(failure_pattern, lower):
                source_ip = ip_match.group(0) if ip_match else "Unknown"
                if counts.get(source_ip, 0) >= 3:
                    severity, reason = "critical", "Repeated authentication failures from the same source."
                elif counts.get(source_ip, 0) >= 2:
                    severity, reason = "high", "Repeated authentication failures detected."
            if re.search(r"access denied|privilege|unauthori[sz]ed|sudo", lower):
                severity, reason = "high", "Privilege or access-control failure requires review."
            if re.search(r"error|exception|timeout", lower) and severity is None:
                severity, reason = "medium", "Operational error pattern may need investigation."
            if severity:
                findings.append({"timestamp": line[:19], "event": line[20:100] or line, "ip": ip_match.group(0) if ip_match else "Unknown", "severity": severity, "reason": reason})
        suspicious = len(findings)
        risk = "critical" if suspicious >= 8 or any(item["severity"] == "critical" for item in findings) else "high" if suspicious >= 4 else "medium" if suspicious else "low"
        result = {"total": len(lines), "failed": failed, "successful": successful, "suspicious": suspicious, "unique_ips": len(set(ips)), "risk": risk, "findings": findings[:100]}
        log_activity("tool.logs", "Analyzed security log metadata", g.user["id"])
    return render_template("log_analyzer.html", result=result)


LEARNING = {
    "security-basics": ("Security fundamentals", "Build durable habits around identity, devices, data, and response.", "Start with the basics: unique credentials, MFA, timely updates, safe backups, and a healthy skepticism toward unexpected requests."),
    "identity-access": ("Identity & access", "Reduce account takeover risk with strong identity controls.", "Use phishing-resistant MFA where possible, apply least privilege, review access regularly, and remove stale accounts quickly."),
    "incident-response": ("Incident response", "Move from alert to recovery with confidence.", "A useful response loop is prepare, identify, contain, eradicate, recover, and learn. Preserve evidence while acting decisively."),
    "network-security": ("Network security", "Protect traffic, services, and boundaries between systems.", "Firewalls filter traffic, IDS/IPS detects or blocks suspicious patterns, VPNs protect remote connections, and segmentation limits lateral movement."),
    "data-security": ("Data security", "Keep sensitive information private, accurate, and available.", "Use encryption at rest and in transit, classify sensitive data, restrict access, and test offline backups before an incident."),
    "application-security": ("Application security", "Build and use software with security in every stage.", "Validate input, protect sessions, patch dependencies, review code, and use secure defaults throughout the development lifecycle."),
}


@app.get("/learn")
def learn():
    return render_template("learn.html", topics=LEARNING)


@app.get("/learn/<slug>")
def learning_detail(slug: str):
    topic = LEARNING.get(slug)
    if topic is None:
        abort(404)
    return render_template("learning_detail.html", slug=slug, topic=topic)


@app.get("/attacks")
def attacks():
    cards = [
        ("Malware", "Software designed to disrupt, damage, or gain unauthorized access.", "verify", "Patch systems, use endpoint protection, restrict execution, and verify downloads."),
        ("Ransomware", "Malware that encrypts or exfiltrates valuable data.", "backup", "Segment offline backups, patch exposed services, and rehearse recovery."),
        ("Phishing", "Social engineering that turns trust into a foothold.", "verify", "Check the sender, destination, urgency, and request through a second channel."),
        ("DDoS", "Flooding a service with traffic so legitimate users cannot reach it.", "resilience", "Use rate limiting, upstream filtering, redundancy, and an incident runbook."),
        ("SQL injection", "Untrusted input changes a database query's meaning.", "validate", "Use parameterized queries, validation, least-privilege database accounts, and testing."),
        ("Cross-site scripting", "Injected script executes in another user's browser.", "escape", "Encode output, sanitize input, use CSP, and protect cookies."),
        ("Brute force", "Repeated guesses target passwords or encryption keys.", "throttle", "Use MFA, long unique passwords, rate limits, lockout controls, and monitoring."),
        ("Man-in-the-middle", "An attacker intercepts or alters communication between parties.", "encrypt", "Use HTTPS, certificate validation, trusted VPNs, and secure Wi-Fi."),
        ("Social engineering", "Manipulating people into revealing information or taking risky actions.", "challenge", "Slow down, verify identity independently, and limit sensitive access."),
        ("Zero-day attack", "Exploitation of a vulnerability before a patch or fix is available.", "monitor", "Segment systems, reduce exposure, monitor behavior, and apply mitigations quickly."),
    ]
    return render_template("attacks.html", cards=cards)


@app.get("/tools")
@login_required
def tools():
    interactive_tools = [
        ("File Hash Generator", "Integrity", "Generate file fingerprints", "Verify file integrity without retaining uploaded files.", "hash_generator", "⌁"),
        ("Security Headers Analyzer", "Web security", "Review browser defenses", "Inspect common HTTP security headers safely.", "security_headers", "◈"),
        ("CVSS Risk Calculator", "Vulnerability management", "Score findings", "Calculate a CVSS 3.1 base score locally.", "cvss_calculator", "▣"),
        ("Security Log Analyzer", "Detection", "Find suspicious patterns", "Analyze pasted logs for authentication and access events.", "log_analyzer", "≡"),
    ]
    tool_catalog = [
    ]
    return render_template("tools.html", interactive_tools=interactive_tools, tool_catalog=tool_catalog)


@app.route("/phishing-quiz", methods=("GET", "POST"))
@login_required
def phishing_quiz():
    answer = None
    if request.method == "POST":
        choice = request.form.get("choice")
        answer = choice == "phishing"
    return render_template("phishing_quiz.html", answer=answer)


@app.route("/phishing", methods=("GET", "POST"))
def phishing():
    return phishing_quiz()


@app.route("/quiz", methods=("GET", "POST"))
def quiz():
    db = get_db()
    questions = db.execute("SELECT * FROM quiz_questions ORDER BY id").fetchall()
    score = None
    breakdown = []
    if request.method == "POST":
        for question in questions:
            selected = request.form.get(f"question_{question['id']}")
            correct = selected == question["answer"]
            breakdown.append((question, selected, correct))
        score = sum(correct for _, _, correct in breakdown)
    return render_template("quiz.html", questions=questions, score=score, breakdown=breakdown)


@app.get("/learning")
def learning():
    return learn()


@app.get("/cyber-attacks")
def cyber_attacks():
    return attacks()


@app.route("/incident-reports", methods=("GET", "POST"))
@login_required
def incident_reports():
    return incidents()


@app.get("/security-tools")
def security_tools():
    return tools()


@app.route("/security-quiz", methods=("GET", "POST"))
@login_required
def security_quiz():
    return quiz()


@app.errorhandler(403)
def forbidden(_error):
    return render_template("error.html", code=403, message="You do not have permission to access this resource."), 403


@app.errorhandler(404)
def not_found(_error):
    return render_template("error.html", code=404, message="The requested page could not be found."), 404


@app.errorhandler(400)
def bad_request(error):
    return render_template("error.html", code=400, message=error.description), 400


with app.app_context():
    init_db()


if __name__ == "__main__":
    app.run(debug=os.environ.get("FLASK_DEBUG") == "1")
