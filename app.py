"""CyberGuard - a small, production-minded Flask security operations portal."""
from __future__ import annotations

import json
import os
import re
import secrets
import sqlite3
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

BASE_DIR = Path(__file__).resolve().parent
DATABASE = os.environ.get("CYBERGUARD_DB", str(BASE_DIR / "cyberguard.db"))

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get("SECRET_KEY", "cyberguard-local-development-key"),
    DATABASE=DATABASE,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("SESSION_COOKIE_SECURE", "0") == "1",
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
                    "CyberGuard Administrator",
                    "admin",
                    "admin@cyberguard.local",
                    generate_password_hash("Admin123!", method="pbkdf2:sha256"),
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


@app.route("/register", methods=("GET", "POST"))
def register():
    if g.user:
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        full_name = request.form.get("full_name", "").strip()
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirmation = request.form.get("confirmation", "")
        if not full_name or not username or not email or len(password) < 8:
            flash("Name, username, valid email, and an 8+ character password are required.", "error")
        elif password != confirmation:
            flash("Passwords do not match.", "error")
        elif not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email):
            flash("Enter a valid email address.", "error")
        else:
            try:
                db = get_db()
                db.execute(
                    """INSERT INTO users
                    (full_name, username, email, password_hash, created_at)
                    VALUES (?, ?, ?, ?, ?)""",
                    (full_name, username, email, generate_password_hash(password, method="pbkdf2:sha256"), utc_now()),
                )
                db.commit()
                log_activity("account.created", f"New account registered: {username}")
                flash("Account created. Sign in to open your console.", "success")
                return redirect(url_for("login"))
            except sqlite3.IntegrityError:
                flash("That username or email is already registered.", "error")
    return render_template("auth/register.html")


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
def password_checker():
    return render_template("password_checker.html")


@app.get("/password")
def password():
    return password_checker()


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
def tools():
    tool_catalog = [
        ("Wireshark", "Network analysis", "Inspect packets", "Capture and analyze network traffic to understand protocols and investigate suspicious connections."),
        ("Kali Linux", "Penetration testing", "Security assessment", "A Linux distribution that bundles tools for authorized testing, forensics, and defensive research."),
        ("Nmap", "Network discovery", "Map services", "Discover hosts and exposed services so teams can reduce unnecessary attack surface."),
        ("Cisco Packet Tracer", "Learning lab", "Practice networking", "Build simulated networks and safely learn routing, switching, and segmentation concepts."),
        ("Wazuh", "SIEM / EDR", "Monitor endpoints", "Collect endpoint telemetry, detect suspicious behavior, and support compliance investigations."),
        ("Autopsy", "Digital forensics", "Investigate evidence", "Analyze disk images and recover artifacts during an authorized forensic investigation."),
        ("FTK Imager", "Digital forensics", "Acquire evidence", "Create forensic images and preview evidence while preserving chain-of-custody workflows."),
    ]
    return render_template("tools.html", tool_catalog=tool_catalog)


@app.route("/phishing-quiz", methods=("GET", "POST"))
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
