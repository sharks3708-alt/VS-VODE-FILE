"""Initialize CyberGuard's SQLite database and seed demo data."""
from app import app, init_db

with app.app_context():
    init_db()
    print(f"Initialized {app.config['DATABASE']}")
