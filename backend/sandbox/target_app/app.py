"""
Deliberately vulnerable Flask target application for the ShieldSphere Attack Simulator.
This is an isolated container — never shares the production DB.
"""
import os
import secrets
import sqlite3
from flask import Flask, request, jsonify, make_response

app = Flask(__name__)

# Initialize an isolated SQLite DB with per-container credentials.
DB_PATH = "/tmp/target.db"


def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT,
            password TEXT,
            role TEXT DEFAULT 'user'
        )
    """)
    username = os.getenv("TARGET_USERNAME") or f"sandbox-{secrets.token_hex(4)}"
    password = os.getenv("TARGET_PASSWORD") or secrets.token_urlsafe(24)
    c.execute(
        "INSERT OR IGNORE INTO users (id, username, password, role) VALUES (?, ?, ?, ?)",
        (1, username, password, "sandbox_admin"),
    )
    conn.commit()
    conn.close()


init_db()


@app.route("/")
def index():
    return jsonify({"app": "ShieldSphere Target", "status": "running"})


# Vulnerable login endpoint (SQL injection possible)
@app.route("/login", methods=["POST", "GET"])
def login():
    username = request.form.get("username", request.args.get("username", ""))
    password = request.form.get("password", request.args.get("password", ""))

    if not username or not password:
        return jsonify({"error": "Missing credentials"}), 400

    # DELIBERATELY VULNERABLE: direct string interpolation — DO NOT use in production
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
        c.execute(query)
        user = c.fetchone()
    except Exception as e:
        return jsonify({"error": str(e), "query": query}), 500
    finally:
        conn.close()

    if user:
        return jsonify({"success": True, "user": user[1], "role": user[3], "message": f"Welcome, {user[1]}!"})
    return jsonify({"success": False, "message": "Invalid credentials"}), 401


# Secure login endpoint (parameterized — for comparison)
@app.route("/login-secure", methods=["POST"])
def login_secure():
    username = request.form.get("username", "")
    password = request.form.get("password", "")

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE username=? AND password=?", (username, password))
    user = c.fetchone()
    conn.close()

    if user:
        return jsonify({"success": True, "user": user[1]})
    return jsonify({"success": False, "message": "Invalid credentials"}), 401


# XSS-vulnerable search endpoint
@app.route("/search")
def search():
    query = request.args.get("q", "")
    # DELIBERATELY VULNERABLE: returns unescaped user input
    html = f"""
    <html><body>
    <h1>Search Results for: {query}</h1>
    <p>No results found for: {query}</p>
    </body></html>
    """
    return make_response(html, 200, {"Content-Type": "text/html"})


# Secure search endpoint (for comparison)
@app.route("/search-secure")
def search_secure():
    import html
    query = request.args.get("q", "")
    safe_query = html.escape(query)
    return f"<html><body><h1>Results for: {safe_query}</h1></body></html>"


# Webhook endpoint for receiving login events from ShieldSphere
@app.route("/webhook/login", methods=["POST"])
def webhook_login():
    """Receives login events from the attacker script."""
    data = request.json or {}
    # Forward to ShieldSphere main backend if configured
    sim_id = os.getenv("SIM_ID", "")
    backend_url = os.getenv("BACKEND_URL", "")
    if backend_url:
        import requests
        try:
            requests.post(f"{backend_url}/api/v1/simulator/webhook", json={**data, "sim_id": sim_id}, timeout=2)
        except Exception:
            pass
    return jsonify({"received": True})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
