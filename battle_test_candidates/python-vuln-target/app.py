"""
python-vuln-target — deliberately vulnerable Flask app for Ironwall evaluation.
5 planted vulnerabilities: SQLi, SSTI, Auth Bypass, Path Traversal, SSRF.
Ground truth for recall/precision measurement.
"""
import os
import sqlite3
import subprocess
import hashlib
from flask import Flask, request, render_template_string, jsonify, send_file, session

app = Flask(__name__)
app.secret_key = "hardcoded-secret-do-not-use-in-production-12345"  # VULN-6: hardcoded secret

DB_PATH = os.path.join(os.path.dirname(__file__), "users.db")


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT DEFAULT 'user'
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT NOT NULL,
            owner_id INTEGER NOT NULL,
            content TEXT
        )
    """)
    # Seed: admin/admin123, user1/pass1
    conn.execute("INSERT OR IGNORE INTO users (username, password, role) VALUES (?, ?, ?)",
                 ("admin", hashlib.md5(b"admin123").hexdigest(), "admin"))
    conn.execute("INSERT OR IGNORE INTO users (username, password, role) VALUES (?, ?, ?)",
                 ("user1", hashlib.md5(b"pass1").hexdigest(), "user"))
    conn.commit()
    conn.close()


# --- VULN-1: SQL Injection via string concatenation ---
@app.route("/api/users")
def search_users():
    """Search users by username. VULNERABLE: raw SQL concatenation."""
    username = request.args.get("username", "")
    conn = get_db()
    # VULN: direct string interpolation into SQL
    query = f"SELECT id, username, role FROM users WHERE username LIKE '%{username}%'"
    cursor = conn.execute(query)
    users = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return jsonify(users)


# --- VULN-1b: SQL Injection in login (bypass) ---
@app.route("/api/login", methods=["POST"])
def login():
    """Login with username/password. VULNERABLE: SQL injection in password field."""
    data = request.get_json() or {}
    username = data.get("username", "")
    password = data.get("password", "")
    conn = get_db()
    # VULN: password directly interpolated — ' OR '1'='1 bypasses auth
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{hashlib.md5(password.encode()).hexdigest()}'"
    cursor = conn.execute(query)
    user = cursor.fetchone()
    conn.close()
    if user:
        session["user_id"] = user["id"]
        session["username"] = user["username"]
        return jsonify({"status": "ok", "user": dict(user)})
    return jsonify({"status": "fail", "msg": "invalid credentials"}), 401


# --- VULN-2: SSTI via render_template_string ---
@app.route("/greet")
def greet():
    """Greet a user by name. VULNERABLE: user input in render_template_string."""
    name = request.args.get("name", "World")
    # VULN: render_template_string with raw user input — {{7*7}} executes
    template = f"<h1>Hello, {name}!</h1>"
    return render_template_string(template)


# --- VULN-2b: SSTI in error page ---
@app.route("/profile")
def profile():
    """User profile page. VULNERABLE: reflects user agent in template."""
    theme = request.args.get("theme", "light")
    user_agent = request.headers.get("User-Agent", "unknown")
    # VULN: user_agent interpolated into template string
    html = f"""
    <html><body class="{theme}">
    <h1>Profile: {{session.get('username', 'Guest')}}</h1>
    <p>Your browser: {user_agent}</p>
    </body></html>
    """
    return render_template_string(html)


# --- VULN-3: Auth Bypass — missing @login_required ---
@app.route("/api/admin/users")
def admin_list_users():
    """Admin: list all users. VULNERABLE: no auth check, no role check."""
    # VULN: no session/auth check — anyone can access
    conn = get_db()
    users = [dict(row) for row in conn.execute("SELECT * FROM users").fetchall()]
    conn.close()
    return jsonify(users)


@app.route("/api/admin/delete_user", methods=["POST"])
def admin_delete_user():
    """Admin: delete a user. VULNERABLE: no auth check."""
    data = request.get_json() or {}
    user_id = data.get("user_id")
    # VULN: no auth, no CSRF, direct SQL concatenation
    conn = get_db()
    conn.execute(f"DELETE FROM users WHERE id = {user_id}")
    conn.commit()
    conn.close()
    return jsonify({"status": "deleted"})


# --- VULN-4: Path Traversal ---
@app.route("/download")
def download_file():
    """Download a file by name. VULNERABLE: path traversal via filename param."""
    filename = request.args.get("file", "")
    base_dir = os.path.join(os.path.dirname(__file__), "uploads")
    # VULN: os.path.join with unsanitized user input allows ../../etc/passwd
    filepath = os.path.join(base_dir, filename)
    try:
        return send_file(filepath)
    except FileNotFoundError:
        return jsonify({"error": "file not found"}), 404


# --- VULN-4b: Path traversal in log viewer ---
@app.route("/logs")
def view_logs():
    """View application logs. VULNERABLE: path traversal."""
    log_name = request.args.get("name", "app.log")
    log_dir = os.path.join(os.path.dirname(__file__), "logs")
    # VULN: direct path join with user input
    log_path = os.path.join(log_dir, log_name)
    try:
        with open(log_path, "r") as f:
            return f"<pre>{f.read()}</pre>"
    except FileNotFoundError:
        return "Log not found", 404


# --- VULN-5: SSRF ---
@app.route("/api/fetch")
def fetch_url():
    """Fetch external URL. VULNERABLE: unrestricted SSRF."""
    import requests
    url = request.args.get("url", "")
    # VULN: no URL validation — can hit internal services (localhost, 169.254, etc.)
    try:
        resp = requests.get(url, timeout=5)
        return jsonify({"status": resp.status_code, "body": resp.text[:500]})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# --- VULN-5b: SSRF via webhook ---
@app.route("/api/webhook", methods=["POST"])
def webhook():
    """Send webhook to configured URL. VULNERABLE: attacker controls target URL."""
    import requests
    data = request.get_json() or {}
    target_url = data.get("callback_url", "")
    payload = data.get("payload", "{}")
    # VULN: attacker controls both URL and payload
    try:
        resp = requests.post(target_url, json={"data": payload}, timeout=5)
        return jsonify({"delivered": True, "response_code": resp.status_code})
    except Exception as e:
        return jsonify({"delivered": False, "error": str(e)})


# --- VULN-6: Command Injection ---
@app.route("/api/ping")
def ping():
    """Ping a host. VULNERABLE: command injection via os.system."""
    host = request.args.get("host", "127.0.0.1")
    # VULN: shell command injection — ; rm -rf / or $(whoami)
    cmd = f"ping -c 1 {host}"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return jsonify({"cmd": cmd, "output": result.stdout, "error": result.stderr})


# --- VULN-7: IDOR (Insecure Direct Object Reference) ---
@app.route("/api/files/<int:file_id>")
def get_file(file_id):
    """Get file metadata. VULNERABLE: no ownership check."""
    conn = get_db()
    # VULN: any user can access any file by ID
    cursor = conn.execute(f"SELECT * FROM files WHERE id = {file_id}")
    row = cursor.fetchone()
    conn.close()
    if row:
        return jsonify(dict(row))
    return jsonify({"error": "not found"}), 404


# --- VULN-8: Weak crypto (MD5) ---
@app.route("/api/hash", methods=["POST"])
def hash_password():
    """Hash a password. VULNERABLE: uses MD5."""
    data = request.get_json() or {}
    password = data.get("password", "")
    # VULN: MD5 for password hashing — fast, rainbow-table-able
    result = hashlib.md5(password.encode()).hexdigest()
    return jsonify({"algorithm": "md5", "hash": result})


# --- Safe route (control) ---
@app.route("/api/health")
def health():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    os.makedirs(os.path.join(os.path.dirname(__file__), "uploads"), exist_ok=True)
    os.makedirs(os.path.join(os.path.dirname(__file__), "logs"), exist_ok=True)
    init_db()
    app.run(debug=True, host="0.0.0.0", port=5000)
