"""
jwt-redirect-target: JWT vulnerabilities + auth issues target.
7 planted vulnerabilities for Ironwall evaluation.
"""
import jwt
import os
from flask import Flask, request, jsonify

app = Flask(__name__)
JWT_SECRET = "weak-jwt-secret-2024"  # VULN-1: weak JWT secret

# VULN-1: Weak JWT secret (CWE-798, HIGH)
# JWT_SECRET above — easily brute-forceable


# VULN-2: JWT None Algorithm (CWE-287, CRITICAL)
@app.route("/api/verify", methods=["POST"])
def verify_token():
    """Verify JWT token. VULNERABLE: accepts 'none' algorithm."""
    data = request.get_json() or {}
    token = data.get("token", "")
    try:
        # VULN: algorithms includes 'none' — attacker can bypass signature
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256", "HS384", "HS512", "none"])
        return jsonify({"valid": True, "user": payload.get("sub")})
    except Exception as e:
        return jsonify({"valid": False, "error": str(e)})


# VULN-3: JWT Secret in URL (CWE-200, MEDIUM)
@app.route("/api/token", methods=["GET"])
def get_token():
    """Generate token. VULNERABLE: accepts secret as query param."""
    username = request.args.get("user", "guest")
    secret = request.args.get("secret", JWT_SECRET)  # VULN: secret from user input
    token = jwt.encode({"sub": username, "role": "user"}, secret, algorithm="HS256")
    return jsonify({"token": token})


# VULN-4: Missing Authorization (CWE-862, HIGH)
@app.route("/api/admin/stats")
def admin_stats():
    """Admin statistics. VULNERABLE: no auth check at all."""
    # VULN: anyone can access — no JWT verification, no role check
    return jsonify({
        "total_users": 15420,
        "total_revenue": "$1,245,000",
        "active_sessions": 843,
    })


# VULN-5: Open Redirect via next parameter (CWE-601, MEDIUM)
@app.route("/login")
def login_page():
    """Login page. VULNERABLE: redirects to arbitrary URL after login."""
    next_url = request.args.get("next", "/dashboard")
    # VULN: no URL validation — attacker can redirect to phishing site
    # In real app: after login, redirect to next_url
    return f'<html><body><a href="{next_url}">Click here to login</a></body></html>'


# VULN-6: Insecure Cookie (CWE-614, MEDIUM)
@app.route("/api/session", methods=["POST"])
def create_session():
    """Create session. VULNERABLE: cookie missing secure flags."""
    from flask import make_response
    resp = make_response(jsonify({"status": "logged_in"}))
    # VULN: no Secure, HttpOnly, or SameSite flags
    resp.set_cookie("session_id", "user-12345-session-token")
    return resp


# VULN-7: User Enumeration (CWE-204, LOW)
users = {"admin": "admin123", "user1": "pass1"}

@app.route("/api/login", methods=["POST"])
def login():
    """Login endpoint. VULNERABLE: different error messages."""
    data = request.get_json() or {}
    username = data.get("username", "")
    password = data.get("password", "")
    if username not in users:
        return jsonify({"error": "User does not exist"}), 401  # VULN: user enum
    if users[username] != password:
        return jsonify({"error": "Incorrect password"}), 401  # VULN: confirms user exists
    return jsonify({"status": "logged_in", "token": "fake-jwt"})


# Safe endpoint
@app.route("/api/health")
def health():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0")  # VULN-8: debug mode
