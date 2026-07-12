"""
injection-misc-target: Resource exhaustion + XXE + LDAP injection + unsafe redirects.
6 planted vulnerabilities — covering CWE categories not yet in test set.
"""
import os
import hashlib
import xml.etree.ElementTree as ET
from flask import Flask, request, jsonify, redirect

app = Flask(__name__)


# VULN-1: XXE via XML parsing (CWE-611, CRITICAL)
@app.route("/api/import", methods=["POST"])
def import_xml():
    """Import XML data. VULNERABLE: XXE via default XML parser."""
    xml_data = request.get_data()
    # VULN: default parser processes external entities
    root = ET.fromstring(xml_data)
    return jsonify({"root_tag": root.tag, "content": root.text})


# VULN-2: LDAP Injection (CWE-90, HIGH)
@app.route("/api/users/search")
def search_users_ldap():
    """Search users via LDAP. VULNERABLE: LDAP injection."""
    username = request.args.get("username", "")
    # VULN: LDAP filter injection — )(|(uid=*)) can bypass auth
    ldap_filter = f"(uid={username})"
    # In real app: ldap.search(filter=ldap_filter)
    return jsonify({"ldap_query": ldap_filter, "note": "VULNERABLE to LDAP injection"})


# VULN-3: Resource Exhaustion via Zip Bomb (CWE-400, MEDIUM)
@app.route("/api/extract", methods=["POST"])
def extract_archive():
    """Extract uploaded archive. VULNERABLE: zip bomb / decompression bomb."""
    import zipfile
    import io
    f = request.files.get("archive")
    if f:
        # VULN: no size limit, no file count check — zip bomb can exhaust disk
        with zipfile.ZipFile(io.BytesIO(f.read())) as zf:
            names = zf.namelist()
            zf.extractall("/tmp/extracted")
        return jsonify({"extracted": len(names), "files": names})
    return jsonify({"error": "no file"}), 400


# VULN-4: Algorithmic Complexity (CWE-400, MEDIUM)
@app.route("/api/hash", methods=["POST"])
def hash_password():
    """Hash a password. VULNERABLE: MD5 + no rate limit."""
    data = request.get_json() or {}
    password = data.get("password", "")
    # VULN: MD5 for passwords (CWE-328)
    result = hashlib.md5(password.encode()).hexdigest()
    return jsonify({"algorithm": "MD5 (INSECURE)", "hash": result})


# VULN-5: Incorrect Permission (CWE-732, HIGH)
@app.route("/api/files/<path:filepath>")
def serve_file(filepath):
    """Serve any file. VULNERABLE: no permission check, any path allowed."""
    # VULN: allows access to any file on the system
    base = os.path.join(os.path.dirname(__file__), "public")
    full_path = os.path.join(base, filepath)
    try:
        with open(full_path, "rb") as f:
            return f.read()
    except Exception:
        return jsonify({"error": "not found"}), 404


# VULN-6: Insecure Direct Object Reference via integer ID (CWE-639, MEDIUM)
orders = {1: {"user": "alice", "total": 99.99}, 2: {"user": "bob", "total": 149.99}}

@app.route("/api/orders/<int:order_id>")
def get_order(order_id):
    """Get order details. VULNERABLE: no ownership check."""
    # VULN: any authenticated user can view any order
    return jsonify(orders.get(order_id, {"error": "not found"}))


# Safe
@app.route("/api/health")
def health():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    app.run(debug=False, host="127.0.0.1")  # Note: NOT vulnerable debug/host
