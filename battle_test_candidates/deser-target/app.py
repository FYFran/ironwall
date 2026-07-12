"""
deser-target: Insecure deserialization + XXE + file upload target.
8 planted vulnerabilities for Ironwall evaluation.
"""
import pickle
import yaml
import os
from flask import Flask, request, jsonify

app = Flask(__name__)
app.secret_key = "deser-secret-1234567890abcdef"  # VULN-1: hardcoded secret

UPLOAD_DIR = os.path.join(os.path.dirname(__file__), "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)


# VULN-1: Hardcoded secret key (CWE-798, HIGH)
# app.secret_key above


# VULN-2: Insecure Pickle Deserialization (CWE-502, CRITICAL)
@app.route("/api/load", methods=["POST"])
def load_pickle():
    """Load data from pickle. VULNERABLE: unpickles user data."""
    data = request.get_data()
    obj = pickle.loads(data)  # VULN: arbitrary code execution
    return jsonify({"result": str(obj)})


# VULN-3: Insecure YAML Deserialization (CWE-502, CRITICAL)
@app.route("/api/config", methods=["POST"])
def load_yaml():
    """Load YAML config. VULNERABLE: yaml.load with unsafe constructor."""
    data = request.get_data()
    config = yaml.load(data, Loader=yaml.Loader)  # VULN: arbitrary code execution
    return jsonify({"config": str(config)})


# VULN-4: Unrestricted File Upload (CWE-434, HIGH)
@app.route("/api/upload", methods=["POST"])
def upload_file():
    """Upload a file. VULNERABLE: no file type/extension validation."""
    f = request.files.get("file")
    if f:
        filepath = os.path.join(UPLOAD_DIR, f.filename)  # VULN: no sanitization
        f.save(filepath)
        return jsonify({"status": "saved", "path": filepath})
    return jsonify({"error": "no file"}), 400


# VULN-5: Path traversal in file download (CWE-22, HIGH)
@app.route("/api/download")
def download_file():
    """Download uploaded file. VULNERABLE: path traversal."""
    filename = request.args.get("name", "")
    filepath = os.path.join(UPLOAD_DIR, filename)  # VULN: ../../../etc/passwd
    try:
        with open(filepath, "rb") as f:
            return f.read()
    except FileNotFoundError:
        return jsonify({"error": "not found"}), 404


# VULN-6: Command injection via uploaded filename (CWE-78, CRITICAL)
@app.route("/api/process", methods=["POST"])
def process_upload():
    """Process uploaded file. VULNERABLE: shell command with filename."""
    filename = request.form.get("filename", "")
    import subprocess
    cmd = f"file uploads/{filename}"  # VULN: filename; rm -rf /
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return jsonify({"output": result.stdout})


# VULN-7: IDOR — no ownership check on files (CWE-639, MEDIUM)
files_db = {}

@app.route("/api/files/<int:file_id>")
def get_file_meta(file_id):
    """Get file metadata. VULNERABLE: no ownership check."""
    meta = files_db.get(file_id, {"error": "not found"})
    return jsonify(meta)


@app.route("/api/files/<int:file_id>/delete", methods=["POST"])
def delete_file(file_id):
    """Delete a file. VULNERABLE: no ownership check, anyone can delete."""
    if file_id in files_db:
        del files_db[file_id]
        return jsonify({"status": "deleted"})
    return jsonify({"error": "not found"}), 404


# VULN-8: Open Redirect (CWE-601, MEDIUM)
@app.route("/api/redirect")
def redirect_user():
    """Redirect to URL. VULNERABLE: no URL validation."""
    url = request.args.get("url", "/")
    # VULN: redirect to any URL — phishing vector
    from flask import redirect
    return redirect(url)


# Safe endpoint (control)
@app.route("/api/health")
def health():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5001)  # VULN-9: debug mode
