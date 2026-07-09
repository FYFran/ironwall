"""CWE-501 Vulnerable: request data flows into Flask session."""
from flask import request, session

def vulnerable_trust_boundary():
    # Source: untrusted user input from cookie
    user_id = request.cookies.get("user_id")
    bar = user_id
    # Sink: trusted session store ← VIOLATION
    session['userid'] = bar

def vulnerable_via_args():
    # Source: request.args
    role = request.args.get("role")
    # Sink: session write
    flask.session['role'] = role
