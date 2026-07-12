"""
Ironwall Custom Python SAST Scanner — CWE-501 (Trust Boundary) + CWE-90 (LDAP Injection).

Standalone scanner that parses Python files with AST to detect patterns that
Bandit's built-in rules miss. Outputs Bandit-compatible JSON.

Usage: python ironwall_custom_scanner.py <target_dir>
Output: JSON array of findings on stdout.
"""

import ast
import json
import os
import sys
from pathlib import Path


# ── Common Utilities ──────────────────────────────────────────────────

REQUEST_ATTRS = {"cookies", "args", "form", "values", "json"}
REQUEST_METHODS = {"get_json", "get_data", "getlist"}
SAFE_CONFIG_METHODS = {"get", "getint", "getfloat", "getboolean"}
LDAP_SEARCH_METHODS = {"search", "search_s", "search_ext", "search_ext_s"}


def _is_request_call(node):
    """request.cookies.get(...), request.args.get(...), request.get_json()"""
    if not isinstance(node, ast.Call):
        return False
    func = node.func
    if not isinstance(func, ast.Attribute):
        return False
    # request.attr.get(...)  e.g., request.cookies.get
    if isinstance(func.value, ast.Attribute):
        inner = func.value
        if isinstance(inner.value, ast.Name) and inner.value.id == "request":
            return inner.attr in REQUEST_ATTRS
    # request.get_json(), request.get_data()
    if isinstance(func.value, ast.Name) and func.value.id == "request":
        return func.attr in REQUEST_METHODS
    return False


def _is_request_subscript(node):
    """request.form['key'], request.args['key']"""
    if not isinstance(node, ast.Subscript):
        return False
    if isinstance(node.value, ast.Attribute):
        if (isinstance(node.value.value, ast.Name)
                and node.value.value.id == "request"):
            return node.value.attr in REQUEST_ATTRS
    return False


def _is_request_source(node):
    return _is_request_call(node) or _is_request_subscript(node)


def _is_constant_source(node):
    return isinstance(node, ast.Constant)


def _is_configparser_call(node):
    if not isinstance(node, ast.Call):
        return False
    func = node.func
    if isinstance(func, ast.Attribute):
        return func.attr in SAFE_CONFIG_METHODS
    return False


def _is_session_sink(target):
    """flask.session['key'] or session['key']"""
    if not isinstance(target, ast.Subscript):
        return False
    val = target.value
    if isinstance(val, ast.Attribute) and val.attr == "session":
        return True
    if isinstance(val, ast.Name) and val.id == "session":
        return True
    return False


def _last_lineno(node):
    """Approximate last line number of an AST node."""
    last = getattr(node, 'lineno', 0)
    for child in ast.walk(node):
        if hasattr(child, 'lineno'):
            last = max(last, child.lineno)
        if hasattr(child, 'end_lineno') and child.end_lineno:
            last = max(last, child.end_lineno)
    return last


# ── Assignment Graph Builder ──────────────────────────────────────────

def _build_conditional_ranges(func_node):
    """Collect line ranges of conditional blocks (if/for/while/try/with/match)."""
    ranges = []
    for node in ast.walk(func_node):
        if not isinstance(node, (ast.If, ast.For, ast.While, ast.Try, ast.With,
                                 ast.Match, ast.AsyncFor, ast.AsyncWith)):
            continue
        bodies = []
        # Standard control flow: body + orelse
        if hasattr(node, 'body'):
            bodies.append(node.body)
        if hasattr(node, 'orelse') and node.orelse:
            bodies.append(node.orelse)
        # Try nodes: handlers + finalbody
        if isinstance(node, ast.Try):
            if hasattr(node, 'finalbody') and node.finalbody:
                bodies.append(node.finalbody)
            for handler in getattr(node, 'handlers', []):
                bodies.append(handler.body)
        # Match/case: each case has a body
        if isinstance(node, ast.Match):
            for case in getattr(node, 'cases', []):
                bodies.append(case.body)
        for body in bodies:
            if body:
                lo = body[0].lineno
                hi = _last_lineno(body[-1])
                ranges.append((lo, hi))
    return ranges


def _build_assignments(func_node):
    """
    Build variable → [(source_expression, lineno, is_conditional)] map.
    is_conditional=True when inside if/for/while/try/with/match.
    """
    ranges = _build_conditional_ranges(func_node)

    def _is_conditional(lineno):
        for lo, hi in ranges:
            if lo <= lineno <= hi:
                return True
        return False

    assignments = {}
    for node in ast.walk(func_node):
        if not hasattr(node, 'lineno'):
            continue
        is_cond = _is_conditional(node.lineno)
        is_aug = isinstance(node, ast.AugAssign)

        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    assignments.setdefault(target.id, []).append(
                        (node.value, node.lineno, is_cond, False))

        elif isinstance(node, ast.AnnAssign):
            if isinstance(node.target, ast.Name) and node.value:
                assignments.setdefault(node.target.id, []).append(
                    (node.value, node.lineno, is_cond, False))

        elif isinstance(node, ast.AugAssign):
            if isinstance(node.target, ast.Name):
                assignments.setdefault(node.target.id, []).append(
                    (node.value, node.lineno, is_cond, True))

    return assignments


# ── Variable Taint Tracing ────────────────────────────────────────────

def _trace_to_source(name, assignments, visited=None, depth=0):
    """
    Trace variable through assignments to check if origin is request.*.
    Returns (is_tainted, source_lineno).

    Conservative heuristic:
    - Report tainted if ANY assignment traces to request.*
    - EXCEPT when the LAST *unconditional* assignment is a safe constant/config.
    - Conditional assignments (inside if/for/while/try) don't clear taint.
    """
    if depth > 12:
        return (False, 0)
    if visited is None:
        visited = set()
    if name in visited:
        return (False, 0)
    visited.add(name)

    if name not in assignments or not assignments[name]:
        return (False, 0)

    assigns = assignments[name]  # [(node, lineno, is_conditional), ...]

    # Heuristic: if the LAST assignment (highest lineno) is an unconditional
    # literal constant AND it's a full Assign (not AugAssign +=), variable is clean.
    # AugAssign accumulates — constant suffix doesn't clear existing taint.
    if assigns:
        last_assign = max(assigns, key=lambda x: x[1])
        last_node, _, last_cond, is_aug = last_assign
        if not last_cond and not is_aug and _is_constant_source(last_node):
            return (False, 0)

    all_assigns = sorted(assigns, key=lambda x: x[1])
    has_taint = False
    taint_line = 0

    for source_node, src_lineno, is_cond, is_aug in all_assigns:
        if _is_request_source(source_node):
            has_taint = True
            taint_line = src_lineno
            continue
        if _is_constant_source(source_node) or _is_configparser_call(source_node):
            continue
        if isinstance(source_node, ast.Name):
            t, l = _trace_to_source(source_node.id, assignments, visited, depth + 1)
            if t:
                has_taint = True
                taint_line = l
            continue
        # Subscript: values[0] — check if base (values) is tainted
        if isinstance(source_node, ast.Subscript):
            if isinstance(source_node.value, ast.Name):
                t, l = _trace_to_source(source_node.value.id, assignments, visited, depth + 1)
                if t:
                    has_taint = True
                    taint_line = l
            continue
        # Expression: check for nested request calls AND tainted names
        if _is_request_source(source_node):
            has_taint = True
            taint_line = src_lineno
        else:
            for child in ast.walk(source_node):
                # Check nested request calls (e.g., urllib.parse.unquote_plus(request.cookies.get(...)))
                if _is_request_source(child):
                    has_taint = True
                    taint_line = src_lineno
                    break
                if isinstance(child, ast.Name) and child.id != name:
                    if child.id not in visited:
                        t, l = _trace_to_source(child.id, assignments, visited.copy(), depth + 1)
                        if t:
                            has_taint = True
                            taint_line = l
                            break

    return (True, taint_line) if has_taint else (False, 0)


# ── CWE-501: Trust Boundary Violation ─────────────────────────────────

def _detect_trust_boundary(tree, filename):
    """Walk module for flask.session writes with tainted values."""
    findings = []
    for func in ast.walk(tree):
        if not isinstance(func, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        assignments = _build_assignments(func)

        for child in ast.walk(func):
            if not isinstance(child, ast.Assign):
                continue
            for target in child.targets:
                if not _is_session_sink(target):
                    continue
                value = child.value
                found_var = None
                found_tainted = False

                # Check 1: Value tainting (session['x'] = TAINTED_VAR)
                if isinstance(value, ast.Name):
                    found_var = value.id
                    found_tainted, _ = _trace_to_source(value.id, assignments)
                elif isinstance(value, ast.Subscript):
                    if isinstance(value.value, ast.Name):
                        found_var = value.value.id
                        found_tainted, _ = _trace_to_source(value.value.id, assignments)
                elif _is_request_source(value):
                    # Direct: session['x'] = request.args.get('x')
                    found_var = "direct_request"
                    found_tainted = True

                if found_var and found_tainted:
                    findings.append({
                        "filename": filename,
                        "test_id": "B901",
                        "test_name": "trust_boundary_violation",
                        "issue_severity": "MEDIUM",
                        "issue_confidence": "MEDIUM",
                        "issue_text": (
                            f"Trust boundary violation (CWE-501): "
                            f"untrusted data in Flask session via '{found_var}'. "
                            f"Session data is trusted downstream — validate before storing."
                        ),
                        "line_number": child.lineno,
                        "code": ast.unparse(child)[:200] if hasattr(ast, 'unparse') else "see source",
                        "more_info": "https://cwe.mitre.org/data/definitions/501.html",
                    })

                # Note: Session key tainting (session[TAINTED_KEY] = value)
                # is a real attack vector (session poisoning) but not tracked
                # separately here — benchmark definition focuses on value tainting.
    return findings


# ── CWE-90: LDAP Injection ────────────────────────────────────────────

def _extract_filter_vars(filter_node):
    """Extract variable names from LDAP filter expression (f-string, .format, %, bare)."""
    vars_found = set()

    if isinstance(filter_node, ast.JoinedStr):  # f-string
        for child in ast.walk(filter_node):
            if isinstance(child, ast.FormattedValue):
                val = child.value
                if isinstance(val, ast.Name):
                    vars_found.add(val.id)
                elif isinstance(val, ast.Subscript):
                    if isinstance(val.value, ast.Name):
                        vars_found.add(val.value.id)

    elif isinstance(filter_node, ast.Call):  # .format()
        if isinstance(filter_node.func, ast.Attribute):
            if filter_node.func.attr == "format":
                for arg in filter_node.args:
                    if isinstance(arg, ast.Name):
                        vars_found.add(arg.id)
                for kw in filter_node.keywords:
                    if isinstance(kw.value, ast.Name):
                        vars_found.add(kw.value.id)

    elif isinstance(filter_node, ast.BinOp) and isinstance(filter_node.op, ast.Mod):
        right = filter_node.right
        if isinstance(right, ast.Name):
            vars_found.add(right.id)
        elif isinstance(right, ast.Tuple):
            for elt in right.elts:
                if isinstance(elt, ast.Name):
                    vars_found.add(elt.id)

    elif isinstance(filter_node, ast.Name):
        vars_found.add(filter_node.id)

    return vars_found


def _is_ldap_search_call(call_node):
    func = call_node.func
    if isinstance(func, ast.Attribute):
        return func.attr in LDAP_SEARCH_METHODS
    return False


def _detect_ldap_injection(tree, filename):
    """Walk module for LDAP search calls with tainted filter variables."""
    findings = []

    for func in ast.walk(tree):
        if not isinstance(func, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        assignments = _build_assignments(func)

        for child in ast.walk(func):
            if not isinstance(child, ast.Call):
                continue
            if not _is_ldap_search_call(child):
                continue
            if len(child.args) < 2:
                continue

            filter_node = child.args[1]
            filter_vars = _extract_filter_vars(filter_node)
            if not filter_vars:
                continue

            for var in filter_vars:
                tainted, _ = _trace_to_source(var, assignments)
                if tainted:
                    findings.append({
                        "filename": filename,
                        "test_id": "B902",
                        "test_name": "ldap_injection",
                        "issue_severity": "MEDIUM",
                        "issue_confidence": "MEDIUM",
                        "issue_text": (
                            f"LDAP injection (CWE-90): "
                            f"untrusted data in LDAP filter via '{var}'. "
                            f"Use parameterized queries or escape special chars "
                            f"( * ( ) \\ \\x00 )."
                        ),
                        "line_number": child.lineno,
                        "code": ast.unparse(child)[:200] if hasattr(ast, 'unparse') else "see source",
                        "more_info": "https://cwe.mitre.org/data/definitions/90.html",
                    })
                    break
    return findings


# ── CWE-22: Path Traversal ────────────────────────────────────────────

FILE_OPEN_FUNCS = {"open", "codecs.open", "io.open", "pathlib.Path.open"}

def _is_file_open_call(call_node):
    """Check if call is a file open: open(...), codecs.open(...), etc."""
    func = call_node.func
    if isinstance(func, ast.Name) and func.id == "open":
        return True
    if isinstance(func, ast.Attribute):
        if func.attr == "open":
            return True
        # codecs.open -> func.value is Name('codecs'), func.attr is 'open'
        if isinstance(func.value, ast.Name):
            full = f"{func.value.id}.{func.attr}"
            if full in FILE_OPEN_FUNCS:
                return True
    return False


def _extract_path_vars(path_node):
    """Extract variable names from path expressions (f-string, os.path.join, concat)."""
    vars_found = set()

    if isinstance(path_node, ast.JoinedStr):  # f-string
        for child in ast.walk(path_node):
            if isinstance(child, ast.FormattedValue):
                val = child.value
                if isinstance(val, ast.Name):
                    vars_found.add(val.id)
                elif isinstance(val, ast.Attribute):
                    if isinstance(val.value, ast.Name):
                        vars_found.add(val.value.id)

    elif isinstance(path_node, ast.Call):  # os.path.join(...)
        if isinstance(path_node.func, ast.Attribute):
            if path_node.func.attr == "join":
                for arg in path_node.args[1:]:  # skip first arg (base dir)
                    if isinstance(arg, ast.Name):
                        vars_found.add(arg.id)
                    elif isinstance(arg, ast.JoinedStr):
                        for child in ast.walk(arg):
                            if isinstance(child, ast.FormattedValue):
                                if isinstance(child.value, ast.Name):
                                    vars_found.add(child.value.id)

    elif isinstance(path_node, ast.Name):
        vars_found.add(path_node.id)

    elif isinstance(path_node, ast.BinOp) and isinstance(path_node.op, ast.Add):
        for side in [path_node.left, path_node.right]:
            if isinstance(side, ast.Name):
                vars_found.add(side.id)
            elif isinstance(side, ast.JoinedStr):
                for child in ast.walk(side):
                    if isinstance(child, ast.FormattedValue):
                        if isinstance(child.value, ast.Name):
                            vars_found.add(child.value.id)

    return vars_found


def _detect_path_traversal(tree, filename):
    """Walk module for file open calls with tainted path variables."""
    findings = []

    for func in ast.walk(tree):
        if not isinstance(func, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        assignments = _build_assignments(func)

        for child in ast.walk(func):
            if not isinstance(child, ast.Call):
                continue
            if not _is_file_open_call(child):
                continue
            if not child.args:
                continue

            path_node = child.args[0]
            path_vars = _extract_path_vars(path_node)
            if not path_vars:
                continue

            for var in path_vars:
                tainted, taint_line = _trace_to_source(var, assignments)
                if tainted:
                    findings.append({
                        "filename": filename,
                        "test_id": "B903",
                        "test_name": "path_traversal",
                        "issue_severity": "MEDIUM",
                        "issue_confidence": "MEDIUM",
                        "issue_text": (
                            f"Path traversal (CWE-22): "
                            f"file path contains user-controlled variable '{var}' "
                            f"(tainted at line {taint_line}). "
                            f"Use os.path.realpath() + whitelist, or reject paths containing '..'."
                        ),
                        "line_number": child.lineno,
                        "code": ast.unparse(child)[:200] if hasattr(ast, 'unparse') else "see source",
                        "more_info": "https://cwe.mitre.org/data/definitions/22.html",
                    })
                    break
    return findings


# ── CWE-79: XSS via Reflected Input ──────────────────────────────────

def _is_response_sink(node):
    """Check if an expression feeds into HTTP response (return, RESPONSE+=, make_response)."""
    if isinstance(node, ast.Return):
        return True
    return False


def _detect_xss(tree, filename):
    """Walk handlers for f-strings/concatenation with tainted vars returned to response."""
    findings = []
    RESPONSE_VARS = {"RESPONSE", "response", "html", "output"}

    for func in ast.walk(tree):
        if not isinstance(func, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        # Only check handler functions (ignore utility functions)
        has_route = False
        for deco in func.decorator_list:
            deco_str = ast.unparse(deco) if hasattr(ast, 'unparse') else ''
            if 'route' in deco_str.lower():
                has_route = True
                break
        if not has_route:
            continue

        assignments = _build_assignments(func)

        # Find all f-strings and concatenations containing tainted vars
        for child in ast.walk(func):
            # Check AugAssign: RESPONSE += f'{tainted_var}'
            if isinstance(child, ast.AugAssign):
                if isinstance(child.target, ast.Name) and child.target.id in RESPONSE_VARS:
                    tainted_vars = _extract_path_vars(child.value)  # reuse path var extractor
                    for var in tainted_vars:
                        tainted, taint_line = _trace_to_source(var, assignments)
                        if tainted:
                            findings.append({
                                "filename": filename,
                                "test_id": "B904",
                                "test_name": "xss_reflected",
                                "issue_severity": "MEDIUM",
                                "issue_confidence": "MEDIUM",
                                "issue_text": (
                                    f"XSS (CWE-79): reflected user input '{var}' "
                                    f"(tainted at L{taint_line}) in HTTP response. "
                                    f"Use html.escape() or template engine auto-escaping."
                                ),
                                "line_number": child.lineno,
                                "code": ast.unparse(child)[:200] if hasattr(ast, 'unparse') else "see source",
                                "more_info": "https://cwe.mitre.org/data/definitions/79.html",
                            })
                            break

            # Check Return: return f'{tainted_var}'
            if isinstance(child, ast.Return) and child.value:
                val = child.value
                tainted_vars = set()
                # Check JoinedStr (f-string) in return
                if isinstance(val, ast.JoinedStr):
                    tainted_vars = _extract_path_vars(val)
                # Check BinOp (concatenation) in return
                elif isinstance(val, ast.BinOp) and isinstance(val.op, ast.Add):
                    tainted_vars = _extract_path_vars(val)
                # Check Name (var) in return
                elif isinstance(val, ast.Name):
                    tainted_vars = {val.id}
                # Check Call in return
                elif isinstance(val, ast.Call):
                    tainted_vars = _extract_path_vars(val)

                for var in tainted_vars:
                    tainted, taint_line = _trace_to_source(var, assignments)
                    if tainted:
                        findings.append({
                            "filename": filename,
                            "test_id": "B904",
                            "test_name": "xss_reflected",
                            "issue_severity": "MEDIUM",
                            "issue_confidence": "MEDIUM",
                            "issue_text": (
                                f"XSS (CWE-79): reflected user input '{var}' "
                                f"(tainted at L{taint_line}) in HTTP response return. "
                                f"Use html.escape() or template engine auto-escaping."
                            ),
                            "line_number": child.lineno,
                            "code": ast.unparse(child)[:200] if hasattr(ast, 'unparse') else "see source",
                            "more_info": "https://cwe.mitre.org/data/definitions/79.html",
                        })
                        break

    return findings



def _detect_open_redirect(tree, filename):
    """Walk handlers for redirect() calls with tainted URL arguments."""
    findings = []

    for func in ast.walk(tree):
        if not isinstance(func, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        has_route = any(
            'route' in (ast.unparse(d) if hasattr(ast, 'unparse') else '').lower()
            for d in func.decorator_list
        )
        if not has_route:
            continue

        assignments = _build_assignments(func)

        for child in ast.walk(func):
            if not isinstance(child, ast.Call):
                continue
            # Match redirect(...) or flask.redirect(...)
            call_str = ast.unparse(child) if hasattr(ast, 'unparse') else ''
            if 'redirect' not in call_str.lower():
                continue
            if not child.args:
                continue

            arg = child.args[0]
            tainted_vars = set()
            if isinstance(arg, ast.Name):
                tainted_vars = {arg.id}
            elif isinstance(arg, ast.JoinedStr):
                tainted_vars = _extract_path_vars(arg)

            for var in tainted_vars:
                tainted, taint_line = _trace_to_source(var, assignments)
                if tainted:
                    findings.append({
                        "filename": filename,
                        "test_id": "B905",
                        "test_name": "open_redirect",
                        "issue_severity": "MEDIUM",
                        "issue_confidence": "MEDIUM",
                        "issue_text": (
                            f"Open Redirect (CWE-601): user-controlled URL '{var}' "
                            f"(tainted at L{taint_line}) passed to redirect(). "
                            f"Validate URL against whitelist or use url_for()."
                        ),
                        "line_number": child.lineno,
                        "code": call_str[:200],
                        "more_info": "https://cwe.mitre.org/data/definitions/601.html",
                    })
                    break
    return findings


# ── Scanner Runner ────────────────────────────────────────────────────

def scan_file(filepath):
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            source = f.read()
    except (OSError, UnicodeDecodeError):
        return []
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return []
    return _detect_trust_boundary(tree, filepath) + _detect_ldap_injection(tree, filepath) + _detect_path_traversal(tree, filepath) + _detect_xss(tree, filepath) + _detect_open_redirect(tree, filepath)


def scan_directory(target):
    all_findings = []
    root = Path(target)
    if root.is_file():
        return scan_file(str(root))
    for pyfile in root.rglob("*.py"):
        if any(p in ("__pycache__", ".venv", "venv", "node_modules", ".git")
               for p in pyfile.parts):
            continue
        all_findings.extend(scan_file(str(pyfile)))
    return all_findings


def main():
    if len(sys.argv) < 2:
        print("Usage: python ironwall_custom_scanner.py <target_dir_or_file>", file=sys.stderr)
        sys.exit(1)
    target = sys.argv[1]
    findings = scan_directory(target)
    print(json.dumps(findings, indent=2))


if __name__ == "__main__":
    main()
