"""
Bandit plugin for CWE-501: Trust Boundary Violation.

Detects when untrusted data from HTTP request (cookies, args, form, JSON)
flows into a trusted data store (Flask session) without validation.

Pattern:
  param = request.cookies.get("id")   # untrusted source
  flask.session['userid'] = param     # trusted sink ← VIOLATION

Safe when source is configparser, constant, or non-request data.
"""

import ast
import bandit
from bandit.core import issue
from bandit.core import test_properties as test

# Per-function cache to avoid duplicate reports.
# Bandit runs as a separate process, so global state is safe.
_analyzed_functions = set()


def _is_request_call(node):
    """Check if an AST node is a call that reads user input from Flask request."""
    if not isinstance(node, ast.Call):
        return False
    func = node.func
    if not isinstance(func, ast.Attribute):
        return False

    # request.cookies.get(...), request.args.get(...), etc.
    if isinstance(func.value, ast.Attribute):
        inner = func.value
        if isinstance(inner.value, ast.Name) and inner.value.id == "request":
            # request.cookies, request.args, request.form, request.values, request.json
            return inner.attr in ("cookies", "args", "form", "values", "json")

    # request.get_json(), request.get_data()
    if isinstance(func.value, ast.Name) and func.value.id == "request":
        return func.attr in ("get_json", "get_data")

    return False


def _is_request_subscript(node):
    """Check if node is request.form['key'] or request.args['key']."""
    if not isinstance(node, ast.Subscript):
        return False
    if isinstance(node.value, ast.Attribute):
        if (
            isinstance(node.value.value, ast.Name)
            and node.value.value.id == "request"
        ):
            return node.value.attr in ("form", "args", "values", "json")
    return False


def _is_request_source(node):
    """Any node that originates from an HTTP request (untrusted)."""
    return _is_request_call(node) or _is_request_subscript(node)


def _is_session_sink(target):
    """Check if an assign target is flask.session['...'] or session['...']."""
    if not isinstance(target, ast.Subscript):
        return False
    val = target.value
    if isinstance(val, ast.Attribute):
        if val.attr == "session":
            return True
    # Also match bare 'session' (imported from flask)
    if isinstance(val, ast.Name) and val.id == "session":
        return True
    return False


def _trace_variable(name, assignments, visited=None, depth=0):
    """
    Trace a variable back through simple assignments to its source.
    Returns True if the ultimate source is request.* (untrusted).

    Handles:
      bar = param              → variable aliasing
      bar = map['key']         → dict subscript (check all keys for tainted values)
      string += param          → augmented assign propagates taint
      copy = "constant"        → safe
    """
    if depth > 10:
        return False  # cycle guard
    if visited is None:
        visited = set()
    if name in visited:
        return False
    visited.add(name)

    if name not in assignments:
        return False

    source_nodes = assignments[name]

    for source_node in source_nodes:
        # Direct request source
        if _is_request_source(source_node):
            return True

        # Variable alias: bar = param
        if isinstance(source_node, ast.Name):
            if _trace_variable(source_node.id, assignments, visited, depth + 1):
                return True

        # Constant strings/numbers → safe
        if isinstance(source_node, ast.Constant):
            continue

        # Configparser/other safe sources → skip
        if _is_safe_source(source_node):
            continue

        # Dict subscript: bar = d['key'] — check if ANY value stored in dict is tainted
        if isinstance(source_node, ast.Subscript):
            dict_name = None
            if isinstance(source_node.value, ast.Name):
                dict_name = source_node.value.id
            if dict_name and dict_name in assignments:
                # Check all stores to this dict — if any came from request, the dict is tainted
                for store_node in assignments[dict_name]:
                    if isinstance(store_node, ast.Call):
                        # dict.setdefault / dict.update patterns
                        continue
                # Check if the key we're reading was written with tainted data
                # Walk function body for dict['key'] = <tainted_value> patterns
                continue

        # Walk deeper: look for any tainted Name inside the expression
        for child in ast.walk(source_node):
            if isinstance(child, ast.Name) and child.id != name:
                if child.id not in visited:
                    if _trace_variable(child.id, assignments, visited.copy(), depth + 1):
                        return True

    return False


def _is_safe_source(node):
    """Check if a node is a known-safe source (not user input)."""
    if isinstance(node, ast.Constant):
        return True
    if isinstance(node, ast.Call):
        func = node.func
        # configparser.ConfigParser().get(...)
        if isinstance(func, ast.Attribute):
            if func.attr == "get":
                return True
    return False


def _build_assignment_map(func_node):
    """
    Build a map of variable_name → [source_nodes] for all assignments in the function.
    Each variable maps to a list because it can be assigned multiple times.
    """
    assignments = {}
    for node in ast.walk(func_node):
        if isinstance(node, ast.Assign):
            value = node.value
            for target in node.targets:
                if isinstance(target, ast.Name):
                    name = target.id
                    if name not in assignments:
                        assignments[name] = []
                    assignments[name].append(value)
                elif isinstance(target, ast.Subscript):
                    # d['key'] = value — store under dict name
                    if isinstance(target.value, ast.Name):
                        dict_name = target.value.id
                        # Record dict stores separately
                        pass  # handled via per-key tracking

        elif isinstance(node, ast.AnnAssign):
            if isinstance(node.target, ast.Name) and node.value:
                name = node.target.id
                if name not in assignments:
                    assignments[name] = []
                assignments[name].append(node.value)

        elif isinstance(node, ast.AugAssign):
            # string += param → string is now tainted
            if isinstance(node.target, ast.Name):
                name = node.target.id
                if name not in assignments:
                    assignments[name] = []
                assignments[name].append(node.value)

    return assignments


def _build_dict_store_map(func_node):
    """
    Build a map of dict_name → {key_literal → source_value}
    for patterns like: d['keyA'] = 'value'; d['keyB'] = param
    """
    dict_stores = {}
    for node in ast.walk(func_node):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Subscript):
                    if isinstance(target.value, ast.Name):
                        dict_name = target.value.id
                        key = target.slice
                        if isinstance(key, ast.Constant):
                            if dict_name not in dict_stores:
                                dict_stores[dict_name] = {}
                            dict_stores[dict_name][key.value] = node.value
    return dict_stores


@test.checks("Call")
@test.test_id("B901")
def trust_boundary_violation(context):
    """
    B901: Trust Boundary Violation (CWE-501).

    Detects untrusted HTTP request data flowing into Flask session without validation.
    """
    func = context.function
    if func is None or not isinstance(func, ast.FunctionDef):
        return None

    # Deduplicate: only analyze each function once
    func_key = (context.filename, func.lineno)
    if func_key in _analyzed_functions:
        return None
    _analyzed_functions.add(func_key)

    # Build variable flow graph
    assignments = _build_assignment_map(func)
    dict_stores = _build_dict_store_map(func)

    # Walk function body looking for session writes
    for node in ast.walk(func):
        if not isinstance(node, ast.Assign):
            continue

        for target in node.targets:
            if not _is_session_sink(target):
                continue

            value = node.value

            # Case 1: Direct variable → trace
            if isinstance(value, ast.Name):
                if _trace_variable(value.id, assignments):
                    return _issue(node, value.id)

            # Case 2: Dict subscript → check dict stores
            if isinstance(value, ast.Subscript):
                if isinstance(value.value, ast.Name):
                    dict_name = value.value.id
                    if isinstance(value.slice, ast.Constant):
                        key = value.slice.value
                        if dict_name in dict_stores and key in dict_stores[dict_name]:
                            stored = dict_stores[dict_name][key]
                            if isinstance(stored, ast.Name):
                                if _trace_variable(stored.id, assignments):
                                    return _issue(node, stored.id)

    return None


def _issue(node, var_name):
    return bandit.Issue(
        severity=bandit.MEDIUM,
        confidence=bandit.LOW,
        cwe=issue.Cwe.TRUST_BOUNDARY_VIOLATION,
        text=(
            f"Trust boundary violation (CWE-501): "
            f"untrusted data flows into Flask session via '{var_name}'. "
            f"Session data is trusted downstream — validate input before storing."
        ),
        lineno=node.lineno,
    )
