"""
Bandit plugin for CWE-90: LDAP Injection.

Detects when untrusted data from HTTP request flows into an LDAP search filter
without proper sanitization or escaping.

Vulnerable pattern:
  param = request.cookies.get("id")       # untrusted source
  bar = param                              # taint flows
  filter = f'(&(objectclass=person)(|(uid={bar})(street=...)))'
  conn.search(base, filter, ...)           # LDAP injection ← VIOLATION

Safe pattern:
  bar = 'bob'                              # constant source
  filter = f'(&(objectclass=person)(|(uid={bar})(street=...)))'
  conn.search(base, filter, ...)           # safe — bar is constant
"""

import ast
import bandit
from bandit.core import issue
from bandit.core import test_properties as test

# Per-function cache
_analyzed_functions = set()

# Well-known LDAP search call patterns
LDAP_SEARCH_PATTERNS = {
    "search",           # conn.search(...)
    "search_s",         # conn.search_s(...)
    "search_ext",       # conn.search_ext(...)
    "search_ext_s",     # conn.search_ext_s(...)
    "extend",           # ldap3 extend.standard search
}

# Untrusted Flask request sources
_REQUEST_ATTRS = {"cookies", "args", "form", "values", "json"}
_REQUEST_METHODS = {"get_json", "get_data"}


def _is_request_call(node):
    """Check if a call reads from Flask request (untrusted)."""
    if not isinstance(node, ast.Call):
        return False
    func = node.func
    if not isinstance(func, ast.Attribute):
        return False

    # request.cookies.get(...), request.args.get(...)
    if isinstance(func.value, ast.Attribute):
        inner = func.value
        if isinstance(inner.value, ast.Name) and inner.value.id == "request":
            return inner.attr in _REQUEST_ATTRS

    # request.get_json(), request.get_data()
    if isinstance(func.value, ast.Name) and func.value.id == "request":
        return func.attr in _REQUEST_METHODS

    return False


def _is_request_subscript(node):
    """Check if node is request.form['key'] or similar."""
    if not isinstance(node, ast.Subscript):
        return False
    if isinstance(node.value, ast.Attribute):
        if (
            isinstance(node.value.value, ast.Name)
            and node.value.value.id == "request"
        ):
            return node.value.attr in _REQUEST_ATTRS
    return False


def _is_request_source(node):
    return _is_request_call(node) or _is_request_subscript(node)


def _is_safe_source(node):
    """Constant or known-safe source."""
    if isinstance(node, ast.Constant):
        return True
    return False


def _extract_fstring_vars(fstring_node):
    """
    Extract variable names from an f-string (JoinedStr) AST node.

    f'uid={bar}' → {'bar'}
    f'(&(uid={bar})(cn={name}))' → {'bar', 'name'}
    """
    vars_found = set()
    for child in ast.walk(fstring_node):
        if isinstance(child, ast.FormattedValue):
            val = child.value
            if isinstance(val, ast.Name):
                vars_found.add(val.id)
            elif isinstance(val, ast.Subscript):
                # f'{d["key"]}' — get the dict name
                if isinstance(val.value, ast.Name):
                    vars_found.add(val.value.id)
    return vars_found


def _extract_format_vars(call_node):
    """
    Extract variable names from '...'.format(var1, var2) or '...'.format(key=var).

    Returns set of variable names.
    """
    vars_found = set()
    for arg in call_node.args:
        if isinstance(arg, ast.Name):
            vars_found.add(arg.id)
    for kw in call_node.keywords:
        if isinstance(kw.value, ast.Name):
            vars_found.add(kw.value.id)
    return vars_found


def _extract_filter_variables(filter_node):
    """
    From the filter argument of a conn.search() call, extract variable names
    that appear in the filter string (f-string or .format() call).

    Returns set of variable name strings.
    """
    if isinstance(filter_node, ast.JoinedStr):
        # f'...(uid={bar})...'
        return _extract_fstring_vars(filter_node)

    if isinstance(filter_node, ast.Call):
        # '...'.format(bar, ...) or '{uid}'.format(uid=bar)
        if isinstance(filter_node.func, ast.Attribute):
            if filter_node.func.attr == "format":
                return _extract_format_vars(filter_node)

    if isinstance(filter_node, ast.BinOp) and isinstance(filter_node.op, ast.Mod):
        # 'uid=' % bar (old-style % formatting)
        vars_found = set()
        right = filter_node.right
        if isinstance(right, ast.Name):
            vars_found.add(right.id)
        elif isinstance(right, ast.Tuple):
            for elt in right.elts:
                if isinstance(elt, ast.Name):
                    vars_found.add(elt.id)
        return vars_found

    # Simple variable: filter = var (where var is the filter string)
    if isinstance(filter_node, ast.Name):
        return {filter_node.id}

    return set()


def _build_assignment_map(func_node):
    """Build variable → [source_expressions] for all assignments in function."""
    assignments = {}
    for node in ast.walk(func_node):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    name = target.id
                    if name not in assignments:
                        assignments[name] = []
                    assignments[name].append(node.value)
        elif isinstance(node, ast.AnnAssign):
            if isinstance(node.target, ast.Name) and node.value:
                name = node.target.id
                if name not in assignments:
                    assignments[name] = []
                assignments[name].append(node.value)
        elif isinstance(node, ast.AugAssign):
            if isinstance(node.target, ast.Name):
                name = node.target.id
                if name not in assignments:
                    assignments[name] = []
                assignments[name].append(node.value)
    return assignments


def _trace_variable(name, assignments, visited=None, depth=0):
    """
    Trace variable back through assignments to check if source is request.*.
    Returns True if variable ultimately comes from untrusted input.
    """
    if depth > 10:
        return False
    if visited is None:
        visited = set()
    if name in visited:
        return False
    visited.add(name)

    if name not in assignments:
        return False

    for source in assignments[name]:
        if _is_request_source(source):
            return True
        if _is_safe_source(source):
            continue
        if isinstance(source, ast.Name):
            if _trace_variable(source.id, assignments, visited, depth + 1):
                return True
        # Walk for nested tainted names
        for child in ast.walk(source):
            if isinstance(child, ast.Name) and child.id != name:
                if child.id not in visited:
                    if _trace_variable(child.id, assignments, visited.copy(), depth + 1):
                        return True
    return False


@test.checks("Call")
@test.test_id("B902")
def ldap_injection(context):
    """
    B902: LDAP Injection (CWE-90).

    Detects untrusted HTTP data flowing into LDAP search filters without
    proper sanitization or escaping.
    """
    func = context.function
    if func is None or not isinstance(func, ast.FunctionDef):
        return None

    # Is this call an LDAP search?
    call_name = context.call_function_name
    call_name_qual = context.call_function_name_qual

    is_ldap_call = False
    if call_name in LDAP_SEARCH_PATTERNS:
        is_ldap_call = True
    elif call_name_qual and "." in call_name_qual:
        # conn.search, connection.search, ldap_conn.search, etc.
        method = call_name_qual.rsplit(".", 1)[-1]
        if method in LDAP_SEARCH_PATTERNS:
            is_ldap_call = True

    if not is_ldap_call:
        return None

    # We have an LDAP search call. Check if the filter argument contains
    # variables that trace to request.* sources.

    # LDAP search signature: search(search_base, search_filter, ...)
    # The filter is typically the 2nd positional argument
    call_node = context.node
    if len(call_node.args) < 2:
        return None

    filter_node = call_node.args[1]

    # Also check keyword arguments
    filter_kw = None
    for kw in call_node.keywords:
        if kw.arg in ("search_filter", "filter", "filterstr"):
            filter_kw = kw.value
            break

    # Extract variables from the filter expression
    filter_vars = _extract_filter_variables(filter_node)
    if filter_kw:
        filter_vars |= _extract_filter_variables(filter_kw)

    if not filter_vars:
        return None

    # Build assignment map for taint tracking
    assignments = _build_assignment_map(func)

    # Check if any filter variable traces to request.*
    for var_name in filter_vars:
        if _trace_variable(var_name, assignments):
            return bandit.Issue(
                severity=bandit.MEDIUM,
                confidence=bandit.MEDIUM,
                cwe=issue.Cwe.LDAP_INJECTION,
                text=(
                    f"LDAP injection (CWE-90): "
                    f"untrusted data flows into LDAP search filter via '{var_name}'. "
                    f"User input in LDAP filters can allow attackers to modify query "
                    f"logic. Use parameterized queries or escape special characters "
                    f"( * ( ) \\ \\x00 )."
                ),
                lineno=call_node.lineno,
            )

    return None
