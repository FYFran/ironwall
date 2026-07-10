#!/usr/bin/env python3
"""Python OBSERVE: AST-based security section extraction.
Invoked by Ironwall Go code via subprocess.
Output: JSON array of ObservedSection objects to stdout.
"""

import ast
import json
import os
import sys
from pathlib import Path

# ─── Security Patterns ────────────────────────────────────────────────

# Functions that indicate SQL operations
SQL_FUNCTIONS = {
    "execute", "executemany", "executescript", "raw", "raw_query",
    "filter", "get", "all", "first", "create", "update", "delete",
    "select", "insert", "bulk_create", "bulk_update",
}

# Functions that indicate command execution
EXEC_FUNCTIONS = {
    "system", "popen", "call", "check_call", "check_output",
    "run", "Popen", "spawn", "exec_command", "pexpect",
}

# Functions that indicate file operations
FILE_FUNCTIONS = {
    "open", "read", "readlines", "write", "writelines",
    "mkdir", "makedirs", "remove", "unlink", "rmdir",
    "chmod", "chown", "symlink", "copy", "move", "rename",
}

# Functions that indicate network/SSRF
NETWORK_FUNCTIONS = {
    "get", "post", "put", "delete", "patch", "head",
    "request", "urlopen", "urlretrieve", "connect",
}

# Functions indicating serialization
SERIALIZE_FUNCTIONS = {
    "loads", "dumps", "load", "dump", "parse", "serialize",
}

# Flask route decorators
ROUTE_DECORATORS = {"route", "get", "post", "put", "delete", "patch"}

# Auth decorators
AUTH_DECORATORS = {"login_required", "auth_required", "require_auth",
                   "authenticated", "has_permission", "has_role",
                   "jwt_required", "token_required"}

# Weak crypto imports
WEAK_CRYPTO = {"md5", "sha1", "des", "rc4", "blowfish"}

# Dangerous modules
DANGEROUS_MODULES = {"pickle", "cPickle", "marshal", "shelve", "eval", "exec", "compile"}

# ─── AST Visitor ──────────────────────────────────────────────────────

class SecurityVisitor(ast.NodeVisitor):
    def __init__(self, filename, imports, source_lines):
        self.filename = filename
        self.imports = imports
        self.source_lines = source_lines
        self.sections = []

    def visit_FunctionDef(self, node):
        concerns = set()
        is_handler = False
        has_auth = False
        node_obj = node  # for closure

        # Check decorators
        for dec in node.decorator_list:
            dec_name = self._decorator_name(dec)
            if dec_name in ROUTE_DECORATORS or dec_name.endswith("_bp"):
                is_handler = True
            if dec_name in AUTH_DECORATORS:
                has_auth = True

        # Walk body for security patterns
        for child in ast.walk(node):
            # Function calls
            if isinstance(child, ast.Call):
                func_name = self._call_name(child)

                # SQL detection
                if func_name in SQL_FUNCTIONS:
                    if self._has_import("sqlalchemy", "sqlite3", "psycopg2",
                                        "mysql", "pymongo", "django.db"):
                        concerns.add("sql")

                # Command execution
                if func_name in EXEC_FUNCTIONS:
                    if self._has_import("os", "subprocess", "commands"):
                        concerns.add("command_exec")

                # File operations
                if func_name in FILE_FUNCTIONS:
                    if self._has_import("os", "shutil", "pathlib"):
                        concerns.add("file_ops")
                elif func_name == "open":
                    concerns.add("file_ops")

                # Network calls
                if func_name in NETWORK_FUNCTIONS:
                    if self._has_import("requests", "urllib", "urllib2",
                                        "httpx", "http.client", "aiohttp"):
                        # Check if URL arg is a variable (not literal)
                        if child.args and not isinstance(child.args[0], ast.Constant):
                            concerns.add("ssrf")
                        concerns.add("network")

                # Serialization
                if func_name in SERIALIZE_FUNCTIONS:
                    if self._has_import("json", "pickle", "yaml", "xml",
                                        "marshal", "msgpack"):
                        concerns.add("serialization")

                # Template rendering
                if func_name in {"render_template", "render_template_string", "render", "Template"}:
                    concerns.add("template")

                # Input handling
                if func_name in {"get", "getlist", "form", "args", "values", "json",
                                 "body", "cookies", "headers", "query_params"}:
                    concerns.add("input")

            # String formatting in SQL context = potential SQLi
            if isinstance(child, ast.BinOp) and isinstance(child.op, ast.Mod):
                if self._near_sql_context(child):
                    concerns.add("sql")

            # Hardcoded secrets
            if isinstance(child, ast.Assign):
                for target in child.targets:
                    if isinstance(target, ast.Name):
                        name_lower = target.id.lower()
                        secret_patterns = [
                            "password", "passwd", "secret", "token", "api_key",
                            "apikey", "private_key", "auth_token", "jwt_secret",
                            "db_pass", "database_url", "redis_password",
                        ]
                        for pat in secret_patterns:
                            if pat in name_lower:
                                if isinstance(child.value, ast.Constant) and isinstance(child.value.value, str):
                                    if child.value.value and len(child.value.value) > 3:
                                        concerns.add("secrets")
                                        break

        if concerns:
            code = self._get_code(node)
            imports_list = self._relevant_imports(concerns)
            self.sections.append({
                "file_path": self.filename,
                "func_name": node.name,
                "line_start": node.lineno,
                "line_end": node.end_lineno or node.lineno,
                "concerns": sorted(concerns),
                "code_snippet": code,
                "imports": imports_list,
                "is_handler": is_handler,
                "has_auth_check": has_auth,
                "package_name": "",
                "struct_name": "",
            })

        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node):
        self.visit_FunctionDef(node)

    def _decorator_name(self, dec):
        if isinstance(dec, ast.Name):
            return dec.id
        if isinstance(dec, ast.Attribute):
            return dec.attr
        if isinstance(dec, ast.Call):
            return self._call_name(dec)
        return ""

    def _call_name(self, call):
        if isinstance(call.func, ast.Name):
            return call.func.id
        if isinstance(call.func, ast.Attribute):
            return call.func.attr
        return ""

    def _has_import(self, *modules):
        for imp in self.imports:
            for mod in modules:
                if mod in imp:
                    return True
        return False

    def _near_sql_context(self, node):
        """Check if a string format operation is near a SQL call."""
        if hasattr(node, 'parent') and isinstance(node.parent, ast.Call):
            return self._call_name(node.parent) in SQL_FUNCTIONS
        return False

    def _relevant_imports(self, concerns):
        mapping = {
            "sql": ["sqlalchemy", "sqlite3", "psycopg2", "mysql", "django.db", "pymongo"],
            "command_exec": ["os", "subprocess"],
            "file_ops": ["os", "shutil", "pathlib"],
            "crypto": ["hashlib", "cryptography", "md5", "sha1"],
            "network": ["requests", "urllib", "httpx", "aiohttp"],
            "ssrf": ["requests", "urllib", "httpx"],
            "serialization": ["json", "pickle", "yaml", "xml", "marshal"],
            "template": ["flask", "jinja2", "django.template"],
            "input": ["flask", "django.http", "aiohttp", "fastapi"],
            "secrets": [],
        }
        relevant = set()
        for c in concerns:
            for pattern in mapping.get(c, []):
                for imp in self.imports:
                    if pattern in imp:
                        relevant.add(imp)
        return sorted(relevant)

    def _get_code(self, node):
        if node.lineno and node.end_lineno:
            lines = self.source_lines[node.lineno-1:node.end_lineno]
            return "".join(lines)
        return ""


# ─── Main ──────────────────────────────────────────────────────────────

def _collect_imports(tree):
    imports = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imports.append(alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                imports.append(node.module)
    return imports


def observe_file(filepath):
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            source = f.read()
    except Exception:
        return []

    try:
        tree = ast.parse(source, filename=filepath)
    except SyntaxError:
        return []

    imports = _collect_imports(tree)
    source_lines = source.splitlines(keepends=True)
    visitor = SecurityVisitor(filepath, imports, source_lines)
    visitor.visit(tree)
    return visitor.sections


def observe_dir(target):
    target = Path(target)
    all_sections = []
    py_files = list(target.rglob("*.py"))
    # Skip test files and venv
    py_files = [f for f in py_files
                if "test" not in f.name.lower().replace("_", "")
                and "venv" not in str(f)
                and ".venv" not in str(f)
                and "__pycache__" not in str(f)]

    for f in py_files:
        sections = observe_file(str(f))
        all_sections.extend(sections)

    return {
        "sections": all_sections,
        "total_files": len(py_files),
        "total_sections": len(all_sections),
    }


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("target", help="Target file or directory")
    args = p.parse_args()

    if os.path.isfile(args.target):
        result = {"sections": observe_file(args.target), "total_files": 1}
    else:
        result = observe_dir(args.target)

    result["total_sections"] = len(result["sections"])
    result["total_funcs"] = len(set(s["func_name"] for s in result["sections"]))
    result["concern_counts"] = {}
    for s in result["sections"]:
        for c in s["concerns"]:
            result["concern_counts"][c] = result["concern_counts"].get(c, 0) + 1

    json.dump(result, sys.stdout, ensure_ascii=False)
