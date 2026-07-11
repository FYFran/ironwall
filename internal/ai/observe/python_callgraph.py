#!/usr/bin/env python3
"""
Ironwall Python Call Graph Builder.

Builds a cross-file call graph for Python projects using stdlib ast.
Mirrors the Go callgraph.go output format for unified TRACE pipeline.

Usage:
    python python_callgraph.py <target_directory>

Output: JSON to stdout — CallGraphResult-compatible structure.
Requires: Python 3.6+ (stdlib only — no dependencies)
"""

import ast
import json
import os
import sys
from pathlib import Path


# ─── Dangerous sink patterns for Python ────────────────────────────────

SINK_PATTERNS = {
    "sql": [
        "execute", "executemany", "cursor", "raw",  # DB-API
        "Query", "Filter", "Get", "Create", "Update", "Delete",  # SQLAlchemy/ORM
    ],
    "command_exec": [
        "system", "popen", "call", "check_output", "run",  # os/subprocess
        "exec", "eval", "compile",
    ],
    "file_ops": [
        "open", "read", "write", "remove", "unlink", "rmdir",
        "read_bytes", "write_bytes", "read_text", "write_text",
    ],
    "network": [
        "urlopen", "Request", "get", "post", "put", "delete",  # urllib/requests
        "connect", "send", "recv",
    ],
    "template": [
        "render", "render_template", "Template",
    ],
    "deserialize": [
        "loads", "dumps", "parse", "decode",
    ],
}


def classify_sink(func_name):
    """Classify a function call as a dangerous sink type. Returns '' if not a sink."""
    for sink_type, patterns in SINK_PATTERNS.items():
        for pattern in patterns:
            if func_name == pattern or func_name.endswith("." + pattern):
                return sink_type
    return ""


# ─── AST Visitor ───────────────────────────────────────────────────────

class CallGraphVisitor(ast.NodeVisitor):
    """Walks a single Python file and collects functions + calls."""

    def __init__(self, file_path, module_path):
        self.file_path = file_path
        self.module_path = module_path  # e.g., "app.handlers.auth"
        self.functions = {}   # func_name -> FuncInfo
        self.imports = {}     # alias -> import_path (e.g., "db" -> "app.db")
        self._current_func = None
        self._top_level_calls = []  # calls at module level

    def visit_Import(self, node):
        for alias in node.names:
            name = alias.asname or alias.name
            self.imports[name] = alias.name
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        module = node.module or ""
        for alias in node.names:
            name = alias.asname or alias.name
            # Build full import path: from .db import queries -> module.db.queries
            if node.level > 0:
                # Relative import — resolve against current package
                parts = self.module_path.split(".")
                if node.level <= len(parts):
                    base = ".".join(parts[:-(node.level)])
                    if module:
                        full = f"{base}.{module}.{alias.name}"
                    else:
                        full = f"{base}.{alias.name}"
                else:
                    full = f"{module}.{alias.name}" if module else alias.name
            else:
                full = f"{module}.{alias.name}" if module else alias.name
            self.imports[name] = full
        self.generic_visit(node)

    def visit_FunctionDef(self, node):
        self._add_function(node, is_async=False)
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node):
        self._add_function(node, is_async=True)
        self.generic_visit(node)

    def _add_function(self, node, is_async):
        prev = self._current_func
        self._current_func = node.name

        # Extract parameters
        params = []
        for arg in node.args.args:
            annotation = ""
            if arg.annotation:
                annotation = ast.unparse(arg.annotation) if hasattr(ast, 'unparse') else str(arg.annotation)
            params.append({"name": arg.arg, "type": annotation})

        # Detect if it's a handler
        is_handler = False
        has_auth_check = False
        for decorator in node.decorator_list:
            decorator_str = ast.unparse(decorator) if hasattr(ast, 'unparse') else str(decorator)
            if any(route in decorator_str.lower() for route in
                   ["route(", "get(", "post(", "put(", "delete(", "patch(",
                    "app.route", "blueprint"]):
                is_handler = True
            if any(auth in decorator_str.lower() for auth in
                   ["login_required", "auth", "permission", "jwt"]):
                has_auth_check = True

        # Check function body for auth-related calls
        if not has_auth_check and node.body:
            for child in ast.walk(node):
                if isinstance(child, ast.Call):
                    call_name = self._get_call_name(child)
                    if call_name and any(a in call_name.lower() for a in
                                         ["login_required", "current_user", "authenticate",
                                          "jwt_required", "has_permission", "check_auth"]):
                        has_auth_check = True
                        break

        # Collect calls within function body
        callees = []
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                call_name = self._get_call_name(child)
                if call_name:
                    callees.append({
                        "func_name": call_name,
                        "file": self.file_path,
                        "line": child.lineno,
                    })

        self.functions[node.name] = {
            "file": self.file_path,
            "decl_line": node.lineno,
            "pkg_path": self.module_path,
            "params": params,
            "callees": callees,
            "callers": [],
            "is_handler": is_handler,
            "has_auth_check": has_auth_check,
        }

        self._current_func = prev

    def visit_Call(self, node):
        # Top-level calls (not inside any function)
        if self._current_func is None:
            call_name = self._get_call_name(node)
            if call_name:
                self._top_level_calls.append({
                    "func_name": call_name,
                    "file": self.file_path,
                    "line": node.lineno,
                })

    def _get_call_name(self, node):
        """Extract the full call name from a Call node."""
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            # obj.method() -> reconstruct
            parts = []
            current = node.func
            while isinstance(current, ast.Attribute):
                parts.insert(0, current.attr)
                current = current.value
            if isinstance(current, ast.Name):
                parts.insert(0, current.id)
            elif isinstance(current, ast.Call):
                # chained call: func()().method()
                parts.insert(0, "()")
            else:
                parts.insert(0, "?")
            return ".".join(parts)
        return None


# ─── Call Graph Builder ────────────────────────────────────────────────

def build_callgraph(root_dir):
    """Build a call graph for all .py files under root_dir."""
    root_dir = Path(root_dir).resolve()
    result = {
        "module_path": root_dir.name,
        "packages": {},
        "total_funcs": 0,
        "total_edges": 0,
        "errors": [],
    }

    # Collect .py files (skip __pycache__, tests, venv)
    py_files = []
    for dirpath, dirnames, filenames in os.walk(root_dir):
        # Skip virtual envs, caches, test dirs
        dirnames[:] = [d for d in dirnames if not d.startswith(".")
                       and d not in ("__pycache__", "venv", ".venv", "env",
                                     "node_modules", ".git", "test", "tests")]
        for f in filenames:
            if f.endswith(".py") and not f.startswith("."):
                py_files.append(os.path.join(dirpath, f))

    if not py_files:
        return result

    # Phase 1: Parse all files, collect functions
    all_functions = {}  # (file_path, func_name) -> func_info
    file_imports = {}   # file_path -> {alias: import_path}
    file_functions = {} # file_path -> set of func_names

    for fpath in py_files:
        try:
            source = Path(fpath).read_text(encoding="utf-8")
            tree = ast.parse(source, filename=fpath)
        except SyntaxError as e:
            result["errors"].append(f"parse {fpath}: {e}")
            continue
        except Exception as e:
            result["errors"].append(f"read {fpath}: {e}")
            continue

        # Compute module path from file path relative to root
        rel = os.path.relpath(fpath, root_dir)
        module_path = os.path.splitext(rel)[0].replace(os.sep, ".")
        if module_path.endswith(".__init__"):
            module_path = module_path[:-9]  # strip .__init__

        visitor = CallGraphVisitor(fpath, module_path)
        visitor.visit(tree)

        all_functions.update(
            {(fpath, name): info for name, info in visitor.functions.items()}
        )
        file_imports[fpath] = visitor.imports
        file_functions[fpath] = set(visitor.functions.keys())

        # Package key uses module path
        pkg_key = module_path
        if pkg_key not in result["packages"]:
            result["packages"][pkg_key] = {
                "dir": os.path.dirname(fpath),
                "files": [],
                "funcs": {},
                "methods": {},
            }
        pkg = result["packages"][pkg_key]
        pkg["files"].append(os.path.basename(fpath))
        for name, info in visitor.functions.items():
            pkg["funcs"][name] = info
            result["total_funcs"] += 1

    # Phase 2: Resolve cross-file calls
    for fpath in py_files:
        imports = file_imports.get(fpath, {})
        module_path = os.path.splitext(
            os.path.relpath(fpath, root_dir)
        )[0].replace(os.sep, ".")
        if module_path.endswith(".__init__"):
            module_path = module_path[:-9]

        for func_name in file_functions.get(fpath, set()):
            func_info = all_functions.get((fpath, func_name))
            if not func_info:
                continue

            # Resolve each callee
            for callee in func_info.get("callees", []):
                callee_name = callee["func_name"]
                # Simple call: func() — same file
                if "." not in callee_name:
                    # Try same file first
                    if callee_name in file_functions.get(fpath, set()):
                        callee_info = all_functions.get((fpath, callee_name))
                        if callee_info:
                            callee_info.setdefault("callers", []).append({
                                "func_name": func_name,
                                "file": fpath,
                                "line": callee["line"],
                            })
                            callee["file"] = callee_info["file"]
                            result["total_edges"] += 1
                        continue
                    # Try resolving via imports
                    for alias, import_path in imports.items():
                        # Check if this import provides the callee
                        resolved_name = f"{import_path}.{callee_name}"
                        for (tf, tn), tfi in all_functions.items():
                            candidate_module = os.path.splitext(
                                os.path.relpath(tf, root_dir)
                            )[0].replace(os.sep, ".")
                            if candidate_module.endswith(".__init__"):
                                candidate_module = candidate_module[:-9]
                            if (candidate_module == import_path or
                                candidate_module == resolved_name or
                                candidate_module.endswith("." + callee_name)):
                                if tn == callee_name:
                                    tfi.setdefault("callers", []).append({
                                        "func_name": func_name,
                                        "file": fpath,
                                        "line": callee["line"],
                                    })
                                    callee["file"] = tfi["file"]
                                    callee["func_name"] = tn
                                    result["total_edges"] += 1
                                    break
                else:
                    # Dotted call: module.func() or obj.method()
                    parts = callee_name.rsplit(".", 1)
                    if len(parts) == 2:
                        obj, method = parts
                        # Try resolving obj as import alias
                        if obj in imports:
                            import_path = imports[obj]
                            for (tf, tn), tfi in all_functions.items():
                                candidate_module = os.path.splitext(
                                    os.path.relpath(tf, root_dir)
                                )[0].replace(os.sep, ".")
                                if candidate_module.endswith(".__init__"):
                                    candidate_module = candidate_module[:-9]
                                if (candidate_module == import_path and
                                        tn == method):
                                    tfi.setdefault("callers", []).append({
                                        "func_name": func_name,
                                        "file": fpath,
                                        "line": callee["line"],
                                    })
                                    callee["file"] = tfi["file"]
                                    callee["func_name"] = tn
                                    result["total_edges"] += 1
                                    break
                        else:
                            # obj is a module name: from X import Y
                            for alias, ipath in imports.items():
                                if ipath.endswith("." + obj) or ipath == obj:
                                    for (tf, tn), tfi in all_functions.items():
                                        candidate_module = os.path.splitext(
                                            os.path.relpath(tf, root_dir)
                                        )[0].replace(os.sep, ".")
                                        if candidate_module.endswith(".__init__"):
                                            candidate_module = candidate_module[:-9]
                                        if (candidate_module == ipath and
                                                tn == method):
                                            tfi.setdefault("callers", []).append({
                                                "func_name": func_name,
                                                "file": fpath,
                                                "line": callee["line"],
                                            })
                                            callee["file"] = tfi["file"]
                                            callee["func_name"] = tn
                                            result["total_edges"] += 1
                                            break
                                    break

    return result


def main():
    if len(sys.argv) < 2:
        print(json.dumps({"error": "Usage: python_callgraph.py <target_directory>"}))
        sys.exit(1)

    target = sys.argv[1]
    if not os.path.isdir(target):
        print(json.dumps({"error": f"Not a directory: {target}"}))
        sys.exit(1)

    result = build_callgraph(target)
    print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    main()
