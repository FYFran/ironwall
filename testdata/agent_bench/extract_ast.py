#!/usr/bin/env python3
"""
Ironwall Python AST Context Extractor.

Usage:
    python extract_ast.py <file_path> <line_number>

Output: JSON to stdout with structured context around the given line.
Used by context_python.go to feed structured code context into the Analyst Agent.

Requires: Python 3.6+ (stdlib only — no dependencies)
"""

import ast
import json
import sys
import textwrap
from pathlib import Path


def main():
    if len(sys.argv) != 3:
        print(json.dumps({"error": "Usage: extract_ast.py <file_path> <line_number>"}))
        sys.exit(1)

    file_path = sys.argv[1]
    try:
        target_line = int(sys.argv[2])
    except ValueError:
        print(json.dumps({"error": f"Invalid line number: {sys.argv[2]}"}))
        sys.exit(1)

    try:
        source = Path(file_path).read_text(encoding="utf-8")
    except FileNotFoundError:
        print(json.dumps({"error": f"File not found: {file_path}"}))
        sys.exit(1)
    except Exception as e:
        print(json.dumps({"error": f"Read error: {e}"}))
        sys.exit(1)

    try:
        tree = ast.parse(source, filename=file_path)
    except SyntaxError as e:
        # Fall back to text-based extraction.
        result = text_fallback(source, file_path, target_line)
        result["parse_error"] = str(e)
        print(json.dumps(result, indent=2))
        sys.exit(0)

    lines = source.split("\n")

    result = {
        "file_path": file_path,
        "language": "python",
        "finding_line": target_line,
        "finding_snippet": "",
        "imports": [],
        "variables": [],
        "surrounding_lines": "",
        "enclosing_func": None,
        "file_summary": f"Python file, {len(lines)} lines",
    }

    # Finding snippet.
    if 1 <= target_line <= len(lines):
        result["finding_snippet"] = lines[target_line - 1].strip()

    # Surrounding lines (±5).
    surround_start = max(0, target_line - 6)
    surround_end = min(len(lines), target_line + 5)
    result["surrounding_lines"] = "\n".join(lines[surround_start:surround_end])

    # Collect imports.
    imports = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imports.append(f"import {alias.name}")
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            names = ", ".join(a.name for a in node.names)
            imports.append(f"from {module} import {names}")
    result["imports"] = imports

    # Collect top-level variables and constants.
    variables = []
    for node in ast.iter_child_nodes(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    variables.append({
                        "name": target.id,
                        "value": get_value_repr(node.value),
                        "line_number": node.lineno,
                    })
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            variables.append({
                "name": node.target.id,
                "value": get_value_repr(node.value) if node.value else None,
                "line_number": node.lineno,
            })
    result["variables"] = variables

    # Find enclosing function or class.
    enclosing = find_enclosing(tree, target_line, lines)
    result["enclosing_func"] = enclosing

    # File summary.
    func_count = sum(1 for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)))
    class_count = sum(1 for n in ast.iter_child_nodes(tree) if isinstance(n, ast.ClassDef))
    result["file_summary"] = (
        f"Python file, {len(lines)} lines, "
        f"{func_count} functions, {class_count} classes"
    )

    print(json.dumps(result, indent=2))


def find_enclosing(tree: ast.AST, target_line: int, lines: list) -> dict | None:
    """Find the function or class containing the target line."""
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            if hasattr(node, "end_lineno") and node.lineno <= target_line <= node.end_lineno:
                return extract_func_or_class(node, lines)
    return None


def extract_func_or_class(node: ast.AST, lines: list) -> dict:
    """Extract details from a function or class definition."""
    info = {
        "name": node.name,
        "start_line": node.lineno,
        "end_line": getattr(node, "end_lineno", node.lineno),
    }

    # Build signature.
    if isinstance(node, ast.ClassDef):
        bases = ", ".join(ast.unparse(b) for b in node.bases) if node.bases else ""
        if bases:
            info["signature"] = f"class {node.name}({bases})"
        else:
            info["signature"] = f"class {node.name}"
    else:
        # Function or async function.
        prefix = "async def" if isinstance(node, ast.AsyncFunctionDef) else "def"
        args = []
        # Build argument list from AST.
        all_args = []
        all_args.extend(node.args.args)
        all_args.extend(node.args.posonlyargs)
        if node.args.vararg:
            all_args.append(node.args.vararg)
        all_args.extend(node.args.kwonlyargs)
        if node.args.kwarg:
            all_args.append(node.args.kwarg)

        for arg in node.args.args:
            arg_str = arg.arg
            if arg.annotation:
                arg_str += f": {ast.unparse(arg.annotation)}"
            args.append(arg_str)

        # Defaults (apply to last N args).
        defaults = node.args.defaults
        if defaults:
            offset = len(args) - len(defaults)
            for i, d in enumerate(defaults):
                args[offset + i] += f"={ast.unparse(d)}"

        # *args, **kwargs.
        if node.args.vararg:
            args.append(f"*{node.args.vararg.arg}")
        if node.args.kwarg:
            args.append(f"**{node.args.kwarg.arg}")

        returns = f" -> {ast.unparse(node.returns)}" if node.returns else ""
        info["signature"] = f"{prefix} {node.name}({', '.join(args)}){returns}"

    # Extract body from source lines.
    body_start = node.lineno
    body_end = getattr(node, "end_lineno", node.lineno)
    if body_end > body_start:
        # Include the def line itself.
        body_lines = lines[body_start - 1 : body_end]
        info["body"] = "\n".join(body_lines)

    return info


def get_value_repr(node: ast.AST | None) -> str:
    """Get a string representation of an AST value node."""
    if node is None:
        return "None"
    if isinstance(node, ast.Constant):
        if isinstance(node.value, str):
            return repr(node.value)
        return str(node.value)
    try:
        return ast.unparse(node)
    except Exception:
        return "<expression>"


def text_fallback(source: str, file_path: str, target_line: int) -> dict:
    """Text-based fallback when AST parsing fails."""
    lines = source.split("\n")
    result = {
        "file_path": file_path,
        "language": "python",
        "finding_line": target_line,
        "finding_snippet": "",
        "imports": [],
        "variables": [],
        "surrounding_lines": "",
        "enclosing_func": None,
        "file_summary": f"Python file, {len(lines)} lines (parse failed — text fallback)",
        "parse_failed": True,
    }

    if 1 <= target_line <= len(lines):
        result["finding_snippet"] = lines[target_line - 1].strip()

    # Surrounding lines.
    surround_start = max(0, target_line - 6)
    surround_end = min(len(lines), target_line + 5)
    result["surrounding_lines"] = "\n".join(lines[surround_start:surround_end])

    # Find nearest def/class by regex.
    import re
    for i in range(target_line - 1, -1, -1):
        m = re.match(r"^\s*(def|class|async def)\s+(\w+)", lines[i])
        if m:
            name = m.group(2)
            result["enclosing_func"] = {
                "name": name,
                "start_line": i + 1,
                "end_line": i + 1,
            }

            # Find block end by indentation.
            header_indent = len(lines[i]) - len(lines[i].lstrip())
            for j in range(i + 1, len(lines)):
                if lines[j].strip() == "":
                    continue
                line_indent = len(lines[j]) - len(lines[j].lstrip())
                if line_indent <= header_indent:
                    result["enclosing_func"]["end_line"] = j
                    body_lines = lines[i : j]
                    result["enclosing_func"]["body"] = "\n".join(body_lines)
                    break
            else:
                result["enclosing_func"]["end_line"] = len(lines)
                body_lines = lines[i:]
                result["enclosing_func"]["body"] = "\n".join(body_lines)
            break

    return result


if __name__ == "__main__":
    main()
