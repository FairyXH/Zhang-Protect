#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Scan this script's project for Python imports, test them with this interpreter,
and append missing third-party distributions to requirements.txt.

Run:  Python\\python.exe check_imports.py

Checks actual absolute imports in batches of isolated subprocesses. A batch shares
sys.modules; imports can run module-level side effects. Relative and dynamic imports
are reported but not executed. The project and interpreter are discovered automatically.
"""

import argparse
import ast
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
import importlib.metadata as metadata
import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import traceback
import tempfile
import shutil
import importlib.util
from contextlib import redirect_stderr, redirect_stdout

SCRIPT_PATH = Path(__file__).resolve()
PROJECT_DIR = SCRIPT_PATH.parent
PYTHON_EXE = Path(sys.executable).resolve()
REPORT_PATH = PROJECT_DIR / "import_check_report.json"
REQUIREMENTS_PATH = PROJECT_DIR / "requirements.txt"
RESULT_PREFIX = "__IMPORT_CHECK_RESULT__:"

EXCLUDED_DIRS = {
    "__pycache__",
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "venv",
    "env",
    "node_modules",
    "site-packages",
    "dist-packages",
    "build",
    "dist",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    "python",
}

# An import name is not necessarily the pip distribution name. None denotes
# a module that is not a separately installable pip requirement.
PACKAGE_MAPPING = {
    "PIL": "Pillow",
    "cv2": "opencv-python",
    "yaml": "PyYAML",
    "fontTools": "fonttools",
    "bs4": "beautifulsoup4",
    "sklearn": "scikit-learn",
    "serial": "pyserial",
    "Crypto": "pycryptodome",
    "Cryptodome": "pycryptodomex",
    "dotenv": "python-dotenv",
    "dateutil": "python-dateutil",
    "fitz": "PyMuPDF",
    "docx": "python-docx",
    "pptx": "python-pptx",
    "jwt": "PyJWT",
    "nacl": "PyNaCl",
    "OpenGL": "PyOpenGL",
    "usb": "pyusb",
    "webdriver_manager": "webdriver-manager",
    "win32api": "pywin32",
    "win32con": "pywin32",
    "win32gui": "pywin32",
    "win32com": "pywin32",
    "win32event": "pywin32",
    "win32process": "pywin32",
    "win32security": "pywin32",
    "pythoncom": "pywin32",
    "pywintypes": "pywin32",
    "win32clipboard": "pywin32",
    "win32service": "pywin32",
    "win32serviceutil": "pywin32",
    "win32file": "pywin32",
    "win32pipe": "pywin32",
    "websocket": "websocket-client",
    "googleapiclient": "google-api-python-client",
    "google_auth_oauthlib": "google-auth-oauthlib",
    "multipart": "python-multipart",
    "gi": "PyGObject",
    "tkinter": None,
    "turtle": None,
    "winreg": None,
}


def norm(name):
    return re.sub(r"[-_.]+", "-", name).lower()


def excluded(path):
    parts = path.relative_to(PROJECT_DIR).parts[:-1]
    return any(part.lower() in EXCLUDED_DIRS for part in parts)


def collect_imports():
    imports = defaultdict(list)
    relative = []
    parse_errors = []
    count = 0
    files = sorted(PROJECT_DIR.rglob("*.py"))
    for file in files:
        if file.resolve() == SCRIPT_PATH or excluded(file):
            continue
        count += 1
        rel = str(file.relative_to(PROJECT_DIR))
        try:
            tree = ast.parse(file.read_text(encoding="utf-8-sig"), filename=rel)
        except (SyntaxError, UnicodeError, OSError) as exc:
            parse_errors.append({"file": rel, "error": str(exc)})
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                # Test aliases separately; one missing import must not mask others.
                for alias in node.names:
                    stmt = "import " + alias.name
                    if alias.asname:
                        stmt += " as " + alias.asname
                    imports[stmt].append({"file": rel, "line": node.lineno})
            elif isinstance(node, ast.ImportFrom):
                stmt = ast.unparse(node)
                location = {"file": rel, "line": node.lineno, "import": stmt}
                if node.level:
                    relative.append(location)
                elif node.module != "__future__":
                    imports[stmt].append({"file": rel, "line": node.lineno})
    return imports, relative, parse_errors, count


def import_roots(imports):
    roots = set()
    for stmt in imports:
        node = ast.parse(stmt).body[0]
        if isinstance(node, ast.Import):
            roots.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            roots.add(node.module.split(".")[0])
    return roots


def local_modules():
    roots = set()
    for entry in PROJECT_DIR.iterdir():
        if entry.name.lower() in EXCLUDED_DIRS:
            continue
        if entry.is_file() and entry.suffix == ".py":
            roots.add(entry.stem)
        elif entry.is_dir() and (
            (entry / "__init__.py").is_file() or any(entry.glob("*.py"))
        ):
            roots.add(entry.name)
    return roots


def read_requirements(path, visited=None):
    """Return normalized installed requirement names (also follows local -r files)."""
    if visited is None:
        visited = set()
    path = path.resolve()
    if path in visited or not path.is_file():
        return set()
    visited.add(path)
    names = set()
    for raw in path.read_text(encoding="utf-8-sig").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        include = re.match(r"^(?:-r\s*|--requirement(?:=|\s+))(.+)$", line)
        if include:
            name = include.group(1).strip().strip("\"'")
            names.update(read_requirements(path.parent / name, visited))
            continue
        # --editable local/path or VCS requirements can expose egg=name.
        egg = re.search(r"[#&]egg=([A-Za-z0-9_.-]+)", line)
        if egg:
            names.add(norm(egg.group(1)))
            continue
        if line.startswith("-") or line.startswith(
            ("git+", "https://", "http://", ".", "/")
        ):
            continue
        match = re.match(r"^([A-Za-z0-9][A-Za-z0-9_.-]*)(?=\s|\[|[<>=!~;#]|$)", line)
        if match:
            names.add(norm(match.group(1)))
    return names


def requirement_names(path):
    """Retain existing direct requirements when rebuilding, without version pins."""
    result = {}
    if not path.is_file():
        return result
    for raw in path.read_text(encoding="utf-8-sig").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        match = re.match(
            r"^([A-Za-z0-9][A-Za-z0-9_.-]*)(?:\[[^]]+\])?(?=\s|[<>=!~;#]|$)", line
        )
        if match:
            name = match.group(1)
            result.setdefault(norm(name), name)
    return result


def run_pipreqs(timeout=120):
    """Use the same interpreter to run pipreqs, saving into a temporary file."""
    if importlib.util.find_spec("pipreqs") is None:
        return {}, "pipreqs not installed in target interpreter; AST fallback used"
    # pipreqs is not directly executable via `-m pipreqs` in common releases.
    # `-m pipreqs.pipreqs` correctly invokes its CLI.
    with tempfile.TemporaryDirectory(prefix="check_imports_") as temp:
        out = Path(temp) / "pipreqs_result.txt"
        cmd = [
            str(PYTHON_EXE),
            "-m",
            "pipreqs.pipreqs",
            str(PROJECT_DIR),
            "--mode",
            "no-pin",
            "--encoding",
            "utf-8",
            "--no-follow-links",
            "--ignore",
            ",".join(sorted(EXCLUDED_DIRS)),
            "--savepath",
            str(out),
            "--force",
        ]
        try:
            run = subprocess.run(
                cmd,
                cwd=str(PROJECT_DIR),
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout,
            )
        except subprocess.TimeoutExpired:
            return {}, f"pipreqs timeout ({timeout}s); AST fallback used"
        except OSError as exc:
            return {}, f"pipreqs execution error: {exc}; AST fallback used"
        if run.returncode != 0 or not out.exists():
            detail = (run.stderr or run.stdout or "no output").strip()[-1200:]
            return (
                {},
                f"pipreqs failed (exit {run.returncode}): {detail}; AST fallback used",
            )
        return requirement_names(out), None


def update_requirements(imports, dry_run=False, pipreqs_timeout=120):
    """Generate an unpinned union of pipreqs, AST and existing direct requirements.

    Make a backup before replacing the original. Never silently claim pipreqs ran.
    """
    previous = requirement_names(REQUIREMENTS_PATH)
    own = local_modules()
    stdlib = set(getattr(sys, "stdlib_module_names", ())) | set(
        sys.builtin_module_names
    )
    installed_map = metadata.packages_distributions()
    ast_candidates = {}
    review = []
    for root in sorted(import_roots(imports)):
        if root in stdlib or root in own:
            continue
        if root in PACKAGE_MAPPING:
            package, source = PACKAGE_MAPPING[root], "mapping"
            if package is None:
                continue
        else:
            distributions = sorted(set(installed_map.get(root, [])))
            if len(distributions) == 1:
                package, source = distributions[0], "installed_metadata"
            elif len(distributions) > 1:
                review.append(
                    {
                        "module": root,
                        "reason": "multiple distributions",
                        "candidates": distributions,
                    }
                )
                continue
            else:
                package, source = root, "inferred_unverified"
                review.append(
                    {
                        "module": root,
                        "suggested_package": package,
                        "reason": "Distribution name guessed from import; verify before installing",
                    }
                )
        ast_candidates.setdefault(
            norm(package), {"package": package, "module": root, "source": source}
        )

    pipreqs_names, pipreqs_error = run_pipreqs(timeout=pipreqs_timeout)
    combined = dict(previous)
    combined.update(pipreqs_names)
    # Known explicit mapping takes priority over pipreqs and prior guesses.
    # Other AST candidates fill holes left by pipreqs, including uninstalled packages.
    for key, item in ast_candidates.items():
        if item["source"] == "mapping" or key not in combined:
            combined[key] = item["package"]
    lines = [combined[k] for k in sorted(combined)]
    new_content = (
        "# Generated by check_imports.py (pipreqs + AST; no version pins)\n"
        + "\n".join(lines)
        + ("\n" if lines else "")
    )
    changed = (
        not REQUIREMENTS_PATH.is_file()
        or REQUIREMENTS_PATH.read_text(encoding="utf-8-sig") != new_content
    )
    backup_path = None
    if changed and not dry_run:
        if REQUIREMENTS_PATH.is_file():
            backup = PROJECT_DIR / "requirements.txt.bak"
            shutil.copy2(REQUIREMENTS_PATH, backup)
            backup_path = str(backup)
        REQUIREMENTS_PATH.write_text(new_content, encoding="utf-8", newline="\n")
    added = [
        {"package": combined[k], "module": item["module"], "source": item["source"]}
        for k, item in sorted(ast_candidates.items())
        if k not in previous
    ]
    return {
        "path": str(REQUIREMENTS_PATH),
        "backup": backup_path,
        "previous_count": len(previous),
        "total_generated": len(lines),
        "pipreqs_count": len(pipreqs_names),
        "pipreqs_error": pipreqs_error,
        "ast_count": len(ast_candidates),
        "added_from_ast": added,
        "needs_review": review,
        "changed": changed,
        "dry_run": dry_run,
    }


def worker():
    """Read one JSON batch from stdin, stream one uniquely framed result/line."""
    sys.path.insert(0, str(PROJECT_DIR))
    statements = json.load(sys.stdin)
    for index, statement in enumerate(statements):
        captured_out, captured_err = io.StringIO(), io.StringIO()
        try:
            with redirect_stdout(captured_out), redirect_stderr(captured_err):
                exec(statement, {})
            result = {"index": index, "status": "success", "error": ""}
        except BaseException:
            result = {
                "index": index,
                "status": "failed",
                "error": traceback.format_exc(),
            }
        # sys.__stdout__ is not redirected by ordinary module print() calls.
        sys.__stdout__.write(
            RESULT_PREFIX + json.dumps(result, ensure_ascii=False) + "\n"
        )
        sys.__stdout__.flush()


def run_batch(number, batch, timeout):
    cmd = [str(PYTHON_EXE), "-u", str(SCRIPT_PATH), "--worker"]
    stdout, problem = "", ""
    try:
        completed = subprocess.run(
            cmd,
            input=json.dumps(batch, ensure_ascii=False),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            cwd=str(PROJECT_DIR),
            timeout=timeout,
        )
        stdout = completed.stdout or ""
        if completed.returncode:
            problem = f"Worker exited {completed.returncode}: {(completed.stderr or '').strip()}"
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout or b""
        if isinstance(stdout, bytes):
            stdout = stdout.decode("utf-8", errors="replace")
        problem = f"Batch {number} exceeded {timeout} seconds"
    except Exception as exc:
        problem = repr(exc)
    parsed = {}
    for line in stdout.splitlines():
        if not line.startswith(RESULT_PREFIX):
            continue
        try:
            item = json.loads(line[len(RESULT_PREFIX) :])
            index = item["index"]
            if isinstance(index, int) and 0 <= index < len(batch):
                parsed[index] = item
        except (ValueError, KeyError, TypeError):
            continue
    items = []
    for index, statement in enumerate(batch):
        item = parsed.get(index)
        if item:
            items.append(
                {
                    "import": statement,
                    "status": item["status"],
                    "error": item.get("error", ""),
                }
            )
        else:
            items.append(
                {
                    "import": statement,
                    "status": "incomplete",
                    "error": problem or "No result from worker",
                }
            )
    return number, items


def main():
    parser = argparse.ArgumentParser(
        description="Batch-check project imports and update requirements.txt"
    )
    parser.add_argument("--batch-size", type=int, default=50)
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument(
        "--timeout", type=int, default=120, help="timeout per batch (seconds)"
    )
    parser.add_argument(
        "--dry-run", action="store_true", help="do not change requirements.txt"
    )
    parser.add_argument(
        "--pipreqs-timeout", type=int, default=120, help="pipreqs timeout (seconds)"
    )
    args = parser.parse_args()
    if min(args.batch_size, args.workers, args.timeout, args.pipreqs_timeout) <= 0:
        parser.error("--batch-size, --workers and --timeout must be positive")
    print("Python Import & requirements check", flush=True)
    print(
        f"Interpreter: {PYTHON_EXE}\nProject: {PROJECT_DIR}\nVersion: {sys.version.split()[0]}",
        flush=True,
    )
    imports, relative, parse_errors, scanned = collect_imports()
    req = update_requirements(
        imports, dry_run=args.dry_run, pipreqs_timeout=args.pipreqs_timeout
    )
    statements = list(imports)
    batches = [
        statements[i : i + args.batch_size]
        for i in range(0, len(statements), args.batch_size)
    ]
    print(
        f"Scanned .py: {scanned}; unique absolute imports: {len(statements)}; batches: {len(batches)}"
    )
    print(
        f"Relative imports not tested: {len(relative)}; parse errors: {len(parse_errors)}"
    )
    print(
        f"Requirements total{' (preview)' if args.dry_run else ''}: {req['total_generated']}; pipreqs: {req['pipreqs_count']}; AST: {req['ast_count']}; needs review: {len(req['needs_review'])}",
        flush=True,
    )
    if req["pipreqs_error"]:
        print(f"[WARNING] {req['pipreqs_error']}", flush=True)
    if req["backup"]:
        print(f"[BACKUP] {req['backup']}", flush=True)
    for item in req["added_from_ast"]:
        print(f"  [ADD] {item['package']} <- {item['module']}")
    for item in req["needs_review"]:
        print(f"  [REVIEW] {item['module']}: {item['reason']}")
    results = {}
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = [
            pool.submit(run_batch, i + 1, batch, args.timeout)
            for i, batch in enumerate(batches)
        ]
        for done, future in enumerate(as_completed(futures), 1):
            batch_no, items = future.result()
            for item in items:
                results[item["import"]] = item
                if item["status"] != "success":
                    last = (
                        item["error"].splitlines()[-1]
                        if item["error"]
                        else "unknown error"
                    )
                    print(
                        f"[{item['status'].upper()}] {item['import']}: {last}",
                        flush=True,
                    )
            print(
                f"[Progress] {done}/{len(batches)} batches (finished batch {batch_no})",
                flush=True,
            )
    ordered = []
    counts = {"success": 0, "failed": 0, "incomplete": 0}
    for statement in statements:
        item = {**results[statement], "locations": imports[statement]}
        ordered.append(item)
        counts[item["status"]] += 1
    report = {
        "python": str(PYTHON_EXE),
        "python_version": sys.version,
        "project": str(PROJECT_DIR),
        "scanned_files": scanned,
        "total_absolute_imports": len(statements),
        "batch_size": args.batch_size,
        "workers": args.workers,
        "timeout_per_batch": args.timeout,
        "summary": counts,
        "results": ordered,
        "relative_imports_not_tested": relative,
        "parse_errors": parse_errors,
        "requirements": req,
    }
    REPORT_PATH.write_text(
        json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    print("\nResult:", counts)
    print(
        f"Relative imports not tested: {len(relative)}; parse errors: {len(parse_errors)}"
    )
    print(f"Report: {REPORT_PATH}\nRequirements: {REQUIREMENTS_PATH}")
    return (
        1
        if counts["failed"]
        or counts["incomplete"]
        or parse_errors
        or req["pipreqs_error"]
        else 0
    )


if __name__ == "__main__":
    if "--worker" in sys.argv:
        worker()
    else:
        sys.exit(main())
