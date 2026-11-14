"""Run only the help entry, record memory, and close its own help dialog."""

import json
from pathlib import Path
import subprocess
import time

import psutil
import win32con
import win32gui
import win32process

PROJECT = Path(__file__).resolve().parents[1]


def main():
    executable = PROJECT / "Release/ZhangProtect.exe"
    log_path = PROJECT / "_build_validation/help-startup.log"
    tracked = set()
    help_seen = False
    help_seconds = None
    peak_working_set = 0
    peak_private = 0
    titles = []
    started = time.perf_counter()
    with log_path.open("wb") as log:
        process = subprocess.Popen(
            [str(executable), "-h"],
            cwd=executable.parent,
            stdout=log,
            stderr=subprocess.STDOUT,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        tracked.add(process.pid)
        try:
            while process.poll() is None and time.perf_counter() - started < 120:
                current = []
                for pid in list(tracked):
                    try:
                        item = psutil.Process(pid)
                        current.append(item)
                        tracked.update(
                            child.pid for child in item.children(recursive=True)
                        )
                    except psutil.Error:
                        pass
                working_set = 0
                private = 0
                for item in current:
                    try:
                        memory = item.memory_info()
                        working_set += memory.rss
                        private += memory.private
                    except psutil.Error:
                        pass
                peak_working_set = max(peak_working_set, working_set)
                peak_private = max(peak_private, private)

                def inspect_window(hwnd, _):
                    nonlocal help_seen, help_seconds
                    _, pid = win32process.GetWindowThreadProcessId(hwnd)
                    if pid not in tracked or not win32gui.IsWindowVisible(hwnd):
                        return
                    title = win32gui.GetWindowText(hwnd)
                    if title and title not in titles:
                        titles.append(title)
                    if title == "命令帮助":
                        help_seen = True
                        if help_seconds is None:
                            help_seconds = time.perf_counter() - started
                        win32gui.PostMessage(hwnd, win32con.WM_CLOSE, 0, 0)

                win32gui.EnumWindows(inspect_window, None)
                time.sleep(0.05)
            if process.poll() is None:
                raise TimeoutError(f"Help startup timed out; windows: {titles}")
            if not help_seen or process.returncode != 0:
                raise RuntimeError(
                    f"Help startup failed: exit={process.returncode}, windows={titles}, log={log_path}"
                )
        finally:
            for pid in sorted(tracked, reverse=True):
                try:
                    item = psutil.Process(pid)
                    if item.is_running():
                        item.terminate()
                except psutil.Error:
                    pass
    result = {
        "mode": "-h (help only)",
        "exit_code": process.returncode,
        "help_dialog_verified": help_seen,
        "seconds_to_help_dialog": round(help_seconds, 3),
        "sampled_combined_peak_working_set_mib": round(peak_working_set / 1024**2, 2),
        "sampled_combined_peak_private_mib": round(peak_private / 1024**2, 2),
        "sampling_interval_seconds": 0.05,
    }
    (PROJECT / "_build_validation/startup-report.json").write_text(
        json.dumps(result, indent=2), encoding="utf-8"
    )
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
