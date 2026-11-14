import os
import sys
import psutil
import tempfile
import subprocess
from main_imports import b64_to_file, hide_console
from NSudoL import NSudoLf

# ============ 初始化 ============


def get_self_path():
    return (
        sys.executable
        if getattr(sys, "frozen", False)
        else os.path.abspath(sys.argv[0])
    )


# 切换当前目录到自身所在目录（避免 %cd% 变化）
_self_dir = os.path.dirname(get_self_path())
os.chdir(_self_dir)

# 固定 Nsudo.exe 路径
_tmp_nsudo_path = os.path.join(tempfile.gettempdir(), "Nsudo.exe")

# ============ 提权逻辑 ============
DETACHED_PROCESS = 0x00000008
CREATE_NEW_PROCESS_GROUP = 0x00000200
CREATE_NO_WINDOW = 0x08000000


def extract_nsudofile():
    b64_to_file(_tmp_nsudo_path, NSudoLf)
    return _tmp_nsudo_path


def kill_nsudoprocs():
    try:
        for p in psutil.process_iter(["pid", "name"]):
            if (
                p.info["name"]
                and p.info["name"].lower() == f"{os.path.basename(_tmp_nsudo_path)}"
            ):
                p.kill()
    except ImportError:
        subprocess.run(
            f"taskkill /f /im {os.path.basename(_tmp_nsudo_path)}",
            shell=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )


def run_nsudo(user_code: str):
    exe_path = get_self_path()

    extra_args = sys.argv[1:]
    full_cmd = [exe_path] + extra_args

    cmd = [
        _tmp_nsudo_path,
        f"-U:{user_code}",
        "-P:E",
    ] + full_cmd

    env = os.environ.copy()
    env["Zhang_ELEVATED"] = "1"

    try:
        proc = subprocess.Popen(
            cmd,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        proc.wait()

        if proc.returncode != 0:
            return False

        return True

    except Exception as e:
        return False


def clear_console():
    os.system("cls")


def elevate_self():
    if os.environ.get("Zhang_ELEVATED") == "1":
        print(f"[*] 已提升的进程:[PID: {os.getpid()}] ({os.getlogin()})")
        os.environ.pop("Zhang_ELEVATED", None)
        return False
    print("[*] 尝试提升到系统权限。")
    extract_nsudofile()
    if not run_nsudo("T"):
        print("[*] TrustedInstaller 提权失败，尝试 SYSTEM")
        if not run_nsudo("S"):
            print("[!] SYSTEM 提权失败，继续以当前权限运行")
            return False
    print("[*] 提权成功，主程序的新进程将以提升权限运行。将在新窗口继续执行操作。")
    if len(sys.argv) == 1:
        hide_console()
    kill_nsudoprocs()
    return True
