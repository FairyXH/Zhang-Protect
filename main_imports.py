import os
import io
import re
import sys
import time
import uuid
import glob
import json
import struct

import powercfg
from powercfg import get_current_plan_guid

try:
    import py7zr
except:
    pass
import shlex
import base64
import shutil
import socket
import random
import warnings
import datetime
import win32net

try:
    import wmi
except:
    pass
import config
import ctypes
import logger
import string
import tempfile
import win32gui
import win32api
import win32con
import socket
import requests
import platform
import pythoncom
import traceback
import reg_reader
import subprocess
import smart_open
import win32netcon
import win32console
import win32process
import configparser
import win32security
from xzzip7 import *
from version import *
import encoding_safety
import win32com.client
from xzzip7dll import *
from Everything import *
from main_paths import *
from pathlib import Path
import concurrent.futures
import task_update_scanner
from ctypes import wintypes
import windows_update_blocker
from SetProToPcoredll import *
from typing import List, Tuple
from smart_open import KeepFolder
from StorageRedirect import StorageRedirect as _StorageRedirectImpl
from file_utils import (
    backup_and_mklink,
    check_and_remove_symlink,
    compare_folder_structure,
    copy_file_via_vss,
    copy_files,
    create_symlink_folder,
    fill_missing_keys,
    get_all_user_profiles,
    get_local_users_sid,
    remove_prefix,
    set_full_permissions,
)
from cmd_runner import RunWrapper
from scheduled_tasks import (
    Create_Schtasks,
    Schtasks_Creater,
    get_local_users,
    get_user_sid,
)
from resource_loader import write_resource, read_resource
from ZhangProxyLauncher import ZhangProxyLauncherf
from ctypes import cdll, c_char_p, c_bool, c_int, c_uint32

# 本文件整合所有常量定义
# main.py中在其他代码中复用的函数均在此文件定义

# 调试模式开关,构建项目时请保持为False
debug_mode = False
# 忽略警告

if not debug_mode:
    warnings.filterwarnings("ignore")

try:
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")
except:
    pass
# 基本变量的定义
config.is_testflag = debug_mode

# 全局缓存
_process_list_cache = None

config.log_dir = ProtectDir[:-1]
if os.path.isfile(lowlog):
    config.log_writetofile = False
else:
    config.log_writetofile = True

if config.is_test_mode():
    logger.log(f"目前处于调试模式")
    logger.log(RunWrapper("whoami").read())


background_reg_path = (
    "HKEY_LOCAL_MACHINE\\SOFTWARE\\Classes\\Directory\\background\\shell"
)

set_admin_attrib_bat = (
    "@echo off"
    + chr(10)
    + "cd /d "
    + chr(34)
    + "%~dp0"
    + chr(34)
    + ""
    + chr(10)
    + "%1 echo 将为当前目录及其子目录下的所有"
    + chr(34)
    + ".exe"
    + chr(34)
    + "文件添加"
    + chr(34)
    + "以管理员身份运行"
    + chr(34)
    + "的兼容性属性,请确认"
    + chr(10)
    + "%1 echo 当前目录:%cd%"
    + chr(10)
    + "%1 pause"
    + chr(10)
    + "cls"
    + chr(10)
    + "for /r %%i in (*.exe) do ("
    + chr(10)
    + "    echo 正在设置: %%~nxi"
    + chr(10)
    + "    reg add "
    + chr(34)
    + "HKCU\\Software\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Layers"
    + chr(34)
    + " /v "
    + chr(34)
    + "%%i"
    + chr(34)
    + " /t REG_SZ /d "
    + chr(34)
    + "~ RUNASADMIN"
    + chr(34)
    + " /f >nul 2>&1"
    + chr(10)
    + "    reg add "
    + chr(34)
    + "HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Layers"
    + chr(34)
    + " /v "
    + chr(34)
    + "%%i"
    + chr(34)
    + " /t REG_SZ /d "
    + chr(34)
    + "~ RUNASADMIN"
    + chr(34)
    + " /f >nul 2>&1"
    + chr(10)
    + ")"
    + chr(10)
    + "cls"
    + chr(10)
    + "echo 操作完成!"
    + chr(10)
    + "%1 pause"
)


def b64_to_file(file, b64code, force=False):
    if (not os.path.isfile(file)) or os.path.isfile(force_out_files) or force:
        try:
            with smart_open.smart_opens(file, "wb") as f:
                write_resource(f, b64code)
            logger.log("释放文件成功:%s" % file)
        except Exception as e:
            logger.log("释放文件失败:%s" % file)


zip7exe_temp = os.path.abspath("7z.exe")
zip7dll_temp = os.path.abspath("7z.dll")


def b64zip_to_file(zip_file, b64code, force=False, extraPath=ProtectDir):
    if (not os.path.isfile(zip_file)) or os.path.isfile(force_out_files) or force:
        try:
            if not extraPath[-1] == "\\":
                extraPath += "\\"
            if not os.path.isdir(extraPath):
                KeepFolder(extraPath)
            with smart_open.smart_opens(zip_file, "wb") as f:
                write_resource(f, b64code)
        except:
            logger.log("释放Zip文件失败:%s" % zip_file)
            return
        try:
            with py7zr.SevenZipFile(zip_file, mode="r") as f:
                f.extractall(path=extraPath)
            logger.log("Py7zr解压Zip文件成功:%s" % zip_file)
        except Exception:
            try:
                logger.log("Py7zr解压失败,尝试7-zip解压:%s" % zip_file)
                b64_to_file(zip7exe_temp, zip7f)
                b64_to_file(zip7dll_temp, zip7dllf)
                RunWrapper(f'"{zip7exe_temp}" x "{zip_file}" -o"{extraPath}" -y').read()
                logger.log("7-zip解压Zip文件成功:%s" % zip_file)
            except:
                logger.log("7-zip解压Zip文件失败:%s" % zip_file)
        try:
            with smart_open.smart_opens(
                zip_file,
                "w",
            ) as f:
                f.write("Finished")
        except:
            pass


def extract_dll(dll_name, dll_b64):

    dll_name = os.path.basename(dll_name)

    # 释放到 sys._MEIPASS 或当前目录
    if hasattr(sys, "_MEIPASS"):
        dll_path = os.path.join(sys._MEIPASS, dll_name)
    else:
        dll_path = os.path.join(os.path.dirname(sys.executable), dll_name)

    b64_to_file(dll_path, dll_b64)


WTS_CURRENT_SERVER_HANDLE = None
WTSUserName = 5
WTSActive = 0

# 加载库
wtsapi32 = ctypes.WinDLL("wtsapi32")
kernel32 = ctypes.WinDLL("kernel32")


# 定义结构体 WTS_SESSION_INFO
class WTS_SESSION_INFO(ctypes.Structure):
    _fields_ = [
        ("SessionId", wintypes.DWORD),
        ("pWinStationName", wintypes.LPWSTR),
        ("State", wintypes.DWORD),
    ]


PWTS_SESSION_INFO = ctypes.POINTER(WTS_SESSION_INFO)
TH32CS_SNAPPROCESS = 0x00000002
MAX_PATH = 260


SetComputerNameExW = ctypes.windll.kernel32.SetComputerNameExW
SetComputerNameExW.argtypes = [wintypes.INT, wintypes.LPCWSTR]
SetComputerNameExW.restype = wintypes.BOOL

ComputerNamePhysicalDnsHostname = 5  # 修改主机名类型


class PROCESSENTRY32(ctypes.Structure):
    _fields_ = [
        ("dwSize", ctypes.wintypes.DWORD),
        ("cntUsage", ctypes.wintypes.DWORD),
        ("th32ProcessID", ctypes.wintypes.DWORD),
        ("th32DefaultHeapID", ctypes.c_void_p),
        ("th32ModuleID", ctypes.wintypes.DWORD),
        ("cntThreads", ctypes.wintypes.DWORD),
        ("th32ParentProcessID", ctypes.wintypes.DWORD),
        ("pcPriClassBase", ctypes.wintypes.LONG),
        ("dwFlags", ctypes.wintypes.DWORD),
        ("szExeFile", ctypes.c_char * MAX_PATH),
    ]


# Windows 11 中的 PROCESS_POWER_THROTTLING_xx 定义
PROCESS_POWER_THROTTLING_CURRENT_VERSION = 1
PROCESS_POWER_THROTTLING_EXECUTION_SPEED = 0x1


# 结构体定义
class PROCESS_POWER_THROTTLING_STATE(ctypes.Structure):
    _fields_ = [
        ("Version", wintypes.ULONG),
        ("ControlMask", wintypes.ULONG),
        ("StateMask", wintypes.ULONG),
    ]


kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
# 函数原型
SetProcessInformation = kernel32.SetProcessInformation
SetProcessInformation.argtypes = [
    wintypes.HANDLE,  # hProcess
    wintypes.DWORD,  # ProcessInformationClass
    wintypes.LPVOID,  # ProcessInformation
    wintypes.DWORD,  # ProcessInformationSize
]
SetProcessInformation.restype = wintypes.BOOL

if not os.path.isfile(ProtectDir + "SetProToPcore.dll"):
    SetProToPcore_dll = "SetProToPcore.dll"
else:
    SetProToPcore_dll = ProtectDir + "SetProToPcore.dll"

extract_dll(SetProToPcore_dll, SetProToPcoredllf)
_DLL_PATH = os.path.join(os.path.dirname(__file__), SetProToPcore_dll)
_SetProToPcore_dll = cdll.LoadLibrary(_DLL_PATH)

# 绑定函数定义
_SetProToPcore_dll.SetAffinityByName.argtypes = [c_char_p, c_bool, c_bool, c_int]
_SetProToPcore_dll.SetAffinityByName.restype = c_int

_SetProToPcore_dll.SetAffinityByPid.argtypes = [c_uint32, c_bool, c_bool, c_int]
_SetProToPcore_dll.SetAffinityByPid.restype = c_int


def set_affinity_by_name(
    process_name: str,
    recursive: bool = False,
    high_priority: bool = False,
    core_type: int = 1,
) -> int:
    """
    设置指定进程名的 CPU 亲和性和优先级。

    参数:
        process_name (str): 目标进程名，例如 "notepad.exe"
        recursive (bool): 是否递归处理子进程，默认 False
        high_priority (bool): 是否设置高优先级，默认 False
        core_type (int): 选择核心类型:
            1 = P-core (大核心)
            2 = E-core (小核心)
            3 = ALL (全部核心)

    返回:
        int: 成功处理的进程数量（0 表示没找到进程，负数表示错误）
    """

    return _SetProToPcore_dll.SetAffinityByName(
        process_name.encode("utf-8"), recursive, high_priority, core_type
    )


def set_affinity_by_pid(
    pid: int, recursive: bool = False, high_priority: bool = False, core_type: int = 1
) -> int:
    """
    设置指定 PID 的 CPU 亲和性和优先级。

    参数:
        pid (int): 目标进程 PID
        recursive (bool): 是否递归处理子进程，默认 False
        high_priority (bool): 是否设置高优先级，默认 False
        core_type (int): 选择核心类型:
            1 = P-core (大核心)
            2 = E-core (小核心)
            3 = ALL (全部核心)

    返回:
        int: 成功处理的进程数量（0 表示没找到进程，负数表示错误）
    """
    try:
        pid = int(pid)
        return _SetProToPcore_dll.SetAffinityByPid(
            pid, recursive, high_priority, core_type
        )
    except:
        return -1


def broadcast_environment_change():
    logger.log("[环境变量广播]尝试发送环境变量变更广播")
    try:
        HWND_BROADCAST = 0xFFFF
        WM_SETTINGCHANGE = 0x001A
        SMTO_ABORTIFHUNG = 0x0002

        SendMessageTimeout = ctypes.windll.user32.SendMessageTimeoutW
        SendMessageTimeout.argtypes = [
            wintypes.HWND,
            wintypes.UINT,
            wintypes.WPARAM,
            wintypes.LPARAM,
            wintypes.UINT,
            wintypes.UINT,
            ctypes.POINTER(wintypes.DWORD),
        ]
        SendMessageTimeout.restype = wintypes.LPARAM

        result = wintypes.DWORD()
        env_str = ctypes.create_unicode_buffer("Environment")

        # 这里传入的是指向字符串缓冲区的整数地址
        lParam_value = ctypes.addressof(env_str)

        SendMessageTimeout(
            HWND_BROADCAST,
            WM_SETTINGCHANGE,
            0,
            lParam_value,
            SMTO_ABORTIFHUNG,
            5000,
            ctypes.byref(result),
        )
    except Exception as e:
        logger.log(f"[环境变量广播]发送失败:{e}")
    finally:
        logger.log("[环境变量广播]广播完成")


_should_broadcast_environment_change = False


def should_broadcast_environment_change(change_to_True=False):
    global _should_broadcast_environment_change
    if change_to_True:
        _should_broadcast_environment_change = True
        return True
    else:
        return _should_broadcast_environment_change


def get_executable_subsystem(path):
    try:
        with open(path, "rb") as f:
            header = f.read(64)
            if len(header) < 64 or header[:2] != b"MZ":
                return None
            f.seek(struct.unpack_from("<I", header, 60)[0])
            header = f.read(94)
            if len(header) < 94 or header[:4] != b"PE\0\0":
                return None
            if struct.unpack_from("<H", header, 24)[0] not in (0x10B, 0x20B):
                return None
            subsystem = struct.unpack_from("<H", header, 92)[0]
            return subsystem if subsystem in (2, 3) else None
    except OSError:
        return None


def get_associated_executable(extension):
    query = ctypes.windll.shlwapi.AssocQueryStringW
    query.argtypes = [
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPCWSTR,
        wintypes.LPCWSTR,
        wintypes.LPWSTR,
        ctypes.POINTER(wintypes.DWORD),
    ]
    query.restype = wintypes.LONG
    executable = ctypes.create_unicode_buffer(32768)
    length = wintypes.DWORD(len(executable))
    if query(0, 2, extension, None, executable, ctypes.byref(length)) == 0:
        return executable.value
    return ""


def get_proxy_subsystem(path):
    extension = os.path.splitext(path)[1].casefold()
    if extension in (".exe", ".com"):
        return get_executable_subsystem(path) or 3
    if extension in (".bat", ".cmd", ".ps1", ".py"):
        return 3
    if extension in (".pyw", ".msc", ".cpl"):
        return 2
    host = get_associated_executable(extension)
    if not host and extension in (".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh"):
        host = os.path.join(WindowsDir, "System32", "wscript.exe")
    return get_executable_subsystem(host) or 2


def sync_proxy_launchers():
    proxy_dir = ProtectDir + "ProxyBin"
    if os.path.islink(proxy_dir) or os.path.isjunction(proxy_dir):
        raise ValueError(f"代理目录不能是目录链接:{proxy_dir}")
    os.makedirs(proxy_dir, exist_ok=True)
    template = read_resource(ZhangProxyLauncherf)
    subsystem_offset = struct.unpack_from("<I", template, 60)[0] + 92
    templates = {}
    for subsystem in (2, 3):
        content = bytearray(template)
        struct.pack_into("<H", content, subsystem_offset, subsystem)
        templates[subsystem] = bytes(content)
    targets = {}
    extensions = []
    for extension in (
        os.environ.get("PATHEXT")
        or ".COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC;.CPL"
    ).split(";") + [".ps1", ".py", ".pyw"]:
        extension = extension.strip().casefold()
        if extension.startswith(".") and extension not in extensions:
            extensions.append(extension)
    excluded_dirs = {
        normalize_environment_path(proxy_dir),
        normalize_environment_path(Maintain_tools_folder),
        normalize_environment_path(ProtectDir + "ZhangProtect-系统维护-ISO镜像"),
    }
    root_names = {
        name.casefold()
        for name in os.listdir(ProtectDir)
        if os.path.splitext(name)[1].casefold() in extensions
        and os.path.isfile(os.path.join(ProtectDir, name))
    }
    candidates = []
    for root, dirs, files in os.walk(ProtectDir):
        dirs[:] = sorted(
            name
            for name in dirs
            if normalize_environment_path(os.path.join(root, name)) not in excluded_dirs
            and not os.path.islink(os.path.join(root, name))
            and not os.path.isjunction(os.path.join(root, name))
        )
        for name in files:
            target = os.path.join(root, name)
            if os.path.splitext(name)[
                1
            ].casefold() in extensions and not os.path.islink(target):
                candidates.append(os.path.relpath(target, ProtectDir))
    aliases = {}
    for relative in sorted(
        candidates,
        key=lambda value: (
            value.count(os.sep),
            extensions.index(os.path.splitext(value)[1].casefold()),
            value.casefold(),
        ),
    ):
        name = os.path.basename(relative).casefold()
        extension = os.path.splitext(name)[1]
        native = extension in (".exe", ".com")
        proxy_name = name if native else name + ".exe"
        if os.path.dirname(relative) and name in root_names:
            logger.log(f"[代理启动器]跳过同名程序:{relative}")
            continue
        if proxy_name in targets:
            logger.log(f"[代理启动器]跳过同名程序:{relative}")
            continue
        if os.path.dirname(relative) or not native:
            targets[proxy_name] = relative
        alias = os.path.splitext(name)[0] + ".exe"
        if not native and alias not in root_names:
            aliases.setdefault(alias, relative)
    for alias, relative in aliases.items():
        targets.setdefault(alias, relative)

    for name, relative in targets.items():
        proxy_path = os.path.join(proxy_dir, name)
        if os.path.lexists(proxy_path):
            if not is_proxy_launcher(proxy_path):
                raise ValueError(f"代理目录存在非托管同名文件:{proxy_path}")
        target = os.path.join(ProtectDir, relative)
        target_data = target.encode("utf-16-le")
        content = (
            templates[get_proxy_subsystem(target)]
            + target_data
            + struct.pack("<I", len(target_data))
            + b"ZPXYv1\0\0"
        )
        if os.path.isfile(proxy_path):
            with open(proxy_path, "rb") as f:
                if f.read() == content:
                    continue
        temporary = proxy_path + "." + uuid.uuid4().hex + ".tmp"
        try:
            with open(temporary, "wb") as f:
                f.write(content)
            os.replace(temporary, proxy_path)
        finally:
            if os.path.isfile(temporary):
                os.remove(temporary)
    for name in os.listdir(proxy_dir):
        proxy_path = os.path.join(proxy_dir, name)
        if name.casefold() not in targets:
            if is_proxy_launcher(proxy_path):
                os.remove(proxy_path)
    logger.log(f"[代理启动器]同步完成:{len(targets)}个,目录:{proxy_dir}")
    return proxy_dir


def is_proxy_launcher(path):
    if os.path.islink(path) or not os.path.isfile(path):
        return False
    try:
        with open(path, "rb") as f:
            f.seek(-8, os.SEEK_END)
            return f.read() == b"ZPXYv1\0\0"
    except OSError:
        return False


def normalize_environment_path(path):
    return os.path.normcase(
        os.path.normpath(os.path.expandvars(path.strip().strip('"')))
    )


def clean_environment_path(value, owned_paths, owned_roots):
    result = []
    for entry in value.split(";"):
        if re.search(r"%ZhangProtect(?:Path)?%", entry, flags=re.IGNORECASE):
            continue
        normalized = normalize_environment_path(entry)
        if normalized in owned_paths:
            continue
        if any(
            normalized == root or normalized.startswith(root + os.sep)
            for root in owned_roots
        ):
            continue
        result.append(entry)
    return ";".join(result)


def set_environment_path():
    global _should_broadcast_environment_change
    try:
        proxy_dir = sync_proxy_launchers()
        system_key = "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment"
        key_path_ls = [system_key]
        for user_key_path in get_all_user_profiles():
            key_path = user_key_path.get("key") + "\\Environment"
            if key_path not in key_path_ls:
                key_path_ls.append(key_path)
        snapshots = {
            key: {
                item["name"].casefold(): item
                for item in reg_reader.reg_read(key)["keys"]
                if item["name"].casefold()
                in ("path", "zhangprotectpath", "zhangprotect")
            }
            for key in key_path_ls
        }
        if "path" not in snapshots[system_key]:
            raise ValueError("无法读取系统Path,停止环境变量同步")
        owned_paths = set()
        owned_roots = {normalize_environment_path(ProtectDir)}
        for values in snapshots.values():
            for entry in values.get("zhangprotectpath", {}).get("value", "").split(";"):
                if entry.strip():
                    owned_paths.add(normalize_environment_path(entry))
            old_root = values.get("zhangprotect", {}).get("value", "")
            if old_root.strip() and os.path.isabs(old_root):
                owned_roots.add(normalize_environment_path(old_root))
        updates = []
        for key, values in snapshots.items():
            old_path = values.get("path", {}).get("value", "")
            new_path = clean_environment_path(old_path, owned_paths, owned_roots)
            if key == system_key:
                new_path = ";".join(
                    [os.path.normpath(ProtectDir), proxy_dir]
                    + ([new_path] if new_path else [])
                )
            if new_path != old_path:
                updates.append((key, "Path", "REG_EXPAND_SZ", new_path))
            if "zhangprotectpath" in values:
                updates.append((key, values["zhangprotectpath"]["name"], None, None))
            if key == system_key:
                if values.get("zhangprotect", {}).get("value") != ProtectDir:
                    updates.append((key, "ZhangProtect", "REG_EXPAND_SZ", ProtectDir))
            elif "zhangprotect" in values:
                updates.append((key, values["zhangprotect"]["name"], None, None))
        if updates:
            backup_path = os.path.join(
                proxy_dir, "environment-backup-" + uuid.uuid4().hex + ".json"
            )
            with open(backup_path, "w", encoding="utf-8") as f:
                json.dump(snapshots, f, ensure_ascii=False, indent=2)
            for key, name, type_str, value in updates:
                if type_str is None:
                    reg_reader.reg_delete_key(key, name, sync=False)
                else:
                    reg_reader.reg_write(
                        key, name, type_str, value, sync=False, sync_hklm=False
                    )
                actual = {
                    item["name"].casefold(): item["value"]
                    for item in reg_reader.reg_read(key)["keys"]
                }
                _should_broadcast_environment_change = True
                if (
                    name.casefold() in actual
                    if type_str is None
                    else actual.get(name.casefold()) != value
                ):
                    raise OSError(
                        f"环境变量写入校验失败:{key}\\{name},备份:{backup_path}"
                    )
        process_path = clean_environment_path(
            os.environ.get("PATH", ""), owned_paths, owned_roots
        )
        os.environ["PATH"] = ";".join(
            [os.path.normpath(ProtectDir), proxy_dir]
            + ([process_path] if process_path else [])
        )
        os.environ["ZhangProtect"] = ProtectDir
        os.environ.pop("ZhangProtectPath", None)
        logger.log(f"[环境变量]同步完成:{ProtectDir};{proxy_dir}")
        return True
    except Exception as e:
        logger.log(f"[环境变量]同步失败:{e}")
        return False


def rename_if_user_equals_computer():
    local_users = get_local_users()  # 你已有的函数
    computer_name = socket.gethostname()
    logger.log(f"当前计算机名: {computer_name}")

    # 判断是否与任何用户名相同（忽略大小写）
    if any(user.lower() == computer_name.lower() for user in local_users):
        # 去除旧的 -Rxxxxx 标识后缀
        base_name = re.sub(r"-R\d{5}$", "", computer_name, flags=re.IGNORECASE)
        rand_suffix = random.randint(10000, 99999)
        new_name = f"{base_name}-R{rand_suffix}"

        logger.log(f"检测到用户名与计算机名相同，将修改为: {new_name}")

        success = SetComputerNameExW(ComputerNamePhysicalDnsHostname, new_name)
        if success:
            logger.log("计算机名修改成功，请重启系统以生效。")
            return new_name
        else:
            err = ctypes.GetLastError()
            logger.log(f"修改失败，错误码: {err}")
            return None
    else:
        logger.log("未发现用户名与计算机名相同，无需修改。")
        return computer_name


def resolve_executable_path(path):
    """
    将命令或路径解析为绝对路径（优先搜索系统PATH）
    """
    path = path.strip('"')

    if os.path.isabs(path):
        return os.path.abspath(path)

    exe_path = shutil.which(path)
    if exe_path:
        return exe_path

    return path


def split_executable_and_args(path):
    """
    从一个命令行字符串中分离可执行文件路径和参数列表。
    :param path: str, 例如 r'"C:\\Program Files\\App\\app.exe" --flag value'
    :return: (exe_path, args_str)
    """
    # 用 Windows 风格解析
    if "'" in path:
        path = path.replace("'", '"')

    parts = shlex.split(path, posix=False)
    if not parts:
        return None, None

    exe_path = parts[0]
    args_str = " ".join(parts[1:]) if len(parts) > 1 else ""

    # 绝对路径检查（防止把参数误识别为路径）
    if not os.path.isabs(exe_path):
        exe_path = resolve_executable_path(exe_path)

    return exe_path, args_str


def get_zhangprotect_schtasks():
    ls = []
    try:
        scheduler = win32com.client.Dispatch("Schedule.Service")
        scheduler.Connect()
        folder = scheduler.GetFolder("\\ZhangProtect")
        for i in folder.GetTasks(0):
            ls.append(i.Name)
    except:
        tasks_csv = RunWrapper("schtasks /query /tn ZhangProtect\\ /FO csv /NH").read()
        for i in tasks_csv.splitlines():
            try:
                task_name = i.split(",")[0].replace('"', "").split("\\")[1]
                ls.append(task_name)
            except:
                continue
    return ls


def clear_runas_schtasks():
    try:
        logger.log(f"[Runas]调用API接口清空Runas残留")
        Folder = "\\ZhangProtect"
        scheduler = win32com.client.Dispatch("Schedule.Service")
        scheduler.Connect()
        folder = scheduler.GetFolder(Folder)
        for i in folder.GetTasks(0):
            name = i.Name
            if "ZhangProtectRunAs" in name:
                folder.DeleteTask(name, 0)
    except:
        logger.log(f"[Runas]调用API接口清空Runas残留失败,转传统模式")
        for i in get_zhangprotect_schtasks():
            if "ZhangProtectRunAs" in i:
                RunWrapper(f"schtasks /Delete /F /tn ZhangProtect\\{i}").read()


def set_exe_runas_admin(target_directory):
    """
    为指定目录下所有 .exe 文件设置以管理员身份运行的兼容性属性
    参数:
        target_directory: 目标目录路径
    """
    registry_path = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Layers"
    for root, dirs, files in os.walk(target_directory):
        for file in files:
            if file.lower().endswith(".exe"):
                exe_full_path = os.path.join(root, file)
                try:
                    reg_reader.reg_write(
                        registry_path, exe_full_path, "REG_SZ", "~ RUNASADMIN"
                    )
                except Exception as e:
                    pass


def runas(user, path, highest=True):
    TaskName = f"ZhangProtectRunAs-{uuid.uuid4()}"
    try:
        logger.log(f"[Runas]调用API接口执行Runas: {user} --> {path}")
        pythoncom.CoInitialize()
        scheduler = win32com.client.Dispatch("Schedule.Service")
        scheduler.Connect()
        exe, arg = split_executable_and_args(path)

        if not os.path.isfile(exe):
            raise Exception("[Runas]路径处理错误,转传统模式。")
        Folder = "\\ZhangProtect"

        # 创建任务计划
        if highest:
            Create_Schtasks(TaskName, exe, arg, user, 4, 3, 1)
        else:
            Create_Schtasks(TaskName, exe, arg, user, 4, 3, 0)
        folder = scheduler.GetFolder(Folder)
        for i in folder.GetTasks(0):
            name = i.Name
            if TaskName in name:
                i.Run(None)
                folder.DeleteTask(name, 0)
        logger.log(f"[Runas]API接口执行Runas完成{user} --> {path}")
        pythoncom.CoUninitialize()
        return True
    except Exception as e:
        logger.log(f"[Runas]API接口执行Runas失败,转传统模式: {user} --> {path};{e}")
        pythoncom.CoUninitialize()
        if '"' in path:
            path = path.replace('"', '\\"')
        command = (
            f'schtasks /Create /F /tn ZhangProtect\\{TaskName} /RU "'
            + user
            + (
                ('" /RL HIGHEST /SC ONCE /ST 00:00 /TR "')
                if highest
                else ('" /SC ONCE /ST 00:00 /TR "')
            )
            + path
            + '"'
        )
        RunWrapper(command).read()
        RunWrapper(f"schtasks /Run /I /tn ZhangProtect\\{TaskName}").read()
        RunWrapper(f"schtasks /Delete /F /tn ZhangProtect\\{TaskName}").read()
        logger.log(f"[Runas]传统模式执行Runas完成{user} --> {path}")
        return False


def set_hidden_windows(filepath):
    import ctypes

    FILE_ATTRIBUTE_HIDDEN = 0x02
    ret = ctypes.windll.kernel32.SetFileAttributesW(
        str(filepath), FILE_ATTRIBUTE_HIDDEN
    )
    if ret == 0:
        raise ctypes.WinError()


def create_nomedia_files(root="."):
    for dirpath, _, _ in os.walk(root):
        try:
            nomedia_path = os.path.join(dirpath, ".nomedia")
            if not os.path.exists(nomedia_path):
                with open(nomedia_path, "w"):
                    pass
                try:
                    set_hidden_windows(nomedia_path)
                except:
                    pass
        except:
            pass


def exit(code=0):
    # try:
    #     sys.stdout.flush()
    #     sys.stderr.flush()
    # except:
    #     pass
    time.sleep(0.1)  # 等待句柄释放
    os._exit(0)  # type: ignore


def get_logon_user():
    ppSessionInfo = PWTS_SESSION_INFO()
    count = wintypes.DWORD()

    users = set()

    if wtsapi32.WTSEnumerateSessionsW(
        WTS_CURRENT_SERVER_HANDLE,
        0,
        1,
        ctypes.byref(ppSessionInfo),
        ctypes.byref(count),
    ):
        for i in range(count.value):
            session = ppSessionInfo[i]
            if session.State == WTSActive:
                pUserName = wintypes.LPWSTR()
                bytesReturned = wintypes.DWORD()
                if wtsapi32.WTSQuerySessionInformationW(
                    WTS_CURRENT_SERVER_HANDLE,
                    session.SessionId,
                    WTSUserName,
                    ctypes.byref(pUserName),
                    ctypes.byref(bytesReturned),
                ):
                    user = pUserName.value
                    if user:
                        users.add(user)
                    wtsapi32.WTSFreeMemory(pUserName)
        wtsapi32.WTSFreeMemory(ppSessionInfo)

    return list(users)


def get_exe_path(handle):
    try:
        return win32process.GetModuleFileNameEx(handle, 0)
    except Exception:
        return None


def get_username_from_handle(handle):
    try:
        token = win32security.OpenProcessToken(handle, win32con.TOKEN_QUERY)
        user_sid = win32security.GetTokenInformation(token, win32security.TokenUser)[0]
        name, domain, _ = win32security.LookupAccountSid(None, user_sid)
        return name  # 去掉域前缀
    except Exception:
        return None


def get_process_list(refresh=False):
    global _process_list_cache

    # 返回缓存（第一次调用没有缓存，或强制刷新时重新生成）
    if _process_list_cache is not None and not refresh:
        return _process_list_cache

    if refresh:
        logger.log("[进程列表]刷新进程映像缓存")

    pro_list = []
    kernel32 = ctypes.windll.kernel32
    snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)

    entry = PROCESSENTRY32()
    entry.dwSize = ctypes.sizeof(PROCESSENTRY32)

    if kernel32.Process32First(snapshot, ctypes.byref(entry)) == 0:
        kernel32.CloseHandle(snapshot)
        return []

    while True:
        pid = entry.th32ProcessID
        try:
            handle = win32api.OpenProcess(
                win32con.PROCESS_QUERY_INFORMATION | win32con.PROCESS_VM_READ,
                False,
                pid,
            )

            name = entry.szExeFile.decode(errors="ignore").casefold()
            execs = get_exe_path(handle)
            if execs:
                execs = execs.casefold()

            username = get_username_from_handle(handle)

            if username and execs:
                proc_direct = {
                    "name": name,
                    "execs": execs,
                    "username": username,
                    "pid": pid,
                }
                pro_list.append(proc_direct)

        except Exception:
            pass
        finally:
            try:
                win32api.CloseHandle(handle)
            except:
                pass

        if not kernel32.Process32Next(snapshot, ctypes.byref(entry)):
            break

    kernel32.CloseHandle(snapshot)

    # 缓存结果
    _process_list_cache = pro_list
    return pro_list


def get_process_num(exe):
    num = 0
    exe = str(exe).casefold()
    for i in get_process_list():
        if i.get("name") == exe:
            num += 1
    return num


def get_user_process_list(user):
    user_process_list = []
    user = user.casefold()
    for i in get_process_list():
        if i.get("username").casefold() == str(user):
            user_process_list.append(i)
    return user_process_list


def get_task_status(TaskName):  # 进程状态
    protect = []
    for i in get_process_list(refresh=True):
        protect.append(i.get("name"))
    if not str(TaskName).casefold() in protect:
        return False
    else:
        return True


def get_exe_task_status(TaskName):  # 进程状态:exe
    protect = []
    for i in get_process_list():
        protect.append(i.get("execs"))
    if not str(TaskName).casefold() in protect:
        return False
    else:
        return True


def TaskKeep(
    TaskName,
    TaskPath,
    alluser=True,
    hight=True,
    run_on_keeptask=None,
    run_on_keeptask_args=None,
):  # 进程守护判断
    TaskName = TaskName.casefold()
    TaskPath = TaskPath.casefold()

    # 执行额外函数
    def do_extra():
        if callable(run_on_keeptask):
            if run_on_keeptask_args is None:
                run_on_keeptask()
            elif isinstance(run_on_keeptask_args, (tuple, list)):
                run_on_keeptask(*run_on_keeptask_args)
            else:
                run_on_keeptask(run_on_keeptask_args)

    if alluser:
        for i in get_logon_user():
            try:
                alive_flag = False

                for j in get_user_process_list(i):
                    if j.get("name") == TaskName:
                        alive_flag = True
                        break

                if not alive_flag:
                    do_extra()  # 执行额外函数
                    runas(i, TaskPath, hight)

            except Exception as e:
                logger.log(
                    str(sys.exc_info()) + "行:" + str(e.__traceback__.tb_lineno),
                )
    else:
        alive_flag = False

        for i in get_process_list():
            if i.get("name") == TaskName:
                alive_flag = True
                break

        if not alive_flag:
            do_extra()  # 执行额外函数
            runas("SYSTEM", TaskPath)


def disable_quick_edit_mode():
    # 获取标准输入的句柄
    stdin_handle = ctypes.windll.kernel32.GetStdHandle(-10)  # -10 表示标准输入设备

    # 获取当前控制台模式
    mode = ctypes.c_ulong()
    ctypes.windll.kernel32.GetConsoleMode(stdin_handle, ctypes.byref(mode))

    # 禁用快速编辑模式 (ENABLE_QUICK_EDIT_MODE = 0x0040)
    mode.value &= ~0x0040

    # 设置新的控制台模式
    ctypes.windll.kernel32.SetConsoleMode(stdin_handle, mode)


def protect_self_process():
    # 获取当前进程句柄
    hProcess = win32api.GetCurrentProcess()

    # 获取当前进程的 DACL
    sd = win32security.GetKernelObjectSecurity(
        hProcess, win32security.DACL_SECURITY_INFORMATION
    )

    dacl = win32security.ACL()

    # 获取当前用户 SID
    user, domain, type = win32security.LookupAccountName("", win32api.GetUserName())

    # 给自己完全权限
    dacl.AddAccessAllowedAce(win32con.ACL_REVISION, win32con.PROCESS_ALL_ACCESS, user)

    # 拒绝 Everyone 终止权限
    everyone, _, _ = win32security.LookupAccountName("", "Everyone")
    dacl.AddAccessDeniedAce(win32con.ACL_REVISION, win32con.PROCESS_TERMINATE, everyone)

    # 应用新的 DACL 到当前进程
    sd.SetSecurityDescriptorDacl(1, dacl, 0)
    win32security.SetKernelObjectSecurity(
        hProcess, win32security.DACL_SECURITY_INFORMATION, sd
    )

    logger.log("Process protection enabled.")


def setpriority(pid=None, priority=0, set_core=False, use_P_core=True):
    """
    priority:
    0->低
    1->低于正常
    2->正常
    3->高于正常
    4->高
    5->实时
    set_core: True -> 要设定修改核心亲和性 ; False -> 不修改
    use_P_core: True -> 使用P核心 ; False -> 使用E核心 (如果支持)
    """
    try:
        priorityclasses = [
            win32process.IDLE_PRIORITY_CLASS,
            win32process.BELOW_NORMAL_PRIORITY_CLASS,
            win32process.NORMAL_PRIORITY_CLASS,
            win32process.ABOVE_NORMAL_PRIORITY_CLASS,
            win32process.HIGH_PRIORITY_CLASS,
            win32process.REALTIME_PRIORITY_CLASS,
        ]
        if pid is None:
            pid = win32api.GetCurrentProcessId()
    except:
        return -1

    try:
        set_affinity_result = 0
        if set_core:
            if not os.path.isfile(Game_Reverse_Core):  # 正常使用P核心
                if use_P_core:
                    set_affinity_result = set_affinity_by_pid(pid, False, False, 1)
                else:
                    set_affinity_result = set_affinity_by_pid(pid, False, False, 2)
            else:  # 反转使用E核心
                if use_P_core:
                    set_affinity_result = set_affinity_by_pid(pid, False, False, 2)
                else:
                    set_affinity_result = set_affinity_by_pid(pid, False, False, 1)
    except:
        logger.log("进程核心设置失败。")
    try:
        handle = win32api.OpenProcess(win32con.PROCESS_ALL_ACCESS, True, pid)
        win32process.SetPriorityClass(handle, priorityclasses[priority])
    except:
        logger.log("进程优先级设置失败。")
    finally:
        logger.log(
            f"修改进程PID:{pid}的优先级为{priority}{f",并已经设置CPU亲和性:{set_affinity_result}" if set_core else ""}"
        )
    return 0


def get_local_drives(Exclude="None"):
    drives = []
    bitmask = ctypes.windll.kernel32.GetLogicalDrives()  # 获取所有逻辑驱动器位掩码

    for letter in string.ascii_uppercase:
        if bitmask & 1:
            drive = f"{letter}:\\"
            # 检查驱动器类型是否为本地磁盘 (DRIVE_FIXED = 3)
            if ctypes.windll.kernel32.GetDriveTypeW(drive) == 3:
                if not drive[0] == Exclude:
                    drives.append(drive[0])
        bitmask >>= 1

    return drives


def clock_show_info(up="", down=""):  # up设定时钟部分,down设定日期部分,会覆盖原有内容
    def check_dict_in_list(datas, list_dict2):
        for key, value in datas.items():
            if not any(
                item.get("name") == key and item.get("value") == value
                for item in list_dict2
            ):
                return False
        return True

    if os.path.isfile(do_no_show_clock_info) or os.path.isfile(user_show_clock_info):
        if " " in up:  # 去除空格
            up = up.replace(" ", "")
        if " " in down:
            down = down.replace(" ", "")
        # 添加分隔符
        if not up == "" and not down == "":
            up = "|" + str(up)
            down = "|" + str(down)
    else:
        up = ""
        down = ""

    reg_path = "HKEY_CURRENT_USER\\Control Panel\\International"
    datas = {
        "sShortDate": f"yyyy/MM/dd'{down}'",
        "sLongDate": f"yyyy'-'MM'-'dd''{down}",
        "sYearMonth": f"yyyy'-'MM''{down}",
        "sShortTime": f"HH:mm",
        "s1159": f"{up}",
        "s2359": f"{up}",
    }

    should_write_flag = False
    for i in reg_reader.reg_read("HKEY_USERS\\")["Folders"]:
        reg_path_i = (
            "HKEY_USERS\\" + i["name"] + "\\" + "\\".join(reg_path.split("\\")[1::])
        )
        reg_path_i_read = reg_reader.reg_read(reg_path_i)["keys"]
        if len(reg_path_i_read) == 0:
            should_write_flag = True
            break
        else:
            if not check_dict_in_list(datas, reg_path_i_read):
                should_write_flag = True
                break
    else:
        logger.log("[任务栏显示信息]注册表数据与要求显示的信息一致。")
        return

    if should_write_flag:
        logger.log("[任务栏显示信息]注册表数据不一致,执行刷新。")
        for i in datas.items():
            reg_reader.reg_write(reg_path, i[0], "REG_SZ", i[1])


def gpupdate():
    RunWrapper("gpupdate /force /wait:0").read()


def str_to_hex(str):
    str_encode = ""
    for i in str:
        str_encode += "\\" + hex(ord(i))[1::]
    return str_encode


def clock_show_mobilehospd_info(name, password, clock_ini, str0="热点", str1="密码"):
    with smart_open.smart_opens(
        clock_ini,
        "r",
    ) as f:
        lines = f.readlines()
    if (
        "quick_note\\use_clock_skin=true" in lines
        or "quick_note\\use_clock_skin=true\n" in lines
    ):
        message = "quick_note\\message=%s\n" % password
    else:
        message = "quick_note\\message=%s:%s\\n%s:%s\n" % (
            str_to_hex(str0),
            name,
            str_to_hex(str1),
            password,
        )
    plugin_line = 0
    change_clag = False
    plugin_local_flag = False
    message_flag = False
    for i in range(len(lines)):
        if "[plugins]" in lines[i]:
            plugin_local_flag = True
            plugin_line = i
        if plugin_local_flag:
            if "quick_note\\message=" in lines[i]:
                message_flag = True
                if not message in lines[i]:
                    lines[i] = message
                    change_clag = True
                break
    else:
        lines.insert(plugin_line + 1, message + "\n")
    with smart_open.smart_opens(
        clock_ini,
        "w",
    ) as f:
        f.writelines(lines)
    if change_clag:
        if os.path.isfile(Digital_Clock_4_flag):
            RunWrapper(
                'taskkill /f /im digital_clock.exe /t & powershell "Get-Process -Name digital_clock | Stop-Process -Force"'
            ).read()
            TaskKeep("digital_clock.exe", Digital_Clock_4_exe, True)


def parse_reg_add_batch(batch_text: str):
    parsed_list = []

    for line in batch_text.splitlines():
        line = line.strip()
        if not line.lower().startswith("reg add"):
            continue

        # 提取 key
        key_match = re.search(r'reg\s+add\s+"?([^\s"]+)"?', line, re.IGNORECASE)
        key = key_match.group(1) if key_match else None
        if not key or "%" in key:
            continue

        # 提取 name（/v 或 /ve）
        name = None
        v_match = re.search(r"/v\s+([^\s]+)", line, re.IGNORECASE)
        ve_match = re.search(r"/ve\b", line, re.IGNORECASE)
        if v_match:
            name = v_match.group(1)
        elif ve_match or (not v_match and not ve_match):
            name = None
        if name is not None and "%" in name:
            continue

        # 提取 type
        type_match = re.search(r"/t\s+([^\s]+)", line, re.IGNORECASE)
        val_type = type_match.group(1) if type_match else None
        if not val_type or "%" in val_type:
            continue

        # 提取 value
        value_match = re.search(r'/d\s+"?([^\r\n\f/"]+)"?', line, re.IGNORECASE)
        value = value_match.group(1) if value_match else None
        if not value or "%" in value:
            continue

        parsed_list.append({"key": key, "name": name, "type": val_type, "value": value})

    return parsed_list


def bat_to_reg_reader(bat):
    for i in parse_reg_add_batch(bat):
        try:
            reg_reader.reg_write(i["key"], i["name"], i["type"], i["value"])
        except:
            pass


def clear_JetBrains_History():
    if os.path.isfile(Everything_es_Exe) and os.path.isfile(Everything_Exe):
        TaskKeep("Everything.exe", f"{Everything_Exe} -startup", True)
        recentProjects_xml_ls = (
            RunWrapper(f"{Everything_es_Exe} recentProjects.xml").read().splitlines()
        )
        if not len(recentProjects_xml_ls) == 0 and not recentProjects_xml_ls[
            0
        ].startswith("Error"):
            for i in recentProjects_xml_ls:
                # i是recentProjects.xml的绝对路径
                if os.path.exists(i):
                    path = os.path.dirname(i)
                    other = os.path.join(path, "other.xml")
                    safe_remove_path(i)
                    safe_remove_path(other)

                logger.log(f"[清理JetBrains历史] 删除文件:{i}")
        else:
            logger.log(f"[清理JetBrains历史] 无需删除")


def hide_console():
    hWnd = win32console.GetConsoleWindow()
    win32gui.ShowWindow(hWnd, win32con.SW_HIDE)


def show_console():
    hWnd = win32console.GetConsoleWindow()
    win32gui.ShowWindow(hWnd, win32con.SW_SHOW)


def safe_remove_path(path):
    """
    删除文件夹或文件，自动判断符号链接，遇到占用或异常跳过。
    """
    logger.log(f"[删除] {path}")
    if not os.path.exists(path):
        return  # 路径不存在，直接返回
    try:
        # /T递归，/C忽略错误继续，/Q静默
        cmd = ["icacls", path, "/grant", "Everyone:F", "/T", "/C", "/Q"]
        subprocess.run(cmd, capture_output=True, text=True)
    except Exception as e:
        pass
    try:
        if os.path.islink(path):
            # 是符号链接，直接unlink
            os.unlink(path)
        elif os.path.isfile(path):
            # 普通文件
            try:
                os.remove(path)
            except Exception:
                # 删除失败跳过
                pass
        else:
            # 其他类型（如设备文件），尝试删除
            try:
                os.remove(path)
            except Exception:
                pass
        try:
            shutil.rmtree(path, ignore_errors=True)
        except Exception:
            pass
    except Exception:
        # 外层异常捕获，防止意外中断
        pass


def all_users_add_to_admin():
    logger.log("添加所有用户到管理员组")
    for i in get_local_users_sid():
        RunWrapper(f"net localgroup administrators \"{i['name']}\" /add")


RestoreAppdata_tips_text = (
    "用户数据重定向说明"
    + chr(10)
    + "----------------------------------------"
    + chr(10)
    + "此目录用于重定向用户数据，以减少系统盘（通常为 C 盘）的存储压力。"
    + chr(10)
    + "然而，数据重定向可能会带来某些副作用，例如部分 UWP 应用无法正常启动等兼容性问题。"
    + chr(10)
    + ""
    + chr(10)
    + "为了解决这些问题，请在该目录下运行以下修复脚本："
    + chr(10)
    + "  • 设置权限.bat：重新设置访问控制权限，确保系统与应用可正常访问用户数据。"
    + chr(10)
    + "  • 重置UWP.bat：修复 UWP 应用因权限或路径异常导致的启动失败问题。"
    + chr(10)
    + ""
    + chr(10)
    + "----------------------------------------"
    + chr(10)
    + "手动修复（针对使用过旧版重定向机制的用户）"
    + chr(10)
    + "----------------------------------------"
    + chr(10)
    + "如果您之前使用过旧版数据重定向，请按照以下步骤手动修复系统环境。"
    + chr(10)
    + "注意：如果您使用的是符号链接（junction/symlink），请先删除链接，并将文件实际迁移到目标目录。"
    + chr(10)
    + "修复前请务必备份重要文件。"
    + chr(10)
    + ""
    + chr(10)
    + "1. 启动 Windows PE 环境，或使用卷影复制服务（VSS）。"
    + chr(10)
    + "2. 将 :\\StorageRedirect\\Users\\用户名\\ProfileImage\\ 下的全部文件迁移至 :\\Users\\用户名\\。"
    + chr(10)
    + "3. 将 :\\StorageRedirect\\Users\\用户名\\Data\\AppData\\ 内的所有文件迁移至 :\\Users\\用户名\\AppData\\Roaming\\。"
    + chr(10)
    + "4. 将 :\\StorageRedirect\\Users\\用户名\\Data\\LocalAppData\\ 内的所有文件迁移至 :\\Users\\用户名\\AppData\\Local\\。"
    + chr(10)
    + "5. 将 :\\StorageRedirect\\Users\\用户名\\Documents\\ 下的所有文件夹迁移至 :\\Users\\用户名\\ 【可能需要处理文件名问题】。"
    + chr(10)
    + ""
    + chr(10)
    + "----------------------------------------"
    + chr(10)
    + "提示"
    + chr(10)
    + "----------------------------------------"
    + chr(10)
    + "• 如果仍遇到 UWP 应用无法打开，请再次执行 修复UWP.bat 并确保权限设置成功。"
    + chr(10)
    + "• 若系统已关闭 UAC（用户账户控制），部分修复操作可能不再需要确认。"
    + chr(10)
    + "• 建议在迁移完成后重启系统以确保所有更改生效。"
)


def set_folder_grant_deny(folder, deny=False):
    """
    让某些文件夹无权限
    """
    try:
        if '"' in folder:
            folder = folder.replace('"', "")
        if deny:
            RunWrapper(f'icacls "{folder}" /setowner SYSTEM /T /C /Q').read()
        RunWrapper(
            f'icacls "{folder}" /{"deny" if deny else "grant"} Everyone:F /inheritance:r /T /C /Q'
        ).read()
    except:
        pass


def fuck_update():
    roaming_folder_ls = ["Tencent\\xwechat\\update", "QQ\\packages\\full"]
    if os.path.isfile(deny_appdata_folder_conf):
        try:
            with smart_open.smart_opens(
                deny_appdata_folder_conf,
                "r",
            ) as f:
                deny_appdata_folder_read = f.read().splitlines()
            for p in deny_appdata_folder_read:
                if not p[0] == "#":
                    if '"' in p:
                        p = p.replace('"', "")
                    if "'" in p:
                        p = p.replace("'", "")
                    roaming_folder_ls.append(p)
        except:
            pass
    else:
        try:
            with smart_open.smart_opens(
                deny_appdata_folder_conf,
                "w",
            ) as f:
                f.write(
                    '#在本配置文件写下文件夹路径,ZhangProtect会自动在每个用户的Appdata下剥夺该文件夹的权限，可用于屏蔽应用自动更新的下载。支持多个，一行一个，仅需写文件夹名。例如"%appdata%\\Tencent\\xwechat\\Update"仅需写为"Tencent\\xwechat\\Update"(无需引号;结尾不要有反斜杠)'
                )
        except:
            pass
    for i in get_all_user_profiles(True):
        try:
            appdata = i["appdata"]
            localappdata = i["localappdata"]
            for j in roaming_folder_ls:
                path_appdata = os.path.join(appdata, j)
                path_localappdata = os.path.join(localappdata, j)
                KeepFolder(path_appdata)
                KeepFolder(path_localappdata)
                set_folder_grant_deny(path_appdata, True)
                set_folder_grant_deny(path_localappdata, True)
        except:
            pass


def change_ccleaner_ini(file):
    if os.path.isfile(file):
        new = []
        with smart_open.smart_opens(file, "r") as f:
            lines = f.read().splitlines()
            for line in lines:
                if any(i.lower() in line.lower() for i in ["=True", "=False"]):
                    if any(
                        i.lower() in line.lower()
                        for i in [
                            "QQ",
                            "WeChat",
                            "WeiXin",
                            "Cookies",
                            "Wipe Free Space",
                            "Password",
                            "Session",
                            "Web Storage",
                        ]
                    ):
                        line = line.replace("=True", "=False").replace(
                            "=true", "=False"
                        )
                        reg_reader.reg_write(
                            "HKEY_CURRENT_USER\\Software\\Piriform\\CCleaner",
                            line.split("=")[0],
                            "REG_SZ",
                            "False",
                        )
                    else:
                        line = line.replace("=False", "=True").replace(
                            "=false", "=True"
                        )
                        reg_reader.reg_write(
                            "HKEY_CURRENT_USER\\Software\\Piriform\\CCleaner",
                            line.split("=")[0],
                            "REG_SZ",
                            "True",
                        )
                new.append(line + "\n")
        if not len(new) == 0:
            with smart_open.smart_opens(file, "w") as f:
                f.writelines(new)
    else:
        ini_default = (
            "[Options]"
            + chr(10)
            + "AP="
            + chr(10)
            + "(App).NET Framework *=True"
            + chr(10)
            + "(App)7-Zip=True"
            + chr(10)
            + "(App)AIDA64 *=True"
            + chr(10)
            + "(App)Adobe *=True"
            + chr(10)
            + "(App)Adobe Acrobat *=True"
            + chr(10)
            + "(App)Adobe Acrobat Distiller *=True"
            + chr(10)
            + "(App)Adobe Acrobat Standard DC=True"
            + chr(10)
            + "(App)Adobe Bridge *=True"
            + chr(10)
            + "(App)Adobe CC *=True"
            + chr(10)
            + "(App)Adobe Flash Player *=True"
            + chr(10)
            + "(App)Android Studio *=True"
            + chr(10)
            + "(App)Apple Install Files=True"
            + chr(10)
            + "(App)Apps/Programs=True"
            + chr(10)
            + "(App)Audio/Video=True"
            + chr(10)
            + "(App)Autocomplete Form History=True"
            + chr(10)
            + "(App)CCleaner *=True"
            + chr(10)
            + "(App)CentBrowser 书签备份*=True"
            + chr(10)
            + "(App)Chkdsk File Fragments=True"
            + chr(10)
            + "(App)Chromium Auto Fill Data *=True"
            + chr(10)
            + "(App)Chromium Bookmark Backup *=True"
            + chr(10)
            + "(App)Chromium Bookmark Favicons *=True"
            + chr(10)
            + "(App)Chromium Caches *=True"
            + chr(10)
            + "(App)Chromium Cookies *=False"
            + chr(10)
            + "(App)Chromium Embedded Framework *=True"
            + chr(10)
            + "(App)Chromium History *=True"
            + chr(10)
            + "(App)Chromium Login Data *=True"
            + chr(10)
            + "(App)Chromium Session *=False"
            + chr(10)
            + "(App)Chromium Sync Data *=True"
            + chr(10)
            + "(App)Chromium Telemetry *=True"
            + chr(10)
            + "(App)Chromium Updates *=True"
            + chr(10)
            + "(App)Chromium Web Storage *=False"
            + chr(10)
            + "(App)Clipboard=True"
            + chr(10)
            + "(App)Compressed Files=True"
            + chr(10)
            + "(App)Cookies=False"
            + chr(10)
            + "(App)CrashRpt *=True"
            + chr(10)
            + "(App)Custom Folders=True"
            + chr(10)
            + "(App)DB Browser for SQLite *=True"
            + chr(10)
            + "(App)DNS Cache=True"
            + chr(10)
            + "(App)Delete Index.dat files=True"
            + chr(10)
            + "(App)Dell *=True"
            + chr(10)
            + "(App)Desktop Shortcuts=True"
            + chr(10)
            + "(App)Documents=True"
            + chr(10)
            + "(App)Douyin=True"
            + chr(10)
            + "(App)Driver Installation Log Files=True"
            + chr(10)
            + "(App)Edge Chromium - Bookmarks Backup=True"
            + chr(10)
            + "(App)Edge Chromium - Compact Databases=True"
            + chr(10)
            + "(App)Edge Chromium - Cookies=False"
            + chr(10)
            + "(App)Edge Chromium - Download History=True"
            + chr(10)
            + "(App)Edge Chromium - Internet Cache=True"
            + chr(10)
            + "(App)Edge Chromium - Internet History=True"
            + chr(10)
            + "(App)Edge Chromium - Last Download Location=True"
            + chr(10)
            + "(App)Edge Chromium - Metrics Temp Files=True"
            + chr(10)
            + "(App)Edge Chromium - Saved Form Information=True"
            + chr(10)
            + "(App)Edge Chromium - Saved Passwords=False"
            + chr(10)
            + "(App)Edge Chromium - Session=False"
            + chr(10)
            + "(App)Empty Recycle Bin=True"
            + chr(10)
            + "(App)Environment Path=True"
            + chr(10)
            + "(App)FL Studio *=True"
            + chr(10)
            + "(App)Foobar2000 *=True"
            + chr(10)
            + "(App)FreeFileSync *=True"
            + chr(10)
            + "(App)GNU *=True"
            + chr(10)
            + "(App)Google Chrome - Bookmarks Backup=True"
            + chr(10)
            + "(App)Google Chrome - Compact Databases=True"
            + chr(10)
            + "(App)Google Chrome - Cookies=False"
            + chr(10)
            + "(App)Google Chrome - Download History=True"
            + chr(10)
            + "(App)Google Chrome - Internet Cache=True"
            + chr(10)
            + "(App)Google Chrome - Internet History=True"
            + chr(10)
            + "(App)Google Chrome - Last Download Location=True"
            + chr(10)
            + "(App)Google Chrome - Metrics Temp Files=True"
            + chr(10)
            + "(App)Google Chrome - Saved Form Information=True"
            + chr(10)
            + "(App)Google Chrome - Saved Passwords=False"
            + chr(10)
            + "(App)Google Chrome - Session=False"
            + chr(10)
            + "(App)Google Update *=True"
            + chr(10)
            + "(App)History=True"
            + chr(10)
            + "(App)InstallShield *=True"
            + chr(10)
            + "(App)Intel *=True"
            + chr(10)
            + "(App)Intel Graphics Command Center *=True"
            + chr(10)
            + "(App)Intel Shader Cache *=True"
            + chr(10)
            + "(App)Internet Download Manager=True"
            + chr(10)
            + "(App)Internet Download Manager *=True"
            + chr(10)
            + "(App)Internet Explorer *=True"
            + chr(10)
            + "(App)Java=True"
            + chr(10)
            + "(App)Java *=True"
            + chr(10)
            + "(App)K-Lite Codec Pack *=True"
            + chr(10)
            + "(App)Kingsoft Office *=True"
            + chr(10)
            + "(App)Kingsoft Office 2013=True"
            + chr(10)
            + "(App)LDPlayer *=True"
            + chr(10)
            + "(App)Last Download Location=True"
            + chr(10)
            + "(App)League of Legends *=True"
            + chr(10)
            + "(App)LockHunter *=True"
            + chr(10)
            + "(App)MATLAB *=True"
            + chr(10)
            + "(App)MS Management Console=True"
            + chr(10)
            + "(App)MS Office Picture Manager=True"
            + chr(10)
            + "(App)MS Search=True"
            + chr(10)
            + "(App)Memory Dumps=True"
            + chr(10)
            + "(App)Menu Order Cache=True"
            + chr(10)
            + "(App)Microsoft DirectX *=True"
            + chr(10)
            + "(App)Microsoft Edge Auto Fill Data *=True"
            + chr(10)
            + "(App)Microsoft Edge Bookmark Backup *=True"
            + chr(10)
            + "(App)Microsoft Edge Bookmark Favicons *=True"
            + chr(10)
            + "(App)Microsoft Edge Caches *=True"
            + chr(10)
            + "(App)Microsoft Edge Cookies *=False"
            + chr(10)
            + "(App)Microsoft Edge History *=True"
            + chr(10)
            + "(App)Microsoft Edge Login Data *=True"
            + chr(10)
            + "(App)Microsoft Edge Logs *=True"
            + chr(10)
            + "(App)Microsoft Edge Session *=False"
            + chr(10)
            + "(App)Microsoft Edge Sync Data *=True"
            + chr(10)
            + "(App)Microsoft Edge Telemetry *=True"
            + chr(10)
            + "(App)Microsoft Edge Updates *=True"
            + chr(10)
            + "(App)Microsoft Edge Web Storage *=False"
            + chr(10)
            + "(App)Microsoft HTML Help *=True"
            + chr(10)
            + "(App)Microsoft Management Console *=True"
            + chr(10)
            + "(App)Microsoft Office *=True"
            + chr(10)
            + "(App)Microsoft Office Unsaved Files *=True"
            + chr(10)
            + "(App)Microsoft OneDrive=True"
            + chr(10)
            + "(App)Microsoft OneDrive *=True"
            + chr(10)
            + "(App)Microsoft Outlook *=True"
            + chr(10)
            + "(App)Microsoft VS Code *=True"
            + chr(10)
            + "(App)Microsoft Visual Studio *=True"
            + chr(10)
            + "(App)Microsoft Visual Studio Backups *=True"
            + chr(10)
            + "(App)Microsoft Visual Studio Installation Packages *=True"
            + chr(10)
            + "(App)Microsoft XNA Game Studio *=True"
            + chr(10)
            + "(App)Minecraft *=True"
            + chr(10)
            + "(App)NVIDIA *=True"
            + chr(10)
            + "(App)NVIDIA Install Files=True"
            + chr(10)
            + "(App)Network Data Usage=True"
            + chr(10)
            + "(App)Network Passwords=False"
            + chr(10)
            + "(App)Node.js=True"
            + chr(10)
            + "(App)Notepad++=True"
            + chr(10)
            + "(App)Notepad++ *=True"
            + chr(10)
            + "(App)Notepad++ - Backups & Unsaved Files *=True"
            + chr(10)
            + "(App)Notepad++ - Session *=False"
            + chr(10)
            + "(App)Npcap Loopback Adapter *=True"
            + chr(10)
            + "(App)OBS *=True"
            + chr(10)
            + "(App)Office 2013=True"
            + chr(10)
            + "(App)Old Prefetch data=True"
            + chr(10)
            + "(App)Ookla Speed Test *=True"
            + chr(10)
            + "(App)Other Explorer MRUs=True"
            + chr(10)
            + "(App)Others=True"
            + chr(10)
            + "(App)PDF24=True"
            + chr(10)
            + "(App)PDF24 Creator *=True"
            + chr(10)
            + "(App)Photos Temp Files=True"
            + chr(10)
            + "(App)Pictures/Images=True"
            + chr(10)
            + "(App)PotPlayer *=True"
            + chr(10)
            + "(App)QQ 临时文件*=False"
            + chr(10)
            + "(App)QQ 日志*=False"
            + chr(10)
            + "(App)QQ影音 缓存*=False"
            + chr(10)
            + "(App)QQ浏览器 缓存*=False"
            + chr(10)
            + "(App)QQ音乐 缓存*=False"
            + chr(10)
            + "(App)Qt Framework *=True"
            + chr(10)
            + "(App)Realtek *=True"
            + chr(10)
            + "(App)Recent Documents=True"
            + chr(10)
            + "(App)Recently Typed URLs=True"
            + chr(10)
            + "(App)RegEdit=True"
            + chr(10)
            + "(App)Remote Desktop=True"
            + chr(10)
            + "(App)Run (in Start Menu)=True"
            + chr(10)
            + "(App)Saved Passwords=False"
            + chr(10)
            + "(App)Start Menu Shortcuts=True"
            + chr(10)
            + "(App)Steam *=True"
            + chr(10)
            + "(App)Steam Games *=True"
            + chr(10)
            + "(App)Steam Installers *=True"
            + chr(10)
            + "(App)Steam Packages *=True"
            + chr(10)
            + "(App)Sysinternals Process Explorer *=True"
            + chr(10)
            + "(App)Sysinternals Process Monitor *=True"
            + chr(10)
            + "(App)Taskbar Jump Lists=True"
            + chr(10)
            + "(App)Temporary Files=True"
            + chr(10)
            + "(App)Temporary Internet Files=True"
            + chr(10)
            + "(App)Tencent QQ *=False"
            + chr(10)
            + "(App)Tencent WeChat *=False"
            + chr(10)
            + "(App)Terraria *=True"
            + chr(10)
            + "(App)Thumbnail Cache=True"
            + chr(10)
            + "(App)Total Uninstall *=True"
            + chr(10)
            + "(App)Total Uninstall Backups *=True"
            + chr(10)
            + "(App)Tray Notifications Cache=True"
            + chr(10)
            + "(App)Universal Windows Platform *=True"
            + chr(10)
            + "(App)User Assist History=True"
            + chr(10)
            + "(App)VMware Personal Desktop Virtualization *=True"
            + chr(10)
            + "(App)VMware Player=True"
            + chr(10)
            + "(App)VMware Workstation=True"
            + chr(10)
            + "(App)WPS Office - Free Office Suite=True"
            + chr(10)
            + "(App)WPS 临时文件*=True"
            + chr(10)
            + "(App)WPS 备份文件*=True"
            + chr(10)
            + "(App)WPS 日志*=True"
            + chr(10)
            + "(App)WPS 更新缓存*=True"
            + chr(10)
            + "(App)WebDAV Cache=True"
            + chr(10)
            + "(App)WinRAR=True"
            + chr(10)
            + "(App)WinRAR *=True"
            + chr(10)
            + "(App)Window Size/Location Cache=True"
            + chr(10)
            + "(App)Windows Activity History *=True"
            + chr(10)
            + "(App)Windows AutoPlay Devices *=True"
            + chr(10)
            + "(App)Windows CD Burning Queue *=True"
            + chr(10)
            + "(App)Windows Calculator *=True"
            + chr(10)
            + "(App)Windows Client Temp Files=True"
            + chr(10)
            + "(App)Windows Credential Manager Saved Credentials *=True"
            + chr(10)
            + "(App)Windows Cryptographic Services *=True"
            + chr(10)
            + "(App)Windows Defender=True"
            + chr(10)
            + "(App)Windows Delivery Optimization Files=True"
            + chr(10)
            + "(App)Windows Device Manager *=True"
            + chr(10)
            + "(App)Windows EdgeHTML *=True"
            + chr(10)
            + "(App)Windows Error Reporting=True"
            + chr(10)
            + "(App)Windows Error Reporting *=True"
            + chr(10)
            + "(App)Windows Event Logs=True"
            + chr(10)
            + "(App)Windows Event Trace Logs=True"
            + chr(10)
            + "(App)Windows Event Viewer *=True"
            + chr(10)
            + "(App)Windows Font Cache *=True"
            + chr(10)
            + "(App)Windows Installer *=True"
            + chr(10)
            + "(App)Windows Lock Screen *=True"
            + chr(10)
            + "(App)Windows Log Files=True"
            + chr(10)
            + "(App)Windows Logs *=True"
            + chr(10)
            + "(App)Windows Media Extensions *=True"
            + chr(10)
            + "(App)Windows Media Player=True"
            + chr(10)
            + "(App)Windows Media Player *=True"
            + chr(10)
            + "(App)Windows Notepad *=True"
            + chr(10)
            + "(App)Windows Notifications=True"
            + chr(10)
            + "(App)Windows Notifications *=True"
            + chr(10)
            + "(App)Windows Photos *=True"
            + chr(10)
            + "(App)Windows Power Efficiency Diagnostics *=True"
            + chr(10)
            + "(App)Windows PowerShell *=True"
            + chr(10)
            + "(App)Windows Printing *=True"
            + chr(10)
            + "(App)Windows Program Compatibility Assistant *=True"
            + chr(10)
            + "(App)Windows Recent Documents *=True"
            + chr(10)
            + "(App)Windows Recycle Bin *=True"
            + chr(10)
            + "(App)Windows Registry Editor *=True"
            + chr(10)
            + "(App)Windows Remote Desktop *=True"
            + chr(10)
            + "(App)Windows Search *=True"
            + chr(10)
            + "(App)Windows Security *=True"
            + chr(10)
            + "(App)Windows Settings *=True"
            + chr(10)
            + "(App)Windows Shell *=True"
            + chr(10)
            + "(App)Windows Shell - Folder View Settings *=True"
            + chr(10)
            + "(App)Windows Start Menu *=True"
            + chr(10)
            + "(App)Windows Subsystems *=True"
            + chr(10)
            + "(App)Windows Task Scheduler *=True"
            + chr(10)
            + "(App)Windows Taskbar *=True"
            + chr(10)
            + "(App)Windows Temporary Files *=True"
            + chr(10)
            + "(App)Windows Update *=True"
            + chr(10)
            + "(App)Windows Volume Mixer *=True"
            + chr(10)
            + "(App)Windows Web Cache=True"
            + chr(10)
            + "(App)Windows Widgets=True"
            + chr(10)
            + "(App)Wipe Free Space=False"
            + chr(10)
            + "(App)Wireshark *=True"
            + chr(10)
            + "(App)Xbox *=True"
            + chr(10)
            + "(App)百度云管家 日志*=True"
            + chr(10)
            + "(App)腾讯产品 日志残留文件*=True"
            + chr(10)
            + "(App)腾讯视频 缓存文件*=True"
            + chr(10)
            + "(App)酷我音乐 广告数据*=True"
            + chr(10)
            + "(App)酷我音乐 歌曲缓存*=True"
            + chr(10)
            + "(App)酷狗音乐 缓存*=True"
            + chr(10)
            + "(Mon)3001=1"
            + chr(10)
            + "(Mon)3006=1"
            + chr(10)
            + "AcqSrc=mmm_ccl_oth_007_745_m"
            + chr(10)
            + "AlphaLSLUT=1764826600"
            + chr(10)
            + "AnalyzerTypes=1|1|1|1|0|0|0"
            + chr(10)
            + "BCD=0,1,"
            + chr(10)
            + "BackupPrompt=0"
            + chr(10)
            + "BrowserMonitoring=0"
            + chr(10)
            + "CookiesToSave=*.avast.com|*.ccleaner.com|*.ccleanercloud.com"
            + chr(10)
            + "CountryCode=HK"
            + chr(10)
            + "DefaultDetailedView=1"
            + chr(10)
            + "DelayTemp=0"
            + chr(10)
            + "DisplayIM=2-1|"
            + chr(10)
            + "FinderInclude1=PATH|C:\\|*.*|RECURSE|0|0|24"
            + chr(10)
            + "FinderInclude2=PATH|D:\\|*.*|RECURSE|0|0|24"
            + chr(10)
            + "FinderIncludeStates=1|0"
            + chr(10)
            + "HCFirstTime=0"
            + chr(10)
            + "HelpImproveCCleaner=0"
            + chr(10)
            + "HideWarnings=1"
            + chr(10)
            + "HomeScreen=2"
            + chr(10)
            + "LastRatedHealthCheck=1"
            + chr(10)
            + "LatestICS=6.35.11488"
            + chr(10)
            + "Monitoring=0"
            + chr(10)
            + "PrefsPrivacyShareData1stParty=0"
            + chr(10)
            + "PrefsPrivacyShareData3rdParty=0"
            + chr(10)
            + "PrefsPrivacyShowOffers1stParty=0"
            + chr(10)
            + "PrefsPrivacyShowOffers3rdParty=0"
            + chr(10)
            + "RunICS=0"
            + chr(10)
            + "STS=MP3ZI2MWQPQS4CUDPTUYC5UIPF3ZI55URE8VKDIKJTBWUTB7FW2S4CUNIPKD425WGIGSWVCDKTJV4NJZG24DSNTSGS5DSDIKKTDFGRJWHE3VIMTYHEGSWXCQIPBV4QJUGI3VGP3UGA3VNQBXGS5VQPJ2GI4A4CUWJ3EWGRJ3GI3DGN3ZGI2DGPT2GW4DQP3XHA2DQDIKKTKENW37GAGSW"
            + chr(10)
            + "ShowCleanWarning=True"
            + chr(10)
            + "ShowEdgeChromiumCleanSuspendedWarning=True"
            + chr(10)
            + "ShowWindowsExplorerCleanWarning=True"
            + chr(10)
            + "SkipUAC=1"
            + chr(10)
            + "SystemMonitoring=0"
            + chr(10)
            + "SystemMonitoringRunningNotification=0"
            + chr(10)
            + "SystemMonitoringSavingsAction=3"
            + chr(10)
            + "UpdateAuto=1"
            + chr(10)
            + "UpdateBackground=0"
            + chr(10)
            + "UpdateCheck=0"
            + chr(10)
            + "UpdateNotify=0"
            + chr(10)
            + "WINDOW_HEIGHT=885"
            + chr(10)
            + "WINDOW_LEFT=320"
            + chr(10)
            + "WINDOW_MAX=0"
            + chr(10)
            + "WINDOW_TOP=97"
            + chr(10)
            + "WINDOW_WIDTH=1280"
            + chr(10)
            + "WipeFreeSpaceDrives="
            + chr(10)
            + "WipeMFTFreeSpace=0"
            + chr(10)
            + "SecureDeleteType=0"
            + chr(10)
            + "WipeAlternateDataStreams=0"
            + chr(10)
            + "WipeClusterTips=0"
            + chr(10)
            + "SecureDeleteMethod=0"
            + chr(10)
            + "(App)Universe Sandbox *=True"
            + chr(10)
            + "(App)Bugsplat *=True"
            + chr(10)
            + "(App)Chocolatey *=True"
            + chr(10)
            + "(App)Everything *=True"
            + chr(10)
            + "(App)Microsoft PowerToys *=True"
            + chr(10)
            + "(App)Norton *=True"
            + chr(10)
            + "(App)Norton Install Files=True"
            + chr(10)
            + "(App)Rainmeter *=True"
            + chr(10)
            + "(App)Game Explorer=True"
            + chr(10)
            + "(App)Microsoft Store *=True"
            + chr(10)
            + "(App)MS Paint=True"
            + chr(10)
            + "(App)Windows Language Libraries *=True"
            + chr(10)
            + "(App)Windows Shell - Theme Colors History *=True"
            + chr(10)
            + "(App)Windows System Assessment Tool *=True"
            + chr(10)
            + "(App)Dolby Access=True"
            + chr(10)
            + "(App)IISExpress *=True"
            + chr(10)
            + "(App)Tencent WeChat Work *=False"
            + chr(10)
            + "(App)WinPcap *=True"
            + chr(10)
            + "(App)Microsoft SQL Server *=True"
            + chr(10)
            + "(App)SketchUp Make *=True"
            + chr(10)
            + "(App)SketchUp Make 2013=True"
            + chr(10)
            + "(App)Wondershare *=True"
            + chr(10)
            + "(App)Wondershare Helper Compact *=True"
            + chr(10)
            + "(App)WPS 轻办公更新缓存*=True"
            + chr(10)
            + "(App)DirectX Shader Cache=True"
            + chr(10)
            + "AmountToClean=48812725"
            + chr(10)
            + "NumOfItemsToClean=389"
        )
        with smart_open.smart_opens(file, "w") as f:
            f.write(ini_default)


def StorageRedirect(datadir, systemdriver):
    """
    兼容代理：实现已抽离到 StorageRedirect.py，主程序与独立的 StorageRedirect.exe
    共用同一份代码，调用方式与抽离前完全一致。

    datadir --> 数据盘符
    systemdriver --> 系统盘符
    均仅传入单个字母即可 --> 例如StorageRedirect("D","C")
    """
    return _StorageRedirectImpl(datadir, systemdriver)


def set_hidden(file_path, hidden=True):
    add_or_l = "+" if hidden else "-"
    RunWrapper(f'attrib /D {add_or_l}s {add_or_l}h {add_or_l}r "{file_path}"').read()
    logger.log(f"[属性]为 {file_path} {"设置" if hidden else "取消"}隐藏属性")


def file_arrange(datadir, sysdir):

    data_special = ["学科文件夹"]  # 此类文件夹内部如果有 hide 文件则隐藏。

    data_keep = ["Files", "Important", "StorageRedirect", "Users"]

    sys_keep = ["Program Files", "Program Files (x86)", "Windows", "Users"]

    def set(path, keep, special=None):
        if special is None:
            special = []
        keep = [i.lower() for i in keep]
        special = [i.lower() for i in special]
        for i in special:
            special_abspath = f"{path}\\{i}"
            special_hide_flag = f"{special_abspath}\\hide"
            if os.path.isfile(special_hide_flag):
                if i in keep:
                    keep.remove(i)
            else:
                keep.append(i)

        for i in os.listdir(f"{path}\\"):
            abs_path = f"{path}\\{i}"
            hidden = not i.lower() in keep
            logger.log(f"[文件整理]{"隐藏" if hidden else "取消隐藏"}文件 {abs_path}")
            set_hidden(abs_path, hidden=hidden)

    set(datadir, data_keep, data_special)
    set(sysdir, sys_keep)


def dir_abs_bare(pattern="*.exe", root="."):
    """
    - pattern: 通配符（默认 *.exe）
    - root:    起始目录（默认当前目录）
    返回: 匹配到的绝对路径列表（Windows 风格反斜杠）。
    """
    root = os.fspath(root)
    search = os.path.join(root, "**", pattern)

    results = []
    # Windows 上 glob 用的是不区分大小写的匹配规则（依赖于底层 os.path）
    for path in glob.iglob(search, recursive=True):
        # 仅保留文件（/A 会显示所有属性，但通配符一般用于文件，这里过滤掉目录）
        if os.path.isfile(path):
            full = os.path.abspath(path)
            results.append(os.path.normpath(full))  # 统一为反斜杠

    return results


def is_connected_network() -> bool:
    """简化版的网络连接检查"""
    # 核心测试网站（选择最稳定的）
    core_urls = [
        "https://www.baidu.com",
        "https://www.bing.com",
        "https://www.qq.com",
        "https://www.cloudflare.com",
        "https://www.microsoft.com",
    ]
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    }
    for url in core_urls:
        try:
            response = requests.get(
                url, headers=headers, timeout=3.0, verify=False, allow_redirects=True
            )
            # 检查状态码和内容长度
            if response.status_code == 200:
                # 简单检查是否有合理的内容
                content = response.text
                if len(content) > 500:  # 确保不是错误页面或空白页
                    # 检查是否有常见HTML标签
                    if "<html" in content.lower() or "<body" in content.lower():
                        return True
                    # 对于API端点等，状态码200即可
                    elif response.headers.get("content-type", ""):
                        return True
        except requests.exceptions.Timeout:
            continue
        except requests.exceptions.ConnectionError:
            continue
        except requests.exceptions.RequestException:
            continue
        except Exception:
            continue

    return False


def zhang_change_all_powercfg(get_str_mode=False, guid=None, Only_Apply_Settings=False):
    """
    修改电源选项设置
    param:
    get_str_mode:改为获取cmd命令列表 GUID使用占位符[guid]
    """
    if guid is None:
        current_plan_guid = get_current_plan_guid()  # 只修改当前计划
    else:
        current_plan_guid = guid  # 用户指定修改的guid
    hibernate_enable = not os.path.isfile(disablehibernate)  # 是否启用休眠
    return powercfg.auto_powercfg_setting(
        get_str_mode=get_str_mode,
        guid=current_plan_guid,
        hibernate_enable=hibernate_enable,
        Only_Apply_Settings=Only_Apply_Settings,
    )


def power_performance(set_powercfg=True):  # 高性能
    try:
        result = powercfg.powercfg_change("ULTIMATE_PERFORMANCE")
        if not result in ["UnChanged", "Changed"]:
            result = powercfg.powercfg_change("HIGH_PERFORMANCE")
        zhang_change_all_powercfg(
            Only_Apply_Settings=(not (set_powercfg and result == "Changed"))
        )
    except Exception as e:
        logger.log(f"[高性能]切换失败:{e}")


def power_save(set_powercfg=True):  # 节能模式
    try:
        result = powercfg.powercfg_change("SLEEPY")
        zhang_change_all_powercfg(
            Only_Apply_Settings=(not (set_powercfg and result == "Changed"))
        )
    except Exception as e:
        logger.log(f"[节能]切换失败:{e}")


def power_normal(set_powercfg=True):  # 平衡模式
    try:
        result = powercfg.powercfg_change("BALANCED")
        zhang_change_all_powercfg(
            Only_Apply_Settings=(not (set_powercfg and result == "Changed"))
        )
    except Exception as e:
        logger.log(f"[平衡]切换失败:{e}")


def powercfg_auto_change():
    if os.path.isfile(donotautopower):  # 自动调整开启时
        power_info = powercfg.get_power_info()
        if (
            power_info.get("ACLineStatus") == 1  # 电源接通时
            or power_info.get("BatteryFlag") == 128  # 没电池的机器
        ):  # 充电器插着的状态
            power_performance()
            logger.log("[自动电源计划]使用电源-->切换到高性能")
        else:
            if os.path.isfile(powerkeep):
                power_save()
                logger.log("[自动电源计划]使用电池-->切换到节能")
            else:
                power_normal()
                logger.log("[自动电源计划]使用电池-->切换到平衡")
    else:  # 自动调整关闭时,不设置具体powercfg设置项
        if os.path.isfile(powerkeep):  # 开启节能模式时
            power_save()
            logger.log("[电源计划]节能模式")
        elif os.path.isfile(normal_disautopwcfg):
            power_normal()
            logger.log("[电源计划]平衡模式")


def AutoScreenshot_lock_ini_config(ini_path, output_dir):
    """
    锁定AutoScreenshot指定 ini 配置参数

    :param ini_path: ini文件路径
    :param output_dir: OutputDir参数值
    """
    try:
        reg_reader.reg_delete_key(
            "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            "Auto Screenshot",
        )
    except:
        pass
    try:
        os.makedirs(output_dir, exist_ok=True)
        ini_dir = os.path.dirname(os.path.abspath(ini_path))
        if ini_dir:
            os.makedirs(ini_dir, exist_ok=True)
        config = configparser.ConfigParser()
        config.optionxform = str
        if os.path.exists(ini_path):
            config.read(ini_path, encoding="utf-8")
        if not config.has_section("main"):
            config.add_section("main")
        fixed_values = {
            "OutputDir": output_dir,
            "MinimizeInsteadOfClose": "1",
            "AutoRun": "0",
            "StartMinimized": "1",
            "StartCaptureOnStartUp": "1",
            "AutoCheckForUpdates": "0",
            "OldScreenshotCleanerEnabled": "1",
            "OldScreenshotCleanerMaxAge": "1w",
        }
        for key, value in fixed_values.items():
            config.set("main", key, str(value))
        with open(ini_path, "w", encoding="utf-8") as f:
            config.write(f)
        logger.log(f"[截屏监控]配置覆盖完成")
    except Exception as e:
        logger.log(f"[截屏监控]配置修改失败:{e}")


def create_shell_new(
    extension: str, title: str, prog_id: str = None, template: str = None
):
    """
    创建 Windows 右键 -> 新建 项

    方式:
    extension -> prog_id
    extension -> ShellNew
    prog_id -> 显示标题

    :param extension: 文件后缀，例如 ".py"
    :param title: 显示名称，例如 "Python 源文件"
    :param prog_id: ProgID，例如 "SourceCode.Python"
    :param template: 模板文件路径
    """

    if not extension.startswith("."):
        extension = "." + extension

    if prog_id is None:
        prog_id = f"Zhang.{extension.lstrip('.')}"

    # 1. 注册扩展名对应 ProgID
    reg_reader.reg_write(f"HKEY_CLASSES_ROOT\\{extension}", "", "REG_SZ", prog_id)

    # 2. 创建 ShellNew
    shell_new_path = f"HKEY_CLASSES_ROOT\\{extension}\\ShellNew"

    if template:
        reg_reader.reg_write(shell_new_path, "FileName", "REG_SZ", template)
    else:
        reg_reader.reg_write(shell_new_path, "NullFile", "REG_SZ", "")

    # 3. 创建 ProgID 描述
    reg_reader.reg_write(f"HKEY_CLASSES_ROOT\\{prog_id}", "", "REG_SZ", title)

    return prog_id


def create_zhang_shell_new():
    try:
        create_shell_new(
            ".docx", "Word文档(docx)", template=f"{NewTemplate_dir}\\template.docx"
        )
        create_shell_new(
            ".pptx",
            "PowerPoint文档(pptx)",
            template=f"{NewTemplate_dir}\\template.pptx",
        )
        create_shell_new(
            ".xlsx", "Excel文档(xlsx)", template=f"{NewTemplate_dir}\\template.xlsx"
        )
        create_shell_new(
            ".bat", "批处理文件(bat)", template=f"{NewTemplate_dir}\\template.bat"
        )
        create_shell_new(
            ".ps1", "PowerShell文件(ps1)", template=f"{NewTemplate_dir}\\template.ps1"
        )
        create_shell_new(".md", "MarkDown(md)")
        create_shell_new(".txt", "文本文档(txt)")
    except:
        pass


def block_all_update():
    """
    扫描注册表和任务计划，禁用所有包含更新相关关键字的服务/计划
    """
    logger.log("[更新禁用]正在扫描和禁用所有更新相关服务、计划")
    try:
        windows_update_blocker.block_windows_update()
    except:
        pass
    try:
        task_update_scanner.disable_update_tasks()
    except:
        pass


def set_BLESync_storage_path(ini_path: str, storage_path: str) -> None:
    with open(ini_path, "r", encoding="utf-8") as f:
        lines = f.readlines()

    in_blesync = False
    modified = False

    for i, line in enumerate(lines):
        stripped = line.strip()

        # 进入 [BLESync] 节
        if stripped.startswith("[") and stripped.endswith("]"):
            in_blesync = stripped.lower() == "[blesync]"
            continue

        # 在 [BLESync] 中修改 StoragePath
        if in_blesync and stripped.lower().startswith("storagepath="):
            newline = "\n" if line.endswith("\n") else ""
            lines[i] = f"StoragePath={storage_path}{newline}"
            modified = True
            break

    if not modified:
        raise ValueError("INI 文件中未找到 [BLESync] 节或 StoragePath 配置项")

    with open(ini_path, "w", encoding="utf-8") as f:
        f.writelines(lines)


def create_kaspersky_whitelist(datadir, systemdriver, force=False):
    """
    生成卡巴斯基排除项导入 CSV 与配置导入 CFG。

    datadir       --> 数据盘符，单个字母即可，例如 "D"
    systemdriver  --> 系统盘符，单个字母即可，例如 "C"
    force         --> 为 True 时覆盖已存在的导入文件

    写入路径固定使用 main_paths 中的 KasperskyCSV / KasperskyCFG，
    CFG 以 KasperskyCFGTemplate 为模板，不接收任意路径。
    返回 (csv_ok, cfg_ok, 排除项条目数)
    """

    def drive_letter(value, fallback):
        text = str(value or "").strip().strip('"')
        if not text or not text[0].isalpha():
            return fallback
        if len(text) > 1 and text[1] not in (":", "\\", "/"):
            return fallback
        return text[0].upper()

    def normal_path(path):
        text = os.path.normpath(str(path))
        if len(text) > 1 and text[1] == ":":
            text = text[0].upper() + text[1:]
        return text

    def dir_mask(path):
        text = normal_path(path)
        return text if text.endswith("\\") else text + "\\"

    def file_mask(path):
        return normal_path(path)

    def raw_dir(path):
        text = str(path)
        return text if text.endswith("\\") else text + "\\"

    def checked_target(value, root):
        target = os.path.abspath(str(value))
        root_path = os.path.abspath(str(root))
        try:
            inside = os.path.commonpath(
                [os.path.normcase(target), os.path.normcase(root_path)]
            ) == os.path.normcase(root_path)
        except ValueError:
            inside = False
        if not inside or ".." in os.path.relpath(target, root_path).split(os.sep):
            raise ValueError("目标路径不在允许目录内:" + target)
        return target

    data_drive = drive_letter(datadir, drive_letter(SystemDir, "C"))
    system_drive = drive_letter(systemdriver, drive_letter(SystemDir, "C"))
    windows_root = WindowsDir or (system_drive + ":\\Windows")
    protect_root = ProtectDir or (windows_root + "\\Protect\\")

    csv_file = checked_target(KasperskyCSV, protect_root)
    cfg_file = checked_target(KasperskyCFG, protect_root)
    template_file = checked_target(KasperskyCFGTemplate, protect_root)
    cfg_possible = bool(cfg_file) and os.path.isfile(template_file)

    if (
        not force
        and not os.path.isfile(force_out_files)
        and os.path.isfile(csv_file)
        and ((not cfg_possible) or os.path.isfile(cfg_file))
    ):
        logger.log("[卡巴斯基]排除项导入文件已存在,跳过生成")
        return (True, os.path.isfile(cfg_file), 0)

    def xml_unescape(value):
        text = str(value)
        text = text.replace("&#x20;", " ")
        text = text.replace("&quot;", '"').replace("&gt;", ">").replace("&lt;", "<")
        return text.replace("&amp;", "&")

    # 模板里已有的排除项保留，只有与本次策略冲突的整体目录在合并时剔除
    template_text = ""
    template_rules = []
    if cfg_possible:
        try:
            with open(
                template_file,
                "r",
                encoding="utf-8",
                errors="surrogateescape",
                newline="",
            ) as handle:
                template_text = handle.read()
            rule_block = re.search(r"<fileRules>(.*?)</fileRules>", template_text, re.S)
            if rule_block:
                for item in re.findall(
                    r"<item_\d+.*?</item_\d+>", rule_block.group(1), re.S
                ):
                    obj = re.search(r'<object\b[^>]*\bmask="([^"]*)"', item)
                    verdict = re.search(r'\bverdict_mask="([^"]*)"', item)
                    triggers = re.search(r'\btriggers="([^"]*)"', item)
                    if not obj:
                        continue
                    mask_value = xml_unescape(obj.group(1))
                    verdict_value = xml_unescape(verdict.group(1)) if verdict else ""
                    trigger_value = triggers.group(1) if triggers else "1"
                    if trigger_value == "2":
                        template_rules.append(("*", verdict_value))
                    elif mask_value:
                        template_rules.append((mask_value, verdict_value or "*"))
        except Exception as e:
            logger.log(f"[卡巴斯基]读取配置模板失败,仅生成项目排除项:{e}")
            template_text = ""
            cfg_possible = False

    entries = []
    seen = set()

    def add(obj, verdict="*"):
        text = str(obj)
        name = str(verdict or "*")
        key = (text.casefold(), name.casefold())
        if key in seen:
            return
        seen.add(key)
        entries.append((text, name))

    # 生产目录整体放行
    add(dir_mask(protect_root))
    add(file_mask(os.path.join(protect_root, "Protect.exe")))
    add(file_mask(os.path.join(protect_root, "Protect.exe")) + "//main")

    # Disable_Safety 等释放到 Windows 根目录的附属文件
    for name in (
        "disable_safety.bat",
        "uwd.exe",
        "install_wim_tweak.exe",
        "EfiGuard.7z",
        "StorageRedirect.exe",
        "iKun_Sound.wav",
        "WifiMobileToolBAT.bat",
        "WifiMobileToolPS.ps1",
    ):
        add(file_mask(os.path.join(windows_root, name)))
    add(dir_mask(os.path.join(windows_root, "EfiGuard")))

    # System32 下的覆写文件、任务文件夹与第三方驱动载荷
    system32 = os.path.join(windows_root, "System32")
    for name in (
        "Narrator.exe",
        "VoiceAccess.exe",
        "rdpwrap.dll",
        "rdpwrap.ini",
        "drivers\\etc\\hosts",
    ):
        add(file_mask(os.path.join(system32, name)))
    add(dir_mask(os.path.join(system32, "Npcap")))
    for name in ("npf.sys", "npcap.sys"):
        add(file_mask(os.path.join(system32, "drivers", name)))

    tasks_root = os.path.join(system32, "Tasks")
    add(dir_mask(os.path.join(tasks_root, "ZhangProtect")))
    add(dir_mask(os.path.join(tasks_root, "Microsoft", "Windows", "Zhang")))

    # RDP Wrapper 与 DGuardInstall(Laneye) 安装目标
    for program_files in (
        os.environ.get("ProgramFiles"),
        os.environ.get("ProgramFiles(x86)"),
    ):
        if program_files:
            add(dir_mask(os.path.join(program_files, "RDP Wrapper")))
            add(dir_mask(os.path.join(program_files, "Laneye")))
    for name in ("DGuardPcap.sys", "DGuardPcap64.sys", "LanEyeDefense.sys"):
        add(file_mask(os.path.join(system32, "drivers", name)))

    # 数据目录与 VeraCrypt 挂载卷中的对应目录
    for relative in ("Files\\Data", "Files\\Develop", "Important"):
        add(dir_mask(f"{data_drive}:\\{relative}"))
        add(
            raw_dir(
                "\\\\?\\GLOBALROOT\\Device\\VeraCryptVolume"
                + data_drive
                + "\\"
                + relative
            )
        )

    # 任务计划对象
    add("tsched:\\\\ZhangProtect\\")
    add("tsched:\\\\ZhangProtect\\*")
    add("tsched:\\\\Microsoft\\Windows\\Zhang\\")
    add("tsched:\\\\Microsoft\\Windows\\Zhang\\*")

    # 对象 + 威胁名组合
    add(
        file_mask(os.path.join(system32, "svchost.exe")),
        "PDM:Trojan.Win32.GenAutorunSchedulerTaskRun.c",
    )
    add(file_mask(os.path.join(system32, "Narrator.exe")), "Trojan.Multi.Accesstr.anr")
    add("tsched:\\\\ZhangProtect\\*", "HEUR:Trojan.Multi.Runner.c")
    add("tsched:\\\\ZhangProtect\\ErrorAutoFix", "HEUR:Trojan.Multi.Runner.c")

    # 全局威胁名排除
    for verdict in (
        "PDM:Trojan.Win32.GenAutorunSchedulerTaskRun.c",
        "HEUR:Trojan.Multi.Runner.c",
        "Trojan.Multi.Accesstr.anr",
        "VHO:Trojan.Win32.Convagent.gen",
        "not-a-virus:RemoteAdmin.Win32.RDPWrap.c",
        "not-a-virus:HEUR:RiskTool.Multi.WinDivert.gen",
        "HEUR:RiskTool.Multi.WinDivert.gen",
        "not-a-virus:HEUR:RiskTool.AndroidOS.Wapron.dkj",
    ):
        add("*", verdict)

    drop_prefixes = (
        f"{data_drive}:\\Files\\",
        f"{data_drive}:\\Storageredirect\\",
        "\\\\?\\GLOBALROOT\\Device\\VeraCryptVolume" + data_drive + "\\Files\\",
    )
    for mask_value, verdict_value in template_rules:
        if mask_value != "*" and any(
            mask_value.casefold().startswith(prefix.casefold())
            for prefix in drop_prefixes
        ):
            continue
        add(mask_value, verdict_value)

    csv_ok = False
    try:
        # 卡巴斯基原生导出格式：UTF-16LE + BOM，CRLF，分号分隔，9 列无表头
        lines = ["1;%s;%s;*;1;0;1;;1" % (obj, verdict) for obj, verdict in entries]
        csv_data = b"\xff\xfe" + ("\r\n".join(lines) + "\r\n").encode("utf-16-le")
        with open(csv_file, "wb") as handle:
            handle.write(csv_data)
            handle.flush()
            os.fsync(handle.fileno())
        csv_ok = True
        logger.log(f"[卡巴斯基]排除项CSV已生成:{csv_file} 条目数:{len(entries)}")
    except Exception as e:
        logger.log(f"[卡巴斯基]排除项CSV生成失败:{e}")

    cfg_ok = False
    if cfg_possible:
        try:
            if not template_text:
                raise ValueError("配置模板内容为空")

            def xml_attr(value):
                text = str(value)
                text = (
                    text.replace("&", "&amp;")
                    .replace("<", "&lt;")
                    .replace(">", "&gt;")
                    .replace('"', "&quot;")
                )
                return text.replace(" ", "&#x20;")

            rule_lines = ["<fileRules>"]
            for index, (obj, verdict) in enumerate(entries):
                if obj == "*":
                    triggers = "2"
                    mask = ""
                elif verdict == "*":
                    triggers = "1"
                    mask = obj
                else:
                    triggers = "3"
                    mask = obj
                rule_lines.append(
                    '    <item_%04d unique_id="679391196" triggers="%s" scope="0" verdict_mask="%s" verdict_path="" detect_type="0" detect_danger="0" description="" userTag="" enabled="1">'
                    % (index, triggers, xml_attr("" if verdict == "*" else verdict))
                )
                rule_lines.append(
                    '        <object unique_id="2898656857" mask="%s" recurse="1" />'
                    % xml_attr(mask)
                )
                rule_lines.append("        <task_list />")
                rule_lines.append(
                    '        <fileHash unique_id="636138305" hashType="0" hashData="" />'
                )
                rule_lines.append("    </item_%04d>" % index)
            rule_lines.append("</fileRules>")
            file_rules_block = "\r\n".join(rule_lines)

            text, count = re.subn(
                r"<fileRules>.*?</fileRules>",
                lambda match: file_rules_block,
                template_text,
                count=1,
                flags=re.S,
            )
            if count != 1:
                raise ValueError("模板中未找到 fileRules 节点")

            # 受信任应用程序：ProtectDir 下所有可执行载荷全组件放行
            extensions = {".exe", ".bat", ".cmd", ".ps1", ".vbs"}
            app_paths = []
            for current, _, filenames in os.walk(protect_root):
                for name in filenames:
                    if os.path.splitext(name)[1].lower() in extensions:
                        app_paths.append(os.path.join(current, name))
            app_paths.append(os.path.join(protect_root, "Protect.exe"))
            for extra in (
                os.path.join(windows_root, "StorageRedirect.exe"),
                os.path.join(windows_root, "uwd.exe"),
                os.path.join(windows_root, "install_wim_tweak.exe"),
                os.path.join(windows_root, "EfiGuard", "EfiDSEFix.exe"),
                os.path.join(windows_root, "EfiGuard", "BOOTICE.exe"),
                os.path.join(windows_root, "EfiGuard", "DiskGenius.exe"),
                os.path.join(system32, "Narrator.exe"),
                os.path.join(system32, "VoiceAccess.exe"),
            ):
                app_paths.append(extra)
            app_paths = sorted(
                set(file_mask(path) for path in app_paths), key=str.casefold
            )

            app_lines = []
            for index, path in enumerate(app_paths):
                app_lines.append(
                    '    <item_%04d unique_id="2847463670" enabled="1" path="%s" controlTriggersMask="12785" description="" userTag="" imageHash_initialized="0" appCheckMode="0" ruleUsageTriggersMask="1" />'
                    % (index, xml_attr(path))
                )
            app_block = "\r\n".join(app_lines)

            text, count = re.subn(
                r'(<item\s+name="exclude\.application_manager".*?<rules>)(.*?)(</rules>)',
                lambda match: match.group(1)
                + "\r\n"
                + app_block
                + "\r\n"
                + match.group(3),
                text,
                count=1,
                flags=re.S,
            )
            if count != 1:
                raise ValueError("模板中未找到 exclude.application_manager/rules 节点")

            # 网络与加密连接扫描的应用排除
            exclude_lines = ["<applicationExcludes>"]
            empty_hash = "0" * 64
            for index, path in enumerate(app_paths):
                exclude_lines.append(
                    '    <item_%04d unique_id="3093138574" enabled="1" description="ON">'
                    % index
                )
                exclude_lines.append(
                    '        <value unique_id="11389295" path="%s" hash="%s">'
                    % (xml_attr(path), empty_hash)
                )
                exclude_lines.append("            <ipEndpoints />")
                exclude_lines.append("        </value>")
                exclude_lines.append("    </item_%04d>" % index)
            exclude_lines.append("</applicationExcludes>")
            excludes_block = "\r\n".join(exclude_lines)

            text, count = re.subn(
                r"<applicationExcludes>.*?</applicationExcludes>",
                lambda match: excludes_block,
                text,
                count=1,
                flags=re.S,
            )
            if count != 1:
                raise ValueError("模板中未找到 applicationExcludes 节点")

            # 关闭扫描加密连接：decodeMode 0=不扫描
            text, count = re.subn(
                r'(<sslControlSettings\b[^>]*\bdecodeMode=")1(")',
                r"\g<1>0\g<2>",
                text,
                count=1,
            )

            with open(cfg_file, "wb") as handle:
                handle.write(text.encode("utf-8", errors="surrogateescape"))
                handle.flush()
                os.fsync(handle.fileno())
            cfg_ok = True
            logger.log(
                f"[卡巴斯基]配置CFG已生成:{cfg_file} 受信任程序:{len(app_paths)} 加密连接扫描:关闭"
            )
        except Exception as e:
            logger.log(f"[卡巴斯基]配置CFG生成失败:{e}")
    else:
        logger.log(f"[卡巴斯基]未找到配置模板,跳过CFG生成:{template_file}")

    return (csv_ok, cfg_ok, len(entries))
