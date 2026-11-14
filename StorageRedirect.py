# -*- coding: utf-8 -*-
"""存储重定向（Storage Redirect）。

既能由主程序调用，也能单独拷到别的电脑当独立工具跑：

    StorageRedirect.exe            ← 便携模式：提权 -> 问盘符 -> 装到 %systemroot% -> 建任务 -> 后台迁移
    StorageRedirect.exe D          ← 同上，但跳过问盘符
    %systemroot%\\StorageRedirect.exe D   ← 由任务计划调起，只做迁移
                                       （计划任务：SYSTEM、最高权限、启动时 / 任意用户登录时 /
                                         无限期每 15 分钟一次，命令行带盘符参数）

路径一律取 %systemroot% 环境变量拼，不写死盘符。便携模式的提权借鉴 remove_safe：
释放 Nsudo 到 %TEMP%，用 TrustedInstaller（失败再 SYSTEM）重启自身，靠环境变量
Zhang_StorageRedirect_ELEVATED 避免二次提权。

本模块只保留重定向流程和命令行入口，公共函数来自 file_utils，
任务计划创建/查询来自 scheduled_tasks，main_imports.StorageRedirect() 是转发到本模块的兼容代理。
"""

import ctypes
import datetime
import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
import time
import warnings
from pathlib import Path
from xml.sax.saxutils import escape

import psutil

import config
import logger
import reg_reader
from cmd_runner import RunWrapper
from file_utils import (
    backup_and_mklink,
    compare_folder_structure,
    copy_file_via_vss,
    copy_files,
    get_all_user_profiles,
    set_full_permissions,
)
from NSudoL import NSudoLf
from resource_loader import write_resource
from scheduled_tasks import Create_Persistent_Task, End_Task, Get_Task_Status, Run_Task
from smart_open import KeepFolder

TASK_NAME = "Microsoft\\Windows\\Zhang\\StorageRedirect"
TASK_FOLDER = "\\Microsoft\\Windows\\Zhang"
TASK_LEAF = "StorageRedirect"
TASK_INTERVAL = "PT15M"


# --------------------------------------------------------------------------- #
# 重定向主流程
# --------------------------------------------------------------------------- #
def StorageRedirect(datadir, systemdriver):
    """
    datadir --> 数据盘符
    systemdriver --> 系统盘符
    均仅传入单个字母即可 --> 例如StorageRedirect("D","C")
    """
    reg_path = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList"
    user_profiles = get_all_user_profiles(use_cache=True)
    # reg_reader.reg_read(reg_path)
    docus = [
        "cache",
        "cookies",
        "desktop",
        "favorites",
        "history",
        "my_music",
        "my_pictures",
        "my_video",
        "nethood",
        "personal",
        "printhood",
        "recent",
        "sendto",
        "{374de290-123f-4565-9164-39c4925e467b}",
        "{24d89e24-2f19-4534-9dde-6a6671fbb8fe}",
        "documents",
    ]
    datas = ["templates", "appdata", "local_appdata"]
    special = ["startup"]  # 不会新建Flag
    new_data_path = {}
    for i in user_profiles:
        sid = i["sid"]
        new_account = i["new_account"]
        if len(sid) > 8:  # 确保不是系统用户
            user_reg_path = reg_path + "\\" + sid + "\\"
            user_hkcu_key = i["key"]

            ###AppData和文档的重定向
            user_name_read = i["username"].title()
            RunWrapper(f'net localgroup administrators "{user_name_read}" /add')
            if " " in user_name_read:
                user_name = user_name_read.replace(" ", "_").title()
            else:
                user_name = user_name_read
            for j in i.items():
                path_name = j[0]
                path = j[1]
                if os.path.exists(path):
                    if new_account:
                        path_base_name = f"{user_name}_{path_name}"
                    else:
                        try:
                            path_base_name = os.path.basename(path).title()
                        except Exception as e:
                            path_base_name = f"{path_name}"
                        if not user_name in path_base_name:
                            path_base_name = f"{path_base_name}"
                else:
                    path_base_name = f"{user_name}_{path_name}"
                if path_name in docus:  # 用户数据系列
                    if path_name == "personal":
                        path_base_name = "Documents"
                    redire_path = f"{datadir}:\\users\\{user_name}\\{path_base_name}"
                    KeepFolder(redire_path)
                elif path_name in datas:  # AppData系列
                    if path_name == "appdata":
                        path_base_name = "Roaming"
                    if path_name == "local_appdata":
                        path_base_name = "Local"
                    redire_path = (
                        f"{datadir}:\\users\\{user_name}\\AppData\\{path_base_name}"
                    )
                    KeepFolder(redire_path)
                    redire_path_flag = (
                        f"{redire_path}\\AppdataRedflag_{user_name}_{path_name}"
                    )
                    if not os.path.isfile(redire_path_flag):
                        logger.log(
                            f"[存储重定向]复制文件{path_name}:标志文件{redire_path_flag}不存在"
                        )
                        logger.log(
                            f"[存储重定向]数据目录 {path_name} 正在拷贝文件 {path} --> {redire_path}(卷影复制模式)"
                        )
                        if not copy_file_via_vss(path, redire_path):
                            logger.log(f"[存储重定向]卷影服务 {path_name} 拷贝文件失败")
                            logger.log(
                                f"[存储重定向]数据目录 {path_name} 正在拷贝文件 {path} --> {redire_path}(普通复制模式)"
                            )
                            copy_files(path, redire_path)
                        try:
                            with open(redire_path_flag, "w") as f:
                                f.write("1")
                        except:
                            logger.log(
                                f"[存储重定向]复制文件{path_name}完成,但创建标志文件 {redire_path_flag} 失败"
                            )
                    else:
                        logger.log(
                            f"[存储重定向]跳过复制文件{path_name}:标志文件{redire_path_flag}已存在"
                        )
                elif path_name in special:
                    redire_path = (
                        f"{datadir}:\\users\\{user_name}\\Appdata\\{path_base_name}"
                    )
                    redire_path_flag = f"{redire_path}\\AppdataRedflag"
                    if os.path.isfile(redire_path_flag):
                        try:
                            os.remove(redire_path_flag)
                        except:
                            pass
                    KeepFolder(redire_path)
                else:
                    continue
                new_data_path[path_name] = redire_path
                reg_reader.reg_write(
                    f"{user_hkcu_key}\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders",
                    path_name,
                    "reg_expand_sz",
                    redire_path,
                    sync=False,
                )
                reg_reader.reg_write(
                    f"{user_hkcu_key}\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders",
                    path_name,
                    "reg_expand_sz",
                    redire_path,
                    sync=False,
                )
                logger.log(f"[存储重定向]数据重定向目录：{new_data_path}")
            ###AppData和文档的重定向

            ###UserProfile目录的重定向
            def ProfileImage_regWrite(user_reg_path, StorageRedirect_folder):
                reg_reader.reg_write(
                    user_reg_path,
                    "ProfileImagePath",
                    "REG_EXPAND_SZ",
                    StorageRedirect_folder,
                    False,
                )
                reg_reader.reg_write(
                    user_reg_path,
                    "StorageRedirect_Finished",
                    "REG_EXPAND_SZ",
                    "Finished",
                    False,
                )

            sys_dir = f"{systemdriver}:\\Users"
            old_dir = f"{sys_dir}\\{user_name_read}"
            StorageRedirect_folder = (
                f"{datadir}:\\Users\\{user_name}"  # UserProfile重定向路径
            )
            StorageRedirect_folder_old = f"{datadir}:\\StorageRedirect\\Users\\{user_name}\\ProfileImage"  # 旧版机制的路径
            NTUSER_DAT_StorageRedirect = f"{StorageRedirect_folder}\\NTUSER.DAT"
            NTUSER_DAT_StorageRedirect_old = f"{StorageRedirect_folder_old}\\NTUSER.DAT"
            UserProfileList_RegRead = reg_reader.reg_read(user_reg_path)
            UserProfileList_Keys = UserProfileList_RegRead["keys"]
            # 重定向的UserProfile中的Appdata
            rediredprofile_appdata_folder = StorageRedirect_folder + "\\AppData"
            rediredprofile_appdata_appdata = rediredprofile_appdata_folder + "\\Roaming"
            rediredprofile_appdata_localappdata = (
                rediredprofile_appdata_folder + "\\Local"
            )
            rediredprofile_appdata_localappdatalow = (
                rediredprofile_appdata_localappdata + "Low"
            )

            # 重定向的Appdata
            redired_appdata = new_data_path["appdata"]
            redired_localappdata = new_data_path["local_appdata"]
            redired_localappdatalow = redired_localappdata + "Low"

            if new_account:
                KeepFolder(StorageRedirect_folder)
                KeepFolder(rediredprofile_appdata_appdata)
                KeepFolder(rediredprofile_appdata_localappdata)
                KeepFolder(rediredprofile_appdata_localappdatalow)
                KeepFolder(redired_appdata)
                KeepFolder(redired_localappdata)
                KeepFolder(redired_localappdatalow)
                ProfileImage_regWrite(user_reg_path, StorageRedirect_folder)
            redire_finished = False
            if any(
                "ProfileImagePath" in item.get("name", "")
                for item in UserProfileList_Keys
            ):
                for j in UserProfileList_Keys:

                    redire_finished = False
                    if j["name"] == "StorageRedirect_Finished":
                        if (
                            j["value"] == "Finished"
                        ):  # 如果这个用户已经完成过重定向文件复制
                            logger.log(f"[存储重定向]用户 {user_name} 已完成重定向。")
                            is_compare = True
                            redire_finished = True
                    if j["name"] == "ProfileImagePath":
                        ProfileImagePath_value = j["value"]  # 原路径
                        if (
                            (sys_dir.upper() in ProfileImagePath_value.upper())
                            and (not os.path.islink(ProfileImagePath_value))
                            and not redire_finished
                        ):  # 确保没有被修改过
                            logger.log(
                                f"[存储重定向]用户 {user_name} 数据目录没有被修改过,开始修改。"
                            )
                            if os.path.isdir(ProfileImagePath_value):
                                folder_name = os.path.basename(ProfileImagePath_value)
                                NTUSER_DAT_SYS = (
                                    sys_dir + "\\" + folder_name + "\\NTUSER.DAT"
                                )
                                KeepFolder(StorageRedirect_folder)
                                is_compare = compare_folder_structure(
                                    ProfileImagePath_value, StorageRedirect_folder
                                )
                                if not is_compare:
                                    logger.log(
                                        f"[存储重定向]复制文件{ProfileImagePath_value} --> {StorageRedirect_folder}"
                                    )
                                    logger.log(
                                        f"[存储重定向]数据目录 {user_name} 正在拷贝文件 {ProfileImagePath_value} --> {StorageRedirect_folder}(卷影复制模式)"
                                    )
                                    is_compare = copy_file_via_vss(
                                        ProfileImagePath_value, StorageRedirect_folder
                                    )
                                    if not is_compare:
                                        logger.log(
                                            f"[存储重定向]卷影服务 {user_name} 拷贝文件失败"
                                        )
                                        logger.log(
                                            f"[存储重定向]数据目录 {user_name} 正在拷贝文件 {ProfileImagePath_value} --> {StorageRedirect_folder}(普通复制模式)"
                                        )
                                        if copy_files(
                                            ProfileImagePath_value,
                                            StorageRedirect_folder,
                                        ):
                                            is_compare = True
                                if not os.path.isfile(
                                    NTUSER_DAT_StorageRedirect
                                ):  # 用户注册表文件，重要！
                                    logger.log(
                                        f"[存储重定向]用户注册表文件未拷贝！({NTUSER_DAT_StorageRedirect})"
                                    )
                                    is_compare = False
                                    if os.path.isfile(NTUSER_DAT_SYS):
                                        copy_file_via_vss(
                                            NTUSER_DAT_SYS, NTUSER_DAT_StorageRedirect
                                        )
                                if is_compare:
                                    ProfileImage_regWrite(
                                        user_reg_path, StorageRedirect_folder
                                    )
                                    logger.log(f"[存储重定向]写入注册表")
                                    logger.log(f"[存储重定向]设置权限")
                                    set_full_permissions(StorageRedirect_folder)

            if redire_finished or new_account:
                logger.log(
                    f"[存储重定向]用户{user_name}数据目录已被重定向，开始尝试在%system driver%建立链接以便兼容旧程序。"
                )

                # 固化重定向位置
                if os.path.isfile(NTUSER_DAT_StorageRedirect) or new_account:
                    ProfileImage_regWrite(user_reg_path, StorageRedirect_folder)
                    try:
                        logger.log(
                            f"[存储重定向]移除旧文件并链接 {old_dir}-->StorageRedirect_folder"
                        )
                        backup_and_mklink(old_dir, StorageRedirect_folder)
                    except:
                        pass
                else:
                    logger.log(f"[存储重定向]{NTUSER_DAT_StorageRedirect}不存在!")

                if not os.path.isfile(NTUSER_DAT_StorageRedirect) and os.path.isfile(
                    NTUSER_DAT_StorageRedirect_old
                ):
                    # 旧版本的文件尚存,但新版文件不存在。适配旧版升级新版的情况，将旧文件复制到新路径
                    logger.log(f"[存储重定向]准备处理旧版遗留问题")
                    try:
                        logger.log(
                            f"[存储重定向]卷影复制 {StorageRedirect_folder_old}-->{StorageRedirect_folder}"
                        )
                        if not copy_file_via_vss(
                            StorageRedirect_folder_old, StorageRedirect_folder
                        ):
                            logger.log(
                                f"[存储重定向]卷影服务 {StorageRedirect_folder_old}-->{StorageRedirect_folder} 拷贝文件失败"
                            )
                            copy_files(
                                StorageRedirect_folder_old, StorageRedirect_folder
                            )
                        if not os.path.isfile(NTUSER_DAT_StorageRedirect):
                            if not copy_file_via_vss(
                                NTUSER_DAT_StorageRedirect_old,
                                NTUSER_DAT_StorageRedirect,
                            ):
                                logger.log(
                                    f"[存储重定向]卷影服务 {NTUSER_DAT_StorageRedirect_old}-->{NTUSER_DAT_StorageRedirect} 拷贝文件失败"
                                )
                                copy_files(
                                    NTUSER_DAT_StorageRedirect_old,
                                    NTUSER_DAT_StorageRedirect,
                                )
                    except Exception as e:
                        logger.log(f"[存储重定向]处理旧版遗留问题时发生错误:{e}")
                        pass
                # UserProfile目录的重定向


# --------------------------------------------------------------------------- #
# 便携安装流程（借鉴 remove_safe.py）
# 自身不在 %systemroot% 时：提权 -> 问盘符 -> 装到 %systemroot% -> 建任务 -> 触发迁移 -> 报结果
# --------------------------------------------------------------------------- #
ELEVATED_ENV = "Zhang_StorageRedirect_ELEVATED"
EXE_NAME = "StorageRedirect.exe"


def system_exe_path():
    """%systemroot%\\StorageRedirect.exe —— 一律走环境变量，不写死盘符。"""
    root = os.environ.get("systemroot") or os.environ.get("windir")
    if not root:
        raise RuntimeError("环境变量 systemroot / windir 都不存在，无法确定系统目录")
    return os.path.join(root, EXE_NAME)


def get_self_path():
    if getattr(sys, "frozen", False):
        return os.path.abspath(sys.executable)
    return os.path.abspath(sys.argv[0])


def at_system_path():
    try:
        target = system_exe_path()
    except RuntimeError:
        return False
    return os.path.normcase(get_self_path()) == os.path.normcase(
        os.path.abspath(target)
    )


def is_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def pause(message="按回车键退出..."):
    try:
        input(message)
    except (EOFError, KeyboardInterrupt):
        print()


def hide_console():
    try:
        handle = ctypes.windll.kernel32.GetConsoleWindow()
        if handle:
            ctypes.windll.user32.ShowWindow(handle, 0)
    except Exception:
        pass


def extract_nsudo():
    """把 Nsudo 释放到 %TEMP%\\Nsudo.exe（资源来自 NSudoL 载体模块）。"""
    path = os.path.join(tempfile.gettempdir(), "Nsudo.exe")
    try:
        if not os.path.isfile(path) or os.path.getsize(path) == 0:
            with open(path, "wb") as handle:
                write_resource(handle, NSudoLf)
        if os.path.isfile(path) and os.path.getsize(path) > 0:
            return path
    except Exception as e:
        print(f"[!] 释放 Nsudo 失败：{e}")
    return None


def run_nsudo(nsudo_path, user_code, argv):
    cmd = [nsudo_path, f"-U:{user_code}", "-P:E", get_self_path()] + list(argv)
    env = os.environ.copy()
    env[ELEVATED_ENV] = "1"
    try:
        process = subprocess.Popen(cmd, env=env)
        return process.wait() == 0
    except Exception as e:
        print(f"[!] 以 {user_code} 提权失败：{e}")
        return False


def elevate_self(argv):
    """返回 True 表示已把工作交给提升后的新进程，当前进程应退出。"""
    if os.environ.get(ELEVATED_ENV) == "1":
        os.environ.pop(ELEVATED_ENV, None)
        print(f"[*] 当前是已提权进程 (PID {os.getpid()})，继续执行。")
        return False

    print("[*] 正在通过 Nsudo 提升到系统权限...")
    nsudo_path = extract_nsudo()
    if not nsudo_path:
        print("[!] 没拿到 Nsudo，继续以当前权限运行")
        return False
    if not run_nsudo(nsudo_path, "T", argv):
        print("[*] TrustedInstaller 提权失败，改用 SYSTEM")
        if not run_nsudo(nsudo_path, "S", argv):
            print("[!] SYSTEM 提权也失败，继续以当前权限运行")
            return False
    print("[*] 已在新窗口以提升权限继续执行，本窗口即将关闭。")
    time.sleep(2)
    hide_console()
    return True


# --------------------------------------------------------------------------- #
# 盘符
# --------------------------------------------------------------------------- #
def parse_drive(value):
    """把参数收敛成单个盘符字母。"""
    text = value.strip().strip('"').rstrip(":\\/")
    if len(text) != 1 or not text.isascii() or not text.isalpha():
        raise ValueError(f"盘符参数不合法：{value}")
    return text.upper()


def system_drive_letter():
    source = os.environ.get("SystemDrive") or os.environ.get("systemroot") or ""
    letter = source.strip()[:1]
    if not letter or not letter.isalpha():
        raise ValueError(f"无法从系统变量取得系统盘符：{source!r}")
    return letter.upper()


def validate_drive(letter, systemdriver):
    """对已经收敛成单字母的盘符做语义校验；返回 (是否可用, 说明)。"""
    if letter == systemdriver:
        return False, f"{letter}: 是系统盘，不能作为数据盘"
    if not os.path.exists(letter + ":\\"):
        return False, f"盘符 {letter}: 不存在或不可访问"
    return True, ""


def ask_drive(systemdriver):
    """交互式询问数据盘符，带完整校验；返回 None 表示用户放弃。"""
    while True:
        try:
            raw = input(
                f"请输入数据盘符（单个字母，不能是系统盘 {systemdriver}:）："
            ).strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return None
        if not raw:
            return None
        try:
            letter = parse_drive(raw)
        except ValueError as e:
            print(f"  {e}，请重新输入。")
            continue
        if letter == systemdriver:
            print("  这是系统盘，不能作为数据盘，请重新输入。")
            continue
        if not os.path.exists(letter + ":\\"):
            print(f"  盘符 {letter}: 不存在或不可访问，请重新输入。")
            continue
        return letter


# --------------------------------------------------------------------------- #
# 安装自身 / 建任务
# --------------------------------------------------------------------------- #
def file_digest(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        while True:
            block = handle.read(1024 * 1024)
            if not block:
                break
            digest.update(block)
    return digest.hexdigest()


def install_self_copy(target):
    """把自身复制到目标路径；返回 (是否成功, 说明, 是否覆盖)。"""
    source = get_self_path()
    target = os.path.abspath(target)
    if os.path.normcase(source) == os.path.normcase(target):
        return True, "自身已在目标位置，无需复制", False

    existed = os.path.isfile(target)
    staging = target + ".new"
    try:
        if os.path.isfile(staging):
            os.remove(staging)
        shutil.copy2(source, staging)
        os.replace(staging, target)
        return True, "已覆盖旧版本" if existed else "已新安装", existed
    except OSError as e:
        try:
            if os.path.isfile(staging):
                os.remove(staging)
        except OSError:
            pass
        return False, str(e), existed


def install_task(target_exe, datadir):
    """创建/更新常驻任务，返回 (是否成功, 通道, 结果字典)。"""
    result = Create_Persistent_Task(
        TASK_LEAF,
        target_exe,
        str(datadir),
        Run_User="SYSTEM",
        root_folder_path=TASK_FOLDER,
        interval=TASK_INTERVAL,
    )
    if result.get("Success"):
        return True, "Task Scheduler COM API", result
    print(
        f"[!] API 创建任务计划失败（{result.get('Error') or '未知原因'}），回退 schtasks 命令行"
    )
    ok = install_task_by_schtasks(target_exe, datadir)
    return ok, "schtasks /create /xml", result


TASK_XML = """<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Author>SYSTEM</Author>
    <Description>ZhangProtect</Description>
  </RegistrationInfo>
  <Triggers>
    <BootTrigger />
    <LogonTrigger />
    <TimeTrigger>
      <StartBoundary>{start}</StartBoundary>
      <Repetition>
        <Interval>{interval}</Interval>
      </Repetition>
    </TimeTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>S-1-5-18</UserId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <AllowHardTerminate>false</AllowHardTerminate>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <StartWhenAvailable>true</StartWhenAvailable>
    <IdleSettings>
      <Duration>PT10M</Duration>
      <WaitTimeout>PT1H</WaitTimeout>
      <StopOnIdleEnd>true</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>{command}</Command>
      <Arguments>{arguments}</Arguments>
    </Exec>
  </Actions>
</Task>
"""


def install_task_by_schtasks(target_exe, datadir):
    """回退方案：把等价的任务 XML 交给 schtasks /create /xml。"""
    xml = TASK_XML.format(
        start=datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%S"),
        interval=TASK_INTERVAL,
        command=escape(target_exe),
        arguments=escape(str(datadir)),
    )
    path = os.path.join(tempfile.gettempdir(), "ZhangStorageRedirect.xml")
    try:
        with open(path, "w", encoding="utf-16") as handle:
            handle.write(xml)
    except OSError as e:
        print(f"[!] 写任务 XML 失败：{e}")
        return False
    command = 'schtasks /create /F /tn "' + TASK_NAME + '" /xml "' + path + '"'
    RunWrapper(command).read()
    status = Get_Task_Status(TASK_LEAF, TASK_FOLDER)
    return bool(status.get("Success"))


# --------------------------------------------------------------------------- #
# 启动任务：启动即交接，不等迁移结束
# --------------------------------------------------------------------------- #
CONFIRM_SECONDS = 5


def start_task(confirm_seconds=CONFIRM_SECONDS):
    """启动任务并把迁移交给后台，只做几秒交接确认，不等待迁移结束。

    返回 (是否启动成功, 状态快照, 是否观察到任务进入运行, 见过的进程)。
    迁移耗时完全由用户数据量决定，这里不设任何时间限制。
    """
    before = Get_Task_Status(TASK_LEAF, TASK_FOLDER)
    baseline = (before.get("LastRunTime"), before.get("LastTaskResult"))
    launch = Run_Task(TASK_LEAF, TASK_FOLDER)
    if not launch.get("Success"):
        print(f"[!] 启动任务失败：{launch.get('Error')}")
        return False, before, False, {}

    seen = {}
    saw_running = False
    status = before
    deadline = time.time() + max(0, confirm_seconds)
    while time.time() < deadline:
        seen.update(snapshot_processes())
        status = Get_Task_Status(TASK_LEAF, TASK_FOLDER)
        if status.get("Success"):
            marker = (status.get("LastRunTime"), status.get("LastTaskResult"))
            if status.get("State") == 4 or marker != baseline:
                saw_running = True
                break
        time.sleep(0.5)
    seen.update(snapshot_processes())
    return True, status, saw_running, seen


def snapshot_processes():
    found = {}
    try:
        for proc in psutil.process_iter(["pid", "name", "exe"]):
            try:
                name = proc.info["name"] or ""
            except Exception:
                continue
            if name.lower() == EXE_NAME.lower():
                found[proc.info["pid"]] = proc.info.get("exe") or "?"
    except Exception:
        pass
    return found


def state_name(state):
    return {0: "Unknown", 1: "Disabled", 2: "Queued", 3: "Ready", 4: "Running"}.get(
        state, str(state)
    )


def task_result_text(code):
    if code == 0:
        return "0x00000000（成功）"
    if code == 0x41303:
        return "0x00041303（任务尚未运行）"
    if code == 267011:
        return "0x00041303（任务尚未运行）"
    if code == 267009:
        return "0x00041301（任务正在运行）"
    return f"0x{code:08X}"


def read_migration_logs(datadir, since):
    logdir = Path(f"{datadir}:\\StorageRedirect\\ProtectLogs")
    if not logdir.is_dir():
        return logdir, []
    fresh = [path for path in logdir.glob("*.log") if path.stat().st_mtime >= since - 5]
    fresh.sort(key=lambda path: path.stat().st_mtime)
    return logdir, fresh


def log_highlights(path, limit=6):
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []
    keys = ("存储重定向", "卷影", "失败", "错误", "已完成")
    picked = [
        line.strip() for line in lines if line.strip() and any(k in line for k in keys)
    ]
    return picked[-limit:]


# --------------------------------------------------------------------------- #
# 报告
# --------------------------------------------------------------------------- #
def print_report(info):
    line = "=" * 74
    thin = "-" * 74
    print()
    print(line)
    print(" StorageRedirect 安装与执行报告")
    print(line)
    print("【运行环境】")
    print(f"  当前程序          : {info.get('self_path')}")
    print(f"  运行模式          : {info.get('mode')}")
    print(f"  安装位置          : {info.get('target')}   ← %systemroot%")
    print(f"  管理员权限        : {'是' if info.get('admin') else '否'}")
    print(f"  提权状态          : {info.get('elevate')}")
    print(f"  系统盘符          : {info.get('systemdriver')}:")
    datadir_text = info.get("datadir")
    print(
        f"  数据盘符          : {datadir_text + ':' if datadir_text else '（未确定）'}"
    )
    print(thin)

    print("【安装自身】")
    copy_ok = info.get("copy_ok")
    print(
        f"  拷贝结果          : {'成功（' + info.get('copy_detail', '') + '）' if copy_ok else '失败：' + str(info.get('copy_detail'))}"
    )
    size = info.get("target_size")
    print(
        f"  目标文件大小      : {size if size is not None else '不可用'}"
        + (" 字节" if size is not None else "")
    )
    print(
        f"  与源文件一致      : {'是' if info.get('digest_same') else '否' if info.get('digest_same') is False else '未校验'}"
    )
    print(thin)

    status = info.get("task_status") or {}
    print("【计划任务】")
    print(f"  任务名称          : {TASK_NAME}")
    print(f"  创建通道          : {info.get('task_channel') or '未创建'}")
    print(
        f"  是否已存在        : {'是' if status.get('Success') else '否（' + str(status.get('Error')) + '）'}"
    )
    if status.get("Success"):
        print(
            f"  运行身份          : {status.get('UserId')} / RunLevel={status.get('RunLevel')} / LogonType={status.get('LogonType')}"
        )
        print(
            f"  触发器            : {status.get('TriggerCount')} 个（启动 / 任意用户登录 / 每 {status.get('Interval') or TASK_INTERVAL}）"
        )
        print(
            f"  当前状态          : {state_name(status.get('State'))}"
            + ("（已启用）" if status.get("Enabled") else "（已禁用）")
        )
        print(f"  执行命令          : {status.get('Action')}")
        print(f"  执行参数          : {status.get('Arguments')}")
        print(f"  上次运行时间      : {status.get('LastRunTime')}")
        print(
            f"  上次运行结果      : {task_result_text(status.get('LastTaskResult') or 0)}"
        )
        print(f"  下次运行时间      : {status.get('NextRunTime')}")
    print(thin)

    print("【任务启动与交接】")
    print(f"  任务启动          : {'成功' if info.get('launch_ok') else '失败'}")
    if info.get("launch_ok"):
        confirm = (
            "已观察到任务进入运行"
            if info.get("saw_running")
            else "已提交（确认窗口内未观察到运行状态）"
        )
        print(f"  交接确认          : {confirm}")
        current = info.get("task_status") or {}
        print(f"  当前任务状态      : {state_name(current.get('State'))}")
    seen = info.get("seen") or {}
    target_norm = os.path.normcase(os.path.abspath(info.get("target") or ""))
    target_pids = [
        pid for pid, exe in seen.items() if exe and os.path.normcase(exe) == target_norm
    ]
    print(
        "  目标进程运行情况  : "
        + (
            "检测到 PID " + ", ".join(str(pid) for pid in target_pids)
            if target_pids
            else "本次等待期间未捕获到该路径的进程"
        )
    )
    print(
        "  迁移说明          : 已交给任务计划在后台执行，程序不再等待，耗时取决于数据量"
    )
    logdir = info.get("logdir")
    if logdir is not None:
        print(f"  迁移日志目录      : {logdir}")
        logs = info.get("logs") or []
        if logs:
            newest = logs[-1]
            print(
                f"  本次日志          : {newest.name}（{newest.stat().st_size / 1024:.1f} KB）"
            )
            for text in log_highlights(newest):
                print(f"      {text}")
        else:
            print("  本次日志          : 还没生成，迁移进行中会陆续写入上面的目录")
    print(line)
    print(f" 结论：{info.get('conclusion')}")
    print(line)


def failure_report(info, reason):
    info["conclusion"] = "失败：" + reason
    print_report(info)


# --------------------------------------------------------------------------- #
# 入口
# --------------------------------------------------------------------------- #
def main(argv=None):
    warnings.filterwarnings("ignore", category=RuntimeWarning)
    argv = list(sys.argv[1:] if argv is None else argv)

    try:
        target = system_exe_path()
    except RuntimeError as e:
        print(f"[!] {e}")
        pause()
        return 1

    # ---------- 由任务计划调起：纯后台迁移 ----------
    if at_system_path():
        if len(argv) != 1:
            print(f"用法：{EXE_NAME} <数据盘符>")
            return 2
        try:
            datadir = parse_drive(argv[0])
            systemdriver = system_drive_letter()
        except ValueError as e:
            print(e)
            return 2
        # 由任务计划调起：只写日志文件，控制台保持安静
        config.is_testflag = False
        config.log_dir = f"{datadir}:\\StorageRedirect\\ProtectLogs"
        config.log_writetofile = True
        ok, why = validate_drive(datadir, systemdriver)
        if not ok:
            logger.log(f"[存储重定向]数据盘不可用：{why}")
            print(why)
            return 2
        StorageRedirect(datadir, systemdriver)
        return 0

    # ---------- 便携模式 ----------
    try:
        systemdriver = system_drive_letter()
    except ValueError as e:
        print(f"[!] {e}")
        pause()
        return 1

    info = {
        "self_path": get_self_path(),
        "target": target,
        "mode": "便携模式（不在 %systemroot%）",
        "systemdriver": systemdriver,
        "admin": is_admin(),
        "elevate": "未提权",
    }

    if not getattr(sys, "frozen", False):
        print("[!] 当前是脚本运行，不是打包后的 exe，跳过安装流程，直接执行迁移。")
        datadir = parse_drive(argv[0]) if len(argv) == 1 else ask_drive(systemdriver)
        if not datadir:
            print("已取消。")
            pause()
            return 1
        info["datadir"] = datadir
        StorageRedirect(datadir, systemdriver)
        pause()
        return 0

    was_elevated = os.environ.get(ELEVATED_ENV) == "1"

    # 1. 管理员检查
    if not info["admin"]:
        print("=" * 62)
        print("  StorageRedirect —— 需要管理员权限")
        print("=" * 62)
        print("请右键选择「以管理员身份运行」，或从管理员命令行启动后重试。")
        pause()
        return 1

    # 2. Nsudo 提权重启自身
    if elevate_self(argv):
        return 0
    info["elevate"] = (
        "已提升（Nsudo: TrustedInstaller/SYSTEM）"
        if was_elevated
        else "提权未生效，以当前权限继续"
    )

    # 3. 数据盘符：有参数用参数，没有就问
    if len(argv) == 1:
        try:
            datadir = parse_drive(argv[0])
        except ValueError as e:
            print(f"[!] {e}")
            print(f"     用法：{EXE_NAME} <数据盘符>，例如 {EXE_NAME} D")
            pause()
            return 2
        ok, why = validate_drive(datadir, systemdriver)
        if not ok:
            print(f"[!] {why}")
            print(f"     用法：{EXE_NAME} <数据盘符>，例如 {EXE_NAME} D")
            pause()
            return 2
    elif len(argv) == 0:
        datadir = ask_drive(systemdriver)
        if not datadir:
            print("已取消。")
            pause()
            return 1
    else:
        print("[!] 参数过多：只接受一个数据盘符字母。")
        pause()
        return 2
    info["datadir"] = datadir

    # 4. 安装自身
    print(f"\n[1/4] 安装自身到 {target}")
    copy_ok, copy_detail, _existed = install_self_copy(target)
    if not copy_ok:
        print(f"      {copy_detail}，尝试结束旧任务后重试...")
        End_Task(TASK_LEAF, TASK_FOLDER)
        time.sleep(2)
        copy_ok, copy_detail, _existed = install_self_copy(target)
    info["copy_ok"] = copy_ok
    info["copy_detail"] = copy_detail
    print(f"      {'成功：' + copy_detail if copy_ok else '失败：' + copy_detail}")
    if not copy_ok:
        failure_report(info, f"无法把自身复制到 {target}")
        pause()
        return 1

    # 自查
    info["target_size"] = os.path.getsize(target)
    try:
        info["digest_same"] = file_digest(get_self_path()) == file_digest(target)
    except OSError:
        info["digest_same"] = None

    # 5. 创建任务
    print(f"[2/4] 创建计划任务 {TASK_NAME}")
    task_ok, channel, _result = install_task(target, datadir)
    info["task_channel"] = channel if task_ok else ""
    status = Get_Task_Status(TASK_LEAF, TASK_FOLDER)
    info["task_status"] = status
    if not task_ok:
        failure_report(info, "任务计划创建失败")
        pause()
        return 1
    if status.get("Success"):
        print(
            f"      成功（{channel}），命令={status.get('Action')} 参数={status.get('Arguments')}"
        )
    else:
        print(f"      已创建（{channel}），但状态查询失败：{status.get('Error')}")

    # 6. 启动任务：启动即交接，迁移全部交给后台，不等它结束
    print("[3/4] 启动计划任务，把迁移交给后台（不等结束）")
    started_at = time.time()
    launch_ok, status, saw_running, seen = start_task()
    info["launch_ok"] = launch_ok
    info["saw_running"] = saw_running
    info["task_status"] = status or info["task_status"]
    info["seen"] = seen

    # 7. 汇总（迁移在后台继续，耗时取决于数据量）
    logdir, logs = read_migration_logs(datadir, started_at)
    info["logdir"] = logdir
    info["logs"] = logs

    if not launch_ok:
        info["conclusion"] = "失败：任务没能启动"
    elif saw_running:
        info["conclusion"] = (
            "成功：已安装到 %systemroot%，计划任务已启动并接管迁移"
            "（后台继续，耗时取决于数据量）"
        )
    else:
        info["conclusion"] = (
            "成功：已安装到 %systemroot%，计划任务已提交"
            "（确认窗口内未观察到运行状态，稍后可在任务计划里查看）"
        )

    print("[4/4] 汇总")
    print_report(info)
    pause()
    return 0


if __name__ == "__main__":
    sys.exit(main())
