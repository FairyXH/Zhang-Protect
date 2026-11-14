import os, sys, shutil
from tkinter import *
from tkinter import messagebox
import ctypes

import smart_open
from cmd_runner import RunWrapper


from main_imports import disable_quick_edit_mode

try:
    disable_quick_edit_mode()
except:
    pass


def install_zhangProtect():
    system_flag = system_entry.get()
    ip_flag = ip_entry.get()

    def show_err():
        messagebox.showerror("错误", "输入的盘符不存在或错误")

    if len(system_flag) in [1, 2]:
        if not ":" in system_flag:
            system_flag += ":"
        if not os.path.exists(system_flag) or not os.path.exists(
            "%s\\Windows" % system_flag
        ):
            show_err()
            return False
    else:
        show_err()
        return False
    if not os.path.isfile("ZhangProtect.exe"):
        messagebox.showerror("错误", "没有找到ZhangProtect.exe,无法使用PE安装")
        return False
    remove_freeze_info = Tk()
    remove_freeze_info.title("Zhang_PE工具箱")
    Label(remove_freeze_info, text="-" * 20 + "Zhang_PE工具箱" + "-" * 20).grid()
    Label(remove_freeze_info, text="创建批处理程序...").grid()
    with smart_open.smart_opens(
        "PE_Install.reg",
        "w",
    ) as f:
        f.write(run_reg)
    bat_file = "PE_Install_ZhangProtect.bat"
    with smart_open.smart_opens(
        bat_file,
        "w",
    ) as f:
        f.write(
            "@echo off"
            + chr(10)
            + "setlocal enabledelayedexpansion"
            + chr(10)
            + "cd /d "
            + chr(34)
            + "%~dp0"
            + chr(34)
            + ""
            + chr(10)
            + "if exist %1 (goto begin) else (goto end)"
            + chr(10)
            + "exit"
            + chr(10)
            + ":begin"
            + chr(10)
            + "echo 执行移除冰点还原"
            + chr(10)
            + "echo 备份SYSTEM注册表"
            + chr(10)
            + "mkdir regback"
            + chr(10)
            + "echo n|copy %1\\windows\\system32\\config\\SYSTEM regback\\SYSTEM /-Y"
            + chr(10)
            + "echo 备份SOFTWARE注册表"
            + chr(10)
            + "mkdir regback"
            + chr(10)
            + "echo n|copy %1\\windows\\system32\\config\\SOFTWARE regback\\SOFTWARE /-Y"
            + chr(10)
            + "echo 加载SYSTEM注册表"
            + chr(10)
            + "reg load HKLM\\SYSTEM1 %1\\windows\\system32\\config\\SYSTEM"
            + chr(10)
            + "echo 加载SOFTWARE注册表"
            + chr(10)
            + "reg load HKLM\\SOFTWARE1 %1\\windows\\system32\\config\\SOFTWARE"
            + chr(10)
            + "echo 修改相关注册表"
            + chr(10)
            + "regedit /s PE_Install.reg"
            + chr(10)
            + "reg add HKEY_LOCAL_MACHINE\\SOFTWARE1\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v EnableLUA /t REG_DWORD /d 0 /f"
            + chr(10)
            + "reg add HKEY_LOCAL_MACHINE\\SOFTWARE1\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v ConsentPromptBehaviorAdmin /t REG_DWORD /d 0 /f"
            + chr(10)
            + "reg add HKEY_LOCAL_MACHINE\\SOFTWARE1\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v PromptOnSecureDesktop /t REG_DWORD /d 0 /f"
            + chr(10)
            + "reg add HKEY_LOCAL_MACHINE\\SOFTWARE1\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v ConsentPromptBehaviorUser /t REG_DWORD /d 3 /f"
            + chr(10)
            + "reg add HKEY_LOCAL_MACHINE\\SOFTWARE1\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v EnableVirtualization /t REG_DWORD /d 0 /f"
            + chr(10)
            + "reg add HKEY_LOCAL_MACHINE\\SOFTWARE1\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v EnableInstallerDetection /t REG_DWORD /d 0 /f"
            + chr(10)
            + "reg add HKEY_LOCAL_MACHINE\\SOFTWARE1\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v ValidateAdminCodeSignatures /t REG_DWORD /d 0 /f"
            + chr(10)
            + "echo 卸载SYSTEM注册表"
            + chr(10)
            + "reg unload HKLM\\SYSTEM1"
            + chr(10)
            + "echo 卸载SOFTWARE注册表"
            + chr(10)
            + "reg unload HKLM\\SOFTWARE1"
            + chr(10)
            + "echo %0 > wtd"
        )
    Label(remove_freeze_info, text="执行批处理程序...").grid()
    RunWrapper("%s %s" % (bat_file, system_flag)).read()
    Label(remove_freeze_info, text="写入ZhangProtect").grid()
    system_protect_dir = "%s\\Protect\\" % ("%s\\Windows" % system_flag)
    system_protect_exe = system_protect_dir + "Protect.exe"
    Protect_PE_Install_bat = system_protect_dir + "Protect_PE_Install.bat"
    if not os.path.exists(system_protect_dir):
        os.mkdir(system_protect_dir)
    for i in ["ipcheck", "lowerlog", "keep_awake", "use_rdpwrap"]:
        with smart_open.smart_opens(system_protect_dir + i, "w") as f:
            f.write("1")
    if not ip_flag == "":
        with smart_open.smart_opens(
            system_protect_dir + "network_base_ip_txt.txt", "w"
        ) as f:
            f.write(ip_flag)
    with smart_open.smart_opens(
        Protect_PE_Install_bat,
        "w",
    ) as f:
        f.write(install_bat)
    shutil.copy("ZhangProtect.exe", system_protect_exe)
    Label(
        remove_freeze_info, text="ZhangProtect写入完毕，将在系统开机后自动安装"
    ).grid()
    messagebox.showinfo("完成", "写入完毕,ZhangProtect将在系统启动后自动安装")
    remove_freeze_info.destroy()
    Tk.mainloop(remove_freeze_info)
    return None


def remove_freeze():
    system_flag = system_entry.get()

    def show_err():
        messagebox.showerror("错误", "输入的盘符不存在或错误")

    if len(system_flag) in [1, 2]:
        if not ":" in system_flag:
            system_flag += ":"
        if not os.path.exists(system_flag) or not os.path.exists(
            "%s\\Windows" % system_flag
        ):
            show_err()
            return False
    else:
        show_err()
        return False
    remove_freeze_info = Tk()
    remove_freeze_info.title("Zhang_PE工具箱")
    Label(remove_freeze_info, text="-" * 20 + "Zhang_PE工具箱" + "-" * 20).grid()
    Label(remove_freeze_info, text="创建批处理程序...").grid()
    bat_file = "PE_Remove_DeepFrz.bat"
    with smart_open.smart_opens(
        bat_file,
        "w",
    ) as f:
        f.write(
            "@echo off"
            + chr(10)
            + "setlocal enabledelayedexpansion"
            + chr(10)
            + "cd /d "
            + chr(34)
            + "%~dp0"
            + chr(34)
            + ""
            + chr(10)
            + "if exist %1 (goto begin) else (goto end)"
            + chr(10)
            + "exit"
            + chr(10)
            + ":begin"
            + chr(10)
            + "echo 执行移除冰点还原"
            + chr(10)
            + "echo 备份SYSTEM注册表"
            + chr(10)
            + "mkdir regback"
            + chr(10)
            + "echo n|copy %1\\windows\\system32\\config\\SYSTEM regback\\SYSTEM /-Y"
            + chr(10)
            + "echo."
            + chr(10)
            + "echo 加载SYSTEM注册表"
            + chr(10)
            + "reg load HKLM\\SYSTEM1 %1\\windows\\system32\\config\\SYSTEM"
            + chr(10)
            + "echo."
            + chr(10)
            + "echo 删除DiskDrive过滤驱动0"
            + chr(10)
            + "set subkey=HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Control\\Class\\{4d36e967-e325-11ce-bfc1-08002be10318}"
            + chr(10)
            + "set valuename=LowerFilters"
            + chr(10)
            + "set delvalue=DfDiskLo"
            + chr(10)
            + "call :sub"
            + chr(10)
            + "echo."
            + chr(10)
            + "echo 删除DiskDrive过滤驱动1"
            + chr(10)
            + "set subkey=HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Control\\Class\\{4d36e967-e325-11ce-bfc1-08002be10318}"
            + chr(10)
            + "set valuename=UpperFilters"
            + chr(10)
            + "set delvalue=DeepFrz"
            + chr(10)
            + "call :sub"
            + chr(10)
            + "echo."
            + chr(10)
            + "echo 删除鼠标过滤驱动"
            + chr(10)
            + "set subkey=HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Control\\Class\\{4d36e96f-e325-11ce-bfc1-08002be10318}"
            + chr(10)
            + "set valuename=UpperFilters"
            + chr(10)
            + "set delvalue=DeepFrz"
            + chr(10)
            + "call :sub"
            + chr(10)
            + "echo."
            + chr(10)
            + "echo 删除键盘过滤驱动"
            + chr(10)
            + "set subkey=HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Control\\Class\\{4d36e96b-e325-11ce-bfc1-08002be10318}"
            + chr(10)
            + "set valuename=UpperFilters"
            + chr(10)
            + "set delvalue=DeepFrz"
            + chr(10)
            + "call :sub"
            + chr(10)
            + "echo."
            + chr(10)
            + "echo 删除Volume过滤驱动0"
            + chr(10)
            + "set subkey=HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Control\\Class\\{71a27cdd-812a-11d0-bec7-08002be2092f}"
            + chr(10)
            + "set valuename=UpperFilters"
            + chr(10)
            + "set delvalue=DeepFrz"
            + chr(10)
            + "call :sub"
            + chr(10)
            + "echo."
            + chr(10)
            + "echo 删除Volume过滤驱动1"
            + chr(10)
            + "set subkey=HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Control\\Class\\{71a27cdd-812a-11d0-bec7-08002be2092f}"
            + chr(10)
            + "set valuename=UpperFilters"
            + chr(10)
            + "set delvalue=FarSpace"
            + chr(10)
            + "call :sub"
            + chr(10)
            + "echo."
            + chr(10)
            + "echo 删除相关注册表"
            + chr(10)
            + "reg delete HKEY_LOCAL_MACHINE\\SYSTEM1\\ControlSet001\\Services\\DeepFrz /f"
            + chr(10)
            + "reg delete HKEY_LOCAL_MACHINE\\SYSTEM1\\ControlSet001\\Services\\DfDiskLo /f"
            + chr(10)
            + "reg delete HKEY_LOCAL_MACHINE\\SYSTEM1\\ControlSet001\\Services\\DFFilter /f"
            + chr(10)
            + "reg delete HKEY_LOCAL_MACHINE\\SYSTEM1\\ControlSet001\\Services\\DFServ /f"
            + chr(10)
            + "reg delete HKEY_LOCAL_MACHINE\\SYSTEM1\\ControlSet001\\Services\\FarDisk /f"
            + chr(10)
            + "reg delete HKEY_LOCAL_MACHINE\\SYSTEM1\\ControlSet001\\Services\\FarSpace /f"
            + chr(10)
            + "reg delete HKEY_LOCAL_MACHINE\\SYSTEM1\\ControlSet001\\Control\\SafeBoot\\Minimal\\DFServ /f"
            + chr(10)
            + "echo."
            + chr(10)
            + "echo 卸载SYSTEM注册表"
            + chr(10)
            + "reg unload HKLM\\SYSTEM1"
            + chr(10)
            + "goto :end"
            + chr(10)
            + ":sub"
            + chr(10)
            + "set subkey=%subkey:HKEY_LOCAL_MACHINE\\SYSTEM=%"
            + chr(10)
            + "set subkey=HKEY_LOCAL_MACHINE\\SYSTEM1%subkey%"
            + chr(10)
            + "echo 注册表项：%subkey%"
            + chr(10)
            + "echo 注册表键：%valuename%"
            + chr(10)
            + "echo 删除值：%delvalue%"
            + chr(10)
            + "for /f "
            + chr(34)
            + "tokens=3 delims= "
            + chr(34)
            + " %%i in ('reg query %subkey% /v %valuename%') do ("
            + chr(10)
            + "set value=%%i"
            + chr(10)
            + "echo 键%valuename%的值是：!value!"
            + chr(10)
            + "echo."
            + chr(10)
            + "set value=!value:%delvalue%\\0=!"
            + chr(10)
            + "set value=!value:%delvalue%=!"
            + chr(10)
            + "echo 删除键：%valuename%"
            + chr(10)
            + "reg delete %subkey% /v %valuename% /f"
            + chr(10)
            + "echo."
            + chr(10)
            + "echo 重新创建键：%valuename%，值：!value!"
            + chr(10)
            + "reg add %subkey% /v %valuename% /t reg_multi_sz /d "
            + chr(34)
            + "!value!"
            + chr(34)
            + " /f "
            + chr(10)
            + "echo."
            + chr(10)
            + ")"
            + chr(10)
            + "goto :eof"
            + chr(10)
            + ":end"
            + chr(10)
            + "echo %0 > wtd"
        )
    Label(remove_freeze_info, text="执行批处理程序...").grid()
    RunWrapper("%s %s" % (bat_file, system_flag)).read()
    Label(remove_freeze_info, text="完成！").grid()
    messagebox.showinfo("完成", "移除冰点还原完毕")
    remove_freeze_info.destroy()
    Tk.mainloop(remove_freeze_info)
    return None


def remove_freeze_install_zhangProtect():
    system_flag = system_entry.get()
    ip_flag = ip_entry.get()

    def show_err():
        messagebox.showerror("错误", "输入的盘符不存在或错误")

    if len(system_flag) in [1, 2]:
        if not ":" in system_flag:
            system_flag += ":"
        if not os.path.exists(system_flag) or not os.path.exists(
            "%s\\Windows" % system_flag
        ):
            show_err()
            return False
    else:
        show_err()
        return False
    if not os.path.isfile("ZhangProtect.exe"):
        messagebox.showerror("错误", "没有找到ZhangProtect.exe,无法使用PE安装")
        return False
    remove_freeze_info = Tk()
    remove_freeze_info.title("Zhang_PE工具箱")
    Label(remove_freeze_info, text="-" * 20 + "Zhang_PE工具箱" + "-" * 20).grid()
    Label(remove_freeze_info, text="创建批处理程序...").grid()
    with smart_open.smart_opens(
        "PE_Install.reg",
        "w",
    ) as f:
        f.write(run_reg)
    bat_file = "PE_Remove_DeepFrz_And_Install.bat"
    with smart_open.smart_opens(
        bat_file,
        "w",
    ) as f:
        f.write(
            "@echo off"
            + chr(10)
            + "setlocal enabledelayedexpansion"
            + chr(10)
            + "cd /d "
            + chr(34)
            + "%~dp0"
            + chr(34)
            + ""
            + chr(10)
            + "if exist %1 (goto begin) else (goto end)"
            + chr(10)
            + "exit"
            + chr(10)
            + ":begin"
            + chr(10)
            + "echo 执行移除冰点还原"
            + chr(10)
            + "echo 备份SYSTEM注册表"
            + chr(10)
            + "mkdir regback"
            + chr(10)
            + "echo n|copy %1\\windows\\system32\\config\\SYSTEM regback\\SYSTEM /-Y"
            + chr(10)
            + "echo 备份SOFTWARE注册表"
            + chr(10)
            + "mkdir regback"
            + chr(10)
            + "echo n|copy %1\\windows\\system32\\config\\SOFTWARE regback\\SOFTWARE /-Y"
            + chr(10)
            + ""
            + chr(10)
            + "echo 加载SYSTEM注册表"
            + chr(10)
            + "reg load HKLM\\SYSTEM1 %1\\windows\\system32\\config\\SYSTEM"
            + chr(10)
            + "echo 加载SOFTWARE注册表"
            + chr(10)
            + "reg load HKLM\\SOFTWARE1 %1\\windows\\system32\\config\\SOFTWARE"
            + chr(10)
            + ""
            + chr(10)
            + "echo 删除DiskDrive过滤驱动0"
            + chr(10)
            + "set subkey=HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Control\\Class\\{4d36e967-e325-11ce-bfc1-08002be10318}"
            + chr(10)
            + "set valuename=LowerFilters"
            + chr(10)
            + "set delvalue=DfDiskLo"
            + chr(10)
            + "call :sub"
            + chr(10)
            + "echo."
            + chr(10)
            + "echo 删除DiskDrive过滤驱动1"
            + chr(10)
            + "set subkey=HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Control\\Class\\{4d36e967-e325-11ce-bfc1-08002be10318}"
            + chr(10)
            + "set valuename=UpperFilters"
            + chr(10)
            + "set delvalue=DeepFrz"
            + chr(10)
            + "call :sub"
            + chr(10)
            + "echo."
            + chr(10)
            + "echo 删除鼠标过滤驱动"
            + chr(10)
            + "set subkey=HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Control\\Class\\{4d36e96f-e325-11ce-bfc1-08002be10318}"
            + chr(10)
            + "set valuename=UpperFilters"
            + chr(10)
            + "set delvalue=DeepFrz"
            + chr(10)
            + "call :sub"
            + chr(10)
            + "echo."
            + chr(10)
            + "echo 删除键盘过滤驱动"
            + chr(10)
            + "set subkey=HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Control\\Class\\{4d36e96b-e325-11ce-bfc1-08002be10318}"
            + chr(10)
            + "set valuename=UpperFilters"
            + chr(10)
            + "set delvalue=DeepFrz"
            + chr(10)
            + "call :sub"
            + chr(10)
            + "echo."
            + chr(10)
            + "echo 删除Volume过滤驱动0"
            + chr(10)
            + "set subkey=HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Control\\Class\\{71a27cdd-812a-11d0-bec7-08002be2092f}"
            + chr(10)
            + "set valuename=UpperFilters"
            + chr(10)
            + "set delvalue=DeepFrz"
            + chr(10)
            + "call :sub"
            + chr(10)
            + "echo."
            + chr(10)
            + "echo 删除Volume过滤驱动1"
            + chr(10)
            + "set subkey=HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Control\\Class\\{71a27cdd-812a-11d0-bec7-08002be2092f}"
            + chr(10)
            + "set valuename=UpperFilters"
            + chr(10)
            + "set delvalue=FarSpace"
            + chr(10)
            + "call :sub"
            + chr(10)
            + "echo."
            + chr(10)
            + "echo 删除相关注册表"
            + chr(10)
            + "reg delete HKEY_LOCAL_MACHINE\\SYSTEM1\\ControlSet001\\Services\\DeepFrz /f"
            + chr(10)
            + "reg delete HKEY_LOCAL_MACHINE\\SYSTEM1\\ControlSet001\\Services\\DfDiskLo /f"
            + chr(10)
            + "reg delete HKEY_LOCAL_MACHINE\\SYSTEM1\\ControlSet001\\Services\\DFFilter /f"
            + chr(10)
            + "reg delete HKEY_LOCAL_MACHINE\\SYSTEM1\\ControlSet001\\Services\\DFServ /f"
            + chr(10)
            + "reg delete HKEY_LOCAL_MACHINE\\SYSTEM1\\ControlSet001\\Services\\FarDisk /f"
            + chr(10)
            + "reg delete HKEY_LOCAL_MACHINE\\SYSTEM1\\ControlSet001\\Services\\FarSpace /f"
            + chr(10)
            + "reg delete HKEY_LOCAL_MACHINE\\SYSTEM1\\ControlSet001\\Control\\SafeBoot\\Minimal\\DFServ /f"
            + chr(10)
            + "echo 修改相关注册表"
            + chr(10)
            + "regedit /s PE_Install.reg"
            + chr(10)
            + "reg add HKEY_LOCAL_MACHINE\\SOFTWARE1\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v EnableLUA /t REG_DWORD /d 0 /f"
            + chr(10)
            + "reg add HKEY_LOCAL_MACHINE\\SOFTWARE1\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v ConsentPromptBehaviorAdmin /t REG_DWORD /d 0 /f"
            + chr(10)
            + "reg add HKEY_LOCAL_MACHINE\\SOFTWARE1\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v PromptOnSecureDesktop /t REG_DWORD /d 0 /f"
            + chr(10)
            + "reg add HKEY_LOCAL_MACHINE\\SOFTWARE1\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v ConsentPromptBehaviorUser /t REG_DWORD /d 3 /f"
            + chr(10)
            + "reg add HKEY_LOCAL_MACHINE\\SOFTWARE1\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v EnableVirtualization /t REG_DWORD /d 0 /f"
            + chr(10)
            + "reg add HKEY_LOCAL_MACHINE\\SOFTWARE1\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v EnableInstallerDetection /t REG_DWORD /d 0 /f"
            + chr(10)
            + "reg add HKEY_LOCAL_MACHINE\\SOFTWARE1\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v ValidateAdminCodeSignatures /t REG_DWORD /d 0 /f"
            + chr(10)
            + "echo."
            + chr(10)
            + "echo 卸载SYSTEM注册表"
            + chr(10)
            + "reg unload HKLM\\SYSTEM1"
            + chr(10)
            + "echo 卸载SOFTWARE注册表"
            + chr(10)
            + "reg unload HKLM\\SOFTWARE1"
            + chr(10)
            + "goto :end"
            + chr(10)
            + ":sub"
            + chr(10)
            + "set subkey=%subkey:HKEY_LOCAL_MACHINE\\SYSTEM=%"
            + chr(10)
            + "set subkey=HKEY_LOCAL_MACHINE\\SYSTEM1%subkey%"
            + chr(10)
            + "echo 注册表项：%subkey%"
            + chr(10)
            + "echo 注册表键：%valuename%"
            + chr(10)
            + "echo 删除值：%delvalue%"
            + chr(10)
            + "for /f "
            + chr(34)
            + "tokens=3 delims= "
            + chr(34)
            + " %%i in ('reg query %subkey% /v %valuename%') do ("
            + chr(10)
            + "set value=%%i"
            + chr(10)
            + "echo 键%valuename%的值是：!value!"
            + chr(10)
            + "echo."
            + chr(10)
            + "set value=!value:%delvalue%\\0=!"
            + chr(10)
            + "set value=!value:%delvalue%=!"
            + chr(10)
            + "echo 删除键：%valuename%"
            + chr(10)
            + "reg delete %subkey% /v %valuename% /f"
            + chr(10)
            + "echo."
            + chr(10)
            + "echo 重新创建键：%valuename%，值：!value!"
            + chr(10)
            + "reg add %subkey% /v %valuename% /t reg_multi_sz /d "
            + chr(34)
            + "!value!"
            + chr(34)
            + " /f "
            + chr(10)
            + "echo."
            + chr(10)
            + ")"
            + chr(10)
            + "goto :eof"
            + chr(10)
            + ":end"
            + chr(10)
            + "echo %0 > wtd"
        )
    Label(remove_freeze_info, text="执行批处理程序...").grid()
    RunWrapper("%s %s" % (bat_file, system_flag)).read()
    Label(remove_freeze_info, text="冰点还原已移除").grid()
    Label(remove_freeze_info, text="写入ZhangProtect").grid()
    system_protect_dir = "%s\\Protect\\" % ("%s\\Windows" % system_flag)
    system_protect_exe = system_protect_dir + "Protect.exe"
    Protect_PE_Install_bat = system_protect_dir + "Protect_PE_Install.bat"
    if not os.path.exists(system_protect_dir):
        os.mkdir(system_protect_dir)
    for i in ["ipcheck", "lowerlog", "keep_awake", "use_rdpwrap"]:
        with smart_open.smart_opens(system_protect_dir + i, "w") as f:
            f.write("1")
    with smart_open.smart_opens(
        Protect_PE_Install_bat,
        "w",
    ) as f:
        f.write(install_bat)
    if not ip_flag == "":
        with smart_open.smart_opens(
            system_protect_dir + "network_base_ip_txt.txt", "w"
        ) as f:
            f.write(ip_flag)
    shutil.copy("ZhangProtect.exe", system_protect_exe)

    Label(
        remove_freeze_info, text="ZhangProtect写入完毕，将在系统开机后自动安装"
    ).grid()
    messagebox.showinfo("完成", "冰点还原已经移除，ZhangProtect将在系统启动后自动安装")
    remove_freeze_info.destroy()
    Tk.mainloop(remove_freeze_info)
    return None


def main():
    global run_reg, install_bat, system_entry, ip_entry
    install_bat = (
        "@echo off"
        + chr(10)
        + "cd %systemroot%\\Protect"
        + chr(10)
        + ":a"
        + chr(10)
        + "if exist %systemroot%\\Protect\\runonce ("
        + chr(10)
        + "reg delete HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run /v ZhangProtectInstall_PE /f"
        + chr(10)
        + "del /f /q %systemroot%\\Protect\\runonce"
        + chr(10)
        + "del /f /q %0"
        + chr(10)
        + "exit"
        + chr(10)
        + ")"
        + chr(10)
        + "call :run"
        + chr(10)
        + ":start"
        + chr(10)
        + "if exist %systemroot%\\Protect\\ProtectConf.conf ("
        + chr(10)
        + "taskkill /f /im Protect.exe /t"
        + chr(10)
        + "call :run"
        + chr(10)
        + "goto ok"
        + chr(10)
        + ") else ("
        + chr(10)
        + "timeout /t 5"
        + chr(10)
        + "goto start)"
        + chr(10)
        + ":ok"
        + chr(10)
        + "timeout /t 5"
        + chr(10)
        + "schtasks /query /tn ZhangProtect\\Protect && goto done || goto ok"
        + chr(10)
        + ":done"
        + chr(10)
        + "echo 1 > %systemroot%\\Protect\\runonce"
        + chr(10)
        + "goto a"
        + chr(10)
        + ":run"
        + chr(10)
        + "mshta vbscript:CreateObject("
        + chr(34)
        + "Shell.Application"
        + chr(34)
        + ").ShellExecute("
        + chr(34)
        + "%systemroot%\\Protect\\Protect.exe"
        + chr(34)
        + ","
        + chr(34)
        + ""
        + chr(34)
        + ","
        + chr(34)
        + ""
        + chr(34)
        + ",runas,0)(window.close)"
        + chr(10)
        + "goto :eof"
    )
    run_reg = (
        "Windows Registry Editor Version 5.00"
        + chr(10)
        + "[HKEY_LOCAL_MACHINE\\SOFTWARE1\\Microsoft\\Windows\\CurrentVersion\\Run]"
        + chr(10)
        + '"ZhangProtectInstall_PE"="mshta vbscript:CreateObject(\\"Shell.Application\\").ShellExecute(\\"cmd\\",\\"/c %systemroot%\\'
        + "\\Protect\\"
        + '\\Protect_PE_Install.bat\\",\\"\\",runas,0)(window.close)"'
    )
    work_dir = os.path.dirname(os.path.abspath(sys.executable))
    os.chdir(work_dir)
    root = Tk()
    root.title("Zhang PETools")
    Label(root, text="-" * 20 + "Zhang_PE工具箱" + "-" * 20).grid()
    Label(root, text="工作目录:%s" % work_dir).grid()
    if not os.path.exists("ZhangProtect.exe"):
        Label(root, text="工作目录缺少 ZhangProtect.exe").grid()
    Label(root, text="输入操作的目标系统盘符").grid()
    system_entry = Entry(root)
    system_entry.insert("0", "C")
    system_entry.grid()
    Label(root, text="输入本机需要设置的网络IP").grid()
    ip_entry = Entry(root)
    ip_entry.insert("0", "")
    ip_entry.grid()
    Label(root, text="-" * 20 + "功能列表" + "-" * 20).grid()
    Button(root, text="PE下移除冰点还原", command=remove_freeze).grid()
    Button(root, text="PE下安装Protect", command=install_zhangProtect).grid()
    Button(root, text="一键执行操作", command=remove_freeze_install_zhangProtect).grid()
    Tk.mainloop(root)


if __name__ == "__main__":
    main()
