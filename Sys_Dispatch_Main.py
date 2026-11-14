import os
import time
import logger
import psutil
import config
import datetime
import win32api
import smart_open
from main_imports import *
from cmd_runner import RunWrapper
import win32gui, win32process, win32con


def active_windows_process_name():  # 焦点窗口进程名
    try:
        pid = win32process.GetWindowThreadProcessId(win32gui.GetForegroundWindow())
        return psutil.Process(pid[-1]).name()
    except:
        pass


def active_windows_process_pid():  # 焦点窗口进程PID
    try:
        pid = win32process.GetWindowThreadProcessId(win32gui.GetForegroundWindow())
        return pid[-1]
    except:
        pass


def sys_dispatch():  # 优先级调度
    # 降低自身进程优先级，减少使用影响
    setpriority(os.getpid(), 1, True, False)
    logger.log("启动不公平调度")
    own_pr_ls = [
        "memreduct.exe",
        "desktopok.exe",
        "ccleaner.exe",
        "sfc.exe",
        "dism.exe",
        "snapshot.exe",
        "snapshot64.exe",
        "icacls.exe",
        "takeown.exe",
        "ping.exe",
        "conhost.exe",
        "protect.exe",
        "sysdispatch.exe",
        "zhangprotectcontrol.exe",
    ]  # 需要降低优先级的程序
    sys_pr_ls = [
        "pyinstaller.exe",
        "black.exe",
        "python.exe",
        "pip.exe",
        "taskmgr.exe",
    ]  # 高于正常优先级的程序
    now_pr_ls = ["explorer.exe", "keyboard_filter.exe"]  # 高优先级进程
    ignore_ls = [
        "vmware-vmx.exe",
        "vmware.exe",
    ]
    if os.path.isfile(sys_dispatch_upperproc):  # 用户自定义的需要提高优先级的进程
        with smart_open.smart_opens(
            sys_dispatch_upperproc,
            "r",
        ) as f:
            upper_proc_ls = f.read().splitlines()
        for i in upper_proc_ls:
            i = str(i).casefold()
            if not i == "":
                if not i[0] == "#":
                    now_pr_ls.append(i)
    else:
        with smart_open.smart_opens(
            sys_dispatch_upperproc,
            "w",
        ) as f:
            f.write(
                f"#开启不公平调度后，在此文件写下进程名,一行一个,井号开头注释;这些进程将保持高优先级以及分配大核心。"
            )

    if os.path.isfile(sys_dispatch_lowerproc):  # 用户自定义的需要降低优先级的进程
        with smart_open.smart_opens(
            sys_dispatch_lowerproc,
            "r",
        ) as f:
            upper_proc_ls = f.read().splitlines()
        for i in upper_proc_ls:
            i = str(i).casefold()
            if not i == "":
                if not i[0] == "#":
                    own_pr_ls.append(i)
    else:
        with smart_open.smart_opens(
            sys_dispatch_lowerproc,
            "w",
        ) as f:
            f.write(
                f"#开启不公平调度后，在此文件写下进程名,一行一个,井号开头注释;这些进程将被降低优先级以及分配小核心。"
            )
    if os.path.isfile(Auto_SetGameToPcore):  # 游戏核心优化
        if os.path.isfile(pause_on_game_list):
            with smart_open.smart_opens(
                pause_on_game_list,
                "r",
            ) as f:
                pause_on_game_ls = f.read().splitlines()
            for i in pause_on_game_ls:
                i = str(i).casefold()
                if not i == "":
                    if not i[0] == "#":
                        if "*" in i:
                            now_pr_ls.append(i.split("*")[0])
                        else:
                            now_pr_ls.append(i)

    if os.path.isfile(sys_dispatch_ignore):  # 用户自定义的忽略的进程
        with smart_open.smart_opens(
            sys_dispatch_ignore,
            "r",
        ) as f:
            upper_proc_ls = f.read().splitlines()
        for i in upper_proc_ls:
            i = str(i).casefold()
            if not i == "":
                if not i[0] == "#":
                    ignore_ls.append(i)
    else:
        with smart_open.smart_opens(
            sys_dispatch_ignore,
            "w",
        ) as f:
            f.write(
                f"#开启不公平调度后，在此文件写下进程名,一行一个,井号开头注释;这些进程将设置正常全核心。"
            )

    for i in get_logon_user():
        for j in get_user_process_list(i):
            pid = int(j.get("pid"))
            proname = j.get("name").casefold()
            if proname in ignore_ls:
                continue
            setpriority(pid, 1, True, False)  # 全部默认低于正常,E核
    active_windows_pro_name_A = str(active_windows_process_name()).casefold()

    while True:
        try:
            active_windows_pro_name = str(active_windows_process_name()).casefold()
            active_windows_pro_pid = int(active_windows_process_pid())
            if active_windows_pro_name is None:
                continue
            for i in get_process_list(True):
                proname = i.get("name").casefold()
                pid = int(i.get("pid"))
                if (
                    proname in own_pr_ls
                    and not proname in sys_pr_ls
                    and not proname in now_pr_ls
                    and not proname == active_windows_pro_name
                ) and (
                    not proname in ignore_ls
                ):  # 属于需要低优先级的进程
                    setpriority(pid, 0, True, False)  # 低优先级
                elif (
                    proname in sys_pr_ls
                    and not proname in own_pr_ls
                    and not proname in now_pr_ls
                    and not proname == active_windows_pro_name
                ) and (
                    not proname in ignore_ls
                ):  # 属于需要高于正常优先级的进程
                    setpriority(pid, 3, True, True)
                elif (
                    proname in now_pr_ls
                    and not proname in own_pr_ls
                    and not proname in sys_pr_ls
                    and not proname == active_windows_pro_name
                ) and (
                    not proname in ignore_ls
                ):  # 属于需要高优先级的进程
                    setpriority(pid, 4, True, True)
                elif proname in ignore_ls:
                    setpriority(pid, 2, False)
                    set_affinity_by_pid(pid, False, False, 3)
            for i in get_logon_user():
                for j in get_user_process_list(i):
                    proname = j.get("name").casefold()
                    pid = int(j.get("pid"))
                    if proname in ignore_ls:
                        continue
                    if (
                        not proname in own_pr_ls
                        and not proname in sys_pr_ls
                        and not proname in now_pr_ls
                        and not proname == active_windows_pro_name
                    ) and (not proname in ignore_ls):
                        setpriority(pid, 1, True, False)  # 后台低于正常,E核
            # 将焦点所在进程优先级设置为高
            if (
                not active_windows_pro_name in own_pr_ls
                and not active_windows_pro_name in now_pr_ls
                and not active_windows_pro_name in sys_pr_ls
            ) and (not active_windows_pro_name in ignore_ls):
                setpriority(active_windows_pro_pid, 4, True, True)  # 高优先级且前台,P核
                if not active_windows_pro_name_A == active_windows_pro_name:
                    pro_log = (
                        "[不公平调度PID:%s,%s]用户%s: 窗口焦点已变更为 %s --> 高优先级(绑定P核心),原焦点 %s --> 低于正常(绑定E核心)\r\n"
                        % (
                            str(os.getpid()),
                            str(datetime.datetime.now()),
                            str(os.getlogin()),
                            active_windows_pro_name,
                            active_windows_pro_name_A,
                        )
                    )
                    logger.log(pro_log)
                    active_windows_pro_name_A = active_windows_pro_name
        except Exception as e:
            logger.log(f"[不公平调度]产生错误:{e}")
        time.sleep(3)


def main():
    global windir, protectdir, protectexe, protectconf
    windir = os.getenv("systemroot")
    protectdir = "%s\\Protect\\" % windir
    protectexe = "%sProtect.exe" % protectdir
    protectconf = "%sProtectConf.conf" % protectdir
    try:
        os.chdir(protectdir)
    except:
        pass
    sys_dispatch()


if __name__ == "__main__":
    main()
