import os
import time
import psutil
import datetime
import win32api
import win32gui, win32process, win32con


def get_process_list():
    pro_list = []
    for i in psutil.pids():
        try:
            proc_direct = {}
            proc = psutil.Process(i)
            proc_direct["name"] = proc.name().casefold()
            proc_direct["execs"] = proc.exe().casefold()
            proc_direct["username"] = proc.username().split("\\")[-1].casefold()
            proc_direct["pid"] = i
            pro_list.append(proc_direct)
        except Exception as e:
            pass
        time.sleep(0.01)
    return pro_list


def get_logon_user():
    ls = []
    for i in get_process_list():
        username = str(i.get("username")).casefold()
        name = str(i.get("name")).casefold()
        if name == "explorer.exe" and not username in ls:
            ls.append(username)
        time.sleep(0.01)
    return ls


def get_user_process_list(user):
    user_process_list = []
    user = user.casefold()
    for i in get_process_list():
        if i.get("username") == str(user):
            user_process_list.append(i)
        time.sleep(0.01)
    return user_process_list


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
    active_windows_pro_name_A = str(active_windows_process_name()).casefold()
    while True:
        try:
            active_windows_pro_name = str(active_windows_process_name()).casefold()
            active_windows_pro_pid = int(active_windows_process_pid())
            if active_windows_pro_name == None:
                continue
            own_pr_ls = [
                "memreduct.exe",
                "desktopok.exe",
                "ccleaner.exe",
                "sfc.exe",
                "dism.exe",
                "snapshot.exe",
                "snapshot64.exe",
                "pycharm.exe",
                "pycharm64.exe",
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
            ]  # 保证高优先级的程序
            now_pr_ls = [
                "explorer.exe",
            ]  # 实时优先级进程
            for i in get_process_list():
                proname = i.get("name").casefold()
                pid = int(i.get("pid"))
                if (
                    proname in own_pr_ls
                    and not proname in sys_pr_ls
                    and not proname in now_pr_ls
                    and not proname == active_windows_pro_name
                ):  # 属于需要降低优先级的进程
                    setpriority(pid, 0)  # 低优先级
                elif (
                    proname in sys_pr_ls
                    and not proname in own_pr_ls
                    and not proname in now_pr_ls
                    and not proname == active_windows_pro_name
                ):  # 属于需要提高优先级的进程
                    setpriority(pid, 3)
                elif (
                    proname in now_pr_ls
                    and not proname in own_pr_ls
                    and not proname in sys_pr_ls
                    and not proname == active_windows_pro_name
                ):  # 属于需要实时优先级的进程
                    setpriority(pid, 4)
                time.sleep(0.01)

            del proname, pid
            for i in get_logon_user():
                for j in get_user_process_list(i):
                    proname = j.get("name").casefold()
                    pid = int(j.get("pid"))
                    if (
                        not proname in own_pr_ls
                        and not proname in sys_pr_ls
                        and not proname in now_pr_ls
                        and not proname == active_windows_pro_name
                    ):
                        setpriority(pid, 1)  # 低于正常
                    time.sleep(0.01)
            # 将焦点所在进程优先级设置为高于正常
            if (
                not active_windows_pro_name in own_pr_ls
                and not active_windows_pro_name in now_pr_ls
                and not active_windows_pro_name in sys_pr_ls
            ):
                setpriority(active_windows_pro_pid, 4)
                if not active_windows_pro_name_A == active_windows_pro_name:
                    pro_log = (
                        "[调度PID:%s,%s]用户%s: 窗口焦点已变更为 %s --> 高优先级,原焦点 %s --> 低于正常\r\n"
                        % (
                            str(os.getpid()),
                            str(datetime.datetime.now()),
                            str(os.getlogin()),
                            active_windows_pro_name,
                            active_windows_pro_name_A,
                        )
                    )
                    with open("sys_dispatch.log", "a") as f:
                        f.write(pro_log)
                    active_windows_pro_name_A = active_windows_pro_name
        except:
            pass
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
