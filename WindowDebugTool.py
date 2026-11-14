import os
import sys
import time
import psutil
import datetime
import win32con
import win32gui
import smart_open
from ntsd import *
import win32process
from ByeByeJY import *
from NSudoZip import *
from PopBlock import *
from cmd_runner import RunWrapper
from main_imports import b64_to_file, b64zip_to_file
from main_imports import disable_quick_edit_mode

try:
    disable_quick_edit_mode()
except:
    pass
self_path = os.path.dirname(sys.executable)
try:
    os.chdir(self_path)
except:
    pass


ntsd_exe = "ntsd.exe"
PopBlock_zip = "PopBlock.7z"
PopBlock_dir = "PopBlock"  # 这是一个文件夹
PopBlock_exe = PopBlock_dir + "\\PopBlock.exe"
PopBlock_install = PopBlock_dir + "\\install.bat"
ByeByeJY_exe = "ByeByeJiYv.exe"
NSudo = "NSudo.exe"


def active_window_process_name():
    try:
        forge = win32gui.GetForegroundWindow()
        pid = win32process.GetWindowThreadProcessId(forge)

        return [psutil.Process(pid[-1]).name(), forge, pid]
    except:
        pass


whitelist = "Whitelist.txt"
Whitels = []
if os.path.isfile(whitelist):
    with smart_open.smart_opens(whitelist, "r") as f:
        Whitels = f.read().splitlines()
if (not os.path.isfile(whitelist)) or len(Whitels) == 0:
    with smart_open.smart_opens(whitelist, "w") as f:
        f.write(
            "explorer.exe\ncode.exe\nqq.exe\nwechat.exe\nByeByeJiYv.exe\nPopBlock.exe\ncmd.exe\nnsudo.exe\nntsd.exe\npowershell.exe\nSHELLHOST.EXE\nSTARTMENUEXPERIENCEHOST.EXE\nProcessMonitor.exe\nosk.exe\nWINDOWSTERMINAL.EXE\nNOTEPAD++.EXE\nSHELLEXPERIENCEHOST.EXE\nProcessExplorer.exe\nntsd.exe\nnsudo.exe\nZhangProtectControl.exe\nAutoRuns.exe\ntaskmgr.exe\nweixin.exe\nmsedge.exe\nnotepad.exe"
        )
    with smart_open.smart_opens(whitelist, "r") as f:
        Whitels = f.read().splitlines()
tasklisttxt = "TaskListLog.txt"

try:
    b64zip_to_file(PopBlock_zip, PopBlockf, extraPath=self_path, force=True)
    b64_to_file(ntsd_exe, ntsdf)
    b64_to_file(ByeByeJY_exe, ByeByeJYf)
    b64_to_file(NSudo, NSudoZipf)
    RunWrapper(PopBlock_install).read()
    if os.path.isfile("starttool"):
        RunWrapper('start "" "%s"' % PopBlock_exe)
        RunWrapper('start "" "%s"' % ByeByeJY_exe)
        RunWrapper('start "" "%s"' % NSudo)
except:
    pass

print("本程序用于窗口调试，可记录当前焦点窗口进程名，并可隐藏窗口和杀死进程")
print("运行结果将记录到工作目录的 %s 内" % tasklisttxt)
print()
print("工作目录下创建文件 hidewindow 可隐藏焦点窗口并挂起")
print("工作目录下创建文件 killtask 可结束焦点窗口进程")
print("工作目录下创建文件 starttool 可自动启动附加工具")
print()
print("工作目录: %s" % os.getcwd())
print("进程白名单(可自行追加进程到 Whitelist.txt): \n%s" % Whitels)
print()
print(
    "窗口模式:%s" % ("隐藏窗口并挂起" if os.path.isfile("hidewindow") else "仅最小化")
)
print("进程模式:%s" % ("结束进程" if os.path.isfile("killtask") else "不操作进程"))

while True:
    try:
        active_window = active_window_process_name()
        # 当前焦点窗口对应进程名
        nowproc = str(active_window[0]).upper()
        # 当前焦点窗口的窗口句柄
        forg = active_window[1]
        # 当前焦点窗口对应进程PID
        propid = active_window[2]
        # 如果焦点进程名不在白名单范围内且不是自身
        if (not str(psutil.Process(os.getpid()).name()).upper() == nowproc) and (
            not nowproc in [str(i).upper() for i in Whitels]
        ):
            with smart_open.smart_opens(tasklisttxt, "a") as f:
                f.write(
                    "\n[%s]已记录当前焦点窗口的进程名(PID: %s):%s"
                    % (datetime.datetime.now(), propid, nowproc)
                )
            win32gui.ShowWindow(forg, win32con.SW_MINIMIZE)  # 最小化窗体
            if os.path.isfile("hidewindow"):
                win32gui.ShowWindow(forg, win32con.SW_HIDE)  # 隐藏窗体
                # 挂起对应进程
                if type(propid) == list:
                    for i in propid:
                        try:
                            psutil.Process(i).suspend()
                        except:
                            pass
                else:
                    try:
                        psutil.Process(propid).suspend()
                    except:
                        pass
            if os.path.isfile("killtask"):
                RunWrapper('Taskkill /f /im "%s" /t' % nowproc).read()
                RunWrapper(
                    '"%s" -U:T -P:E -ShowWindowMode:Hide -Wait cmd /c Taskkill /f /im "%s" /t'
                    % (NSudo, nowproc)
                ).read()
                RunWrapper("Taskkill /f /im Nsudo.exe /t").read()
        time.sleep(1)
    except:
        time.sleep(1)
