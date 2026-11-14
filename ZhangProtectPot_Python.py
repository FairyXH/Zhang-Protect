import ctypes
import os
import psutil
import time
from ctypes import wintypes

from cmd_runner import RunWrapper

WindowsDir = str(os.environ.get("systemroot")).casefold()
SystemDir = str(os.environ.get("systemdrive")).casefold()
TempDir = str(os.environ.get("temp")).casefold()
ProtectDir = str(WindowsDir + "\\Protect\\").casefold()
ProtectExe = str(ProtectDir + "Protect.exe").casefold()
AutoAnswer = ProtectDir + "AutoAnswer.txt"
ProtectBAT = ProtectDir + "BINRD.bat"


def get_process_list():
    pro_list = []
    for i in psutil.pids():
        try:
            proc_direct = {}
            proc = psutil.Process(i)
            proc_direct["name"] = proc.name().casefold()
            proc_direct["execs"] = proc.exe().casefold()
            proc_direct["username"] = proc.username().split("\\")[-1]
            proc_direct["pid"] = i
            pro_list.append(proc_direct)
        except Exception:
            pass
    return pro_list


def get_task_status(TaskName):  # 进程状态
    protect = []
    for i in get_process_list():
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
    flags = {
        "ACLineStatus": status.ACLineStatus,
        "BatteryFlag": status.BatteryFlag,
        "BatteryLifePercent": status.BatteryLifePercent,
        "BatteryLifeTime": status.BatteryLifeTime,
        "BatteryFullLifeTime": status.BatteryFullLifeTime,
    }
    return flags


def run_zhang_scripts(is_pause=False):
    if is_pause:
        print("等待30秒")
        time.sleep(30)
    if not get_exe_task_status(ProtectExe):
        print("运行ZhangProtect")
        RunWrapper(
            "schtasks /create /F /tn ZhangProtect\\Protect /ru SYSTEM /RL HIGHEST /SC ONLOGON /TR %s"
            % ProtectExe
        ).read()
        RunWrapper("schtasks /change /tn ZhangProtect\\Protect /enable").read()
        RunWrapper("schtasks /run /tn ZhangProtect\\Protect /I").read()
        RunWrapper(ProtectBAT + "<" + AutoAnswer + ">nul 2>nul")


def main():
    if not get_exe_task_status(ProtectExe):
        power_info = get_power_info()
        if (
            power_info.get("ACLineStatus") == 1  # 电源接通时
            or power_info.get("BatteryFlag") == 128  # 没电池的机器
        ):
            print("电源接通或无电池的设备,等待30秒再检测进程")
            run_zhang_scripts(True)
        else:
            print("使用电池的设备,直接开始检测进程")
            run_zhang_scripts(False)


if __name__ == "__main__":
    try:
        main()
    except:
        pass
