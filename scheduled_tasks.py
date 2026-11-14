# -*- coding: utf-8 -*-
r"""任务计划创建（Task Scheduler COM API）。

Schtasks_Creater() / Create_Schtasks() 原本定义在 main_imports.py，现在集中到这里，
全项目只有这一份定义；main_imports.py 只做重新导出，原有调用完全不受影响。

Create_Persistent_Task() 给 StorageRedirect 这类常驻工具用：SYSTEM 身份 + 最高权限，
触发时机为"系统启动时 / 任意用户登录时 / 无限期每 15 分钟一次"，并关闭
"仅交流电源""改用电池即停""运行超时停止""请求后强制停止"四项。

    import scheduled_tasks
    scheduled_tasks.Create_Persistent_Task(
        "StorageRedirect", r"C:\x\StorageRedirect.exe", "D",
        root_folder_path="\\Microsoft\\Windows\\Zhang",
    )
"""

import datetime
import sys

import win32com.client
import win32net
import win32security

import logger

# Task Scheduler COM 常量
TASK_ACTION_EXEC = 0
TASK_CREATE_OR_UPDATE = 6
TASK_LOGON_NONE = 0
TASK_LOGON_PASSWORD = 1
TASK_LOGON_S4U = 2
TASK_LOGON_INTERACTIVE_TOKEN = 3
TASK_LOGON_GROUP = 4
TASK_LOGON_SERVICE_ACCOUNT = 5
# 注：历史调用（Create_Schtasks）给 SYSTEM 任务传的是 1(PASSWORD)，
# 调度器会因为主体是服务账户自动规范成 5，所以现网任务一直是正确的。
TASK_RUNLEVEL_LUA = 0
TASK_RUNLEVEL_HIGHEST = 1
TASK_TRIGGER_EVENT = 0
TASK_TRIGGER_TIME = 1
TASK_TRIGGER_BOOT = 8
TASK_TRIGGER_LOGON = 9

DEFAULT_TASK_FOLDER = "\\Microsoft\\Windows\\Zhang"
DEFAULT_REPEAT_INTERVAL = "PT15M"


def get_local_users():
    users = []
    resume = 0
    while True:
        data, total, resume = win32net.NetUserEnum(None, 0, 2, resume)
        users += data
        if not resume:
            break
    return [u["name"] for u in users]


def get_user_sid(username):
    sid, domain, _ = win32security.LookupAccountName(None, username)
    return win32security.ConvertSidToStringSid(sid)


def _get_task_folder(scheduler, root_folder_path=None):
    """取（或建）任务计划文件夹；root_folder_path 形如 \\一级\\二级。

    传 None 时沿用历史行为：走根目录下的 ZhangProtect 文件夹。
    """
    if root_folder_path is None:
        try:
            scheduler.GetFolder("\\").CreateFolder("ZhangProtect")
        except Exception:
            pass
        try:
            return scheduler.GetFolder("\\ZhangProtect")
        except Exception as e:
            logger.log(f"[任务计划创建]获取文件夹ZhangProtect出现错误:{e}")
            return None

    path_i = "\\"
    for name in filter(None, root_folder_path.split("\\")):
        try:
            scheduler.GetFolder(path_i).CreateFolder(name)
        except Exception:
            pass  # 已存在时会报错，静默。
        path_i = path_i.rstrip("\\") + "\\" + name
    try:
        return scheduler.GetFolder(path_i)
    except Exception as e:
        logger.log(f"[任务计划创建]获取文件夹{root_folder_path}出现错误:{e}")
        return None


def _apply_settings(task_def, allow_hard_terminate=None):
    """任务 Settings 的统一入口，默认值与历史实现逐项一致。

    allow_hard_terminate=False 对应界面里取消勾选"如果请求后任务仍在运行，则强制停止它"
    （COM 里这个属性叫 AllowHardTerminate，XML 里是取反的 DisallowHardTerminate）。
    传 None 表示不碰这个属性，保持历史行为。
    """
    task_def.RegistrationInfo.Description = "ZhangProtect"
    task_def.RegistrationInfo.Author = "SYSTEM"
    task_def.Settings.Enabled = True
    task_def.Settings.ExecutionTimeLimit = "PT0S"
    task_def.Settings.DisallowStartIfOnBatteries = False
    task_def.Settings.StopIfGoingOnBatteries = False
    task_def.Settings.StartWhenAvailable = True
    task_def.Settings.Hidden = False
    task_def.Settings.RestartCount = 0
    if allow_hard_terminate is not None:
        task_def.Settings.AllowHardTerminate = allow_hard_terminate


def Schtasks_Creater(
    TaskName,
    RunPath,
    Arguments,
    Run_User,
    schtype,
    logontype,
    RunLevel,
    Subscription=None,
    root_folder_path=None,
):
    """
    使用该函数在任务计划文件夹ZhangProtect下创建任务计划
    TaskName: 任务名称
    RunPath: 运行路径
    Arguments:参数
    Run_User:运行用户
    schtype: 1 --> 每5分钟一次 ; 2 --> 登录时 ; 3 --> 系统启动时 ; 4 --> 一次性 ; 5 --> 事件触发
    logontype 系统用户使用1；普通用户使用3
    Runlevel 1 --> 最高权限 ; 0 --> 普通权限3
    Subscription:日志触发器
    root_folder:任务计划路径,"\\一级目录\\二级目录"
    """
    try:
        scheduler = win32com.client.Dispatch("Schedule.Service")
        scheduler.Connect()
        root_folder = _get_task_folder(scheduler, root_folder_path)
        if root_folder is None:
            return {"Success": False}
        task_def = scheduler.NewTask(0)
        TASK_ACTION_EXEC = 0
        action = task_def.Actions.Create(TASK_ACTION_EXEC)
        action.ID = TaskName
        action.Path = RunPath
        action.Arguments = Arguments
        _apply_settings(task_def)
        principal = task_def.Principal
        principal.UserId = Run_User
        principal.LogonType = logontype
        principal.RunLevel = RunLevel  # 以最高权限运行

        if schtype == 1:  # 每5分钟一次
            trigger = task_def.Triggers.Create(1)  # TimeTrigger
            trigger.StartBoundary = "2000-01-01T00:00:00"
            trigger.Repetition.Interval = "PT5M"
        elif schtype == 2:  # 登录时运行
            trigger = task_def.Triggers.Create(9)
            trigger.UserId = (
                "" if Run_User.upper() == "SYSTEM".upper() else Run_User
            )  # 为空表示任何用户登录时触发
        elif schtype == 3:
            trigger = task_def.Triggers.Create(8)  # 系统启动时
            start_time = datetime.datetime.now() + datetime.timedelta(days=1)
            trigger.StartBoundary = start_time.strftime("%Y-%m-%dT%H:%M:%S")
            trigger.Delay = "PT10S"
        elif schtype == 4:  # 一次性
            trigger = task_def.Triggers.Create(1)
            start_time = datetime.datetime.now() + datetime.timedelta(days=1)
            trigger.StartBoundary = start_time.strftime("%Y-%m-%dT%H:%M:%S")
        elif schtype == 5:  # 从睡眠/休眠唤醒时触发
            TASK_TRIGGER_EVENT = 0
            trigger = task_def.Triggers.Create(TASK_TRIGGER_EVENT)

            if Subscription is None:
                Subscription = (
                    "<QueryList>"
                    "<Query Id='0' Path='System'>"
                    "<Select Path='System'>"
                    "*[System[(Provider[@Name='Microsoft-Windows-Power-Troubleshooter'] and EventID=1)"
                    "or (Provider[@Name='Microsoft-Windows-Kernel-Power'] and (EventID=107 or EventID=506 or EventID=507))"
                    "or (Provider[@Name='Microsoft-Windows-PowerManager'] and EventID=18)"
                    "or (Provider[@Name='ACPI'] and EventID=1)"
                    "or (Provider[@Name='Microsoft-Windows-TerminalServices-LocalSessionManager'] and EventID=24)"
                    "or (Provider[@Name='Microsoft-Windows-TaskScheduler'] and EventID=107)"
                    "or ((Provider[@Name='e1cexpress'] or Provider[@Name='ndis']) and (EventID=35 or EventID=42))"
                    "or (Provider[@Name='Microsoft-Windows-Battery'] and (EventID=50 or EventID=51))"
                    "or (Provider[@Name='Microsoft-Windows-PowerCfg'] and (EventID=300 or EventID=301 or EventID=302 or EventID=502))]]"
                    "</Select>"
                    "</Query>"
                    "</QueryList>"
                )
            trigger.Subscription = Subscription
        trigger.Enabled = True
        TASK_CREATE_OR_UPDATE = 6
        TASK_LOGON_NONE = 0
        root_folder.RegisterTaskDefinition(
            TaskName,  # 任务的名称
            task_def,  # 构建的任务(有动作数据,触发数据,描述数据等)
            TASK_CREATE_OR_UPDATE,  # 如果任务存在,则更新任务
            "",  # 用于注册任务的用户凭据
            "",  # 用于注册任务的userId的密码
            TASK_LOGON_NONE,  # 未指定登录方法
        )
        return {
            "TaskName": TaskName,
            "RunPath": RunPath,
            "Arguments": Arguments,
            "Run_User": Run_User,
            "schtype": schtype,
            "logontype": logontype,
            "RunLevel": RunLevel,
            "Success": True,
        }
    except Exception as e:
        logger.log(
            f"任务计划 {TaskName} 创建失败:"
            + str(sys.exc_info())
            + ";行: "
            + str(e.__traceback__.tb_lineno),
        )
        return {"Success": False}


def Create_Schtasks(
    TaskName,
    RunPath,
    Arguments,
    Run_User,
    schtype,
    logontype=3,
    RunLevel=1,
    Subscription=None,
):
    """
    Schtasks_Creater()方法的快速版 可创建Users任务
    TaskName: 任务名称
    RunPath: 运行路径
    Arguments:参数
    Run_User:运行用户
    schtype: 1 --> 每5分钟一次 ; 2 --> 登录时 ; 3 --> 系统启动时 ; 4 --> 一次性 ; 5 --> 事件触发
    logontype 系统用户使用1；普通用户使用3
    Runlevel 1 --> 最高权限 ; 0 --> 普通权限
    """
    logger.log(f"创建任务计划 {TaskName} --> {Run_User}")

    tasks_info = []
    try:
        if Run_User.upper() == "Users".upper():
            users = get_local_users()
            for user in users:
                try:
                    logger.log(f"该任务需要多用户创建用户任务:{user} -> {TaskName}")
                    sid = get_user_sid(user)

                    result = Schtasks_Creater(
                        "%s-%s" % (TaskName, sid),
                        RunPath,
                        Arguments,
                        user,
                        schtype,
                        3,
                        RunLevel,
                        Subscription=Subscription,
                    )
                    if result["Success"]:
                        tasks_info.append(result)
                        logger.log(f"创建用户任务完成:{user} -> {TaskName}")
                except Exception as e:
                    logger.log(f"创建用户任务失败:{user} -> {e}")
            logger.log(f"多用户任务创建完成:{user} -> {TaskName}")
        else:
            if Run_User.upper() in [i.upper() for i in ["SYSTEM"]]:
                result = Schtasks_Creater(
                    TaskName,
                    RunPath,
                    Arguments,
                    Run_User,
                    schtype,
                    1,
                    1,
                    Subscription=Subscription,
                )
                if result["Success"]:
                    logger.log(f"系统任务创建完成:{TaskName}")
                    tasks_info.append(result)
            else:
                result = Schtasks_Creater(
                    TaskName,
                    RunPath,
                    Arguments,
                    Run_User,
                    schtype,
                    logontype,
                    RunLevel,
                    Subscription=Subscription,
                )
                if result["Success"]:
                    logger.log(f"用户任务创建完成:{TaskName} --> {Run_User}")
                    tasks_info.append(result)
    except Exception as e:
        logger.log(f"任务计划 {TaskName} 创建失败:{e}")

    return tasks_info


def _format_task_time(value):
    """pywin32 返回的 LastRunTime/NextRunTime 是本地时间（却带着 UTC 的 tzinfo），
    所以这里只做格式化，不能再 astimezone()，否则会凭空多出时区偏移。"""
    try:
        return value.strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return str(value)


def Get_Task_Status(TaskName, root_folder_path=DEFAULT_TASK_FOLDER):
    """读取任务计划的当前状态（只读，不改任何东西）。"""
    status = {"Success": False, "Name": TaskName, "Folder": root_folder_path}
    try:
        scheduler = win32com.client.Dispatch("Schedule.Service")
        scheduler.Connect()
        task = scheduler.GetFolder(root_folder_path).GetTask(TaskName)
        definition = task.Definition
        action = definition.Actions.Item(1)
        triggers = definition.Triggers.Count
        interval = ""
        for index in range(1, triggers + 1):
            trigger = definition.Triggers.Item(index)
            if trigger.Type == TASK_TRIGGER_TIME:
                interval = trigger.Repetition.Interval
        status.update(
            {
                "Success": True,
                "Path": task.Path,
                "State": task.State,
                "Enabled": bool(definition.Settings.Enabled),
                "LastTaskResult": task.LastTaskResult,
                "UserId": definition.Principal.UserId,
                "RunLevel": definition.Principal.RunLevel,
                "LogonType": definition.Principal.LogonType,
                "Action": action.Path,
                "Arguments": action.Arguments,
                "TriggerCount": triggers,
                "Interval": interval,
                "ExecutionTimeLimit": definition.Settings.ExecutionTimeLimit,
                "AllowHardTerminate": bool(definition.Settings.AllowHardTerminate),
                "DisallowStartIfOnBatteries": bool(
                    definition.Settings.DisallowStartIfOnBatteries
                ),
                "StopIfGoingOnBatteries": bool(
                    definition.Settings.StopIfGoingOnBatteries
                ),
            }
        )
        # 时间字段依赖 win32timezone，单独兜住，避免一个字段把整个状态查询拖垮
        try:
            status["LastRunTime"] = _format_task_time(task.LastRunTime)
        except Exception as e:
            status["LastRunTime"] = f"不可用（{e}）"
        try:
            status["NextRunTime"] = _format_task_time(task.NextRunTime)
        except Exception as e:
            status["NextRunTime"] = f"不可用（{e}）"
    except Exception as e:
        status["Error"] = str(e)
    return status


def Run_Task(TaskName, root_folder_path=DEFAULT_TASK_FOLDER):
    """立即启动任务（使用任务里已存的参数）。"""
    try:
        scheduler = win32com.client.Dispatch("Schedule.Service")
        scheduler.Connect()
        scheduler.GetFolder(root_folder_path).GetTask(TaskName).Run("")
        return {"Success": True}
    except Exception as e:
        return {"Success": False, "Error": str(e)}


def End_Task(TaskName, root_folder_path=DEFAULT_TASK_FOLDER):
    """结束正在运行的任务实例。"""
    try:
        scheduler = win32com.client.Dispatch("Schedule.Service")
        scheduler.Connect()
        scheduler.GetFolder(root_folder_path).GetTask(TaskName).Stop(0)
        return {"Success": True}
    except Exception as e:
        return {"Success": False, "Error": str(e)}


def Create_Persistent_Task(
    TaskName,
    RunPath,
    Arguments="",
    Run_User="SYSTEM",
    root_folder_path=DEFAULT_TASK_FOLDER,
    interval=DEFAULT_REPEAT_INTERVAL,
    start_boundary=None,
):
    """创建常驻任务：启动时 + 任意用户登录时 + 无限期每 interval 一次。

    - 运行身份 Run_User（默认 SYSTEM，服务账户登录类型），最高权限；
    - 关闭"仅在使用交流电源时启动""改用电池电源则停止""运行超时则停止"
      "请求后仍在运行则强制停止"四项；
    - 重复间隔只挂在第三个（时间）触发器上，前两个触发器每次开机/登录各跑一次。
    """
    try:
        scheduler = win32com.client.Dispatch("Schedule.Service")
        scheduler.Connect()
        root_folder = _get_task_folder(scheduler, root_folder_path)
        if root_folder is None:
            return {"Success": False}

        task_def = scheduler.NewTask(0)
        action = task_def.Actions.Create(TASK_ACTION_EXEC)
        action.ID = TaskName
        action.Path = RunPath
        action.Arguments = Arguments

        _apply_settings(task_def, allow_hard_terminate=False)

        principal = task_def.Principal
        principal.UserId = Run_User
        principal.LogonType = (
            TASK_LOGON_SERVICE_ACCOUNT
            if Run_User.upper() == "SYSTEM"
            else TASK_LOGON_INTERACTIVE_TOKEN
        )
        principal.RunLevel = TASK_RUNLEVEL_HIGHEST

        # 1. 系统启动时
        boot = task_def.Triggers.Create(TASK_TRIGGER_BOOT)
        boot.Enabled = True

        # 2. 任意用户登录时（UserId 为空 = 任意用户）
        logon = task_def.Triggers.Create(TASK_TRIGGER_LOGON)
        logon.UserId = "" if Run_User.upper() == "SYSTEM" else Run_User
        logon.Enabled = True

        # 3. 无限期地每 interval 一次
        repeat = task_def.Triggers.Create(TASK_TRIGGER_TIME)
        if start_boundary is None:
            start_boundary = datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
        repeat.StartBoundary = start_boundary
        repeat.Repetition.Interval = interval
        repeat.Repetition.Duration = ""  # 空字符串 = 无限期
        repeat.Enabled = True

        root_folder.RegisterTaskDefinition(
            TaskName,
            task_def,
            TASK_CREATE_OR_UPDATE,
            "",
            "",
            TASK_LOGON_NONE,
        )
        logger.log(f"[任务计划创建]常驻任务创建完成:{TaskName}")
        return {
            "TaskName": TaskName,
            "RunPath": RunPath,
            "Arguments": Arguments,
            "Run_User": Run_User,
            "interval": interval,
            "Success": True,
        }
    except Exception as e:
        logger.log(f"[任务计划创建]常驻任务 {TaskName} 创建失败:{sys.exc_info()}")
        return {"Success": False, "Error": str(e)}
