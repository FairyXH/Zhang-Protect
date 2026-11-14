import win32com.client
import logger

UPDATE_KEYWORDS = [
    "update",
    "upgrade",
    "uso",
    "orchestrator",
    "medic",
    "windowsupdate",
    "edgeupdate",
    "install",
    "sih",
]


WHITE_LIST = [
    "ZhangProtect",
]


def is_update_task(name, path, action_path=""):

    text = (name + " " + path + " " + action_path).lower()

    for item in WHITE_LIST:
        if item.lower() in text:
            return False

    for key in UPDATE_KEYWORDS:
        if key in text:
            return True

    return False


def scan_folder(folder):

    # 扫描任务
    try:
        tasks = folder.GetTasks(0)

        for task in tasks:

            try:
                name = task.Name
                path = task.Path

                action_path = ""

                try:
                    for action in task.Definition.Actions:
                        action_path += str(action.Path)
                except:
                    pass

                if is_update_task(name, path, action_path):

                    if task.Enabled:

                        logger.log(f"[任务计划禁用] {path}")

                        task.Enabled = False

            except Exception as e:
                logger.log(f"[任务处理失败]{e}")

    except Exception:
        pass

    # 递归子目录
    try:
        folders = folder.GetFolders(0)

        for sub in folders:
            scan_folder(sub)

    except:
        pass


def disable_update_tasks():

    logger.log("[任务计划]开始扫描")

    scheduler = win32com.client.Dispatch("Schedule.Service")

    scheduler.Connect()

    root = scheduler.GetFolder("\\")

    scan_folder(root)

    logger.log("[任务计划]扫描完成")
