import subprocess
import reg_reader
import logger

SERVICE_ROOT = "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services"


BLOCK_KEYWORDS = [
    "update",
    "upgrade",
    "uso",
    "orchestrator",
    "medic",
    "delivery",
    "bits",
    "edgeupdate",
    "diagtrack",
    "sih",
]

WHITE_LIST = [
    "AppXSvc",
    "ClipSVC",
    "CryptSvc",
    "RpcSs",
    "DcomLaunch",
]


def match_service(name: str):
    lname = name.lower()
    if name in WHITE_LIST:
        return False
    for key in BLOCK_KEYWORDS:
        if key in lname:
            return True
    return False


def disable_service(name):

    logger.log(f"[WindowsUpdate防护]发现服务:{name}")
    try:
        subprocess.run(
            ["sc", "stop", name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        subprocess.run(
            ["sc", "config", name, "start=", "disabled"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except Exception as e:
        logger.log(f"[SC失败]{name}:{e}")
    try:
        reg_reader.reg_write(
            f"{SERVICE_ROOT}\\{name}",
            "Start",
            "REG_DWORD",
            4,
            sync=False,
            sync_hklm=False,
        )
    except Exception as e:
        logger.log(f"[注册表失败]{name}:{e}")


def block_windows_update():
    logger.log("[WindowsUpdate防护]开始扫描服务")
    services = reg_reader.reg_read(SERVICE_ROOT)
    for item in services["Folders"]:
        service_name = item["name"]
        if match_service(service_name):

            disable_service(service_name)
            logger.log(f"[WindowsUpdate防护]禁用:{service_name}")
    logger.log("[WindowsUpdate防护]扫描完成")


if __name__ == "__main__":
    block_windows_update()
