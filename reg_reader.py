import winreg

import win32api
import win32con
import pywintypes
import win32security

import logger

WRITE_DAC = 0x00040000
WRITE_OWNER = 0x00080000
TAKE_OWNERSHIP = WRITE_OWNER  # TAKE_OWNERSHIP 权限值等同于 WRITE_OWNER
DELETE = 0x00010000
# 根键映射
ROOT_KEYS = {
    "HKEY_LOCAL_MACHINE": winreg.HKEY_LOCAL_MACHINE,
    "HKEY_CURRENT_USER": winreg.HKEY_CURRENT_USER,
    "HKEY_CLASSES_ROOT": winreg.HKEY_CLASSES_ROOT,
    "HKEY_USERS": winreg.HKEY_USERS,
    "HKEY_CURRENT_CONFIG": winreg.HKEY_CURRENT_CONFIG,
    "HKLM": winreg.HKEY_LOCAL_MACHINE,
    "HKCU": winreg.HKEY_CURRENT_USER,
    "HKCR": winreg.HKEY_CLASSES_ROOT,
    "HKU": winreg.HKEY_USERS,
    "HKCC": winreg.HKEY_CURRENT_CONFIG,
}
REG_TYPE_MAP = {
    "REG_SZ": winreg.REG_SZ,
    "REG_EXPAND_SZ": winreg.REG_EXPAND_SZ,
    "REG_DWORD": winreg.REG_DWORD,
    "REG_QWORD": winreg.REG_QWORD,
    "REG_BINARY": winreg.REG_BINARY,
    "REG_MULTI_SZ": winreg.REG_MULTI_SZ,
}


def enable_privilege(priv_name):
    """启用进程权限"""
    hToken = win32security.OpenProcessToken(
        win32api.GetCurrentProcess(),
        win32con.TOKEN_ADJUST_PRIVILEGES | win32con.TOKEN_QUERY,
    )
    privilege_id = win32security.LookupPrivilegeValue(None, priv_name)
    win32security.AdjustTokenPrivileges(
        hToken, False, [(privilege_id, win32con.SE_PRIVILEGE_ENABLED)]
    )


def take_ownership(root_key, sub_path):
    """接管注册表项所有权并赋权限"""
    access = winreg.KEY_READ | winreg.KEY_WOW64_64KEY | WRITE_DAC | TAKE_OWNERSHIP
    with winreg.OpenKey(root_key, sub_path, 0, access) as key:
        handle = key.handle  # 关键：拿到真实的 HKEY 整数句柄

        user_sid = win32security.GetTokenInformation(
            win32security.OpenProcessToken(
                win32api.GetCurrentProcess(), win32con.TOKEN_QUERY
            ),
            win32security.TokenUser,
        )[0]

        win32security.SetSecurityInfo(
            handle,
            win32security.SE_REGISTRY_KEY,
            win32security.OWNER_SECURITY_INFORMATION,
            user_sid,
            None,
            None,
            None,
        )


def recursive_delete_key(root_key, sub_path):
    """递归删除注册表键"""
    try:
        with winreg.OpenKey(
            root_key,
            sub_path,
            0,
            winreg.KEY_READ | winreg.KEY_WRITE | winreg.KEY_WOW64_64KEY,
        ) as key:
            while True:
                try:
                    subkey = winreg.EnumKey(key, 0)
                    recursive_delete_key(root_key, f"{sub_path}\\{subkey}")
                except OSError:
                    break
        winreg.DeleteKeyEx(root_key, sub_path, winreg.KEY_WOW64_64KEY, 0)
    except FileNotFoundError:
        pass


def reg_delete_key_set(key: str, value: str = None):
    """主函数：value=None 删除整个注册表键，否则删除该值"""
    try:
        root_str, sub_path = key.split("\\", 1)
        root_key = ROOT_KEYS[root_str.upper()]
    except Exception as e:
        logger.log(f"[注册表删除]出现错误:{e}")

    try:
        enable_privilege(win32con.SE_TAKE_OWNERSHIP_NAME)
        take_ownership(root_key, sub_path)

        if value is None:
            logger.log(f"[注册表删除]删除键及其子键值: {key}")
            recursive_delete_key(root_key, sub_path)
        else:
            logger.log(f"[注册表删除]删除值: {value}(键: {key})")
            with winreg.OpenKey(
                root_key, sub_path, 0, winreg.KEY_SET_VALUE | winreg.KEY_WOW64_64KEY
            ) as k:
                winreg.DeleteValue(k, value)
    except:
        pass


def reg_delete_key(key: str, value: str = None, sync=True):
    path_split = key.split("\\")
    if (
        path_split[0].upper()
        in (
            "HKCU",
            "HKEY_CURRENT_USER",
            "HKEY_USERS",
            "HKLM",
            "HKEY_LOCAL_MACHINE",
        )
        and sync
    ):
        logger.log(
            "[注册表写入]此注册表操作将同步到 HKEY_USERS\\ 下的所有项 和 HKEY_LOCAL_MACHINE下的同路径"
        )
        try:
            keys = "\\".join(path_split[1::])
            for i in reg_read("HKEY_USERS\\")["Folders"]:
                path_i = "HKEY_USERS\\" + i["name"] + "\\" + keys
                reg_delete_key_set(path_i, value)
            reg_delete_key_set("HKEY_LOCAL_MACHINE\\" + keys, value)
        except:
            pass
    else:
        reg_delete_key_set(key, value)


# 注册表写入函数
def reg_write_set(path: str, name, type_str: str, value):
    try:  # 提权尝试
        root_str, sub_path = path.split("\\", 1)
        root_key = ROOT_KEYS[root_str.upper()]
        enable_privilege(win32con.SE_TAKE_OWNERSHIP_NAME)
        take_ownership(root_key, sub_path)
    except:
        pass

    try:
        logger.log(
            f"[注册表写入]键:{path} ; 值: {name} ; 类型: {type_str} ; 数据: {value}"
        )
        root_key_name, sub_path = path.split("\\", 1)
        root_key = ROOT_KEYS[root_key_name.upper()]
        access = winreg.KEY_SET_VALUE | winreg.KEY_WOW64_64KEY
        type_str = type_str.upper()
        with winreg.CreateKeyEx(root_key, sub_path, 0, access) as key:
            type_str = type_str.upper()
            if type_str == "REG_SZ":
                winreg.SetValueEx(key, name, 0, winreg.REG_SZ, str(value))
            elif type_str == "REG_DWORD":
                winreg.SetValueEx(key, name, 0, winreg.REG_DWORD, int(value))
            elif type_str == "REG_QWORD":
                winreg.SetValueEx(key, name, 0, winreg.REG_QWORD, int(value))
            elif type_str == "REG_EXPAND_SZ":
                winreg.SetValueEx(key, name, 0, winreg.REG_EXPAND_SZ, str(value))
            elif type_str == "REG_MULTI_SZ":
                if isinstance(value, str):
                    # 自动分割换行文本为列表
                    value = [v.strip() for v in value.splitlines() if v.strip()]
                elif not isinstance(value, list):
                    logger.log("[注册表写入] REG_MULTI_SZ 类型应为 list 或多行字符串")
                    return
                winreg.SetValueEx(key, name, 0, winreg.REG_MULTI_SZ, value)
            elif type_str == "REG_BINARY":
                if isinstance(value, str):
                    try:
                        # 支持 hex 字符串如 "01 02 03 FF"
                        value = bytes.fromhex(value)
                    except ValueError:
                        logger.log(
                            "[注册表写入] REG_BINARY 类型的十六进制字符串格式错误"
                        )
                        return
                elif not isinstance(value, (bytes, bytearray)):
                    logger.log("[注册表写入] REG_BINARY 类型应为 hex 字符串或 bytes")
                    return
                winreg.SetValueEx(key, name, 0, winreg.REG_BINARY, value)
            else:
                logger.log(f"[注册表写入] 不支持的数据类型: {type_str}")
                return
    except Exception as e:
        logger.log(f"[注册表写入] 出现错误: {e}")


# 注册表读取函数
def reg_read(path: str):
    try:  # 提权尝试
        root_str, sub_path = path.split("\\", 1)
        root_key = ROOT_KEYS[root_str.upper()]
        enable_privilege(win32con.SE_TAKE_OWNERSHIP_NAME)
        take_ownership(root_key, sub_path)
    except:
        pass

    result = {
        "Target": path,
        "Folders": [],
        "keys": [],
    }

    try:
        root_key_name, sub_path = path.split("\\", 1)
        root_key = ROOT_KEYS[root_key_name.upper()]
        access = winreg.KEY_READ | winreg.KEY_WOW64_64KEY
        logger.log(f"[注册表读取]键: {path}")
        with winreg.OpenKey(root_key, sub_path, 0, access) as key:
            # 子项（Folders）
            try:
                i = 0
                while True:
                    subkey_name = winreg.EnumKey(key, i)
                    result["Folders"].append({"name": subkey_name, "default": "None"})
                    i += 1
            except OSError:
                pass

            # 键值（keys）
            try:
                i = 0
                while True:
                    name, value, type_id = winreg.EnumValue(key, i)
                    type_name = {
                        winreg.REG_SZ: "REG_SZ",
                        winreg.REG_DWORD: "REG_DWORD",
                        winreg.REG_EXPAND_SZ: "REG_EXPAND_SZ",
                    }.get(type_id, f"TYPE_{type_id}")
                    result["keys"].append(
                        {"name": name, "type": type_name, "value": str(value)}
                    )
                    i += 1
            except OSError:
                pass

    except:
        return result
    return result


def reg_write(path: str, name, type_str: str, value, sync=True, sync_hklm=True):
    path_split = path.split("\\")
    keys = "\\".join(path_split[1::])
    if (
        path_split[0].upper()
        in (
            "HKCU",
            "HKEY_CURRENT_USER",
            "HKEY_USERS",
            "HKLM",
            "HKEY_LOCAL_MACHINE",
        )
        and sync
    ):
        logger.log(
            "[注册表写入]此注册表操作将同步到 HKEY_USERS\\ 下的所有项 和 HKEY_LOCAL_MACHINE下的同路径"
        )
        try:
            for i in reg_read("HKEY_USERS\\")["Folders"]:
                path_i = "HKEY_USERS\\" + i["name"] + "\\" + keys
                reg_write_set(path_i, name, type_str, value)
        except:
            pass
    else:
        reg_write_set(path, name, type_str, value)
    if sync_hklm:
        reg_write_set("HKEY_LOCAL_MACHINE\\" + keys, name, type_str, value)


def reg_value_exists(path: str, name: str) -> bool:
    try:  # 提权尝试
        root_str, sub_path = path.split("\\", 1)
        root_key = ROOT_KEYS[root_str.upper()]
        enable_privilege(win32con.SE_TAKE_OWNERSHIP_NAME)
        take_ownership(root_key, sub_path)
    except:
        pass

    root_key_name, sub_path = path.split("\\", 1)
    root_key = ROOT_KEYS[root_key_name.upper()]
    access = winreg.KEY_READ | winreg.KEY_WOW64_64KEY

    try:
        with winreg.OpenKey(root_key, sub_path, 0, access) as key:
            try:
                winreg.QueryValueEx(key, name)
                return True
            except FileNotFoundError:
                return False
    except FileNotFoundError:
        return False
