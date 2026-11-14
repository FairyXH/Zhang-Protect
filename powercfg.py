import ctypes
import subprocess
from ctypes import wintypes
import winreg
import uuid
import os
import logger
import reg_reader
from main_paths import use_TurboSwitch, TurboDisabled
from cmd_runner import RunWrapper

# 加载 powrprof.dll 库
powrprof = ctypes.WinDLL("powrprof.dll")
# 定义 PowerWriteDCValueIndex API
PowerWriteACValueIndex = powrprof.PowerWriteACValueIndex
PowerWriteACValueIndex.argtypes = [
    wintypes.HANDLE,
    ctypes.POINTER(ctypes.c_byte * 16),  # SchemeGuid
    ctypes.POINTER(ctypes.c_byte * 16),  # SubGroupOfPowerSettingsGuid
    ctypes.POINTER(ctypes.c_byte * 16),  # PowerSettingGuid
    wintypes.DWORD,  # Value
]
PowerWriteACValueIndex.restype = wintypes.DWORD
PowerWriteDCValueIndex = powrprof.PowerWriteDCValueIndex
PowerWriteDCValueIndex.argtypes = PowerWriteACValueIndex.argtypes
PowerWriteDCValueIndex.restype = wintypes.DWORD

PowerDuplicateScheme = powrprof.PowerDuplicateScheme
PowerDuplicateScheme.argtypes = [
    ctypes.c_void_p,
    ctypes.POINTER(ctypes.c_byte * 16),
    ctypes.POINTER(ctypes.POINTER(ctypes.c_byte * 16)),
]
PowerDuplicateScheme.restype = ctypes.c_uint

PowerGetActiveScheme = powrprof.PowerGetActiveScheme
PowerGetActiveScheme.argtypes = [
    ctypes.c_void_p,
    ctypes.POINTER(ctypes.POINTER(ctypes.c_byte * 16)),
]
PowerGetActiveScheme.restype = ctypes.c_uint

PowerSetActiveScheme = powrprof.PowerSetActiveScheme
PowerSetActiveScheme.argtypes = [wintypes.HANDLE, ctypes.POINTER(ctypes.c_byte * 16)]
PowerSetActiveScheme.restype = wintypes.DWORD
POWER_PLANS_GUID = {
    "SLEEPY": "a1841308-3541-4fab-bc81-f71556f20b4a",  # 节能
    "BALANCED": "381b4222-f694-41f0-9685-ff5bb260df2e",  # 平衡
    "HIGH_PERFORMANCE": "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c",  # 高性能
    "ULTIMATE_PERFORMANCE": "e9a42b02-d5df-448d-aa00-03f14749eb61",  # 卓越性能
}

PowerReadACValueIndex = powrprof.PowerReadACValueIndex
PowerReadACValueIndex.argtypes = [
    wintypes.HANDLE,
    ctypes.POINTER(ctypes.c_byte * 16),  # SchemeGuid
    ctypes.POINTER(ctypes.c_byte * 16),  # SubGroupGuid
    ctypes.POINTER(ctypes.c_byte * 16),  # SettingGuid
    ctypes.POINTER(wintypes.DWORD),  # Value
]
PowerReadACValueIndex.restype = wintypes.DWORD

PowerReadDCValueIndex = powrprof.PowerReadDCValueIndex
PowerReadDCValueIndex.argtypes = PowerReadACValueIndex.argtypes
PowerReadDCValueIndex.restype = wintypes.DWORD


# === Power Setting Subgroup GUIDs ===
POWER_SUBGROUPS = {
    "SUB_SLEEP": "{238C9FA8-0AAD-41ED-83F4-97BE242C8F20}",  # 睡眠
    "SUB_VIDEO": "{7516B95F-F776-4464-8C53-06167F40CC99}",  # 显示器
    "SUB_DISK": "{0012EE47-9041-4B5D-9B77-535FBA8B1442}",  # 硬盘
    "SUB_BUTTONS": "{4F971E89-EEBD-4455-A8DE-9E59040E7347}",  # 电源按钮 / 睡眠按钮 / 盖子
    "SUB_PROCESSOR": "{54533251-82BE-4824-96C1-47B60B740D00}",  # 处理器
    "SUB_AWAYMODE": "{5D3E9A59-E9D5-4B00-A6BD-FF34FF516548}",  # 离开模式
    "SUB_NONE": "{fea3413e-7e05-4911-9a71-700331f1c294}",
}

# === Power Setting GUIDs ===
POWER_SETTINGS = {
    # --- Sleep ---
    "STANDBYIDLE": "{29F6C1DB-86DA-48C5-9FDB-F2B67B1F44DA}",  # Sleep after
    "HIBERNATEIDLE": "{9D7815A6-7EE4-497E-8888-515A05F02364}",  # Hibernate after
    "ALLOWAWAYMODE": "{98A7F580-01F7-48AA-9C0F-44352B5D0C0E}",  # Allow away mode
    # --- Video ---
    "VIDEOIDLE": "{3C0BC021-C8A8-4E07-A973-6B14CBCB2B7E}",  # Turn off display
    # --- Disk ---
    "DISKIDLE": "{6738E2C4-E8A5-4A42-B16A-E040E769756E}",  # Disk idle timeout
    # --- Buttons / Lid ---
    "PBUTTONACTION": "{7648EFA3-DD9C-4E3E-B566-50F929386280}",  # Power button action
    "SBUTTONACTION": "{96996BC0-AD50-47EC-923B-6F41874DD9EB}",  # Sleep button action
    "LIDACTION": "{5CA83367-6E45-459F-A27B-476B1D01C936}",  # Lid close action
    # --- Processor ---
    "PROCTHROTTLEMAX": "{BC5038F7-23E0-4960-96DA-33ABAF5935EC}",  # Max processor state
    "PROCTHROTTLEMIN": "{893DEE8E-2BEF-41E0-89C6-B55D0929964C}",  # Min processor state
    # --- Away Mode ---
    "AWAYMODE": "{25DFA149-5DD1-4736-B5AB-E8A37B5B8187}",  # Away mode
    "RTCWAKE": "{bd3b718a-0680-4d9d-8ab2-e1d2b4ac806d}",
    "SYSTEMREQUIRED": "{a4b195f5-8225-47d8-8012-9d41369786e2}",
    "ALLOWSTANDBY": "{abfc2519-3608-4c2a-94ea-171b0ed546ab}",
    "HYBRIDSLEEP": "{94ac6d29-73ce-41a6-809f-6363ba21b47e}",
    "VIDEONORMALLEVEL": "{aded5e82-b909-4619-9949-f5d71dac0bcb}",
    "PERFBOOSTMODE": "{be337238-0d82-4146-a960-4f3749d470c7}",
}


def guid_bytes(guid_str: str):
    guid_obj = uuid.UUID(guid_str.strip().strip("{}"))
    return ctypes.cast(
        ctypes.pointer(ctypes.create_string_buffer(guid_obj.bytes_le)),
        ctypes.POINTER(ctypes.c_byte * 16),
    )


def get_current_plan_guid() -> str:
    """获取当前活动电源计划 GUID"""
    p_guid = ctypes.POINTER(ctypes.c_byte * 16)()
    res = PowerGetActiveScheme(None, ctypes.byref(p_guid))
    if res != 0:
        logger.log(f"[电源计划] 获取当前电源计划失败: {res}")
        return None
    guid_bytes_arr = bytes(p_guid.contents)
    return str(uuid.UUID(bytes_le=guid_bytes_arr))


def get_current_plan_brightness() -> dict:
    """
    读取当前电源计划中保存的亮度策略值

    :return: {"AC": int, "DC": int}  (0~100)
    """
    result = {"AC": None, "DC": None}
    try:
        scheme_guid = get_current_plan_guid()
        scheme = guid_bytes(scheme_guid)
        subgroup = guid_bytes(POWER_SUBGROUPS["SUB_VIDEO"])
        setting = guid_bytes(POWER_SETTINGS["VIDEONORMALLEVEL"])

        ac_value = wintypes.DWORD()
        dc_value = wintypes.DWORD()

        # AC
        if (
            PowerReadACValueIndex(
                None, scheme, subgroup, setting, ctypes.byref(ac_value)
            )
            == 0
        ):
            result["AC"] = int(ac_value.value)

        # DC
        if (
            PowerReadDCValueIndex(
                None, scheme, subgroup, setting, ctypes.byref(dc_value)
            )
            == 0
        ):
            result["DC"] = int(dc_value.value)

    except Exception:
        pass

    return result


def auto_set_plan_brightness(guid_str):
    ac_brightness = 0
    dc_brightness = 0
    try:
        brightness = get_current_plan_brightness()
        ac_brightness = brightness.get("AC")
        dc_brightness = brightness.get("DC")
        if ac_brightness is not None:
            modify_power_plan(
                guid_str,
                POWER_SUBGROUPS["SUB_VIDEO"],
                POWER_SETTINGS["VIDEONORMALLEVEL"],
                int(ac_brightness),
                True,  # AC
            )

        if dc_brightness is not None:
            (
                guid_str,
                POWER_SUBGROUPS["SUB_VIDEO"],
                POWER_SETTINGS["VIDEONORMALLEVEL"],
                int(dc_brightness),
                False,  # DC
            )
    except Exception as e:
        logger.log(f"[电源计划]计划 {guid_str} 亮度写入失败:{e}")
    finally:
        logger.log(
            f"[电源计划]计划 {guid_str} 亮度写入成功。AC:{ac_brightness} DC:{dc_brightness}"
        )


def set_power_plan_api(guid_str: str) -> bool:
    """
    切换电源计划，并保证亮度不发生变化
    """
    try:
        auto_set_plan_brightness(guid_str)
        guid_ptr = guid_bytes(guid_str)
        res = PowerSetActiveScheme(None, guid_ptr)
        if res != 0:
            logger.log(f"[电源计划] API切换失败，GUID={guid_str}")
            return False

        logger.log(f"[电源计划] API切换成功，GUID={guid_str}")
        return True

    except Exception as e:
        logger.log(f"[电源计划] 切换异常：{e}")
        return False


# 记录注册/复制后的 GUID
REGISTERED_GUIDS = {}


def duplicate_scheme_if_needed(base_guid: str) -> str:
    """复制计划，返回新注册 GUID"""
    new_guid_ptr = ctypes.POINTER(ctypes.c_byte * 16)()
    res = PowerDuplicateScheme(None, guid_bytes(base_guid), ctypes.byref(new_guid_ptr))
    if res != 0:
        logger.log(f"[电源计划] 复制电源计划失败: {res}")
        return None
    guid_bytes_arr = bytes(new_guid_ptr.contents)
    new_guid_str = str(uuid.UUID(bytes_le=guid_bytes_arr))
    logger.log(f"[电源计划] 已复制电源计划 {base_guid} → 新注册 GUID: {new_guid_str}")
    return new_guid_str


def set_power_plan_cmd(guid_str: str) -> bool:
    """CMD兜底切换"""
    try:
        auto_set_plan_brightness(guid_str)
        subprocess.run(
            ["powercfg", "/SETACTIVE", guid_str], check=True, capture_output=True
        )
        logger.log(f"[电源计划] CMD切换成功，GUID={guid_str}")
        return True
    except subprocess.CalledProcessError as e:
        logger.log(f"[电源计划] CMD切换失败: {e.stderr.decode(errors='ignore')}")
        return False


def get_current_plan_name() -> str:
    """
    获取当前活动电源计划名称

    返回值:
        str: 当前电源计划的名称，值与 powercfg_change() 的 plan 参数一致：
            - 'SLEEPY'
            - 'BALANCED'
            - 'HIGH_PERFORMANCE'
            - 'ULTIMATE_PERFORMANCE'
            - 'UNKNOWN'  如果当前 GUID 未知
    """
    current_guid = get_current_plan_guid()
    if not current_guid:
        return "UNKNOWN"

    # 先检查 REGISTERED_GUIDS（复制注册的计划）
    for plan_name, guid in REGISTERED_GUIDS.items():
        if current_guid.lower() == guid.lower():
            return plan_name

    # 再检查原始 POWER_PLANS_GUID
    for plan_name, guid in POWER_PLANS_GUID.items():
        if current_guid.lower() == guid.lower():
            return plan_name

    return "UNKNOWN"


def powercfg_change(plan: str) -> str:
    """
    切换电源计划

    参数:
        plan (str): 目标电源计划，可选值为：
            - 'SLEEPY'           节能模式
            - 'BALANCED'         平衡模式
            - 'HIGH_PERFORMANCE' 高性能模式
            - 'ULTIMATE_PERFORMANCE' 卓越性能模式（高级/隐藏计划）

    返回值:
        str: 是否切换成功
            - 'UnKnow'  未知电源计划
            - 'UnChanged' 已是目标计划,未切换
            - 'Changed' 任意方案切换成功
            - 'Fail' 所有方案均切换失败
    """
    plan = plan.upper()
    if plan not in POWER_PLANS_GUID:
        logger.log(f"[电源计划] 未知电源计划: {plan}")
        return "UnKnow"

    base_guid = POWER_PLANS_GUID[plan]
    target_guid = REGISTERED_GUIDS.get(plan, base_guid)

    # 检查当前计划是否已经是目标
    current_guid = get_current_plan_guid()
    if current_guid and current_guid.lower() == target_guid.lower():
        logger.log(f"[电源计划] 当前已是目标电源计划 {plan}，无需切换")
        return "UnChanged"

    # 先 清理注册表
    try:
        subprocess.run(
            ["powercfg", "-restoredefaultschemes"], check=True, capture_output=True
        )
    except:
        pass

    # 先 API 尝试
    if set_power_plan_api(target_guid):
        REGISTERED_GUIDS[plan] = target_guid
        return "Changed"

    # API失败，尝试复制注册再切换
    new_guid = duplicate_scheme_if_needed(base_guid)
    if new_guid and set_power_plan_api(new_guid):
        REGISTERED_GUIDS[plan] = new_guid
        return "Changed"

    # CMD兜底
    logger.log(f"[电源计划] API切换失败，尝试CMD兜底 {plan}...")
    if set_power_plan_cmd(target_guid) or (new_guid and set_power_plan_cmd(new_guid)):
        REGISTERED_GUIDS[plan] = new_guid or target_guid
        return "Changed"

    # 卓越性能或其他计划失败，尝试降级高性能
    if plan == "ULTIMATE_PERFORMANCE":
        logger.log("[电源计划] 尝试降级到高性能...")
        high_guid = REGISTERED_GUIDS.get(
            "HIGH_PERFORMANCE", POWER_PLANS_GUID["HIGH_PERFORMANCE"]
        )
        if set_power_plan_api(high_guid) or set_power_plan_cmd(high_guid):
            REGISTERED_GUIDS["HIGH_PERFORMANCE"] = high_guid
            return "Changed"

    logger.log(f"[电源计划] 切换 {plan} 失败")
    return "Fail"


def refresh_current_power_plan(scheme_guid: str):
    """
    刷新当前电源计划，使修改的设置立即生效，不切换计划。
    :param scheme_guid: 当前激活的电源计划 GUID
    """
    scheme = guid_bytes(scheme_guid)
    result = PowerSetActiveScheme(None, scheme)
    logger.log(f"电源计划刷新{"失败" if result != 0 else "成功"}: {scheme_guid}")


__all__ = ["get_all_power_plans"]


def get_all_power_plans():
    """
    更完整地复刻 powercfg /list 功能：
    - 注册表获取所有电源计划 GUID
    - PowerReadFriendlyName 获取名称
    - PowerGetActiveScheme 获取当前方案
    - 调用 powercfg /list 验证校对，仅保留存在的项

    返回：
        List: 包含当前所有电源计划GUID
    """
    result = {}

    # 注册表列出方案 GUID
    try:
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes",
        ) as key:
            i = 0
            while True:
                try:
                    subkey = winreg.EnumKey(key, i)
                    result[subkey.lower()] = {
                        "guid": subkey.lower(),
                        "name": "(未知)",
                        "active": False,
                    }
                    i += 1
                except OSError:
                    break
    except FileNotFoundError:
        pass

    # PowerReadFriendlyName 获取名称
    PowerReadFriendlyName = powrprof.PowerReadFriendlyName
    PowerReadFriendlyName.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(ctypes.c_byte * 16),
        ctypes.POINTER(ctypes.c_byte * 16),
        ctypes.POINTER(ctypes.c_byte * 16),
        wintypes.LPWSTR,
        ctypes.POINTER(wintypes.DWORD),
    ]
    PowerReadFriendlyName.restype = wintypes.DWORD

    def get_friendly_name(guid_str):
        guid = uuid.UUID(guid_str)
        gbuf = (ctypes.c_byte * 16).from_buffer_copy(guid.bytes_le)
        buflen = wintypes.DWORD(1024)
        buf = ctypes.create_unicode_buffer(buflen.value)
        res = PowerReadFriendlyName(
            None, ctypes.byref(gbuf), None, None, buf, ctypes.byref(buflen)
        )
        return buf.value if res == 0 else None

    for guid in list(result.keys()):
        name = get_friendly_name(guid)
        if name:
            result[guid]["name"] = name

    guid_ptr = ctypes.POINTER(ctypes.c_byte * 16)()
    if PowerGetActiveScheme(None, ctypes.byref(guid_ptr)) == 0:
        active_guid = str(uuid.UUID(bytes_le=bytes(guid_ptr.contents))).lower()
        if active_guid in result:
            result[active_guid]["active"] = True
        else:
            result[active_guid] = {
                "guid": active_guid,
                "name": get_friendly_name(active_guid) or "(未知)",
                "active": True,
            }

    power_cfg_test = RunWrapper("powercfg.exe /LIST").read()
    return_ls = []
    for i in result.keys():
        if i in power_cfg_test:
            return_ls.append(i)

    return return_ls


def resolve_guid(value: str, mapping: dict) -> str:
    """
    兼容：
    - GUID 字符串
    - powercfg 别名
    """
    if not value:
        logger.log("GUID/别名不能为空")
        return ""

    v = value.strip()

    # 已经是 GUID
    if v.startswith("{") and v.endswith("}"):
        return v

    # 是别名
    if v in mapping:
        return mapping[v]

    logger.log(f"无法识别的 GUID 或别名: {value}")
    return ""


def modify_power_plan(
    scheme_guid: str,
    subgroup: str,
    setting: str,
    value: int,
    is_ac: bool = True,
):
    """
    兼容 powercfg 别名 / GUID 的 PowerWrite API 封装

    :param scheme_guid: 电源计划 GUID（必须是 GUID）
    :param subgroup: 子组 GUID 或别名（如 SUB_SLEEP）
    :param setting: 设置项 GUID 或别名（如 STANDBYIDLE）
    :param value: DWORD 数值（0 = 从不）
    :param is_ac: True=AC, False=DC
    """

    # 解析 GUID
    scheme = guid_bytes(scheme_guid)

    subgroup_guid = resolve_guid(subgroup, POWER_SUBGROUPS)
    setting_guid = resolve_guid(setting, POWER_SETTINGS)

    subgroup_ptr = guid_bytes(subgroup_guid)
    setting_ptr = guid_bytes(setting_guid)

    if is_ac:
        ret = PowerWriteACValueIndex(
            None,
            scheme,
            subgroup_ptr,
            setting_ptr,
            wintypes.DWORD(value),
        )
    else:
        ret = PowerWriteDCValueIndex(
            None,
            scheme,
            subgroup_ptr,
            setting_ptr,
            wintypes.DWORD(value),
        )

    if ret != 0:
        logger.log(f"PowerWrite failed, error code: {ret}")


def disable_all_wake_sources():
    """
    禁用所有可唤醒设备（wake_armed）
    """
    logger.log("正在禁用所有可唤醒设备")
    try:
        proc = subprocess.run(
            ["powercfg", "-devicequery", "wake_armed"],
            capture_output=True,
            text=True,
            check=False,
        )
        devices = proc.stdout.splitlines()
    except Exception:
        devices = []

    for dev in devices:
        dev = dev.strip()
        if not dev:
            continue
        try:
            subprocess.run(
                ["powercfg", "-devicedisablewake", dev],
                capture_output=True,
                check=False,
            )
        except Exception:
            continue


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
    flags = {}
    flags["ACLineStatus"] = status.ACLineStatus
    flags["BatteryFlag"] = status.BatteryFlag
    flags["BatteryLifePercent"] = status.BatteryLifePercent
    flags["BatteryLifeTime"] = status.BatteryLifeTime
    flags["BatteryFullLifeTime"] = status.BatteryFullLifeTime
    return flags


def auto_powercfg_setting(
    get_str_mode=False, guid=None, hibernate_enable=True, Only_Apply_Settings=False
):
    """
    修改电源选项设置
    param:
    get_str_mode:改为获取cmd命令列表 GUID使用占位符[guid]
    """
    if guid is None:
        current_plan_guid = get_current_plan_guid()  # 只修改当前计划
    else:
        current_plan_guid = guid  # 用户指定修改的guid
    powercfg_settings_list = [
        # ========================
        # 睡眠 / 休眠（AC + DC）
        # ========================
        # 睡眠状态下多久进入休眠（30 分钟 / 从不）
        ("SUB_SLEEP", "HIBERNATEIDLE", "1800" if hibernate_enable else "0", True),
        ("SUB_SLEEP", "HIBERNATEIDLE", "1800" if hibernate_enable else "0", False),
        # 使计算机进入睡眠状态
        ("SUB_SLEEP", "STANDBYIDLE", "0" if not hibernate_enable else "0", True),
        ("SUB_SLEEP", "STANDBYIDLE", "0" if not hibernate_enable else "900", False),
        # 允许离开模式（Away Mode）
        # 启用休眠：否(0) | 禁用休眠：是(1)
        ("SUB_SLEEP", "AWAYMODE", "0" if hibernate_enable else "1", True),
        ("SUB_SLEEP", "AWAYMODE", "0" if hibernate_enable else "1", False),
        # ========================
        # 电源按钮 / 睡眠按钮 / 盖子
        # ========================
        # 电源按钮：不采取任何操作
        ("SUB_BUTTONS", "PBUTTONACTION", "0", True),
        ("SUB_BUTTONS", "PBUTTONACTION", "0", False),
        # 睡眠按钮：不采取任何操作
        ("SUB_BUTTONS", "SBUTTONACTION", "0", True),
        ("SUB_BUTTONS", "SBUTTONACTION", "0", False),
        # 关闭盖子：
        # 启用休眠：睡眠(1)
        # 禁用休眠：不执行任何操作(0)
        ("SUB_BUTTONS", "LIDACTION", "1" if hibernate_enable else "0", True),
        ("SUB_BUTTONS", "LIDACTION", "1" if hibernate_enable else "0", False),
        # ========================
        # 显示器（AC / DC）
        # ========================
        # 关闭显示器（AC：从不）
        ("SUB_VIDEO", "VIDEOIDLE", "0", True),
        # 关闭显示器（DC：5 分钟）
        ("SUB_VIDEO", "VIDEOIDLE", "300", False),
        # ========================
        # 处理器性能
        # ========================
        # 处理器最大性能（AC：100%）
        (
            "SUB_PROCESSOR",
            "PROCTHROTTLEMAX",
            (
                "99"
                if (
                    (not get_str_mode)
                    and os.path.isfile(use_TurboSwitch)
                    and os.path.isfile(TurboDisabled)
                )
                else "100"
            ),
            True,
        ),  # 兼容睿频控制器
        # 处理器最大性能（DC：99%）
        ("SUB_PROCESSOR", "PROCTHROTTLEMAX", "99", False),
        # 处理器性能提升模式（AC：1）
        (
            "SUB_PROCESSOR",
            "PERFBOOSTMODE",
            (
                "0"
                if (
                    (not get_str_mode)
                    and os.path.isfile(use_TurboSwitch)
                    and os.path.isfile(TurboDisabled)
                )
                else "1"
            ),
            True,
        ),  # 兼容睿频控制器
        # 处理器性能提升模式（DC：0）
        ("SUB_PROCESSOR", "PERFBOOSTMODE", "0", False),
        ("SUB_SLEEP", "RTCWAKE", "0", True),  # AC 禁止唤醒
        ("SUB_SLEEP", "RTCWAKE", "0", False),  # DC 禁止唤醒
        (
            "SUB_SLEEP",
            "SYSTEMREQUIRED",
            "0",
            True,
        ),  # AC 应用程序系统所需的请求将被忽略。
        (
            "SUB_SLEEP",
            "SYSTEMREQUIRED",
            "0",
            False,
        ),  # DC 应用程序系统所需的请求将被忽略。
        ("SUB_SLEEP", "ALLOWSTANDBY", "1", True),  # AC 允许睡眠
        ("SUB_SLEEP", "ALLOWSTANDBY", "1", False),  # DC 允许睡眠
        ("SUB_SLEEP", "HYBRIDSLEEP", "1", True),  # AC 允许混合睡眠
        ("SUB_SLEEP", "HYBRIDSLEEP", "1", False),  # DC 允许混合睡眠
        (
            "SUB_NONE",
            "{f15576e8-98b7-4186-b944-eafa664402d9}",
            "0",
            True,
        ),  # AC 禁用S0联网
        (
            "SUB_NONE",
            "{f15576e8-98b7-4186-b944-eafa664402d9}",
            "0",
            False,
        ),  # DC 禁用S0联网
    ]
    cmd_str = []
    if get_str_mode:
        for setting in powercfg_settings_list:
            cmd = f"powercfg {"/setacvalueindex" if bool(setting[3]) else "/setdcvalueindex"} [guid] {setting[0]} {setting[1]} {setting[2]}"
            cmd_str.append(cmd)
        return cmd_str
    for j in powercfg_settings_list:  # 电源设置
        grp_guid = j[0]
        set_guid = j[1]
        ser_value_b = j[2]
        is_ac = bool(j[3])
        if ser_value_b.lower().startswith("0x"):
            ser_value = int(ser_value_b, 16)
        else:
            ser_value = int(ser_value_b)
        cmd = f"powercfg {"/setacvalueindex" if is_ac else "/setdcvalueindex"} {current_plan_guid} {grp_guid} {set_guid} {ser_value_b}"
        logger.log(
            f"[电源设置]正在设置:{grp_guid} --> {set_guid} --> {ser_value_b} --> AC:{is_ac}"
        )
        try:
            modify_power_plan(current_plan_guid, grp_guid, set_guid, ser_value, is_ac)
        except Exception as e:
            logger.log(f"[电源设置]API接口设置异常,使用命令行执行:{e}")
            RunWrapper(cmd)
        finally:
            logger.log(
                f"[电源设置]API接口设置完毕:{grp_guid} --> {set_guid} --> {ser_value_b} --> AC:{is_ac}"
            )
    if Only_Apply_Settings:
        return ["True"]
    reg_reader.reg_write(
        "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Task Scheduler",
        "DisableWakeToRun",
        "reg_dword",
        1,
    )  # 禁止任务计划唤醒
    disable_all_wake_sources()  # 禁用所有唤醒器
    logger.log(f"[电源设置]当前计划 [{current_plan_guid}] 成功应用配置。")
    return ["True"]
