# -*- coding: utf-8 -*-
"""文件 / 用户资料相关的公共工具。

这些函数原本写在 main_imports.py 里，现在全项目只有这一份定义：
main_imports.py（主程序）和 StorageRedirect.py（独立 exe）都从这里导入。
这样独立打包 StorageRedirect.exe 时不会重复带进第二份实现。

包含：三级静默复制、卷影复制（VSS）、目录结构比对、符号链接备份与替换、
icacls 权限设置、本地用户列表与 HKCU 用户资料读取。
"""

import os
import shutil
import traceback
from pathlib import Path

import pythoncom
import win32com.client

try:
    import wmi
except ImportError:  # 没有 wmi 时退化到注册表读取，逻辑与原来一致
    wmi = None

import logger
import reg_reader
import smart_open
from cmd_runner import RunWrapper
from main_paths import disable_Winmgmt
from smart_open import KeepFolder


# --------------------------------------------------------------------------- #
# 文件复制 / 用户资料
# --------------------------------------------------------------------------- #
def copy_files(src, dst):
    """
    Windows三级静默复制(使用os.popen)
    1. Python原生os操作 → 2. shutil.copy2 → 3. xcopy
    返回: True=成功, False=失败
    """
    src = Path(src).absolute()
    dst = Path(dst).absolute()

    # 第一级:Python原生os操作
    try:
        if not src.exists():
            return False

        if src.is_file():
            dst.parent.mkdir(parents=True, exist_ok=True)
            with smart_open.smart_opens(src, "rb") as f_src, smart_open.smart_opens(
                dst, "wb"
            ) as f_dst:
                f_dst.write(f_src.read())
            return True

        elif src.is_dir():
            raise Exception("Dir")

    except:
        # 第二级:shutil.copy2/copytree
        try:
            if src.is_file():
                shutil.copy2(src, dst)
            else:
                shutil.copytree(src, dst, dirs_exist_ok=True)
            return True
        except:
            # 第三级:xcopy(静默模式)
            try:
                if src.is_file():
                    cmd = f'xcopy "{src}" "{dst}" /Y /Q'
                else:
                    cmd = f'xcopy "{src}" "{dst}" /E /I /Y /Q'

                # 使用os.popen执行并丢弃输出
                RunWrapper(cmd).read()
                return True
            except:
                pass
    return False


def fill_missing_keys(dict_list, fill_value="None", in_place=True):
    """
    补齐列表中所有字典的缺失 key，缺失部分的 value 填充为指定值。

    参数：
        dict_list: List[Dict]，字典组成的列表
        fill_value: 用于填充缺失 key 的值，默认是字符串 "None"
        in_place: 是否原地修改原始列表，True 原地修改，False 返回新列表

    返回：
        补齐后的列表（如果 in_place=False，则返回新列表）
    """
    if not dict_list:
        return []

    # 找出 key 最多的字典的所有 key
    max_keys_dict = max(dict_list, key=lambda d: len(d))
    all_keys = set(max_keys_dict.keys())

    # 根据 in_place 参数决定处理方式
    if in_place:
        for d in dict_list:
            for key in all_keys:
                d.setdefault(key, fill_value)
        return dict_list
    else:
        new_list = []
        for d in dict_list:
            new_dict = {key: d.get(key, fill_value) for key in all_keys}
            new_list.append(new_dict)
        return new_list


def get_local_users_sid():
    try:
        if os.path.isfile(disable_Winmgmt):
            return []
        c = wmi.WMI()
        result = []
        for user in c.Win32_UserAccount(LocalAccount=True):
            result.append({"name": user.Name, "sid": user.SID})
        return result
    except:
        return []


user_profile_cache = []


def _fetch_user_profiles():
    ls = []
    users_profile_reader = reg_reader.reg_read("HKEY_USERS\\")
    wmi_get_test = get_local_users_sid()
    ProfileList_reg_path = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList"
    ProfileList_reg_reader = reg_reader.reg_read(ProfileList_reg_path)
    ProfileList_sids = [
        i["name"] for i in ProfileList_reg_reader["Folders"] if len(i["name"]) > 8
    ]
    for i in users_profile_reader["Folders"]:
        dic = {}
        dic_temp = {}
        try:
            i = i["name"]
            dic["sid"] = i
            dic["new_account"] = False
            dic["key"] = f"HKEY_USERS\\{i}"
            i_keys = reg_reader.reg_read(f"HKEY_USERS\\{i}\\Volatile Environment")[
                "keys"
            ]
            if len(i_keys) == 0:
                continue
            for j in i_keys:
                j_name = j["name"].replace(" ", "_").lower()
                dic[j_name] = j["value"].lower()
                dic_temp[j_name] = j["value"].lower()
            users_folder_reader = reg_reader.reg_read(
                f"HKEY_USERS\\{i}\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders"
            )
            for k in users_folder_reader["keys"]:
                k_name = k["name"].replace(" ", "_").lower()
                k_value = k["value"].lower()
                try:
                    for m in dic_temp.keys():
                        if f"%{m}%" in k_value:
                            k_value = k_value.replace(f"%{m}%", dic[m])
                except:
                    pass
                dic[k_name] = k_value
        except:
            continue

        ls.append(dic)
    for i in wmi_get_test:
        i_sid = i["sid"]
        if not i_sid in ProfileList_sids:
            ls.append({"sid": i_sid, "new_account": True, "username": i["name"]})

    return fill_missing_keys(ls, fill_value="None", in_place=True)


def _update_cache(new_data):
    """用新数据更新缓存"""
    global user_profile_cache

    # 创建缓存查找表
    cache_lookup = {item["sid"]: item for item in user_profile_cache}

    # 更新或添加新条目
    for item in new_data:
        cache_lookup[item["sid"]] = item

    # 保存回全局缓存
    user_profile_cache = list(cache_lookup.values())


def _merge_with_cache(new_data):
    """合并新数据和缓存"""
    # 获取新数据中已有的sid
    new_sids = {item["sid"] for item in new_data}

    # 从缓存中获取不重复的旧数据
    additional_data = [
        item for item in user_profile_cache if item["sid"] not in new_sids
    ]

    return new_data + additional_data


def get_all_user_profiles(use_cache=False):
    """
    获取用户资料，可选择性地使用缓存补全数据
    :param use_cache: 是否使用缓存补全数据，默认为False
    :return: 用户资料列表，如果启用缓存则合并新旧数据
    """
    # 获取新数据（这里跳过实际获取逻辑）
    new_data = _fetch_user_profiles()  # 实际获取数据的内部函数

    # 更新缓存（总是用新数据刷新缓存）
    _update_cache(new_data)

    # 如果不使用缓存，直接返回新数据
    if not use_cache:
        return new_data

    # 如果使用缓存，合并数据（以新数据为准）
    return _merge_with_cache(new_data)


# --------------------------------------------------------------------------- #
# 符号链接与权限
# --------------------------------------------------------------------------- #
def remove_prefix(path):
    if ":" in path:
        path = path.split(":")
        return f"{path[0][-1]}:{path[1]}"
    return None


def check_and_remove_symlink(link_path, expected_target):
    link_path = remove_prefix(os.path.normcase(link_path))
    expected_target = remove_prefix(os.path.normcase(expected_target))

    if os.path.islink(link_path):
        actual_target = os.readlink(link_path)
        actual_target = remove_prefix(os.path.normcase(actual_target))

        if os.path.realpath(actual_target) == os.path.realpath(expected_target):
            if os.path.exists(actual_target):
                logger.log(f"[链接]符号链接正确，指向：{actual_target}，且目标可访问")
                return True
            else:
                logger.log(f"[链接]符号链接的目标路径不可访问，正在删除链接...")
                os.remove(link_path)  # 删除符号链接
                return False
        else:
            logger.log(
                f"[链接]符号链接的目标不正确，实际指向：{actual_target}，预期指向：{expected_target}，正在删除链接..."
            )
            os.remove(link_path)  # 删除符号链接
            return False
    else:
        logger.log(f"[链接]{link_path} 不是一个符号链接")
        return False


def create_symlink_folder(src, link_name):
    """
    为文件夹创建符号链接
    :param src: 目标文件夹路径（符号链接指向的路径）
    :param link_name: 符号链接的路径（新建的链接路径）
    """
    try:
        os.symlink(src, link_name, target_is_directory=True)
        return True
    except Exception as e:
        return False


def backup_and_mklink(scr, lnkname):
    """
    将传入的文件夹scr重命名为scr.bak，并在原位创建一个符号链接指向lnkname
    """
    if (not os.path.islink(scr)) or (not os.path.exists(scr)):
        scr_folder_dir, scr_folder_name = os.path.split(scr)
        scr_bak_name = f"{scr_folder_name}.bak"
        bak_path = os.path.join(scr_folder_dir, scr_bak_name)
        i = 0
        while os.path.exists(bak_path):
            i += 1
            scr_bak_name = f"{scr_folder_name}.bak{i}"
            bak_path = os.path.join(scr_folder_dir, scr_bak_name)
            if i > 10:
                break
        logger.log(
            f"[链接]尝试为目录 {scr} 建立指向 {lnkname} 的链接,原目录备份为 {bak_path}"
        )
        try:
            os.rename(scr, bak_path)
        except:
            pass
        KeepFolder(lnkname)
        create_symlink_folder(lnkname, scr)
    elif os.path.islink(scr):
        check_and_remove_symlink(scr, lnkname)


def set_full_permissions(folder_path):
    """
    给指定文件夹及其子文件设置权限：
    - SYSTEM、Administrators、ALL APPLICATION PACKAGES、Everyone、ALL RESTRICTED APPLICATION PACKAGES
    """
    if not os.path.exists(folder_path):
        return
    RunWrapper(
        f'icacls "{folder_path}" /grant "SYSTEM":(OI)(CI)(F) /grant "Users":(OI)(CI)(F) /grant "Administrators":(OI)(CI)(F) /grant "ALL APPLICATION PACKAGES":(OI)(CI)(RX) /grant "Everyone":(OI)(CI)(F) /T /C /Q'
    ).read()
    RunWrapper(
        f'icacls "{folder_path}" /grant "ALL RESTRICTED APPLICATION PACKAGES":(OI)(CI)(RX) /T /C /Q'
    ).read()


# --------------------------------------------------------------------------- #
# 卷影复制
# --------------------------------------------------------------------------- #
def copy_file_via_vss(src_path, dst_path):
    def get_volume_from_path(path):
        drive, _ = os.path.splitdrive(path)
        if drive and not drive.endswith("\\"):
            drive += "\\"
        return drive

    volume = get_volume_from_path(src_path)
    pythoncom.CoInitialize()
    all_success = True
    try:
        if os.path.isfile(disable_Winmgmt):
            return False
        wmi = win32com.client.Dispatch("WbemScripting.SWbemLocator")
        service = wmi.ConnectServer(".", "root\\cimv2")

        # 创建快照
        in_params = (
            service.Get("Win32_ShadowCopy")
            .Methods_("Create")
            .InParameters.SpawnInstance_()
        )
        in_params.Properties_.Item("Volume").Value = volume
        in_params.Properties_.Item("Context").Value = "ClientAccessible"

        out_params = service.ExecMethod("Win32_ShadowCopy", "Create", in_params)
        ret_val = out_params.Properties_.Item("ReturnValue").Value
        shadow_id = out_params.Properties_.Item("ShadowID").Value

        if ret_val != 0:
            logger.log(f"[卷影复制] 创建快照失败，错误代码: {ret_val}")
            return False

        shadows = service.ExecQuery(
            f"SELECT * FROM Win32_ShadowCopy WHERE ID = '{shadow_id}'"
        )
        shadow = next(iter(shadows), None)
        if shadow is None:
            logger.log("[卷影复制] 未找到卷影快照对象")
            return False

        shadow_path = shadow.DeviceObject + "\\"
        drive, tail = os.path.splitdrive(src_path)
        relative_path = tail.lstrip("\\")
        src_in_shadow = os.path.join(shadow_path, relative_path)

        def safe_copy(src, dst):
            nonlocal all_success
            try:
                shutil.copy2(src, dst)
            except PermissionError:
                # 目标文件被占用/无权限 → 跳过，不记失败
                logger.log(f"[卷影复制][跳过覆盖冲突] {dst}")
            except OSError as e:
                if e.errno in (13, 17):  # 13=权限错误, 17=文件已存在
                    logger.log(f"[卷影复制][跳过覆盖冲突] {dst}")
                else:
                    logger.log(f"[卷影复制][失败跳过] {src} → {dst} : {e}")
                    all_success = False
            except Exception as e:
                logger.log(f"[卷影复制][失败跳过] {src} → {dst} : {e}")
                all_success = False

        try:
            if os.path.isdir(src_in_shadow):
                os.makedirs(dst_path, exist_ok=True)
                for root, dirs, files in os.walk(src_in_shadow):
                    rel_dir = os.path.relpath(root, src_in_shadow)
                    target_dir = os.path.join(dst_path, rel_dir)
                    os.makedirs(target_dir, exist_ok=True)
                    for file in files:
                        src_file = os.path.join(root, file)
                        dst_file = os.path.join(target_dir, file)
                        safe_copy(src_file, dst_file)
            else:
                os.makedirs(os.path.dirname(dst_path), exist_ok=True)
                safe_copy(src_in_shadow, dst_path)

        except Exception as e:
            logger.log(f"[卷影复制] 复制时出错: {e}")
            traceback.print_exc()
            all_success = False
        finally:
            shadow.Delete_()

        if all_success:
            logger.log(f"[卷影复制] 完成: {src_path} → {dst_path}")
            return True
        else:
            logger.log(f"[卷影复制] 存在部分失败: {src_path} → {dst_path}")
            return True

    except Exception as ex:
        logger.log(f"[卷影复制] 复制 {src_path} → {dst_path} 失败: {ex}")
        return False
    finally:
        pythoncom.CoUninitialize()


def compare_folder_structure(folder1, folder2):
    def get_structure(root):
        structure = set()
        for dirpath, dirnames, filenames in os.walk(root):
            rel_dir = os.path.relpath(dirpath, root)
            if rel_dir == ".":
                rel_dir = ""
            else:
                structure.add(("dir", rel_dir.replace("\\", "/")))
            for f in filenames:
                path = os.path.join(rel_dir, f).replace("\\", "/")
                structure.add(("file", path))
        return structure

    struct1 = get_structure(folder1)
    struct2 = get_structure(folder2)

    return struct1 == struct2
