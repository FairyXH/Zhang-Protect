# logger.py
import datetime
import os
import sys

import psutil
from colorama import init, Fore, Style

import smart_open

init()

# 导入项目配置和版本信息
import config
from version import version

_log_file_name = ""
date = datetime.datetime.now().strftime("%Y-%m-%d-%H-%M-%S-%f")[:-3]
_log_file_name_base = f"[{os.getpid()}][{date}]"
number = 0
log_size = 0
log_file = ""
gil_stat = sys._is_gil_enabled()


def fresh():
    global log_dir, log_writetofile, testmode, max_log_size, cpu_low_flag, log_size
    log_dir = config.log_dir
    log_writetofile = config.log_writetofile
    testmode = config.is_test_mode()
    max_log_size = config.max_log_size
    cpu_low_flag = config.low_cpu_flag
    if os.path.isfile(log_file):
        log_size = os.path.getsize(log_file) / (1024**2)


def get_process_memory_usage() -> str:
    """获取当前进程的内存使用量(MB)"""
    process = psutil.Process(os.getpid())
    mem_info = process.memory_info()
    return f"{mem_info.rss / 1024 / 1024:.2f} MB"


def get_log_file():
    global log_file, _log_file_name, number
    smart_open.KeepFolder(log_dir)
    fresh_flag = False
    if log_size >= max_log_size:
        number += 1
        fresh_flag = True
    _log_file_name = _log_file_name_base + f"[{number}].log"
    log_file = f"{log_dir}\\{_log_file_name}"
    if fresh_flag:
        fresh()
    return log_file


def write_to_log_file(content):
    try:
        if log_writetofile:
            with smart_open.write_log(get_log_file(), "a") as f:
                f.write(content)
    except Exception as e:
        return f" (日志写入失败: {e})"
    return ""


def log(*args, sep=" ", end="\n", file=None, flush=False):
    content = sep.join(str(arg) for arg in args) + end
    """
    日志记录函数，用于替换print()

    :param content: 要记录的日志内容
    """
    fresh()
    if (not testmode and not log_writetofile) or cpu_low_flag:
        return
    current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    pid = os.getpid()
    memory_usage = get_process_memory_usage()
    # 获取文件写入状态信息
    if log_writetofile:
        write_status = f"(日志已写入文件)]\n[当前大小({number}):{log_size:.3f} MB/分片大小:{max_log_size} MB]"
    else:
        write_status = " (日志未写入文件)]"
    # 构建日志内容
    log_content = (
        f"{'=' * 15}\n"
        f"[{current_time} v{version}]\n"
        f"PID: {pid} ; "
        f"内存用量: {memory_usage}\n"
        f"GIL: {gil_stat}\n"
        f"[是否写入日志文件: {f'是' if log_writetofile else '否'}{write_status}\n"
        f"{'-' * 15}\n"
        f"{Fore.RED +content+Style.RESET_ALL}\n"
        f"{'=' * 15}"
    )
    # 决定是否输出到控制台
    if testmode:
        print(log_content)
    # 写入日志文件
    if log_writetofile:
        write_to_log_file(
            log_content.replace(Fore.RED, "").replace(Style.RESET_ALL, "")
        )
