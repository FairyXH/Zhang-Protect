import os
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from queue import Queue
import logger
import chardet

import config

# 最大并发数 = CPU核心数 × 2
MAX_WORKERS = os.cpu_count() * 2
_executor = ThreadPoolExecutor(max_workers=MAX_WORKERS)

# 后台清理线程队列
_cleanup_queue = Queue()
_cleanup_thread_started = False

# 已提交命令记录（避免重复执行相同命令）
_running_commands = {}
_running_commands_lock = threading.Lock()


class RunWrapper:
    def __init__(self, cmd: str):
        # 控制是否输出调试日志
        self.testflag = config.is_test_mode()
        self.cmd = cmd
        self._output = None
        self._completed = threading.Event()

        # 启动后台清理线程（只启动一次）
        global _cleanup_thread_started
        if not _cleanup_thread_started:
            threading.Thread(target=_cleanup_worker, daemon=True).start()
            _cleanup_thread_started = True

        # 检查是否已有同样命令在执行中
        with _running_commands_lock:
            if cmd in _running_commands:
                if self.testflag:
                    logger.log(f"[跳过] 命令已存在: {cmd}")
                self._future = _running_commands[cmd]._future
                self._completed = _running_commands[cmd]._completed
                return
            else:
                _running_commands[cmd] = self

        # 提交任务执行（非阻塞）
        if self.testflag:
            logger.log(f"[非阻塞] 提交命令: {self.cmd}")
        self._future = _executor.submit(self._run)

    def _run(self):
        try:
            process = subprocess.Popen(
                self.cmd,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=False,
            )
            if self.testflag:
                logger.log(f"[非阻塞] 启动进程: {self.cmd}")
            out, _ = process.communicate()
            try:
                if isinstance(out, bytes):
                    encoding = chardet.detect(out)["encoding"] or "utf-8"
                    out = out.decode(encoding, errors="replace")
            except:
                out = "[Error] 解码失败"
            self._output = out
        except Exception as e:
            self.err = f"[Error] 执行失败: {self.cmd} : {e}"
            if self.testflag:
                logger.log(self.err)
            self._output = self.err
        finally:
            self._completed.set()
            _cleanup_queue.put(self)

    def read(self):
        """阻塞直到完成并返回输出（仅执行一次）"""
        if self.testflag:
            logger.log(f"[阻塞] 等待命令输出: {self.cmd}")
        self._completed.wait()
        return self._output

    def __str__(self):
        return ""

    def _cleanup(self):
        """清理已完成命令，移出缓存"""
        with _running_commands_lock:
            if _running_commands.get(self.cmd) == self:
                del _running_commands[self.cmd]
        if self.testflag:
            logger.log(f"[清理] 命令完成: {self.cmd}")

    @staticmethod
    def all_completed() -> bool:
        """判断是否所有命令都已执行完毕"""
        with _running_commands_lock:
            for wrapper in _running_commands.values():
                if not wrapper._completed.is_set():
                    return False
        return True


def _cleanup_worker():
    while True:
        wrapper = _cleanup_queue.get()
        wrapper._cleanup()
        _cleanup_queue.task_done()
        time.sleep(0.1)
