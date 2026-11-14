# watchdog_thread.py

import threading
import time
import logger
import traceback
import contextlib


class WatchdogThread:
    def __init__(self, name, target, timeout=10):
        """
        :param name: 线程名
        :param target: 线程执行函数，必须接收一个参数（self）
        :param timeout: 看门狗超时秒数
        """
        self.name = name
        self.target = target
        self.timeout = timeout
        self._lock = threading.Lock()
        self._last_feed = time.time()
        self._thread = None
        self._watchdog_thread = None
        self._stop_event = threading.Event()

    def feed(self):
        """手动喂狗：调用此函数可更新心跳"""
        with self._lock:
            self._last_feed = time.time()

    def smart_sleep(self, seconds, interval=0.5):
        """
        安全 sleep：在 sleep 期间自动喂狗，避免误判为卡死
        """
        end_time = time.time() + seconds
        while time.time() < end_time and not self._stop_event.is_set():
            time.sleep(min(interval, end_time - time.time()))
            self.feed()

    @contextlib.contextmanager
    def auto_feed(self, interval=0.5):
        """
        自动喂狗上下文管理器：用于包裹长时间阻塞操作
        示例：
            with wd.auto_feed():
                os.popen("long command")
        """
        stop_event = threading.Event()

        def _feeder():
            while not stop_event.is_set():
                self.feed()
                time.sleep(interval)

        feeder_thread = threading.Thread(target=_feeder, daemon=True)
        feeder_thread.start()
        try:
            yield
        finally:
            stop_event.set()
            feeder_thread.join()

    def _watchdog_loop(self):
        while not self._stop_event.is_set():
            with self._lock:
                elapsed = time.time() - self._last_feed
            if elapsed > self.timeout:
                logger.log(f"[{self.name}] 看门狗超时（{elapsed:.1f}s），重启线程...")
                self._restart_thread()
                with self._lock:
                    self._last_feed = time.time()
            time.sleep(1)

    def _thread_wrapper(self):
        while not self._stop_event.is_set():
            try:
                self.target(self)
            except Exception:
                logger.log(f"[{self.name}] 线程异常退出:")
                traceback.print_exc()
            time.sleep(1)

    def _restart_thread(self):
        if self._thread and self._thread.is_alive():
            return
        self._thread = threading.Thread(target=self._thread_wrapper, daemon=True)
        self._thread.start()

    def start(self):
        """启动线程与看门狗"""
        self._restart_thread()
        self._watchdog_thread = threading.Thread(
            target=self._watchdog_loop, daemon=True
        )
        self._watchdog_thread.start()

    def stop(self):
        """终止线程与看门狗"""
        self._stop_event.set()
