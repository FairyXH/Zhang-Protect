import asyncio
import functools


class AwaitTool:
    def __init__(self):
        self._marked = set()
        self._pending = []

    def __call__(self, func=None):
        if isinstance(func, str):
            self._marked.add(func)
            return self
        elif func:
            self._marked.add(func.__name__)

            @functools.wraps(func)
            async def wrapper(*args, **kwargs):
                loop = asyncio.get_event_loop()
                return await loop.run_in_executor(None, lambda: func(*args, **kwargs))

            return wrapper
        return self._Context(self)

    def __await__(self, func=None):
        if func and func.__name__ in self._marked:
            loop = asyncio.get_event_loop()
            return loop.run_in_executor(None, lambda: func())
        return func()

    def run(self, func, *args, **kwargs):
        if func.__name__ in self._marked:
            task = asyncio.create_task(self._wrap(func, args, kwargs))
            self._pending.append(task)
            return task
        return func(*args, kwargs)

    async def _wrap(self, func, args, kwargs):
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, lambda: func(*args, **kwargs))

    @property
    def all_done(self):
        return all(t.done() for t in self._pending)

    async def wait_all(self):
        if self._pending:
            await asyncio.gather(*self._pending)
            self._pending.clear()

    class _Context:
        def __init__(self, parent):
            self.parent = parent
            self._original = set()

        def __enter__(self):
            self._original = self.parent._marked.copy()
            self.parent._marked.update(self.parent._marked)
            return self.parent

        def __exit__(self, *args):
            self.parent._marked = self._original


# 创建实例
tool = AwaitTool()

# 导出主要功能
mark_async = tool
run_async = tool.run
all_done = lambda: tool.all_done
wait_all = tool.wait_all
