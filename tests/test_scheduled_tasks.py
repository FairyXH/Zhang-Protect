"""锁定任务计划公共模块的约束（不创建任何真实任务）。

Schtasks_Creater / Create_Schtasks / get_local_users / get_user_sid 原本在
main_imports.py，现在只在 scheduled_tasks.py 定义一次，main_imports 只做重新导出。

    Python\\Python.exe -m unittest tests.test_scheduled_tasks -v
"""

import ast
import sys
import unittest
from pathlib import Path

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT))

MOVED = ("Schtasks_Creater", "Create_Schtasks", "get_local_users", "get_user_sid")


def top_level_definitions(path):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    return {
        node.name: node.lineno
        for node in tree.body
        if isinstance(node, ast.FunctionDef)
    }


def imported_modules(path):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                names.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
            names.add(node.module.split(".")[0])
    return names


class ScheduledTasksTests(unittest.TestCase):
    def test_definitions_only_in_scheduled_tasks(self):
        found = {}
        for path in sorted(PROJECT.glob("*.py")):
            for name in top_level_definitions(path):
                if name in MOVED:
                    found.setdefault(name, []).append(f"{path.name}:{name}")
        for name in MOVED:
            with self.subTest(name=name):
                self.assertEqual(found.get(name), [f"scheduled_tasks.py:{name}"])

    def test_main_imports_reexports_same_objects(self):
        import main_imports
        import scheduled_tasks

        for name in MOVED:
            with self.subTest(name=name):
                self.assertIs(
                    getattr(main_imports, name), getattr(scheduled_tasks, name)
                )

    def test_persistent_task_exists_and_reused(self):
        import StorageRedirect
        import scheduled_tasks

        self.assertTrue(callable(scheduled_tasks.Create_Persistent_Task))
        self.assertIs(
            StorageRedirect.Create_Persistent_Task,
            scheduled_tasks.Create_Persistent_Task,
        )

    def test_scheduled_tasks_is_a_leaf_module(self):
        """叶子模块：不能反向依赖主程序，否则独立 exe 会被撑大。"""
        imports = imported_modules(PROJECT / "scheduled_tasks.py")
        for forbidden in (
            "main_imports",
            "StorageRedirect",
            "file_utils",
            "main_paths",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, imports)

    def test_storage_redirect_does_not_import_main_imports(self):
        self.assertNotIn(
            "main_imports", imported_modules(PROJECT / "StorageRedirect.py")
        )

    def test_settings_use_allow_hard_terminate(self):
        """COM 里的属性名是 AllowHardTerminate（XML 里才是 DisallowHardTerminate）。"""
        source = (PROJECT / "scheduled_tasks.py").read_text(encoding="utf-8")
        self.assertIn("task_def.Settings.AllowHardTerminate", source)
        self.assertNotIn("task_def.Settings.DisallowHardTerminate", source)


if __name__ == "__main__":
    unittest.main()
