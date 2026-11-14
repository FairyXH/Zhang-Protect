"""锁定"公共函数全项目只有一份"这条约束。

这 14 个函数曾经同时存在于 main_imports.py 和 StorageRedirect.py，导致独立打包
StorageRedirect.exe 时必须小心别把主程序一起拖进去。现在它们只在 file_utils.py
里定义一次，主程序和独立 exe 都从这里导入——这些用例防止以后又复制一份回去。

    Python\\Python.exe -m unittest tests.test_file_utils_single_source -v
"""

import ast
import sys
import unittest
from pathlib import Path

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT))

SHARED = (
    "copy_files",
    "fill_missing_keys",
    "get_local_users_sid",
    "_fetch_user_profiles",
    "_update_cache",
    "_merge_with_cache",
    "get_all_user_profiles",
    "remove_prefix",
    "check_and_remove_symlink",
    "create_symlink_folder",
    "backup_and_mklink",
    "set_full_permissions",
    "copy_file_via_vss",
    "compare_folder_structure",
)


def top_level_definitions(path):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    return {
        node.name: node.lineno
        for node in tree.body
        if isinstance(node, ast.FunctionDef)
    }


def imported_module_names(path):
    """文件里所有 import 到的模块名（含 from ... import）。"""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                names.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
            names.add(node.module.split(".")[0])
    return names


class SingleSourceTests(unittest.TestCase):
    def test_each_shared_function_is_defined_exactly_once(self):
        found = {}
        for path in sorted(PROJECT.glob("*.py")):
            for name in top_level_definitions(path):
                if name in SHARED:
                    found.setdefault(name, []).append(f"{path.name}:{name}")
        for name in SHARED:
            with self.subTest(name=name):
                self.assertEqual(len(found.get(name, [])), 1, found.get(name))

    def test_definitions_live_in_file_utils(self):
        definitions = top_level_definitions(PROJECT / "file_utils.py")
        for name in SHARED:
            with self.subTest(name=name):
                self.assertIn(name, definitions)

    def test_main_imports_reexports_the_same_objects(self):
        import file_utils
        import main_imports

        for name in SHARED:
            with self.subTest(name=name):
                if name.startswith("_"):
                    continue
                self.assertIs(getattr(main_imports, name), getattr(file_utils, name))

    def test_storage_redirect_uses_file_utils(self):
        import file_utils
        import StorageRedirect

        self.assertIs(StorageRedirect.copy_files, file_utils.copy_files)
        self.assertIs(
            StorageRedirect.get_all_user_profiles, file_utils.get_all_user_profiles
        )
        self.assertNotIn(
            "copy_files", top_level_definitions(PROJECT / "StorageRedirect.py")
        )

    def test_file_utils_does_not_depend_on_main_imports(self):
        """叶子模块：一旦反向依赖 main_imports，独立 exe 会被撑大并形成循环导入。"""
        self.assertNotIn(
            "main_imports", imported_module_names(PROJECT / "file_utils.py")
        )
        self.assertNotIn(
            "StorageRedirect", imported_module_names(PROJECT / "file_utils.py")
        )

    def test_storage_redirect_does_not_import_main_imports(self):
        self.assertNotIn(
            "main_imports", imported_module_names(PROJECT / "StorageRedirect.py")
        )


if __name__ == "__main__":
    unittest.main()
