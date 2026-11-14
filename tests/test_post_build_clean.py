"""构建后清理脚本的回归测试（在临时目录里造一个假工程，不碰真项目）。

Python\\Python.exe -m unittest tests.test_post_build_clean -v
"""

import contextlib
import importlib.util
import io
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

PROJECT = Path(__file__).resolve().parents[1]


def load_module(root):
    """按指定根目录加载一份全新模块（脚本靠环境变量定位工程）。"""
    spec = importlib.util.spec_from_file_location(
        f"post_build_clean_{id(root)}", PROJECT / "构建后清理.py"
    )
    module = importlib.util.module_from_spec(spec)
    with patch.dict(os.environ, {"ZHANG_CLEAN_ROOT": str(root)}, clear=False):
        spec.loader.exec_module(module)
    return module


class CleanTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

        # 构建中间物
        (self.root / "build").mkdir()
        (self.root / "build" / "big.bin").write_bytes(b"x" * 4096)
        (self.root / "dist").mkdir()
        (self.root / "dist" / "ZhangProtect.exe").write_bytes(b"MZ" * 2048)
        (self.root / "ZhangProtect.spec").write_text("spec", encoding="utf-8")
        (self.root / "build.log").write_text("log", encoding="utf-8")
        (self.root / "__pycache__").mkdir()
        (self.root / "__pycache__" / "a.pyc").write_bytes(b"pyc")
        (self.root / "sub").mkdir()
        (self.root / "sub" / "__pycache__").mkdir()
        (self.root / "sub" / "__pycache__" / "b.pyc").write_bytes(b"pyc")

        # 生成物与校验目录
        (self.root / "_resource_data").mkdir()
        (self.root / "_resource_data" / "X.bin").write_bytes(b"ZPRES" + b"y" * 1024)
        validation = self.root / "_build_validation"
        validation.mkdir()
        (validation / "prebuild-check.json").write_text("{}", encoding="utf-8")
        (validation / "make.bat.bak").write_text("bak", encoding="utf-8")
        (validation / "old.log").write_text("log", encoding="utf-8")

        # 必须保留的东西
        (self.root / "files").mkdir()
        (self.root / "files" / "keep.exe").write_bytes(b"MZ")
        (self.root / "main.py").write_text("print(1)", encoding="utf-8")
        (self.root / "Python").mkdir()
        (self.root / "Python" / "__pycache__").mkdir()
        (self.root / "Python" / "__pycache__" / "vendor.pyc").write_bytes(b"pyc")
        (self.root / "develop").write_text("", encoding="utf-8")

    def tearDown(self):
        self.temp.cleanup()

    def test_build_only_keeps_generated_data(self):
        module = load_module(self.root)
        self.assertEqual(module.main(["--build-only", "--quiet"]), 0)

        self.assertFalse((self.root / "build").exists())
        self.assertFalse((self.root / "dist").exists())
        self.assertFalse((self.root / "ZhangProtect.spec").exists())
        self.assertFalse((self.root / "build.log").exists())
        self.assertFalse((self.root / "__pycache__").exists())
        self.assertFalse((self.root / "sub" / "__pycache__").exists())

        # 生成物与校验目录不能被 --build-only 动
        self.assertTrue((self.root / "_resource_data" / "X.bin").exists())
        self.assertTrue((self.root / "_build_validation" / "make.bat.bak").exists())

    def test_full_clean_removes_derived_data(self):
        module = load_module(self.root)
        self.assertEqual(module.main(["--quiet"]), 0)

        self.assertFalse((self.root / "_resource_data").exists())
        validation = self.root / "_build_validation"
        self.assertTrue((validation / "prebuild-check.json").exists())
        self.assertFalse((validation / "make.bat.bak").exists())
        self.assertFalse((validation / "old.log").exists())

    def test_precious_paths_survive(self):
        module = load_module(self.root)
        module.main(["--quiet"])

        self.assertTrue((self.root / "files" / "keep.exe").exists())
        self.assertTrue((self.root / "main.py").exists())
        self.assertTrue((self.root / "develop").exists())
        self.assertTrue((self.root / "Python" / "__pycache__" / "vendor.pyc").exists())

    def test_dry_run_deletes_nothing(self):
        module = load_module(self.root)
        module.main(["--dry-run", "--quiet"])

        self.assertTrue((self.root / "build" / "big.bin").exists())
        self.assertTrue((self.root / "_resource_data" / "X.bin").exists())

    def test_keep_resource_data_flag(self):
        module = load_module(self.root)
        module.main(["--keep-resource-data", "--quiet"])

        self.assertTrue((self.root / "_resource_data" / "X.bin").exists())
        self.assertFalse((self.root / "build").exists())

    def test_second_run_is_noop(self):
        module = load_module(self.root)
        module.main(["--quiet"])
        fresh = load_module(self.root)
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            self.assertEqual(fresh.main(["--quiet"]), 0)
        self.assertIn("0 项", buffer.getvalue())


if __name__ == "__main__":
    unittest.main()
