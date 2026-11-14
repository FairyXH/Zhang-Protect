"""StorageRedirect 便携模式的纯函数/判定测试（不建任务、不改系统）。

Python\\Python.exe -m unittest tests.test_storage_redirect_cli -v
"""

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT))

import StorageRedirect as sr


class DriveTests(unittest.TestCase):
    def test_parse_drive_normalises(self):
        self.assertEqual(sr.parse_drive("d"), "D")
        self.assertEqual(sr.parse_drive(" D "), "D")
        self.assertEqual(sr.parse_drive("D:"), "D")
        self.assertEqual(sr.parse_drive("e:\\"), "E")

    def test_parse_drive_rejects_junk(self):
        for bad in ("", "DD", "1", "D:\\x", "%", "中文"):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                sr.parse_drive(bad)

    def test_validate_drive_rejects_system_drive(self):
        letter = sr.system_drive_letter()
        ok, why = sr.validate_drive(letter, letter)
        self.assertFalse(ok)
        self.assertIn("系统盘", why)

    def test_validate_drive_rejects_missing_drive(self):
        system = sr.system_drive_letter()
        # 找一个既不是系统盘、也不存在的盘符
        letter = next(
            candidate
            for candidate in "ZYXWVUTSRQPONMLKJIHGFED"
            if candidate != system and not os.path.exists(candidate + ":\\")
        )
        ok, why = sr.validate_drive(letter, system)
        self.assertFalse(ok)
        self.assertIn("不存在", why)

    def test_validate_drive_accepts_existing_drive(self):
        system = sr.system_drive_letter()
        existing = next(
            candidate
            for candidate in "DEFGHIJKLMNOPQRSTUVWXYZ"
            if candidate != system and os.path.exists(candidate + ":\\")
        )
        self.assertEqual(sr.validate_drive(existing, system), (True, ""))


class PathTests(unittest.TestCase):
    def test_system_exe_path_uses_env(self):
        with patch.dict(os.environ, {"systemroot": r"X:\FakeWin"}, clear=False):
            self.assertEqual(
                sr.system_exe_path(), os.path.join(r"X:\FakeWin", "StorageRedirect.exe")
            )

    def test_system_exe_path_without_env_raises(self):
        # Windows 的 os.environ 键大小写不敏感，统一按大写过滤
        env = {
            key: value
            for key, value in os.environ.items()
            if key.upper() not in ("SYSTEMROOT", "WINDIR")
        }
        with patch.dict(os.environ, env, clear=True), self.assertRaises(RuntimeError):
            sr.system_exe_path()

    def test_at_system_path_false_for_this_process(self):
        self.assertFalse(sr.at_system_path())


class InstallCopyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def test_copy_creates_target(self):
        source = self.root / "src.exe"
        source.write_bytes(b"MZ fake")
        target = self.root / "dst" / "StorageRedirect.exe"
        target.parent.mkdir()
        with patch.object(sr, "get_self_path", return_value=str(source)):
            ok, detail, existed = sr.install_self_copy(target)
        self.assertTrue(ok, detail)
        self.assertFalse(existed)
        self.assertEqual(target.read_bytes(), b"MZ fake")

    def test_copy_overwrites_target(self):
        source = self.root / "src.exe"
        source.write_bytes(b"MZ new")
        target = self.root / "StorageRedirect.exe"
        target.write_bytes(b"MZ old")
        with patch.object(sr, "get_self_path", return_value=str(source)):
            ok, detail, existed = sr.install_self_copy(target)
        self.assertTrue(ok, detail)
        self.assertTrue(existed)
        self.assertEqual(target.read_bytes(), b"MZ new")

    def test_copy_same_path_is_noop(self):
        source = self.root / "StorageRedirect.exe"
        source.write_bytes(b"MZ")
        with patch.object(sr, "get_self_path", return_value=str(source)):
            ok, detail, existed = sr.install_self_copy(source)
        self.assertTrue(ok)
        self.assertIn("目标位置", detail)


if __name__ == "__main__":
    unittest.main()
