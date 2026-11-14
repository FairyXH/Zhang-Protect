"""构建前检查脚本自身的回归测试。

重点不是"能跑通"，而是"能抓坏文件"：0 字节、截断、CRC 损坏、载荷大小错位、
缺模块都必须被判为 FAIL，否则这项检查就只是个摆设。

    Python\\Python.exe -m unittest tests.test_prebuild_check -v
"""

import importlib.util
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

PROJECT = Path(__file__).resolve().parents[1]


def load_module():
    spec = importlib.util.spec_from_file_location(
        "prebuild_check", PROJECT / "构建前检查.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


prebuild = load_module()


class PeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def test_rejects_empty_file(self):
        empty = self.root / "empty.exe"
        empty.write_bytes(b"")
        with self.assertRaises(prebuild.Invalid) as caught:
            prebuild.inspect_pe(empty)
        self.assertIn("0 字节", str(caught.exception))

    def test_rejects_truncated_file(self):
        source = PROJECT / "files" / "7z.exe"
        truncated = self.root / "truncated.exe"
        truncated.write_bytes(source.read_bytes()[:512])
        with self.assertRaises(prebuild.Invalid):
            prebuild.inspect_pe(truncated)

    def test_rejects_non_pe(self):
        fake = self.root / "fake.exe"
        fake.write_bytes(b"MZ" + b"\0" * 4094)
        with self.assertRaises(prebuild.Invalid):
            prebuild.inspect_pe(fake)

    def test_accepts_real_native_exe(self):
        machine, sections = prebuild.inspect_pe(PROJECT / "files" / "7z.exe")
        self.assertEqual(machine, 0x8664)
        self.assertGreater(sections, 0)

    def test_accepts_real_frozen_exe(self):
        machine, _ = prebuild.inspect_pe(PROJECT / "files" / "format_changer_tool.exe")
        self.assertIn(machine, (0x14C, 0x8664))


class ArchiveTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def _smallest_archive(self):
        return min(
            (PROJECT / "files").glob("*.7z"), key=lambda path: path.stat().st_size
        )

    def test_accepts_real_archive(self):
        prebuild.verify_archive(self._smallest_archive(), timeout=120)

    def test_rejects_truncated_archive(self):
        source = self._smallest_archive()
        data = source.read_bytes()
        cut = self.root / "cut.7z"
        cut.write_bytes(data[: len(data) // 2])
        with self.assertRaises(prebuild.Invalid):
            prebuild.verify_archive(cut, timeout=120)

    def test_rejects_bit_rot(self):
        source = self._smallest_archive()
        data = bytearray(source.read_bytes())
        for offset in range(len(data) // 3, min(len(data), len(data) // 3 + 4096)):
            data[offset] ^= 0xFF
        rotten = self.root / "rot.7z"
        rotten.write_bytes(bytes(data))
        with self.assertRaises(prebuild.Invalid):
            prebuild.verify_archive(rotten, timeout=120)


class PayloadTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        (self.root / "files").mkdir()
        (self.root / "_resource_data").mkdir()
        self.patches = [
            patch.object(prebuild, "PROJECT", self.root),
            patch.object(prebuild, "FILES_DIR", self.root / "files"),
            patch.object(prebuild, "RESOURCE_DIR", self.root / "_resource_data"),
        ]
        for item in self.patches:
            item.start()

    def tearDown(self):
        for item in self.patches:
            item.stop()
        self.temp.cleanup()

    def _make_payload(self, payload=b"MZ payload", blob=None, module_text=None):
        source = self.root / "files" / "demo.exe"
        source.write_bytes(payload)
        blob_path = self.root / "_resource_data" / "demo.bin"
        blob_path.write_bytes(
            prebuild.RESOURCE_MAGIC + (payload if blob is None else blob)
        )
        module = self.root / "demo.py"
        module.write_text(
            (
                module_text
                if module_text is not None
                else prebuild.REFERENCE_HEADER
                + "from resource_loader import EmbeddedResource as _EmbeddedResource\n\n"
                + "__all__ = ['demof']\n"
                + "demof = _EmbeddedResource('demo.bin')\n"
            ),
            encoding="utf-8",
        )
        return source, blob_path, module

    def test_consistent_payload_passes(self):
        self._make_payload()
        self.assertEqual(prebuild.check_payload("demo.exe", "demo", "demof"), [])

    def test_size_mismatch_fails(self):
        self._make_payload(payload=b"MZ payload", blob=b"short")
        problems = prebuild.check_payload("demo.exe", "demo", "demof")
        self.assertTrue(
            any("大小与源文件不一致" in item for item in problems), problems
        )

    def test_empty_payload_fails(self):
        _source, blob, _module = self._make_payload()
        blob.write_bytes(b"")
        problems = prebuild.check_payload("demo.exe", "demo", "demof")
        self.assertTrue(any("魔数头" in item for item in problems), problems)
        self.assertTrue(
            any("大小与源文件不一致" in item for item in problems), problems
        )

    def test_legacy_module_fails(self):
        self._make_payload(module_text="demof = 'QUJD'\n")
        problems = prebuild.check_payload("demo.exe", "demo", "demof")
        self.assertTrue(any("旧版 base64" in item for item in problems), problems)

    def test_missing_reference_module_fails(self):
        _source, _blob, module = self._make_payload()
        module.unlink()
        problems = prebuild.check_payload("demo.exe", "demo", "demof")
        self.assertTrue(any("缺少引用模块" in item for item in problems), problems)


class ClosureTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.patch = patch.object(prebuild, "PROJECT", self.root)
        self.patch.start()

    def tearDown(self):
        self.patch.stop()
        self.temp.cleanup()

    def test_distinguishes_guarded_and_required_imports(self):
        (self.root / "helper.py").write_text("import json\n", encoding="utf-8")
        (self.root / "entry.py").write_text(
            "import os\n"
            "import helper\n"
            "try:\n"
            "    import msvcrt_only_module\n"
            "except ImportError:\n"
            "    pass\n",
            encoding="utf-8",
        )
        analysed, imports = prebuild.build_closure(self.root / "entry.py")
        self.assertIn("helper", {path.stem for path in analysed})
        self.assertFalse(imports["os"])
        self.assertFalse(imports["helper"])
        self.assertTrue(imports["msvcrt_only_module"])


class BundleLayoutTests(unittest.TestCase):
    """锁住 PyInstaller 6 的模块分布认知，防止后续改动把判定改回误报。"""

    def test_module_locations_are_recognised(self):
        from PyInstaller.archive.readers import CArchiveReader

        executable = PROJECT / "files" / "Disable_Safety.exe"
        archive = CArchiveReader(str(executable))
        entries = dict(archive.toc)
        pyz = archive.open_embedded_archive(
            [k for k, v in entries.items() if v[-1] == "z"][0]
        )
        available = set(pyz.toc) | prebuild.bundled_modules(archive, entries)
        for name in (
            "os",
            "re",
            "collections",
            "struct",
            "win32api",
            "win32gui",
            "json",
        ):
            self.assertIn(name, available, f"{name} 应当能在冻结包里定位到")


class FailurePageTests(unittest.TestCase):
    """失败警告页：打包脚本靠它的存在与否决定弹哪个窗口。"""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def _report(self, failures):
        report = prebuild.Report()
        for index in range(7):
            report.add(1, f"files/ok{index}.exe", prebuild.OK, "x64")
        for subject, detail in failures:
            report.add(1, subject, prebuild.FAIL, detail)
        report.add(3, "orphan.exe", prebuild.WARN, "载荷存在但未登记")
        return report

    def test_page_contains_failures_and_counts(self):
        report = self._report(
            [
                ("files/NewTemplate.7z", "Unexpected end of archive"),
                ("files/ntsd.exe", "节区表越界"),
            ]
        )
        page = prebuild.write_failure_page(report, self.root / "p.html", 4.2, "x.json")
        text = page.read_text(encoding="utf-8")

        self.assertNotIn("__FAIL_ROWS__", text)
        self.assertNotIn("__OK__", text)
        self.assertIn("构建前检查未通过", text)
        self.assertIn(">7</div>", text)  # 通过计数
        self.assertIn(">2</div>", text)  # 失败计数
        self.assertIn("files/NewTemplate.7z", text)
        self.assertIn("节区表越界", text)
        self.assertIn("orphan.exe", text)  # 警告块
        self.assertIn("4.2", text)
        self.assertEqual(text.count('<tr><td class="grp">'), 3)

    def test_page_escapes_html(self):
        report = self._report([("<script>x</script>", "a & b <c>")])
        page = prebuild.write_failure_page(report, self.root / "p.html")
        text = page.read_text(encoding="utf-8")

        self.assertNotIn("<script>x</script>", text)
        self.assertIn("&lt;script&gt;x&lt;/script&gt;", text)
        self.assertIn("a &amp; b &lt;c&gt;", text)

    def test_page_creates_missing_directory(self):
        target = self.root / "deep" / "nested" / "p.html"
        page = prebuild.write_failure_page(self._report([]), target)
        self.assertTrue(page.is_file())


if __name__ == "__main__":
    unittest.main()
