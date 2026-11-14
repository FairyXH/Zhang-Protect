import ast
import base64
import copy
import ctypes
from ctypes import wintypes
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import tempfile
import types
import unittest
import uuid
from resource_loader import read_resource

PROJECT = Path(__file__).resolve().parents[1]
SYSTEM_KEY = (
    r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Environment"
)
USER_KEY = r"HKEY_USERS\test-user\Environment"


class Registry:
    def __init__(self, values):
        self.values = values
        self.writes = []

    def reg_read(self, key):
        return {"keys": copy.deepcopy(list(self.values.get(key, {}).values()))}

    def reg_write(self, key, name, type_str, value, **kwargs):
        assert kwargs == {"sync": False, "sync_hklm": False}
        self.values.setdefault(key, {})[name.casefold()] = {
            "name": name,
            "type": type_str,
            "value": value,
        }
        self.writes.append((key, name))

    def reg_delete_key(self, key, name, **kwargs):
        assert kwargs == {"sync": False}
        self.values[key].pop(name.casefold(), None)
        self.writes.append((key, name))


def registry_values(**values):
    return {
        name.casefold(): {"name": name, "type": "REG_EXPAND_SZ", "value": value}
        for name, value in values.items()
    }


class ProxyEnvironmentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.probe_temp = tempfile.TemporaryDirectory()
        cls.probe = Path(cls.probe_temp.name) / "probe.exe"
        subprocess.run(
            [
                str(PROJECT / "mingw64/bin/g++.exe"),
                str(PROJECT / "tests/proxy_probe.cpp"),
                "-o",
                str(cls.probe),
                "-municode",
                "-static",
                "-Os",
                "-s",
            ],
            check=True,
            capture_output=True,
        )
        cls.template = (PROJECT / "files/ZhangProxyLauncher.exe").read_bytes()
        cls.gui_probe = Path(cls.probe_temp.name) / "gui-probe.exe"
        subprocess.run(
            [
                str(PROJECT / "mingw64/bin/g++.exe"),
                str(PROJECT / "tests/proxy_gui_probe.cpp"),
                "-o",
                str(cls.gui_probe),
                "-municode",
                "-mwindows",
                "-static",
                "-Os",
                "-s",
                "-lshell32",
            ],
            check=True,
            capture_output=True,
        )
        source = ast.parse((PROJECT / "main_imports.py").read_text(encoding="utf-8"))
        names = {
            "sync_proxy_launchers",
            "is_proxy_launcher",
            "normalize_environment_path",
            "clean_environment_path",
            "set_environment_path",
            "get_executable_subsystem",
            "get_associated_executable",
            "get_proxy_subsystem",
        }
        cls.code = compile(
            ast.Module(
                body=[
                    node
                    for node in source.body
                    if isinstance(node, ast.FunctionDef) and node.name in names
                ],
                type_ignores=[],
            ),
            str(PROJECT / "main_imports.py"),
            "exec",
        )

    @classmethod
    def tearDownClass(cls):
        cls.probe_temp.cleanup()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="zhang-proxy-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "安装目录 & tools"
        self.root.mkdir()
        self.messages = []
        self.env = {
            "os": os,
            "base64": base64,
            "struct": struct,
            "uuid": uuid,
            "json": json,
            "re": re,
            "ctypes": ctypes,
            "wintypes": wintypes,
            "WindowsDir": os.environ["SystemRoot"],
            "ProtectDir": str(self.root) + os.sep,
            "ZhangProxyLauncherf": base64.b64encode(self.template),
            "read_resource": read_resource,
            "Maintain_tools_folder": str(self.root / "ZhangProtect-系统维护"),
            "logger": types.SimpleNamespace(log=self.messages.append),
            "_should_broadcast_environment_change": False,
            "get_all_user_profiles": lambda: [{"key": r"HKEY_USERS\test-user"}],
        }
        exec(self.code, self.env)
        original_env = os.environ.copy()
        self.addCleanup(lambda: (os.environ.clear(), os.environ.update(original_env)))

    def tool(self, relative):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(self.probe, path)
        return path

    def test_native_forwarding_unicode_arguments_stdio_cwd_and_exit(self):
        target = self.tool("工具 ! & %/probe.exe")
        proxy_dir = Path(self.env["sync_proxy_launchers"]())
        args = [
            "space value",
            "",
            'a"b',
            "尾部\\",
            "%PATH%",
            "&|<>^!",
            "\\\\server\\path",
        ]
        result = subprocess.run(
            [str(proxy_dir / "probe.exe"), *args],
            cwd=self.temp.name,
            input="stdin-data\n",
            capture_output=True,
            encoding="utf-8",
        )
        self.assertEqual(result.returncode, 37)
        self.assertEqual(
            result.stdout.splitlines(), [self.temp.name, *args, "stdin-data"]
        )
        self.assertEqual(result.stderr.strip(), "probe-stderr")
        direct = subprocess.run(
            [str(target), *args],
            cwd=self.temp.name,
            input="stdin-data\n",
            capture_output=True,
            encoding="utf-8",
        )
        self.assertEqual(
            (result.returncode, result.stdout, result.stderr),
            (direct.returncode, direct.stdout, direct.stderr),
        )

    def test_gui_proxy_matches_subsystem_cwd_arguments_and_show_state(self):
        target = self.root / "GUI 工具" / "window.exe"
        target.parent.mkdir()
        shutil.copyfile(self.gui_probe, target)
        proxy_dir = Path(self.env["sync_proxy_launchers"]())
        proxy = proxy_dir / "window.exe"
        self.assertEqual(self.env["get_executable_subsystem"](str(target)), 2)
        self.assertEqual(self.env["get_executable_subsystem"](str(proxy)), 2)
        startup = subprocess.STARTUPINFO()
        startup.dwFlags = subprocess.STARTF_USESHOWWINDOW
        startup.wShowWindow = 7
        results = []
        for index, executable in enumerate((target, proxy)):
            report = Path(self.temp.name) / f"gui-report-{index}.txt"
            result = subprocess.run(
                [str(executable), str(report), "中文 空格", 'a"b', ""],
                cwd=self.temp.name,
                startupinfo=startup,
                timeout=10,
            )
            self.assertEqual(result.returncode, 41)
            results.append(report.read_text(encoding="utf-8"))
        self.assertEqual(results[0], results[1])
        self.assertEqual(
            results[1].splitlines()[:3], ["no-console", self.temp.name, "7"]
        )

    def test_conflicts_idempotence_and_stale_cleanup(self):
        self.tool("root.exe")
        self.tool("a/root.exe")
        winner = self.tool("a/probe.exe")
        self.tool("b/deep/probe.exe")
        proxy_dir = Path(self.env["sync_proxy_launchers"]())
        self.assertFalse((proxy_dir / "root.exe").exists())
        proxy = proxy_dir / "probe.exe"
        timestamp = proxy.stat().st_mtime_ns
        self.env["sync_proxy_launchers"]()
        self.assertEqual(timestamp, proxy.stat().st_mtime_ns)
        winner.unlink()
        self.env["sync_proxy_launchers"]()
        self.assertIn("b\\deep\\probe.exe".encode("utf-16-le"), proxy.read_bytes())
        (self.root / "b/deep/probe.exe").unlink()
        unmanaged = proxy_dir / "manual.exe"
        unmanaged.write_bytes(b"user-owned")
        self.env["sync_proxy_launchers"]()
        self.assertFalse(proxy.exists())
        self.assertEqual(unmanaged.read_bytes(), b"user-owned")

    def test_command_lookup_uses_proxy_path_from_another_working_directory(self):
        target = self.tool("tools/probe.exe")
        proxy_dir = self.env["sync_proxy_launchers"]()
        child_env = os.environ.copy()
        child_env["PATH"] = f"{self.root};{proxy_dir}"
        result = subprocess.run(
            [os.environ["COMSPEC"], "/d", "/c", "probe.exe lookup"],
            cwd=self.temp.name,
            env=child_env,
            input="pipe-input\n",
            capture_output=True,
            encoding="utf-8",
        )
        self.assertEqual(result.returncode, 37)
        lines = result.stdout.splitlines()
        self.assertEqual(os.path.normcase(lines[0]), os.path.normcase(self.temp.name))
        self.assertEqual(lines[1:], ["lookup", "pipe-input"])

    def test_batch_proxy_original_name_alias_arguments_and_working_directory(self):
        probe = self.tool("批处理 %PATH% & !/inspect.exe")
        batch = probe.parent / "runner.cmd"
        batch.write_text(
            '@echo off\n"%~dp0inspect.exe" %*\nexit /b %errorlevel%\n', encoding="ascii"
        )
        proxy_dir = Path(self.env["sync_proxy_launchers"]())
        args = ["space value", "", "%PATH%", "literal ! text"]
        result = subprocess.run(
            [str(proxy_dir / "runner.exe"), *args],
            cwd=self.temp.name,
            input="stdin-data\n",
            capture_output=True,
            encoding="utf-8",
        )
        self.assertEqual(result.returncode, 37, result.stderr)
        lines = result.stdout.splitlines()
        self.assertEqual(os.path.normcase(lines[0]), os.path.normcase(self.temp.name))
        self.assertEqual(lines[1:], [*args, "stdin-data"])
        child_env = os.environ.copy()
        child_env["PATH"] = f"{self.root};{proxy_dir}"
        result = subprocess.run(
            [os.environ["COMSPEC"], "/d", "/c", "runner.cmd lookup"],
            cwd=self.temp.name,
            env=child_env,
            input="pipe-input\n",
            capture_output=True,
            encoding="utf-8",
        )
        self.assertEqual(result.returncode, 37, result.stderr)
        lines = result.stdout.splitlines()
        self.assertEqual(os.path.normcase(lines[0]), os.path.normcase(self.temp.name))
        self.assertEqual(lines[1:], ["lookup", "pipe-input"])

    def test_script_types_pathext_and_export_folders(self):
        os.environ["PATHEXT"] = ".COM;.EXE;.BAT;.CMD;.VBS;.ZPCUSTOM"
        script_dir = self.root / "scripts"
        script_dir.mkdir()
        scripts = [
            "batch.bat",
            "custom.zpcustom",
            "visual.vbs",
            "python.py",
            "shell.ps1",
        ]
        for name in scripts:
            (script_dir / name).write_text("", encoding="ascii")
        for excluded in ["ZhangProtect-系统维护", "ZhangProtect-系统维护-ISO镜像"]:
            self.tool(excluded + "/nested/exported.exe")
            (self.root / excluded / "nested/exported.cmd").write_text(
                "", encoding="ascii"
            )
        proxy_dir = Path(self.env["sync_proxy_launchers"]())
        for name in scripts:
            self.assertTrue((proxy_dir / (name + ".exe")).is_file(), name)
            self.assertTrue((proxy_dir / (Path(name).stem + ".exe")).is_file(), name)
        self.assertFalse(any(proxy_dir.glob("exported*")))
        for name in ["batch", "custom", "visual", "python", "shell"]:
            (
                script_dir
                / next(item for item in scripts if item.startswith(name + "."))
            ).unlink()
        self.env["sync_proxy_launchers"]()
        self.assertFalse(any(proxy_dir.iterdir()))

    def test_python_and_windows_script_host_dispatch(self):
        python_dir = self.root / "Python"
        python_dir.mkdir()
        os.link(PROJECT / "Python/python.exe", python_dir / "python.exe")
        for filename in ["python313.dll", "vcruntime140.dll", "vcruntime140_1.dll"]:
            source = PROJECT / "Python" / filename
            if source.exists():
                os.link(source, python_dir / filename)
        script_dir = self.root / "scripts"
        script_dir.mkdir()
        (script_dir / "pyscript.py").write_text(
            "import os,sys\nprint(os.getcwd())\nprint(sys.argv[1])\nsys.exit(23)\n",
            encoding="ascii",
        )
        (script_dir / "vbscript.vbs").write_text(
            'Set f = CreateObject("Scripting.FileSystemObject").CreateTextFile(WScript.Arguments(0), True)\n'
            "f.WriteLine WScript.Arguments(1)\nf.Close\nWScript.Quit 24\n",
            encoding="ascii",
        )
        proxy_dir = Path(self.env["sync_proxy_launchers"]())
        child_env = os.environ.copy()
        child_env["PYTHONHOME"] = str(PROJECT / "Python")
        child_env["PYTHONUTF8"] = "1"
        result = subprocess.run(
            [str(proxy_dir / "pyscript.exe"), "space value"],
            cwd=self.temp.name,
            env=child_env,
            capture_output=True,
            encoding="utf-8",
        )
        self.assertEqual(result.returncode, 23, result.stderr)
        self.assertEqual(result.stdout.splitlines(), [self.temp.name, "space value"])
        report = Path(self.temp.name) / "script-report.txt"
        result = subprocess.run(
            [str(proxy_dir / "vbscript.exe"), str(report), "space value"],
            cwd=self.temp.name,
            capture_output=True,
        )
        self.assertEqual(result.returncode, 24, result.stderr)
        self.assertEqual(report.read_text().strip(), "space value")

    def test_registry_migration_preserves_other_paths_and_is_idempotent(self):
        old_root = r"D:\OldProtect"
        unrelated = r"D:\OldProtectOther\bin;%SystemRoot%\System32;C:\Other"
        registry = Registry(
            {
                SYSTEM_KEY: registry_values(
                    Path=rf"%ZhangProtectPath%;{old_root}\removed;{unrelated}",
                    ZhangProtect=old_root + "\\",
                    ZhangProtectPath=old_root + ";" + old_root + r"\old-tool",
                    PRIVATE_TOKEN="must-not-be-backed-up",
                ),
                USER_KEY: registry_values(
                    Path=rf"%zhangprotectpath%;{self.root}\deleted;C:\UserTools",
                    ZhangProtect=old_root + "\\",
                    ZhangProtectPath=old_root,
                ),
            }
        )
        self.env["reg_reader"] = registry
        os.environ["PATH"] = rf"{old_root}\removed;{self.root}\old;C:\ProcessTools"
        self.assertTrue(self.env["set_environment_path"]())
        expected = f"{self.root};{self.root / 'ProxyBin'};{unrelated}"
        self.assertEqual(registry.values[SYSTEM_KEY]["path"]["value"], expected)
        self.assertEqual(registry.values[USER_KEY]["path"]["value"], r"C:\UserTools")
        self.assertNotIn("zhangprotectpath", registry.values[SYSTEM_KEY])
        self.assertNotIn("zhangprotect", registry.values[USER_KEY])
        self.assertEqual(
            os.environ["PATH"], f"{self.root};{self.root / 'ProxyBin'};C:\\ProcessTools"
        )
        backups = list((self.root / "ProxyBin").glob("environment-backup-*.json"))
        self.assertEqual(len(backups), 1)
        self.assertNotIn(
            "must-not-be-backed-up", backups[0].read_text(encoding="utf-8")
        )
        writes = len(registry.writes)
        self.assertTrue(self.env["set_environment_path"]())
        self.assertEqual(len(registry.writes), writes)

    def test_unmanaged_collision_stops_before_registry_changes(self):
        self.tool("a/probe.exe")
        proxy_dir = self.root / "ProxyBin"
        proxy_dir.mkdir()
        (proxy_dir / "probe.exe").write_bytes(b"user-owned")
        registry = Registry({SYSTEM_KEY: registry_values(Path=r"C:\Windows")})
        self.env["reg_reader"] = registry
        self.assertFalse(self.env["set_environment_path"]())
        self.assertEqual(registry.writes, [])
        self.assertEqual((proxy_dir / "probe.exe").read_bytes(), b"user-owned")

    def test_registry_write_failure_is_reported_and_backup_is_kept(self):
        registry = Registry({SYSTEM_KEY: registry_values(Path=r"C:\Windows")})
        registry.reg_write = lambda *args, **kwargs: None
        self.env["reg_reader"] = registry
        self.assertFalse(self.env["set_environment_path"]())
        self.assertEqual(registry.values[SYSTEM_KEY]["path"]["value"], r"C:\Windows")
        self.assertEqual(
            len(list((self.root / "ProxyBin").glob("environment-backup-*.json"))), 1
        )
        self.assertTrue(any("写入校验失败" in message for message in self.messages))


if __name__ == "__main__":
    unittest.main()
