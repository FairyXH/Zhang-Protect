import ast
import base64
import contextlib
import hashlib
import importlib.util
import io
import os
from pathlib import Path
import sys
import tempfile
import tracemalloc
import types
import unittest
from unittest.mock import patch

import file2base
from resource_loader import (
    EmbeddedResource,
    RESOURCE_CHUNK_SIZE,
    RESOURCE_MAGIC,
    read_resource,
    write_resource,
)

PROJECT = Path(__file__).resolve().parents[1]


class ResourceLoaderTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        previous = Path.cwd()
        os.chdir(self.root)
        self.addCleanup(os.chdir, previous)
        self.addCleanup(tracemalloc.stop)

    def generate(self, content=b"sample\x00resource", name="sample", var="samplef"):
        source = self.root / "source.bin"
        source.write_bytes(content)
        with contextlib.redirect_stdout(io.StringIO()):
            file2base.mode2_make(source, name, var)
        spec = importlib.util.spec_from_file_location(name, self.root / (name + ".py"))
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return getattr(module, var)

    def test_reference_import_is_lazy_and_preserves_variable_name(self):
        reference = self.generate()
        self.assertIsInstance(reference, EmbeddedResource)
        self.assertLess((self.root / "sample.py").stat().st_size, 512)
        resource = self.root / "_resource_data/sample.bin"
        resource.unlink()
        spec = importlib.util.spec_from_file_location("sample", self.root / "sample.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        self.assertEqual(module.__all__, ["samplef"])
        with patch.object(sys, "_MEIPASS", str(self.root), create=True):
            with self.assertRaises(FileNotFoundError):
                read_resource(module.samplef)

    def test_streamed_data_and_frozen_resource_path(self):
        content = bytes(range(256)) * 9000
        reference = self.generate(content)
        with patch.object(sys, "_MEIPASS", str(self.root), create=True):
            self.assertEqual(read_resource(reference), content)
        self.assertEqual(read_resource(base64.b64encode(content)), content)
        encoded = base64.b64encode(content)
        wrapped = b"\n".join(encoded[i : i + 71] for i in range(0, len(encoded), 71))
        self.assertEqual(read_resource(wrapped), content)
        self.assertEqual(
            read_resource(base64.b64encode(content).decode("ascii")), content
        )

    def test_executable_resources_are_classified_as_data(self):
        from PyInstaller.depend.bindepend import classify_binary_vs_data

        content = (PROJECT / "files/ZhangProxyLauncher.exe").read_bytes()
        reference = self.generate(content)
        payload = self.root / "_resource_data" / reference.name
        self.assertEqual(classify_binary_vs_data(str(payload)), "DATA")
        with patch.object(sys, "_MEIPASS", str(self.root), create=True):
            self.assertEqual(read_resource(reference), content)

    def test_large_resource_copy_has_bounded_python_memory(self):
        folder = self.root / "_resource_data"
        folder.mkdir()
        chunk = b"x" * RESOURCE_CHUNK_SIZE
        with (folder / "large.bin").open("wb") as output:
            output.write(RESOURCE_MAGIC)
            for _ in range(64):
                output.write(chunk)
        tracemalloc.start()
        with patch.object(sys, "_MEIPASS", str(self.root), create=True):
            with (self.root / "output.bin").open("wb") as output:
                write_resource(output, EmbeddedResource("large.bin"))
        _, peak = tracemalloc.get_traced_memory()
        self.assertLess(peak, 4 * RESOURCE_CHUNK_SIZE)
        self.assertEqual(
            (self.root / "output.bin").stat().st_size, 64 * RESOURCE_CHUNK_SIZE
        )

    def test_legacy_migration_is_streamed_and_repeatable(self):
        content = b"legacy-data\x00" * 180000
        module = self.root / "legacy.py"
        module.write_bytes(b'legacyf = b"' + base64.b64encode(content) + b'"\n')
        self.assertTrue(file2base.migrate_legacy_resource("legacy", "legacyf"))
        self.assertTrue(file2base.migrate_legacy_resource("legacy", "legacyf"))
        self.assertEqual(
            (self.root / "_resource_data/legacy.bin").read_bytes(),
            RESOURCE_MAGIC + content,
        )
        self.assertLess(module.stat().st_size, 512)

    def test_failed_migration_keeps_original_module_and_payload(self):
        module = self.root / "legacy.py"
        original = b'legacyf = b"invalid!"\n'
        module.write_bytes(original)
        folder = self.root / "_resource_data"
        folder.mkdir()
        (folder / "legacy.bin").write_bytes(b"previous-data")
        with self.assertRaises(ValueError):
            file2base.migrate_legacy_resource("legacy", "legacyf")
        self.assertEqual(module.read_bytes(), original)
        self.assertEqual((folder / "legacy.bin").read_bytes(), b"previous-data")

    def test_existing_file_does_not_open_resource(self):
        tree = ast.parse((PROJECT / "main_imports.py").read_text(encoding="utf-8"))
        node = next(
            item
            for item in tree.body
            if isinstance(item, ast.FunctionDef) and item.name == "b64_to_file"
        )
        namespace = {
            "os": os,
            "write_resource": write_resource,
            "force_out_files": str(self.root / "force"),
            "smart_open": types.SimpleNamespace(smart_opens=open),
            "logger": types.SimpleNamespace(log=lambda value: None),
        }
        exec(
            compile(
                ast.Module(body=[node], type_ignores=[]), "main_imports.py", "exec"
            ),
            namespace,
        )
        destination = self.root / "existing.bin"
        destination.write_bytes(b"keep")
        namespace["b64_to_file"](str(destination), EmbeddedResource("missing.bin"))
        self.assertEqual(destination.read_bytes(), b"keep")
        with patch.object(sys, "_MEIPASS", str(self.root), create=True):
            reference = self.generate(b"replace")
            namespace["b64_to_file"](str(destination), reference, force=True)
        self.assertEqual(destination.read_bytes(), b"replace")

    def test_hook_collects_only_referenced_resources_without_importing_them(self):
        self.generate(name="needed", var="neededf")
        self.generate(name="unused", var="unusedf")
        spec = importlib.util.spec_from_file_location(
            "resource_hook", PROJECT / "pyinstaller_hooks/hook-resource_loader.py"
        )
        hook = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(hook)
        collected = []
        api = types.SimpleNamespace(
            module_graph=types.SimpleNamespace(
                iter_graph=lambda: iter(
                    [
                        types.SimpleNamespace(filename=str(self.root / "needed.py")),
                        types.SimpleNamespace(filename=None),
                    ]
                )
            ),
            add_datas=collected.extend,
        )
        hook.hook(api)
        self.assertEqual(
            collected,
            [(str(self.root / "_resource_data/needed.bin"), "_resource_data")],
        )


if __name__ == "__main__":
    unittest.main()
