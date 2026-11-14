# -*- coding: utf-8 -*-
"""逐个文件校验「构建项目并打包.bat」产出的三件套。

    Python\\Python.exe tests\\verify_release_artifacts.py
    Python\\Python.exe tests\\verify_release_artifacts.py --skip-archive-crc   # 跳过 7z 全量解压校验

校验对象（路径由构建项目并打包.bat 决定）：
    1. <ZhangProtect-Windows>\\ZhangProtect.exe                       copy 出来的那份
    2. <Zhang多功能整合程序>\\可执行文件\\Python打包好\\ZhangProtect.exe   move 过去的那份
    3. <ZhangProtect-Windows>\\Zhang多功能整合程序.7z                  整合包（密码 123456）

逐项检查：存在性、大小、哈希一致、PE 结构、版本信息、内嵌载荷、压缩包完整性、
包内清单（不该有派生目录）、包内关键文件与磁盘内容一致、时间戳。
"""

import argparse
import hashlib
import json
import os
import struct
import subprocess
import sys
import time
from pathlib import Path

PROJECT = Path(__file__).resolve().parents[1]
# PROJECT = .../Zhang多功能整合程序/源代码/Python版本/Zhang多功能整合程序
OUTER = PROJECT.parents[2]  # .../Zhang多功能整合程序
REPO = PROJECT.parents[3]  # .../ZhangProtect-Windows

EXE_COPY = REPO / "ZhangProtect.exe"
EXE_MOVED = OUTER / "可执行文件" / "Python打包好" / "ZhangProtect.exe"
ARCHIVE = REPO / "Zhang多功能整合程序.7z"
SEVEN_ZIP = PROJECT / "files" / "7z.exe"
PASSWORD = "123456"
RESOURCE_DIR = Path("_resource_data")
RESOURCE_MAGIC = b"ZPRES\x01\r\n"

# 整合包里绝对不该出现的东西
FORBIDDEN_COMPONENTS = {
    "_resource_data",
    "_build_validation",
    "__pycache__",
    "build",
    "dist",
}


def forbidden_hits(paths, project_depth):
    """按路径分量判断，避免 distutils / scipy.special / libgfortran.spec 这类误报。"""
    hits = []
    for path in paths:
        parts = [part.lower() for part in path.split("\\") if part]
        if any(part in FORBIDDEN_COMPONENTS for part in parts):
            hits.append(path)
        elif (
            parts and parts[-1].endswith(".spec") and path.count("\\") == project_depth
        ):
            hits.append(path)
    return hits


class Result:
    def __init__(self):
        self.rows = []
        self.failed = 0
        self.warned = 0

    def add(self, name, ok, detail="", warn=False):
        status = "OK" if ok else ("WARN" if warn else "FAIL")
        if not ok:
            if warn:
                self.warned += 1
            else:
                self.failed += 1
        self.rows.append((status, name, detail))
        print(f"  [{status}] {name}" + (f"  —  {detail}" if detail else ""))
        return ok

    def summary(self):
        ok = sum(1 for row in self.rows if row[0] == "OK")
        print("-" * 78)
        print(
            f"结果：通过 {ok}   警告 {self.warned}   失败 {self.failed}"
            f"   共 {len(self.rows)} 项"
        )
        return 0 if self.failed == 0 else 1


def sha256(path, chunk=1024 * 1024):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        while block := handle.read(chunk):
            digest.update(block)
    return digest.hexdigest()


def human(size):
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024 or unit == "GB":
            return f"{size:.1f} {unit}" if unit != "B" else f"{size} B"
        size /= 1024
    return f"{size:.1f} GB"


def pe_info(path):
    """返回 (machine, section_count, subsystem) ；结构不对就抛 ValueError。"""
    with open(path, "rb") as handle:
        if handle.read(2) != b"MZ":
            raise ValueError("缺少 MZ 头")
        handle.seek(0x3C)
        offset = struct.unpack("<I", handle.read(4))[0]
        handle.seek(offset)
        if handle.read(4) != b"PE\0\0":
            raise ValueError("缺少 PE 签名")
        machine, sections = struct.unpack("<HH", handle.read(4))
        handle.seek(offset + 24 + 44)
        subsystem = struct.unpack("<H", handle.read(2))[0]
    return machine, sections, subsystem


def version_strings(path):
    """读 PE 资源里的 VS_VERSIONINFO 文本（依赖 pywin32，读不到就返回空）。"""
    try:
        import win32api
    except Exception:
        return {}
    info = {}
    try:
        raw = win32api.GetFileVersionInfo(str(path), "\\VarFileInfo\\Translation")
        translations = []
        if raw:
            data = raw[1]
            for index in range(0, len(data), 4):
                chunk = data[index : index + 4]
                if len(chunk) == 4:
                    translations.append(struct.unpack("<HH", chunk))
        for language, codepage in translations:
            for field in ("FileVersion", "ProductVersion", "ProductName"):
                try:
                    value = win32api.GetFileVersionInfo(
                        str(path),
                        f"\\StringFileInfo\\{language:04x}{codepage:04x}\\{field}",
                    )
                    if value:
                        info[field] = value[1]
                except Exception:
                    pass
    except Exception:
        return info
    return info


def run_seven_zip(args, timeout=3600):
    command = [str(SEVEN_ZIP), *args]
    proc = subprocess.run(
        command,
        capture_output=True,
        timeout=timeout,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    output = proc.stdout.decode("oem", "replace") + proc.stderr.decode("oem", "replace")
    return proc.returncode, output


def read_archive_entry(archive, entry, timeout=600):
    """把包内单个文件解到内存（-so），失败返回 None。"""
    command = [
        str(SEVEN_ZIP),
        "e",
        "-so",
        f"-p{PASSWORD}",
        "-bd",
        str(archive),
        entry,
    ]
    proc = subprocess.run(
        command,
        capture_output=True,
        timeout=timeout,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    if proc.returncode != 0 or not proc.stdout:
        return None
    return proc.stdout


ARCHIVE_PREFIX = "Zhang多功能整合程序\\源代码\\Python版本\\Zhang多功能整合程序\\"


# --------------------------------------------------------------------------- #
def check_exe(path, result, label):
    print(f"\n== {label}")
    print(f"   路径：{path}")
    if not result.add(f"{label}: 文件存在", path.is_file(), str(path)):
        return
    size = path.stat().st_size
    result.add(f"{label}: 体积合理", size > 600 * 1024 * 1024, human(size))
    try:
        machine, sections, subsystem = pe_info(path)
        result.add(
            f"{label}: PE 结构",
            machine in (0x8664, 0x14C) and sections > 0,
            f"machine=0x{machine:X} 节数={sections} subsystem={subsystem}",
        )
    except ValueError as exc:
        result.add(f"{label}: PE 结构", False, str(exc))
    info = version_strings(path)
    if info:
        result.add(
            f"{label}: 版本信息",
            bool(info.get("FileVersion")),
            " / ".join(f"{k}={v}" for k, v in info.items()),
        )
    return size


def check_payload(path, result, label):
    """确认 exe 里 126 个载荷齐全，且 StorageRedirectRes.bin 与本地一致。"""
    try:
        from PyInstaller.archive.readers import CArchiveReader
    except Exception as exc:  # noqa: BLE001
        result.add(f"{label}: 载荷检查", False, f"没有 PyInstaller：{exc}", warn=True)
        return
    try:
        archive = CArchiveReader(str(path))
        entries = [name for name in archive.toc if "_resource_data" in name]
        result.add(f"{label}: 内嵌载荷数量", len(entries) == 126, f"{len(entries)} 个")
        local = PROJECT / RESOURCE_DIR / "StorageRedirectRes.bin"
        source = PROJECT / "files" / "StorageRedirect.exe"
        key = next(
            (name for name in entries if name.endswith("StorageRedirectRes.bin")),
            None,
        )
        if key is None:
            result.add(f"{label}: StorageRedirect 载荷一致", False, "包里没有这个载荷")
        else:
            data = archive.extract(key)
            if local.is_file():
                expect = local.read_bytes()
                note = f"包内 {len(data)} 字节 / 本地 bin {len(expect)} 字节"
            elif source.is_file():
                expect = RESOURCE_MAGIC + source.read_bytes()
                note = f"包内 {len(data)} 字节 / 源 exe+头 {len(expect)} 字节"
            else:
                expect = b""
                note = "磁盘上既没有 bin 也没有源 exe"
            result.add(
                f"{label}: StorageRedirect 载荷一致",
                bool(expect) and data == expect,
                note,
            )
        # 抽查若干载荷的首部魔数
        sample = entries[:5]
        bad = [name for name in sample if archive.extract(name)[:8] != RESOURCE_MAGIC]
        result.add(
            f"{label}: 载荷魔数抽查",
            not bad,
            f"抽查 {len(sample)} 个，异常 {len(bad)} 个",
        )
    except Exception as exc:  # noqa: BLE001
        result.add(f"{label}: 载荷检查", False, f"{type(exc).__name__}: {exc}")


def check_archive(result, skip_crc=False):
    print(f"\n== 整合包")
    print(f"   路径：{ARCHIVE}")
    if not result.add("整合包: 文件存在", ARCHIVE.is_file(), str(ARCHIVE)):
        return
    size = ARCHIVE.stat().st_size
    result.add("整合包: 体积合理", size > 100 * 1024 * 1024, human(size))

    if not skip_crc:
        started = time.perf_counter()
        code, output = run_seven_zip(["t", "-y", "-bd", f"-p{PASSWORD}", str(ARCHIVE)])
        tail = [
            line.strip()
            for line in output.splitlines()
            if "Everything is Ok" in line or "Error" in line or "error" in line
        ]
        result.add(
            "整合包: CRC 全量校验",
            code == 0,
            (tail[-1] if tail else output.strip()[-160:])
            + f"  ({time.perf_counter() - started:.0f}s)",
        )

    code, output = run_seven_zip(["l", "-slt", f"-p{PASSWORD}", str(ARCHIVE)])
    paths = []
    marker = "Path = "
    for line in output.splitlines():
        line = line.strip()
        if line.startswith(marker) and len(line) > len(marker):
            paths.append(line[len(marker) :])
    if not paths:
        result.add("整合包: 清单可读", False, output[-200:])
        return
    files = [item for item in paths if not item.endswith("\\")]
    result.add(
        "整合包: 条目数量",
        len(paths) > 500,
        f"{len(files)} 个文件 / {len(paths)} 个条目",
    )

    depth = ARCHIVE_PREFIX.count("\\") + 1
    hits = forbidden_hits(paths, depth)
    result.add(
        "整合包: 不含派生/中间目录",
        not hits,
        (
            "干净（无 _resource_data / _build_validation / build / dist / __pycache__）"
            if not hits
            else f"{len(hits)} 项，例如 {hits[0]}"
        ),
    )

    # 包内应包含的关键文件
    joined = "\n".join(item.lower() for item in paths)
    for must in (
        "main.py",
        "makefile.py",
        "构建前检查.py",
        "构建后清理.py",
        "exclude.txt",
        "files\\7z.exe",
        "files\\storageRedirect.exe",
    ):
        result.add(f"整合包: 含 {must}", must.lower() in joined)

    # 包内 files\ 完整性：磁盘上有多少个 exe/7z/dll，包里就该有同样多
    for pattern, label in (("*.exe", "exe"), ("*.7z", "7z"), ("*.dll", "dll")):
        disk = sorted(item.name.lower() for item in (PROJECT / "files").glob(pattern))
        packed = [name for name in disk if f"files\\{name}" in joined]
        result.add(
            f"整合包: files\\{label} 齐全",
            len(packed) == len(disk),
            f"磁盘 {len(disk)} 个 / 包内 {len(packed)} 个",
        )

    # 包内文件与磁盘逐字节比对（防打包时被换掉/截断）
    for rel in (
        "main.py",
        "makefile.py",
        "StorageRedirect.py",
        "scheduled_tasks.py",
        "构建前检查.py",
        "构建后清理.py",
        "tests\\verify_full_build.py",
        "files\\StorageRedirect.exe",
    ):
        local = PROJECT / rel
        if not local.is_file():
            result.add(f"包内字节比对: {rel}", False, "磁盘上找不到源文件")
            continue
        data = read_archive_entry(ARCHIVE, ARCHIVE_PREFIX + rel)
        if data is None:
            result.add(f"包内字节比对: {rel}", False, "解包失败（可能未打包）")
            continue
        same = hashlib.sha256(data).hexdigest() == sha256(local)
        result.add(
            f"包内字节比对: {rel}",
            same,
            f"{human(len(data))} / 磁盘 {human(local.stat().st_size)}",
        )

    return paths


def check_timestamps(result, paths):
    """打包脚本会把文件时间改成 3000-01-01，确认生效。"""
    try:
        from PyInstaller.archive.readers import CArchiveReader  # noqa: F401
    except Exception:
        pass
    samples = [
        PROJECT / "main.py",
        PROJECT / "构建前检查.py",
        PROJECT / "files" / "7z.exe",
    ]
    for path in samples:
        if not path.is_file():
            continue
        stamp = time.strftime("%Y-%m-%d", time.localtime(path.stat().st_mtime))
        result.add(f"时间戳: {path.name}", stamp.startswith("3000"), stamp)


def check_clean_tree(result):
    print("\n== 构建后目录状态")
    leftovers = []
    for name in ("build", "dist", "_resource_data", "__pycache__"):
        if (PROJECT / name).exists():
            leftovers.append(name)
    specs = list(PROJECT.glob("*.spec"))
    logs = list(PROJECT.glob("*.log"))
    result.add(
        "目录: build/dist/_resource_data 已清理",
        not leftovers,
        str(leftovers) if leftovers else "干净",
    )
    result.add(
        "目录: 无残留 .spec",
        not specs,
        str([p.name for p in specs]) if specs else "干净",
    )
    result.add(
        "目录: 无残留构建日志",
        not logs,
        str([p.name for p in logs]) if logs else "干净",
    )
    validation = PROJECT / "_build_validation"
    if validation.is_dir():
        extra = [
            p.name for p in validation.iterdir() if p.name != "prebuild-check.json"
        ]
        result.add(
            "目录: _build_validation 只剩报告",
            not extra,
            str(extra) if extra else "干净",
        )


def main(argv=None):
    parser = argparse.ArgumentParser(description="产物逐项校验")
    parser.add_argument(
        "--skip-archive-crc", action="store_true", help="跳过 7z 全量 CRC 校验"
    )
    parser.add_argument("--json", default="", help="把结果写成 JSON 报告（默认只打印）")
    args = parser.parse_args(argv)

    started = time.perf_counter()
    result = Result()
    print("=" * 78)
    print(f"产物校验  {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"工程：{PROJECT}")
    print("=" * 78)

    print("\n== 两份可执行文件")
    sizes = {}
    for label, path in (("copy 版", EXE_COPY), ("move 版", EXE_MOVED)):
        sizes[label] = check_exe(path, result, label)

    if EXE_COPY.is_file() and EXE_MOVED.is_file():
        digest_copy = sha256(EXE_COPY)
        digest_moved = sha256(EXE_MOVED)
        result.add(
            "两份 exe 完全一致",
            digest_copy == digest_moved,
            f"{digest_copy[:16]}… / {digest_moved[:16]}…",
        )

    if EXE_MOVED.is_file():
        check_payload(EXE_MOVED, result, "move 版")

    paths = check_archive(result, skip_crc=args.skip_archive_crc)
    if paths:
        check_timestamps(result, paths)
    check_clean_tree(result)

    print()
    code = result.summary()
    print(f"总用时 {time.perf_counter() - started:.1f} 秒")
    print("=" * 78)

    if args.json:
        Path(args.json).write_text(
            json.dumps(
                {
                    "time": time.strftime("%Y-%m-%d %H:%M:%S"),
                    "rows": result.rows,
                    "failed": result.failed,
                    "warned": result.warned,
                },
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )
    return code


if __name__ == "__main__":
    sys.exit(main())
