# -*- coding: utf-8 -*-
"""构建后清理：删掉构建中间物、临时文件和过期的备份。

    python 构建后清理.py                 # 完整清理（打包/压缩完成后）
    python 构建后清理.py --build-only    # 只清构建中间物（make.bat 单独跑完）
    python 构建后清理.py --keep-resource-data
    python 构建后清理.py --dry-run

清理范围只在本工程目录内，永远不会越界：
    build/ dist/ *.spec __pycache__/ 根目录 *.log          构建中间物
    _resource_data/                                       载荷副本（可由 makefile.py 秒级重建）
    _build_validation/                                    校验报告之外的临时件与备份
"""

import argparse
import os
import shutil
import sys
import time
from pathlib import Path

# 允许测试把清理根目录指向临时目录，默认就是本脚本所在工程
_ROOT_OVERRIDE = os.environ.get("ZHANG_CLEAN_ROOT")
PROJECT = (
    Path(_ROOT_OVERRIDE).resolve()
    if _ROOT_OVERRIDE
    else Path(__file__).resolve().parent
)

# 这些目录里可能有别人家的东西，扫描 __pycache__ 时跳过
PRUNE_SKIP = {"Python", "node", "files", ".venv", "venv", "C++_Files", ".git"}

KEEP_IN_VALIDATION = {"prebuild-check.json"}


def human(size):
    if size < 1024:
        return f"{size} B"
    if size < 1048576:
        return f"{size / 1024:.1f} KB"
    if size < 1073741824:
        return f"{size / 1048576:.1f} MB"
    return f"{size / 1073741824:.2f} GB"


def dir_size(path):
    total = 0
    for root, dirs, names in os.walk(path, onerror=lambda exc: None):
        for name in names:
            try:
                total += os.path.getsize(os.path.join(root, name))
            except OSError:
                pass
    return total


def measure(path):
    try:
        return dir_size(path) if path.is_dir() else path.stat().st_size
    except OSError:
        return 0


class Cleaner:
    def __init__(self, dry_run=False):
        self.dry_run = dry_run
        self.removed = []
        self.failed = []
        self.freed = 0

    def _inside_project(self, path):
        try:
            path.resolve().relative_to(PROJECT.resolve())
            return True
        except (ValueError, OSError):
            return False

    def remove(self, path, reason=""):
        path = Path(path)
        if not path.exists():
            return
        if not self._inside_project(path):
            self.failed.append((path, "不在工程目录内，已跳过"))
            return
        size = measure(path)
        if self.dry_run:
            self.removed.append((path, size, reason))
            self.freed += size
            return
        if path.is_dir() and not path.is_symlink():
            # 目录里可能有个别文件被占用：能删多少删多少，剩下的单独报出来
            shutil.rmtree(path, ignore_errors=True)
        else:
            try:
                path.unlink()
            except OSError as exc:
                self.failed.append((path, str(exc)))
                return
        left = measure(path) if path.exists() else 0
        freed = size - left
        if freed:
            self.removed.append((path, freed, reason))
            self.freed += freed
        if left or path.exists():
            detail = (
                f"剩余 {human(left)} 无法删除（文件被占用）" if left else "目录未能删除"
            )
            self.failed.append((path, detail))

    # ---------------- 各类清理 ----------------
    def clean_build_artifacts(self):
        for name in ("build", "dist"):
            self.remove(PROJECT / name, "构建中间目录")
        for spec in PROJECT.glob("*.spec"):
            self.remove(spec, "PyInstaller 描述文件")
        for log in PROJECT.glob("*.log"):
            self.remove(log, "构建日志")
        # 打包脚本会把 Release 里的 exe 搬走，只剩下空目录
        release = PROJECT / "Release"
        if release.is_dir() and not any(release.iterdir()):
            self.remove(release, "空的 Release 目录")
        for cache in self._pycache_dirs():
            self.remove(cache, "__pycache__")

    def _pycache_dirs(self):
        for root, dirs, _files in os.walk(PROJECT):
            here = Path(root)
            if here != PROJECT and any(
                part in PRUNE_SKIP for part in here.relative_to(PROJECT).parts
            ):
                dirs[:] = []
                continue
            dirs[:] = [d for d in dirs if d not in PRUNE_SKIP and d != "__pycache__"]
            cache = here / "__pycache__"
            if cache.is_dir():
                yield cache

    def clean_resource_data(self):
        target = PROJECT / "_resource_data"
        if target.is_dir():
            self.remove(target, "载荷副本（makefile.py 可重建）")

    def clean_validation(self):
        folder = PROJECT / "_build_validation"
        if not folder.is_dir():
            return
        for child in folder.iterdir():
            if child.name in KEEP_IN_VALIDATION:
                continue
            self.remove(child, "校验临时件/备份")

    # ---------------- 输出 ----------------
    def report(self, title):
        print("=" * 72)
        print(f"{title}{'（演练模式，未真正删除）' if self.dry_run else ''}")
        print("=" * 72)
        if self.removed:
            for path, size, reason in sorted(self.removed, key=lambda item: -item[1]):
                try:
                    shown = path.relative_to(PROJECT)
                except ValueError:
                    shown = path
                print(f"  - {str(shown):<52} {human(size):>10}  {reason}")
            print("-" * 72)
            print(f"共删除 {len(self.removed)} 项，释放 {human(self.freed)}")
        else:
            print("  目录本来就是干净的，无需清理。")
        if self.failed:
            print("-" * 72)
            print(f"有 {len(self.failed)} 项没能删除（多为文件被占用）：")
            for path, why in self.failed:
                try:
                    shown = path.relative_to(PROJECT)
                except ValueError:
                    shown = path
                print(f"  ! {shown}: {why}")
        print("=" * 72)


def main(argv=None):
    parser = argparse.ArgumentParser(description="构建后清理")
    parser.add_argument(
        "--build-only", action="store_true", help="只清构建中间物，保留载荷与校验目录"
    )
    parser.add_argument(
        "--keep-resource-data", action="store_true", help="保留 _resource_data"
    )
    parser.add_argument("--dry-run", action="store_true", help="只报告，不删除")
    parser.add_argument("--quiet", action="store_true", help="只输出一行结果")
    args = parser.parse_args(argv)

    started = time.perf_counter()
    cleaner = Cleaner(dry_run=args.dry_run)
    cleaner.clean_build_artifacts()

    if not args.build_only:
        if not args.keep_resource_data:
            cleaner.clean_resource_data()
        cleaner.clean_validation()

    if args.quiet:
        lead = "预计释放" if args.dry_run else "释放"
        print(
            f"清理完成：{len(cleaner.removed)} 项，{lead} {human(cleaner.freed)}"
            + (f"，{len(cleaner.failed)} 项被占用" if cleaner.failed else "")
        )
    else:
        cleaner.report(
            "构建后清理（只清中间物）" if args.build_only else "构建后清理（完整）"
        )
        if cleaner.removed and any(
            path.name == "_resource_data" for path, _size, _r in cleaner.removed
        ):
            print(
                "提示：_resource_data 是按需生成的载荷副本，"
                "下次从源码运行或构建前执行 Python\\Python.exe makefile.py 即可重建。"
            )
        print(f"用时 {time.perf_counter() - started:.1f} 秒")

    return 1 if cleaner.failed else 0


if __name__ == "__main__":
    sys.exit(main())
