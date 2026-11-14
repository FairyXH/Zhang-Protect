# Agent Context · Zhang 多功能整合程序

## 项目性质

Windows 10/11 x64 的「整合 / 守护 / 优化」工具集。单文件 `ZhangProtect.exe`（`main.py`）既是安装器也是常驻主程序，安装后复制为 `%SystemRoot%\Protect\Protect.exe`，以 SYSTEM 计划任务常驻。

## 关键事实

- 版本：`2026.11.12.0`（`version.py`），与 `file_version_info.txt` 同步。
- 功能开关：`configure_tags.py` 的 `config_tags`，共 **94 项**，是 GUI、`-h` 帮助、标记文件的唯一权威来源。开关 = `C:\Windows\Protect\<名字>` 空文件是否存在。
- 主循环：`main.py` 的 `starter()` → `define()` → `pope()` → `application()`，每轮 `time.sleep(60)`；三线程 + `thread_monitor.WatchdogThread(timeout=60)`。
- 资源机制（与旧版文档不同，注意）：
  `files/X` → `makefile.py` → `_resource_data/X.bin`（魔数 `ZPRES\x01\r\n`）+ 根目录 `X.py` 引用存根 → `pyinstaller_hooks/hook-resource_loader.py` 收集 → 运行时 `resource_loader.EmbeddedResource`。
  **不再使用 base64 内联**，旧文档 `files/README.md` 里"base64 内嵌"的表述是历史说法。
- `_resource_data/` 是生成物，已 gitignore；`files/` 是源载荷（131 文件 / 743MB），已入库。

## 构建

1. 工具链需自行补齐：`Python/`（CPython 3.13.5 x64）、`mingw64/`（GCC 14.2.0），两者不入库。
2. `install_pip_modules.bat` → `make.bat`（或 `构建项目.bat`）。
3. 顺序硬约束：`makefile.py` 必须先于 PyInstaller，否则 hook 报 `Missing resource data`。
4. `make.bat` 会创建 `ZhangProtectLock` 与 `develop`：前者让 `main.py` 拒绝在源码目录运行，后者让 `ControlMain.py` 跳过"未安装"检查。源码调试前删除这两个文件。
5. 构建前检查：`构建前检查.py`，报告 `_build_validation/prebuild-check.json`；失败时 `make.bat` 以非 0 退出且不产出。
6. 发布打包：`构建项目并打包.bat`（7z 密码 `123456`，排除规则 `exclude.txt`）。

## 仓库状态

- 远端：`https://github.com/FairyXH/Zhang-Protect.git`，分支 `main`，可见性 Public。
- 本地为**新建仓库**，首次推送以 `--force` 覆盖旧历史（旧的 base64 内联结构已废弃）。
- 入库范围：源码 + `files/` 载荷（约 750MB）；排除 `Python/`、`mingw64/`、`_resource_data/`、构建产物、构建标记、`.mimosa/`、`_build_validation/`。
- 文档分工：根 `README.md` 面向仓库与构建者；`files/README.md` 是随 exe 释放的终端用户手册，**不要删除或压缩它**（`makefile.py` 会把它作为 `READMEf` 嵌入）。

## 已知约束

- 仅 Win10+ x64；大量功能依赖 Win11 电源/显示 API。
- `ZhangProtectLock` 会让主程序静默退出，排障时先确认它不存在。
- `files/` 内容变更后必须重跑 `makefile.py` 才生效。
- `zip7.exe`/`7z.dll` 同时是构建工具（`构建前检查.py` 用它做 CRC 校验）和载荷，不要移走。

## 排障入口

- 主程序日志：`C:\Windows\Protect\[PID][时间].log`（`lowerlog` 标记可关闭）。
- 构建日志：`make.bat` 直接输出到控制台，无独立日志文件。
- 校验报告：`_build_validation/prebuild-check.json`、`_build_validation/prebuild-fail.html`。
