# Zhang 多功能整合程序 · ZhangProtect

![version](https://img.shields.io/badge/version-2026.11.12.0-blue)
![platform](https://img.shields.io/badge/platform-Windows%2010%2F11%20x64-lightgrey)
![python](https://img.shields.io/badge/python-3.13-3776AB)
![payload](https://img.shields.io/badge/payload-743MB-orange)

Windows 10/11 x64 上的**整合 / 守护 / 优化**工具集。核心是一个以 `SYSTEM` 权限常驻的主程序，通过「在目录里创建空文件即开启某项功能」的标记文件机制，驱动 **94 项**开关式功能；配套一个复选框 GUI 配置管理器，以及 **131 个**随主程序释放的内置工具载荷（自研 C++ 工具、Python 打包工具、第三方便携软件）。

主程序由 PyInstaller 打为单文件 `ZhangProtect.exe`，全部载荷在构建期嵌入 exe，运行时释放到 `C:\Windows\Protect\`。

> [!WARNING]
> 这是**高风险系统级工具**：以 SYSTEM 权限常驻、修改注册表/服务/计划任务、关闭 UAC 与安全中心、重定向用户目录，且**卸载不会还原已做的修改**。完整修改清单见 [`files/README.md` §6](files/README.md)。请仅在你有完全控制权、可随时重装的机器上使用。

---

## 目录

- [1. 项目定位](#1-项目定位)
- [2. 功能概览](#2-功能概览)
- [3. 运行架构](#3-运行架构)
- [4. 仓库结构](#4-仓库结构)
- [5. 构建](#5-构建)
- [6. 使用](#6-使用)
- [7. 功能开关机制](#7-功能开关机制)
- [8. 内置工具载荷](#8-内置工具载荷)
- [9. 测试与校验](#9-测试与校验)
- [10. 风险与已知限制](#10-风险与已知限制)
- [11. 版权与许可](#11-版权与许可)

---

## 1. 项目定位

| 项 | 值 |
| --- | --- |
| 名称 | Zhang 多功能整合程序（ZhangProtect） |
| 版本 | `2026.11.12.0`（`version.py`） |
| 平台 | Windows 10 / 11，仅 x64 |
| 运行时 | Python 3.13（项目自带 `Python\`，不入库） |
| 主程序 | `ZhangProtect.exe` ← `main.py`（9761 行）单文件打包 |
| 安装位置 | `%SystemRoot%\Protect\Protect.exe` |
| 配置 | `%SystemRoot%\Protect\ProtectConf.conf`（11 行） |
| 开关 | `%SystemRoot%\Protect\<标记文件名>` 存在即开启 |
| 载荷 | `files\` 131 个文件 / 743MB，构建期嵌入 exe |
| 用户手册 | [`files/README.md`](files/README.md)（46KB，随安装释放为 `C:\Windows\Protect\README.md`） |

本仓库是**完整源码 + 构建载荷**，可直接重建 `ZhangProtect.exe`。两个内嵌工具链（`Python\` 460MB、`mingw64\` 698MB）不入库，重建方式见 [§5.1](#51-工具链准备)。

---

## 2. 功能概览

94 项开关按用途分为以下类别（每项的具体行为见 [`files/README.md` §4](files/README.md)）：

| 类别 | 数量 | 代表功能 |
| --- | ---: | --- |
| 显示 / 桌面 / 美化 | 18 | 桌面时钟、iKun 图标每日轮换、隐藏任务栏、去快捷方式箭头、任务栏秒 |
| 电源 / 休眠 / 合盖 | 13 | 电源计划自动切换、合盖睡眠、隐藏电源菜单项、睿频控制 |
| 进程守护 | 10 | 守护 `explorer.exe`、DesktopOK、Memreduct、Everything、simplewall、LocalSend |
| 其他 / 杂项 | 10 | 文件服务器、流量消耗器、截图监控、ShareX 接管截屏、单次强制释放 |
| 网络 / IP / MAC / RDP | 8 | 断网自动换 IP、随机 MAC、多网卡负载均衡、RDPWrap、802.1x 自动结束 |
| 游戏优化 | 8 | 游戏时暂停主程序、切高性能电源、屏蔽快捷键、外置红点、P 核绑定 |
| 安全 / 隐私 | 8 | 关闭 UAC、清事件日志、禁用 Winmgmt、蓝牙 HFP/绝对音量、禁 Hyper-V |
| WiFi / 移动热点 | 7 | 自动热点、随机 SSID/密码、360AP 接管、隐藏热点设置页 |
| 维护 / 备份 / 清理 | 7 | 系统备份与每日增量、重注册 DLL、删 mstsc 记录、清 JetBrains 历史、校时 |
| 存储 / 文件 / U 盘 | 5 | 存储重定向（不可逆）、文件整理、U 盘写保护或共享、Autorun.inf 陷阱 |

能力边界（由源码实现决定）：

- **安装/更新/卸载**：`-q` 静默安装、`-u` 覆盖更新并 MD5 校验、卸载走 `Uninstaller.bat`。
- **配置控制台**：tkinter GUI，94 个复选框一键写盘；另有 `-c` 直接拉起配置页。
- **三线程 + 看门狗**：进程守护、二次任务、游戏暂停监控各自独立，异常退出后重启。
- **计划任务自愈**：`ZhangProtect\ProtectKeeper` 每 5 分钟检查并拉起主程序。
- **非阻塞命令执行**：`cmd_runner.RunWrapper` 用线程池执行外部命令，相同命令自动去重。

---

## 3. 运行架构

```
ZhangProtect.exe  (main.py：安装器 / 更新器 / 配置入口)
        │  首次安装：复制自身 → C:\Windows\Protect\Protect.exe
        │  创建计划任务 ZhangProtect\Protect (SYSTEM / ONLOGON / HIGHEST)
        ▼
Protect.exe  (常驻主程序，工作目录 C:\Windows\Protect\)
        ├─ 主循环：每 60 秒一轮
        │    ├─ 扫描标记文件 → 应用/回退对应策略
        │    ├─ 重建/启用 ZhangProtect\* 计划任务
        │    └─ 按策略守护进程、释放载荷、写注册表
        ├─ TaskKeeping_Thread      （看门狗 60s，异常重启）
        ├─ second_run_tasks        （登录后二次任务）
        └─ pause_on_game_monitor   （检测到游戏 → 暂停主循环）
                 ▲
                 │ 每 5 分钟自愈
        ZhangProtect\ProtectKeeper → ZhangProtectPot.exe
        ZhangProtect\ProtectPot    （用户会话拉起）

配置管理器：ZhangProtectControl.exe (ControlMain.py)
        勾选 94 项 → 写入设置 = 创建空文件 / 取消 = 删除文件
```

### 3.1 标记文件机制

「开关」不是配置文件里的布尔值，而是 `C:\Windows\Protect\` 下**一个同名空文件是否存在**。
`configure_tags.py` 的 `config_tags` 是唯一权威清单（名称 ↔ 文件名 ↔ GUI 文案）：

```python
("开启自动热点", "openwifi"),
("使用不公平调度(自研)", "Disable_sys_dispatch"),
("开启存储重定向(不可逆)", "use_storage_redirect"),
```

主循环每轮重新读取这些文件，所以改开关**无需重启**（最多等 60 秒）。反过来，手工 `type nul > openwifi` 也能开启功能。

### 3.2 资源配置链路（当前实现）

早期版本把载荷 base64 内联进 `.py` 字面量，现已改为**外部资源 + 引用存根**：

```
files\README.md
    │  makefile.py 调用 file2base.mode2_make()
    ▼
_resource_data\README.bin           ← 原始字节 + 8 字节魔数 ZPRES\x01\r\n
README.py                           ← 只含 EmbeddedResource('README.bin') 的引用存根
    │  pyinstaller_hooks\hook-resource_loader.py 扫描所有"生成存根"，
    │  把这些 .bin 作为 datas 打进 exe 的 _MEIPASS\_resource_data\
    ▼
resource_loader.EmbeddedResource    ← 运行时按魔数校验后流式读出
```

`_resource_data\` 是**生成物**：`makefile.py` 从 `files\` 秒级重建，因此被 `.gitignore` 排除。
仓库只保留 `files\` 原始载荷和生成的引用存根（根目录 131 个同名 `.py`）。

---

## 4. 仓库结构

```
Zhang多功能整合程序/
├── main.py                     # 主程序：安装/配置/守护/全部功能（9761 行）
├── main_imports.py             # 核心函数库（注册表、任务计划、重定向、备份…3049 行）
├── main_paths.py               # 全局路径与标记文件常量（374 行）
├── configure_tags.py           # 94 项功能开关清单（唯一权威）
├── ControlMain.py              # → ZhangProtectControl.exe 配置管理器 GUI
│
├── config.py / logger.py / version.py      # 配置 / 日志 / 版本
├── cmd_runner.py               # 线程池非阻塞命令执行（同命令去重）
├── resource_loader.py          # 嵌资源读取 + 魔数校验
├── file2base.py                # files/ → _resource_data/ + 引用存根
├── smart_open.py               # 自动编码探测的文件读写
├── thread_monitor.py           # 看门狗线程
├── reg_reader.py               # 注册表读写（自动提权）
├── powercfg.py                 # 电源计划切换（powrprof API）
├── scheduled_tasks.py          # 计划任务封装
│
├── Sys_Dispatch_Main.py        # → SysDispatch.exe 「不公平调度」
├── ZhangProtectPot_Python.py   # → ZhangProtectPot.exe 守护启动器
├── StorageRedirect.py          # → StorageRedirect.exe 存储重定向
├── Zhang_IPhelper.py           # → Zhang_ip_helper.exe 断网换 IP
├── Zhang_lan_scan.py           # → Zhang_lan_scan.exe 内网端口扫描（学习用途）
├── Traffic_Killer.py           # → Traffic_Killer.exe 流量消耗
├── WifiMobileTool.py           # → WifiMobileTool.exe 热点保活
├── file_server.py              # → file_server.exe HTTP 文件服务器
├── format_changer_tool.py      # → format_changer_tool.exe 批量转码
├── WindowDebugTool.py          # → WindowDebugTool.exe 窗口调试
├── Zhang_PE_Tool_Main.py       # → Zhang_PE_Tool.exe PE 环境部署
├── remove_safe.py              # → Disable_Safety.exe 安全项一键开关
├── restoreconfs.py             # → RestoreConf.exe 恢复热点/时钟/右键菜单
├── weiwei_zhang.py             # → WeiWeiFont.exe 字体替换
│
├── files/                      # 构建载荷 131 个文件（743MB，入库）
├── C++_Files/                  # 自研 C++ 工具源码 14 个
├── ZhangProtectPot_C++/        # 守护启动器 C++ 实现
├── pyinstaller_hooks/          # 资源收集 + scheduled_tasks 钩子
├── tests/                      # 回归测试与发布校验 14 个文件（12 个 Python 脚本 + 2 个 C++ 探针）
├── docs/AGENT_CONTEXT.md       # 开发交接上下文
│
├── make.bat                    # 主构建：载荷→C++→工具→校验→PyInstaller
├── make_C_files.bat            # MinGW64 编译 C++ 工具到 files\
├── make_pythontools_files.bat  # 打包 14 个 Python 工具到 files\
├── makefile.py                 # 载荷清单（files → _resource_data + 存根）
├── 构建项目.bat                # = make.bat
├── 构建项目并打包.bat          # 全流程 + 复制产物 + 7z 整合包
├── 构建前检查.py               # CRC / PE / 载荷 / PyInstaller 归档校验
├── 构建后清理.py               # 清理中间物（可 --dry-run）
│
└── <资源名>.py                 # 131 个生成存根，每个只有一行 EmbeddedResource 引用
```

**不入库**（`.gitignore`）：`Python\`、`mingw64\`、`_resource_data\`、`build\`、`dist\`、`Release\`、`*.spec`、`develop`、`ZhangProtectLock`、`_build_validation\`、`import_check_report.json`、`.mimosa\`。

---

## 5. 构建

### 5.1 工具链准备

仓库刻意不提交工具链，需按需补齐到同名目录：

| 目录 | 内容 | 获取方式 |
| --- | --- | --- |
| `Python\` | CPython 3.13.5 x64 + 全套 site-packages | 用 [python-build-standalone](https://github.com/astral-sh/python-build-standalone) 或同版本嵌入式发行版解压到 `Python\`，再跑 `install_pip_modules.bat` |
| `mingw64\` | GCC 14.2.0（`g++` / `windres`） | 解压 MinGW-w64 到 `mingw64\`，确认 `mingw64\bin\g++.exe` 存在 |

> `make_C_files.bat` 直接写死 `%cd%\mingw64\bin`，路径不能改。

### 5.2 依赖

```bat
:: 扫描 import 生成 requirements.txt，再按镜像安装（含 black / PyInstaller / pywin32 / scapy / numpy 等）
install_pip_modules.bat
```

`requirements.txt` 由 `check_imports.py` 自动生成，含少量扫描噪声条目（如 `_testcapi`），安装时会被 pip 跳过，属正常现象。

### 5.3 构建流程

```bat
make.bat            :: 或 构建项目.bat
```

`make.bat` 的顺序（顺序不可颠倒）：

| # | 步骤 | 说明 |
| --- | --- | --- |
| 1 | 写 `ZhangProtectLock` / `develop` | 防止在源码目录直接运行已打包产物；开启 ControlMain 开发模式 |
| 2 | `python makefile.py` | **必须最先执行**：载荷要在打包工具之前生成，否则 hook 找不到 `_resource_data` |
| 3 | `vercode.py` + `black` + 图标脚本 | 版本号、格式化、生成 `icons.py` |
| 4 | `make_C_files.bat` | MinGW64 编译 15 个 C++ 工具 → `files\` |
| 5 | `make_pythontools_files.bat` | PyInstaller 打包 14 个 Python 工具 → `files\` |
| 6 | 再次 `makefile.py` | 把刚生成的工具纳入载荷 |
| 7 | `构建前检查.py` | 7z CRC、PE 结构、载荷魔数/大小、PyInstaller 归档完整性 |
| 8 | `PyInstaller --onefile main.py` | 产出 `dist\ZhangProtect.exe` |
| 9 | 复制到 `Release\` + `构建后清理.py` | 清理 `build\` `dist\` `__pycache__` 等 |

一键整合并压缩分发包：

```bat
构建项目并打包.bat
```

它会依次执行依赖检查、`main.py -h` 冒烟、全量格式化、`make.bat`、把 exe 复制到上两级目录、启动 exe `-h`、压缩 `Zhang多功能整合程序.7z`（密码 `123456`，排除清单 `exclude.txt`），最后调用 `构建后清理.py`。任一步失败会停在 `:build_failed`，**不复制、不移动任何产物**。

### 5.4 产物

| 路径 | 说明 |
| --- | --- |
| `Release\ZhangProtect.exe` | 主程序单文件，全部载荷内嵌（datas 不压缩），体积约等于 `files\` 合计 + 代码，约 750MB 量级 |
| `dist\`、`build\`、`*.spec` | 中间物，构建结束后清理 |
| `_build_validation\prebuild-check.json` | 构建前检查报告 |
| `..\..\..\..\ZhangProtect.exe` | `构建项目并打包.bat` 复制出的测试副本 |

### 5.5 常见坑

- **`ZhangProtectLock` 存在时 `main.py` 直接退出**：这是构建脚本故意写的，源码调试前先删掉它和 `develop`。
- **`_resource_data` 缺失**：先跑 `python makefile.py`，不要直接 PyInstaller。
- **`pip uninstall pathlib`**：`make.bat` 会执行，因为 3.13 上第三方 `pathlib` 会遮蔽标准库。
- **构建前检查失败**：报告在 `_build_validation\prebuild-check.json`，失败时还会生成 `prebuild-fail.html`；按报告里的 `FAIL` 项修对应文件，别跳过检查。
- **`files\` 里替换了文件**：必须重跑 `makefile.py`，否则 exe 里还是旧载荷。

---

## 6. 使用

### 6.1 安装 / 更新 / 卸载

```bat
:: 首次安装（GUI 引导，推荐）
ZhangProtect.exe

:: 静默安装（默认配置，自动提权）
ZhangProtect.exe -q

:: 更新到当前 exe 版本（保留配置，MD5 校验）
ZhangProtect.exe -u

:: 卸载：运行主程序 → 选「否」→「卸载」
```

安装完成后自动创建计划任务并提示一分钟后重启。**卸载不还原程序做过的修改。**

### 6.2 命令行参数

| 参数 | 作用 |
| --- | --- |
| `-t` `/t` | 调试模式：显示控制台并输出日志 |
| `-h` `/h` `/?` | 命令帮助，同时列出全部 94 项开关名 |
| `-q` `/q` | 静默安装（默认配置） |
| `-u` `/u` | 用当前 exe 覆盖安装 |
| `-c` `/c` | 直接打开配置控制台 |

### 6.3 配置控制台

`C:\Windows\Protect\ZhangProtectControl.exe`（源码 `ControlMain.py`）：

- 复选框按 `config_tags` 自动排布，启动时按标记文件回填状态；
- **写入设置**：勾选→建空文件，取消→删文件，然后弹窗提示；
- **刷新进程**：`schtasks /End` + `taskkill` + 重新 `schtasks /Run`；
- **打开配置修改页**：等价于 `Protect.exe -c`。

### 6.4 主配置项（`ProtectConf.conf`，11 行）

| 行 | 配置项 | 默认值 |
| ---: | --- | --- |
| 1 | 非提升守护的进程名 | `explorer.exe` |
| 2 | 非提升守护的启动命令 | `echo.` |
| 3 | 提升（SYSTEM）守护的进程名 | `explorer.exe` |
| 4 | 提升守护的启动命令 | `echo.` |
| 5 | 主循环定期执行的命令 | `echo.` |
| 6 | 数据盘盘符 | 自动选择首个可写非系统盘 |
| 7 | 定期写入目录（诱导同步） | `C:\ProgramData\OnedriveTest` |
| 8 | 定时关机/休眠/重启 | `0`；格式 `xx:xx`，尾部 `r`=重启，`*` 分隔多个 |
| 9 | 高级功能开关 | `0`；`1` 开启增强模式 |
| 10 | 移动热点信息 | `SSID*密码*频段`（频段 0=Auto/1=2.4G/2=5G） |
| 11 | 扫描目标 IPv4（已弃用） | `Disable` |

格式错误会导致主程序反复回到配置界面，改完务必逐行核对。

---

## 7. 功能开关机制

开启任意功能有两种等价方式：

```bat
:: 方式一：GUI
C:\Windows\Protect\ZhangProtectControl.exe

:: 方式二：命令行（创建空文件即开启，删除即关闭）
type nul > C:\Windows\Protect\openwifi
del C:\Windows\Protect\openwifi
```

- 清单权威来源：`configure_tags.py`（94 项），GUI 与 `-h` 帮助都由它驱动；
- 生效时机：主循环下一轮（约 60 秒），无需重启；
- 互斥关系：部分开关有优先级，例如 `RemoveChangeMAC` 存在时覆盖 `AutoChangeMAC`，`closewifi` 优先于 `openwifi`；
- 单项行为、依赖条件、具体注册表/命令：见 [`files/README.md` §4](files/README.md)。

---

## 8. 内置工具载荷

`files\` 下 131 个文件按来源分三类：

| 来源 | 数量 | 生成方式 | 示例 |
| --- | ---: | --- | --- |
| 自研 C++（有源码） | 16 | `make_C_files.bat`（MinGW64，15 份源码，`SetProToPcore` 同时产出 exe/dll） | `ZhangProtectPot.exe`、`taskbar_hider.exe`、`runas_user.exe`、`TurboSwitch.exe`、`keyboard_filter.exe` |
| Python 打包 | 14 | `make_pythontools_files.bat`（PyInstaller） | `SysDispatch.exe`、`Zhang_ip_helper.exe`、`file_server.exe`、`Disable_Safety.exe`、`StorageRedirect.exe` |
| 第三方软件与配套资源 | 101 | 作者收集，直接入库（含 dll/ini/inf/字体/文档） | `CCleaner.7z`、`Everything.7z`、`IDM.7z`、`WizTree.exe`、`RDPWrap.7z`、`PingFangTTF.7z` |

完整清单与每个工具的用途见 [`files/README.md` §5](files/README.md)。`makefile.py` 是载荷与变量名的唯一映射表。

> 载荷里有激活工具（KMS/MAS）、驱动签名绕过（EfiGuard）、多用户 RDP 补丁等敏感软件。它们只是**构建输入**，仓库不提供可用性保证，请自行确认使用场景的合法性。

---

## 9. 测试与校验

`tests\` 下 14 个脚本，多数基于 `unittest`，用项目自带解释器运行：

```bat
:: 单元测试
Python\Python.exe -m unittest tests.test_resource_loader -v
Python\Python.exe -m unittest tests.test_prebuild_check -v
Python\Python.exe -m unittest tests.test_post_build_clean -v
Python\Python.exe -m unittest tests.test_scheduled_tasks -v
Python\Python.exe -m unittest tests.test_file_utils_single_source -v
Python\Python.exe -m unittest tests.test_storage_redirect_cli -v
Python\Python.exe -m unittest tests.test_proxy_environment -v

:: 发布校验（需要先构建出产物）
Python\Python.exe tests\verify_release_artifacts.py
Python\Python.exe tests\verify_full_build.py
Python\Python.exe tests\verify_build_startup.py

:: 冻结包资源冒烟（在 PyInstaller 产物环境里跑）
Python\Python.exe tests\resource_frozen_smoke.py

:: 需要真实 GUI / 代理环境
python tests\profile_resource_startup.py
python tests\proxy_gui_probe.cpp        :: 编译后运行，见文件头注释
```

校验重点不是"能跑通"，而是"能抓坏文件"：0 字节、截断、CRC 损坏、载荷大小错位、缺模块都必须判 `FAIL`。

---

## 10. 风险与已知限制

1. **不可逆修改**：存储重定向、全盘文件时间改写、关闭 UAC、替换 `Narrator.exe`/`VoiceAccess.exe`、隐藏管理员账户 `ZhangProtectAdmin` 等，均无内置还原路径。
2. **安全等级显著下降**：会关闭 Defender 实时保护、SmartScreen、驱动签名校验、Hyper-V、Windows 更新相关服务，并放开 `RunAsPPL`、`limitblankpassworduse`。
3. **反作弊冲突**：`SysDispatch` 持续改进程优先级与核心绑定，`pause_on_game` 会结束 memreduct/desktopok 等进程，可能触发反作弊。
4. **实验性代码**：`ddos()`（HTTP/SYN/Ping 压测）与 `Zhang_lan_scan` 为源码保留的实验功能，默认关闭，请勿用于未授权目标。
5. **仅 Win10+ x64**：大量功能依赖 Win10/11 才有的 API 与策略键。
6. **第三方版权**：内置软件多为非正版分发，仅供个人构建与学习，禁止商用。
7. **仓库体积**：`files\` 743MB，首次克隆较慢；未使用 Git LFS（单文件均 <100MB，`PingFangTTF.7z` 68.6MB 与 `Disable_Safety.exe` 51.7MB 会触发 GitHub 50MB 警告）。
8. **公开仓库风险**：本仓库包含第三方商业软件二进制与激活工具，公开发布可能收到 DMCA 投诉。

---

## 11. 版权与许可

- 本仓库**未附开源许可证**，作者保留权利；按原作者说明，**请勿商用**。
- `files\` 内第三方软件的著作权归各自作者，本仓库仅将其作为构建输入留存。
- 自研 C++ 工具源码位于 `C++_Files\` 与 `ZhangProtectPot_C++\`，Python 源码位于根目录。
- 使用本程序造成的任何系统损坏、数据丢失或合规问题，由使用者自行承担。

---

*版本 `2026.11.12.0` · 用户手册：[`files/README.md`](files/README.md) · 开发交接：[`docs/AGENT_CONTEXT.md`](docs/AGENT_CONTEXT.md)*
