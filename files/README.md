# Zhang 多功能整合程序（ZhangProtect）使用说明

> 本文档覆盖所有功能模块、内置 `.exe` 程序用途，以及程序对系统所做的具体修改。
---

## 目录

1. [项目简介](#1-项目简介)
2. [安装与使用](#2-安装与使用)
3. [主配置项详解（ProtectConf.conf）](#3-主配置项详解protectconfconf)
4. [功能详解（按开关文件逐项说明）](#4-功能详解按开关文件逐项说明)
   - [4.1 WiFi / 移动热点类](#41-wifi--移动热点类)
   - [4.2 电源 / 休眠 / 关机类](#42-电源--休眠--关机类)
   - [4.3 显示 / 桌面 / 时钟类](#43-显示--桌面--时钟类)
   - [4.4 网络 / IP / MAC 类](#44-网络--ip--mac-类)
   - [4.5 存储重定向 / 文件类](#45-存储重定向--文件类)
   - [4.6 游戏优化类](#46-游戏优化类)
   - [4.7 守护进程类](#47-守护进程类)
   - [4.8 安全 / 隐私 / 更新类](#48-安全--隐私--更新类)
   - [4.9 系统美化类](#49-系统美化类)
   - [4.10 系统维护 / 其他类](#410-系统维护--其他类)
5. [内置 .exe 程序一览](#5-内置-exe-程序一览)
   - [5.1 自研 C++ 工具（有源码）](#51-自研-c-工具有源码)
   - [5.2 由 Python 源码打包的独立工具](#52-由-python-源码打包的独立工具)
   - [5.3 内置第三方便携工具](#53-内置第三方便携工具)
6. [程序对系统所做的具体优化修改汇总](#6-程序对系统所做的具体优化修改汇总)
7. [目录结构与构建方法](#7-目录结构与构建方法)
8. [风险与注意事项](#8-风险与注意事项)

---

## 1. 项目简介

本项目是一个 **Windows 系统"整合/守护/优化"型工具**，作者将其设计为：

- 以 **SYSTEM 最高权限**通过计划任务常驻运行的主程序（`Protect.exe`）；
- 一个 **GUI 配置控制台**（tkinter），用于安装、更新、卸载和设置 11 项核心参数；
- 一个 **配置管理器**（`ZhangProtectControl.exe`），以复选框形式开关约 90 项功能；
- 大量 **base64 内嵌的第三方便携软件与自研 C++ 小工具**，随主程序自动释放到 `C:\Windows\Protect\`；
- 一套 **"标记文件"机制**：在 `C:\Windows\Protect\` 下创建某个文件即代表"开启某功能"，删除即代表"关闭某功能"，主程序循环扫描这些文件并实时应用。

### 核心设计思想

| 机制 | 说明 |
| --- | --- |
| 主进程 | `Protect.exe`（由 `main.py` 打包），安装后复制到 `C:\Windows\Protect\Protect.exe` |
| 常驻方式 | 计划任务 `ZhangProtect\Protect`，以 `SYSTEM` 用户、最高权限、登录时触发 |
| 守护方式 | 3 个常驻线程 + 看门狗：进程守护线程、后台任务线程、游戏暂停监控线程 |
| 功能开关 | 在 `C:\Windows\Protect\` 下创建/删除无扩展名标记文件（详见第 4 章） |
| 配置 | `C:\Windows\Protect\ProtectConf.conf`，共 11 行核心配置 |
| 工具释放 | 首次运行或遇到 `force_out_files` 标记时，将内嵌 exe/7z 释放到 Protect 目录 |

### 主程序命令行参数

| 参数 | 作用 |
| --- | --- |
| `-t` / `/t` | 调试模式（显示控制台、打印日志） |
| `-h` / `/h` / `/?` | 显示命令帮助（同时列出全部功能开关名） |
| `-q` / `/q` | 静默安装（使用默认配置，自动请求提权） |
| `-u` / `/u` | 更新程序（用当前可执行文件覆盖已安装版本，保留配置） |
| `-c` / `/c` | 直接打开程序配置控制台 |

---

## 2. 安装与使用

### 2.1 首次安装（推荐）

1. 右键以管理员身份运行 `ZhangProtect.exe`（或 `python main.py`）。
2. 弹出"程序配置控制台"，选择 **是 → 安装/更新**。
3. 在 GUI 中输入 11 项配置（见第 3 章），点击 **保存配置**。
4. 点击 **安装程序**。
5. 程序自动创建计划任务并提示 **一分钟后重启计算机**，重启后生效。

> 安装前请暂时退出安全软件、关闭安全中心实时保护，否则部分释放和注册表操作可能被拦截。

### 2.2 静默安装

```bat
ZhangProtect.exe -q
```

使用默认配置安装（守护 `explorer.exe`、自动热点 `Windows-WiFi(1-8)-<机器码>*12345678*1`、数据盘自动选择第一个可写非系统盘）。

### 2.3 更新

```bat
ZhangProtect.exe -u
```

程序结束自身进程、覆盖 `Protect.exe`、MD5 校验后重新拉起计划任务。

### 2.4 卸载

运行主程序选择 **否 → 卸载**；程序删除 `Protect.exe` 并调用 `C:\Windows\Protect\Uninstaller.bat`，之后会重启计算机。

> **注意**：卸载不会还原程序所做的修改（源码明确提示"不会还原之前做的更改"）。

### 2.5 日常使用

- 打开 `C:\Windows\Protect\ZhangProtectControl.exe`（配置管理器），勾选需要启用的功能，点击"写入设置"；
- 主程序每 60 秒循环一次，自动应用新策略；
- 桌面右键菜单会生成 **"ZhangProtect选项"** 子菜单（需在配置管理器中启用"桌面右键菜单"），包含维护模式、命令行、清理工具、启动项管理等快捷入口。

---

## 3. 主配置项详解（ProtectConf.conf）

配置文件位于 `C:\Windows\Protect\ProtectConf.conf`，共 **11 行**，每行对应控制台中的一个输入框：

| 行 | 配置项 | 默认值 | 说明 |
| --- | --- | --- | --- |
| 1 | 第一个守护进程名 | `explorer.exe` | 非提升运行的守护目标（进程名） |
| 2 | 第一个守护启动命令 | `echo.` | 非提升运行的启动命令 |
| 3 | 第二个守护进程名 | `explorer.exe` | 提升（SYSTEM）运行的守护目标 |
| 4 | 第二个守护启动命令 | `echo.` | 提升运行的启动命令 |
| 5 | 自动执行命令（提升运行） | `echo.` | 主循环定期自动执行的命令 |
| 6 | 数据盘盘符 | 自动选择 | 存储重定向、备份、用户数据的目标盘（如 `D`） |
| 7 | 定期写入目录（诱导同步） | `C:\ProgramData\OnedriveTest` | 用于诱导 OneDrive 同步的目录 |
| 8 | 自动关机/休眠/重启时间 | `0` | 格式 `xx:xx`，末尾加 `r` 表示重启，多个时间用 `*` 分隔 |
| 9 | 高级功能开关 | `0` | 输入 `1` 开启"增强模式"（隐藏设置界面、自动热点等高级功能） |
| 10 | 移动热点信息 | `SSID*密码*频段` | 频段：`0`=Auto、`1`=2.4G、`2`=5G；SSID 1-23 位，密码 8-15 位 |
| 11 | 扫描目标 IPv4（已弃用） | `Disable` | 旧版压力测试目标，默认关闭 |

---

## 4. 功能详解（按开关文件逐项说明）

> **通用开启方法**：在 `C:\Windows\Protect\` 目录下创建对应名称的空文件（无扩展名）即开启；删除该文件即关闭。
> 更直观的方式：运行 `ZhangProtectControl.exe`，勾选对应复选框并点"写入设置"。
> 每项给出的"源码行为"基于 `main.py` / `main_imports.py` 实际代码。

### 4.1 WiFi / 移动热点类

| 开关文件名 | 功能名称 | 源码行为与使用方法 |
| --- | --- | --- |
| `openwifi` | 开启自动热点 | 允许主程序自动创建 Windows 移动热点（配合 KeepWifi 计划任务每 5 分钟/登录时运行 `WifiShare.ps1`）。开启方法：创建 `openwifi` 文件。 |
| `closewifi` | 关闭自动热点（优先） | 优先级最高，存在该文件时强制停止热点共享并阻止 360AP 启动。 |
| `randomwifissid` | 随机热点 SSID | 每次启动生成 8 位随机 SSID，并显示在时钟栏/弹窗中。 |
| `randomwifipwd` | 随机热点密码 | 每次启动生成 8 位随机密码（8-15 位）。 |
| `clock_show_wifiinfo` | 桌面时钟热点信息 | 在 Digital Clock 4 桌面时钟的 settings.ini 中写入当前热点 SSID/密码。 |
| `use_360_ap_flag` | 使用 360AP 作为热点 | 自动启动 `360AP.exe /menufree /school`，并持续改写其 `config.ini`（关闭弹窗、固定 SSID/密码、隐藏托盘等）。需要先安装 `APInstaller.exe`。 |
| `remove_all_wifi` | 移除所有保存的 WIFI | 执行 `netsh wlan delete profile *` 并删除重定向目录下所有 WiFi XML。 |
| `hide_mobilehospset` | 隐藏移动热点设置界面 | 注册表写入 `SettingsPageVisibility = hide:network-mobilehotspot`，隐藏 Windows 设置的移动热点页。 |

### 4.2 电源 / 休眠 / 关机类

| 开关文件名 | 功能名称 | 源码行为与使用方法 |
| --- | --- | --- |
| `donotautopower` | 自动调整电源计划（优先） | 存在时由程序接管电源计划切换（节能/平衡/高性能/卓越性能），否则保持系统默认策略。 |
| `powerkeep` | 使用节能电源计划 | 强制切换到节能电源计划（API 优先，CMD 兜底，复制计划保留亮度）。 |
| `usehibernate` | 使用休眠代替关机 | 允许休眠功能（与 `disablehibernate` 互斥）。 |
| `disablehibernate` | 禁用休眠 | 执行 `powercfg /h off` 类操作并删除休眠文件，同时移除 `usehibernate` 标记。 |
| `donotforcebluescreen` | 禁用强制蓝屏快捷键 | 不写入崩溃热键相关注册表（默认会启用某些测试用蓝屏快捷键）。 |
| `hide_shutdown` | 隐藏电源选项关机 | 注册表 `PolicyManager\device\Start` 写入 `HideShutDown=1`。 |
| `hide_restart` | 隐藏电源选项重启 | 同上写入 `HideRestart=1`。 |
| `hide_sleep` | 隐藏电源选项睡眠 | 同上写入 `HideSleep=1`。 |
| `hide_hibernate` | 隐藏电源选项休眠 | 同上写入 `HideHibernate=1`。 |
| `ListeningLid` | 监听合盖事件（睡眠） | 守护 `Auto_Lid_Sleep.exe`，合盖自动触发睡眠/休眠（需同时存在 `donotautopower` 且未禁用休眠）。 |
| `use_TurboSwitch` | 简易睿频控制器 | 守护 `TurboSwitch.exe`，托盘一键切换处理器睿频/性能状态。 |
| `AutoPowerOptionsOK`（内置于文件包） | 电源选项增强工具 | 安装 `AutoPowerOptionsOK.exe` 增强电源设置管理（便携工具，无独立开关）。 |

### 4.3 显示 / 桌面 / 时钟类

| 开关文件名 | 功能名称 | 源码行为与使用方法 |
| --- | --- | --- |
| `Digital_Clock_4_flag` | 显示桌面时钟 | 守护 `Digital_Clock_4\digital_clock.exe`，桌面显示数字时钟（支持热点信息、自定义信息）。 |
| `show_DeskDisp` | 守护桌面文字 | 守护 `DeskDisp.exe`，在桌面显示自定义文字。 |
| `do_no_change_icon` | 不修改驱动器图标 | 存在时不执行"每日更换 iKun 图标"的驱动器图标写入。 |
| `ikunicon` | 每日更换 iKun 图标 | 按星期几（1-7）将 `iKun_icon\<n>.ico` 写入所有盘符 `DriveIcons\...\DefaultIcon`。 |
| `clock_show_wifiinfo` | 时钟栏显示热点信息 | 见 4.1。 |
| `do_no_show_clock_info` | 在时钟栏显示热点信息 | 将热点 SSID/密码写入系统时钟栏（需开启热点且未关闭显示）。 |
| `user_show_clock_info` | 在时钟栏自定义信息 | 读取 `C:\Windows\Protect\自定义时钟信息.txt`（第 1 行=时间栏，第 2 行=日期栏）写入时钟栏。 |
| `lock_volume` | 锁定音量为 100% | 循环执行 `set_volume.vbs` 将系统音量锁定为 100%。 |
| `keep_desktopok` | 守护 DesktopOK | 守护 `DesktopOK.exe -bg -startup`，保存/恢复桌面图标布局。 |
| `autorestart_desktopok` | 定期刷新 DesktopOK | 每轮主循环结束并重启 `desktopok.exe`。 |
| `Auto_Copy_DesktopOKConf` | 自动覆盖 DesktopOK 配置 | 将 `DesktopOK-Backup.ini` 复制到所有用户 `%AppData%\DesktopOK\DesktopOK.ini`，保持布局一致。 |
| `keep_DesktopGoose` | 守护桌面大鹅 | 守护 `DesktopGoose\GooseDesktop.exe` 桌面宠物。 |
| `HideMyPC` | 隐藏此电脑图标 | 注册表隐藏桌面/此电脑中的"此电脑"图标（CLSID `{20D04FE0-...}`）。 |
| `TaskbarNoPinnedList` | 关闭任务栏固定项 | 注册表 `TaskbarNoPinnedList=1`，禁止任务栏固定应用。 |
| `RemoveICONArrow` | 去除快捷方式箭头 | 注册表 `Shell Icons\29 = TransparentIcon.ico`，快捷方式箭头变透明。 |
| `ShowSecondsInSystemClock` | 任务栏时钟显示秒 | 注册表 `ShowSecondsInSystemClock=1`（HKLM + HKCU）。 |
| `taskbarhide` | 隐藏任务栏 | 守护 `taskbar_hider.exe`（全局快捷键/托盘切换隐藏任务栏）。 |
| `allowIsPinnedToMyPC` | 去除此电脑左侧固定项 | 删除"此电脑"侧边栏固定项注册表（保留桌面命名空间图标）。 |
| `doautoruninf` | 处理 Autorun.inf | 对可移动磁盘执行：删除/隐藏 `autorun.inf` 并创建不可删除的 `autorun.inf\protect..\` 陷阱目录。 |
| `AutoRemove_DRIVE_REMOVABLE_flag` | 登录时弹出所有 U 盘 | 注册计划任务，登录时运行 `AutoRemove_DRIVE_REMOVABLE.exe` 安全弹出所有可移动磁盘。 |
| `Disable_Safety`（独立 exe） | 禁用安全相关设置 | 独立工具，可关闭防火墙、关闭 Hyper-V、开启测试签名/禁用驱动签名校验、禁用 Windows 更新等（见 5.1）。 |

### 4.4 网络 / IP / MAC 类

| 开关文件名 | 功能名称 | 源码行为与使用方法 |
| --- | --- | --- |
| `ipcheck` | 断网自动更换 IP | 守护 `Zhang_IpHelper.exe /a`：每 5-10 秒用 `www.baidu.com`（可改 `network_test_url.txt`）探测网络，断网时在同一网段内寻找可用 IP 并切换；支持 `network_segment.txt` 自定义网段、`network_base_ip_txt.txt` 记录原始 IP。 |
| `AutoChangeMAC` | 自动随机修改网卡 MAC | 定时将物理网卡 MAC 改为随机值（保留前 3 段）。 |
| `RemoveChangeMAC` | 移除修改网卡 MAC（优先） | 删除注册表 `NetworkAddress` 覆盖值，恢复硬件 MAC；存在时自动删除 `AutoChangeMAC`。 |
| `use_network_balance` | 多网络适配器负载均衡 | 创建网卡组（NetSwitchTeam）实现多网卡负载均衡（依赖 WMI，禁用 WMI 时不生效）。 |
| `disable_Proxy_ongame` | 游戏时关闭系统代理 | 游戏运行期间将所有用户的 `ProxyEnable=0`，游戏结束恢复。 |
| `fuck_8021x` | 自动结束 8021x | 每轮检测到网络后 `taskkill /f /im 8021x.exe` 和 `suservice.exe`，并注册计划任务防止校园网认证进程拉起。 |
| `RDP_Display_Cha` | RDP 显卡优化 | 写入远程桌面 WDDM/AVC/H.264 硬件编码、RemoteFX 等优化注册表（见第 6 章）。 |
| `use_rdpwrap` | 使用 RDPWrap | 释放并安装 `RDPWrap`（多用户远程桌面补丁），执行 `install.bat`。 |
| `auto_Timesync` | 自动校准时间 | 安装 `NetTime` / 运行 `Timesync.exe /auto` 自动校时。 |
| `keep_simplewall` | 守护 simplewall | 守护 `simplewall.exe -minimized` 简易防火墙。 |

### 4.5 存储重定向 / 文件类

| 开关文件名 | 功能名称 | 源码行为与使用方法 |
| --- | --- | --- |
| `use_storage_redirect` | 开启存储重定向（不可逆） | **核心功能**。将每个用户的桌面/文档/下载/收藏夹/音乐/图片/视频/AppData 等用户数据目录，以及整个用户配置文件（`ProfileImagePath`），重定向到数据盘（如 `D:\Users\<用户名>\`）。首次使用卷影复制（VSS）拷贝，之后注册表写入 `User Shell Folders` / `ProfileImagePath`；同时创建隐藏管理账户、设置全权限。源码提示此操作**不可逆**。 |
| `use_file_arrange` | 开启文件整理 | 将系统盘 `Users` 下各用户数据按结构整理到重定向目录。 |
| `change_all_filetime_flag` | 修改文件时间 | 将全部驱动器（含系统盘）所有文件创建/修改时间改为 `3000-01-01`，用于对抗还原软件的时间检测。 |
| `del_system_logs` | 删除系统日志 | 用 `wevtutil cl` 清空所有事件日志并禁用日志通道（`/e:false`）。 |
| `autoreregdll` | 自动重新注册 DLL | 循环执行 `regsvr32 /s %windir%\system32\*.dll` 和 `*.ocx`。 |
| `use_file_server` | 启用文件服务器 | 守护 `file_server.exe`（HTTP 简易文件服务器），默认端口 18080（可改 `file_server_port.txt`），共享数据盘根目录。 |
| `use_USB_protect` | 连接 U 盘写保护或共享 | 存在时：赋予 U 盘 Everyone 完全权限、隐藏/删除 autorun.inf、并 `net share USBDiskShare=盘符 /grant:everyone,full` 共享；删除标记则取消共享。 |
| `Traffic_Killer_flag` | 使用流量消耗器 | 启动 `Traffic_Killer.exe`，从 `Traffic_Killer_url.txt`（默认联通测速文件 `https://cesubao.chinaunicom.cn/1000.bin`）持续下载消耗流量。 |
| `use_storage_redirect` 相关 | WiFi 信息持久化 | 将 `WlanSvc` 数据目录重定向到 `数据盘:\StorageRedirect\Wlansvc`，还原环境下仍保留 WiFi 配置；提示手动用 DataLgloo 重定向注册表 `HKLM\SOFTWARE\Microsoft\WlanSvc` 和 `NetworkList`。 |
| `SystemBackup` / `daily_system_backup` | 自动备份系统 | 开启自动系统备份：执行 CCleaner 清理、`DISM` 组件清理、用 `SnapShot.exe` 对系统盘制作镜像（`.sna`）+ 哈希校验；`daily_system_backup` 开启每天增量备份。备份目录 `数据盘:\Important\System_Backup`。 |

### 4.6 游戏优化类

| 开关文件名 | 功能名称 | 源码行为与使用方法 |
| --- | --- | --- |
| `pause_on_game` | 游戏运行时暂停程序 | 检测到 `自定义游戏暂停进程.txt` 中进程运行时，暂停所有后台线程和大部分计划任务，避免干扰游戏。 |
| `pause_on_game_list`（配置文件） | 自定义游戏暂停进程 | 一行一个进程名；`进程名*noreddot` 表示该游戏运行时不显示外置红点；游戏开始/结束时自动运行 `run_on_pause_on_game_start_bat.bat` / `run_on_pause_on_game_end_bat.bat`。 |
| `highper_on_game` | 游戏时切换高性能 | 游戏运行期间切到高性能电源计划，结束后切回原计划。 |
| `disable_Proxy_ongame` | 游戏时关闭系统代理 | 见 4.4。 |
| `ZhangGameRedDotflag` | 游戏时使用外置红点 | 守护 `ZhangGameRedDot.exe`（屏幕中央显示准星红点，跟随鼠标所在显示器）。 |
| `Auto_SetGameToPcore` | 自动优化游戏进程 | 游戏运行期间将游戏进程绑定到 **P 核**（性能核）并提高优先级。 |
| `Game_Reverse_Core` | 进程调度反转核心类型 | 与上面相反，将游戏绑定到 **E 核**（能效核）。 |
| `FilterKeyOnGame` | 游戏时屏蔽部分快捷键 | 守护 `keyboard_filter.exe`，游戏期间屏蔽易误触的系统快捷键。 |
| `use_movemouse` | 守护挂机工具 | 守护 `MoveMouse.exe`（自动移动鼠标防挂机），并自动写入"挂机"动作配置。 |
| `use_fraps` | 守护 Fraps | 守护 `Fraps\fraps.exe` 录屏工具，并注册 Fraps 视频解码器。 |
| `keep_speccy` | 守护 Speccy 托盘 | 守护 `Speccy\Speccy64.exe /totray`，任务栏显示硬件温度。 |
| `keep_memreduct` | 守护 Memreduct | 守护 `memreduct.exe /minimized` 自动内存清理。 |
| `keep_awake` | 保持电脑唤醒 | 守护 `Awake.exe`，防止系统睡眠/锁屏待机。 |
| `GameKeyBoardTool`（无独立开关） | 游戏挂机按键工具 | 独立工具 `GameKeyBoardTool.exe`，随机按键模拟（MoveMouse 配置中已内置调用）。 |
| `FuckKeyBoardZ.exe`（配合 `fuck_keyboard`） | 优化键盘操作 | 见 4.9。 |

### 4.7 守护进程类

主程序内置"进程守护线程"，每轮循环确保以下程序存活（对应开关文件存在时），程序退出即自动拉回：

| 开关文件 | 守护目标 |
| --- | --- |
| `keep_desktopok` | `desktopok.exe -bg -startup` |
| `keep_memreduct` | `memreduct.exe /minimized` |
| `keep_awake` | `Awake.exe` |
| `keep_DesktopGoose` | `GooseDesktop.exe` |
| `keep_speccy` | `Speccy64.exe /totray` |
| `keep_simplewall` | `simplewall.exe -minimized` |
| `KeepPopBlock` | `PopBlock.exe -hide`（弹窗拦截） |
| `KeepEverything` | `Everything.exe -startup`（文件搜索） |
| `use_fraps` | `fraps.exe` |
| `use_movemouse` | `MoveMouse.exe` |
| `use_TurboSwitch` | `TurboSwitch.exe` |
| `Digital_Clock_4_flag` | `digital_clock.exe` |
| `show_DeskDisp` | `DeskDisp.exe` |
| `taskbarhide` | `taskbar_hider.exe` |
| `EnableAutoScreenshot` | `AutoScreenshot.exe -autorun`（截图监控，输出到 `数据盘:\Files\Data\AutoScreenshot`） |
| `Disable_sys_dispatch` | `SysDispatch.exe`（不公平调度） |
| `DisableBluetoothHFP` | `BluetoothHFPGuard.exe`（蓝牙 HFP 禁用） |
| `keep_awake` | `Awake.exe` |
| `use_file_server` | `file_server.exe 数据盘:\` |
| `ipcheck` | `Zhang_IpHelper.exe /a` |
| 第一个/第二个守护进程 | 配置文件中第 1、3 行指定的任意进程 |

另外：
- `more_keep_process`（`更多守护进程.conf`）：自定义额外守护列表，一行一个进程名。
- 进程守护线程自带看门狗（`thread_monitor.py`），卡死 60 秒自动重启线程。

### 4.8 安全 / 隐私 / 更新类

| 开关文件名 | 功能名称 | 源码行为与使用方法 |
| --- | --- | --- |
| `DisableLUA` | 关闭 UAC | 注册表 `EnableLUA=0`，关闭用户账户控制。 |
| `Disable_Safety.exe`（独立） | 关闭安全相关设置 | 见 5.1（关闭防火墙、测试签名、禁用更新等）。 |
| `AutoPreCFlag` | 关闭全局权限设置 | 存在时跳过"给全盘/系统目录授予 Everyone 权限"的预处理。 |
| `excludeflag` | 关闭杀毒白名单设置 | 存在时跳过杀毒软件（如火绒）白名单/排除项的自动写入。 |
| `del_mstsc_log` | 移除 mstsc 的记录 | 删除所有用户的 `Default.rdp` 及远程桌面客户端注册表历史。 |
| `BT_DisableAbsoluteVolume` | 禁用蓝牙绝对音量 | 注册表 `DisableAbsoluteVolume=1`，解决蓝牙耳机音量不可调问题。 |
| `AutoClearJetBrainsHistory` | 自动清理 JetBrains 历史 | 清除各用户 `%AppData%\JetBrains` 下的最近项目/搜索历史。 |
| `disable_Winmgmt` | 禁用 Winmgmt（不建议） | 停止并禁用 WMI 服务（源码标注"不建议"，会破坏部分功能）。 |
| `need_hyper_v` | 不要关闭 Hyper-v | 存在时保留 `hypervisorlaunchtype`，不执行关闭 Hyper-V 的 bcdedit。 |
| `block_all_update`（无开关，恒执行） | 禁用更新 | 每个后台循环调用 `windows_update_blocker.py` 禁用含 update/orchestrator/medic 等服务，并禁用含 update 关键字的计划任务（白名单 `ZhangProtect`）。 |
| `Run_on_no_network`（配置文件） | 断网自动脚本 | 检测到断网时以 SYSTEM 运行 `C:\Windows\Protect\run_on_no_network.bat`。 |
| `run_on_Power_Troubleshooter_bat`（配置文件） | 唤醒自动脚本 | 系统唤醒时以 SYSTEM 运行 `run_on_WakeUP.bat`。 |
| `deny_appdata_folder_conf`（配置文件） | 自定义夺权文件夹 | 剥夺各用户 `%AppData%` 下指定文件夹权限（默认屏蔽微信/QQ 更新目录），阻止应用自动更新下载。 |
| `HuorongData`（内置） | 火绒安全设置导入 | 导入 `ZhangProtect火绒安全设置导入.dat` 到火绒，隐藏托盘、自动启动、关闭消息弹窗。 |
| `keep_DesktopGoose` | 桌面宠物（娱乐） | 见 4.3。 |

### 4.9 系统美化类

| 开关文件名 | 功能名称 | 源码行为与使用方法 |
| --- | --- | --- |
| `fuck_keyboard` | 优化键盘操作 | 守护 `FuckKeyBoardZ.exe`：强制 NumLock 开启、CapsLock 关闭（防误触）。 |
| `break_key_pgup_pgdn` | 屏蔽键盘上的 PgUp 和 PgDn | 注册表 `Scancode Map` 写入 `00 00 00 00 00 00 00 00 03 00 00 00 00 00 51 E0 00 00 49 E0 00 00 00 00`，全局屏蔽。 |
| `enable_desktopmenu` | 启用桌面右键菜单 | 注册表生成桌面右键"ZhangProtect选项"子菜单（含维护模式、命令行、清理、启动项管理、MAC 修改、时间校准、提权终端等 16+ 项）；`更多桌面右键菜单.txt` 可自定义追加（`标签*命令`）。 |
| `PingFangTTF`（内置） | 安装苹方字体 | 释放 `PingFangTTF.7z` 并复制到系统字体目录、写入注册表。 |
| `FontTools`（内置） | 字体工具 | 释放字体工具集（FontTools.7z），可管理/修复系统字体。 |
| `NewTemplate`（内置） | 新建模板 | 释放右键"新建"菜单模板（NewTemplate.7z）。 |
| `iKun_icon` / `iKun_Sound` | iKun 图标与音效 | 见 `ikunicon`；`iKun_Sound.wav` 释放到系统目录。 |
| `DesktopOK` | 桌面布局保存 | 见 4.3。 |
| `AutoScreenshot` | 自动截图 | 见 4.7（可配置输出目录）。 |

### 4.10 系统维护 / 其他类

| 开关文件名 | 功能名称 | 源码行为与使用方法 |
| --- | --- | --- |
| `force_out_files` | 强制释放文件（单次） | 存在时强制覆盖释放所有内嵌 exe/7z，执行后自动删除该标记。 |
| `lowerlog` | 禁用日志 | 存在时主程序不写日志文件（`C:\Windows\Protect\lowerlog`）。 |
| `SystemBackup` / `daily_system_backup` | 系统自动备份 | 见 4.5。 |
| `enable_desktopmenu` | 右键菜单维护入口 | 见 4.9（维护模式、系统更新模式、清理、驱动备份等入口）。 |
| `ProtectKeeper`（计划任务） | 程序自愈 | 每 5 分钟检查主程序，未运行则自动拉起。 |
| `BatKeeperRun`（计划任务） | 批处理守护 | 每 5 分钟运行 `BatKeeper.vbs`，保持指定批处理脚本运行。 |
| `MainTainClean` / `维护模式.bat` | 系统维护模式 | 一键进入维护模式（清理、检查、更新维护脚本）。 |
| `Maintain_tools_folder` / `Maintain_tools_ISO` | 维护工具包 | 生成 `ZhangProtect-系统维护` 目录并打包 ISO，包含系统维护工具。 |
| `AutoRunCommand`（`数据盘:\Files\AutoCommand\AutoCommand.bat`） | 自动命令 | 检测到该批处理被修改时自动以 SYSTEM 运行（所有问题自动回答 Y）。 |
| `SystemInfoChanger`（内置） | 修改系统信息 | 独立工具修改系统 OEM 信息（品牌、型号、Logo 等）。 |
| `Zhang_PE_Tool`（内置） | PE 工具箱 | PE 环境下向目标系统安装 ZhangProtect（离线安装、移除冰点等）。 |
| `Zhang_lan_scan`（内置，已弃用） | 局域网扫描 | 简易 HTTP 路径+端口扫描工具（源码注明"仅供学习参考，效率低下"）。 |
| `WindowDebugTool`（内置） | 窗口调试 | 监控焦点窗口，记录进程名；可隐藏窗口/挂起进程/结束进程（白名单模式）。 |
| `format_changer_tool`（内置） | 格式转换工具 | `FormatTool.exe 原后缀 目标后缀 [去除字符串]`，用 ffmpeg 批量转换当前目录文件。 |
| `ZhangKeyLauncher`（内置） | 快捷键启动器 | 全局热键快速启动指定程序（`ZhangKeyLauncher.exe`）。 |

---

## 5. 内置 .exe 程序一览

> 所有程序均随主程序自动释放到 `C:\Windows\Protect\` 对应子目录。下表按来源分为三类。

### 5.1 自研 C++ 工具（有源码）

源码位于 `C++_Files\`，由 `make_C_files.bat` 用项目自带 MinGW64 编译：

| 程序 | 作用 |
| --- | --- |
| `Protect.exe` | 主程序（`main.py` 打包），由 `ZhangProtect.exe` 安装并常驻；接受 `-t/-h/-q/-u/-c` 参数。 |
| `ZhangProtectPot.exe` | 守护/启动器：`ProtectKeeper` 计划任务每 5 分钟检查并拉起 `Protect.exe`；同时是 `ProtectPot`（用户级）计划任务目标。 |
| `ZhangProtectControl.exe` | 配置管理器（GUI），对应 `ControlMain.py`：复选框式开关全部功能，并支持"写入设置/刷新进程/打开配置修改页"。 |
| `ZhangProtectPot_C++`（`ZhangProtectStartUpTool.cpp`） | 同 `ZhangProtectPot.exe` 的 C++ 实现（守护自启）。 |
| `FuckKeyBoardZ.exe` | 键盘优化：强制 NumLock 开、CapsLock 关。 |
| `GameKeyBoardTool.exe` | 游戏挂机按键工具：随机按下/释放按键，防止挂机掉线。 |
| `ZhangGameRedDot.exe` | 外置红点准星：在鼠标所在显示器屏幕中心绘制准星红点（带托盘）。 |
| `ZhangKeyLauncher.exe` | 全局快捷键启动器：绑定快捷键快速启动指定应用。 |
| `SetProToPcore.exe` / `SetProToPcore.dll` | 进程核心/优先级设置：按进程名或 PID 设置 P 核/E 核绑定、高优先级、递归子进程。 |
| `AutoRemove_DRIVE_REMOVABLE.exe` | 登录时安全弹出所有可移动驱动器（`IOCTL_STORAGE_EJECT_MEDIA`）。 |
| `taskbar_hider.exe` | 隐藏/恢复任务栏（托盘菜单 + 全局热键）。 |
| `runas_user.exe` | 以指定用户身份运行程序（支持任务计划、SYSTEM/用户切换，`/h` 查看帮助）。 |
| `Auto_Lid_Sleep.exe` | 监听笔记本合盖事件，触发睡眠/休眠（`SetSuspendState`）。 |
| `keyboard_filter.exe` | 键盘过滤：游戏/全局模式下屏蔽指定系统快捷键组合。 |
| `TurboSwitch.exe` | 简易睿频控制器：一键切换处理器睿频开关（托盘）。 |
| `BluetoothHFPGuard.exe` | 蓝牙 HFP 禁用守护：禁用 HFP 相关服务（`-restore` 恢复）。 |
| `AutoDisplayConfig.exe` | 自动显示配置：设置多显示器布局/分辨率/DPI 参数。 |

### 5.2 由 Python 源码打包的独立工具

| 程序 | 对应源码 | 作用 |
| --- | --- | --- |
| `ZhangProtect.exe` | `main.py` | 安装/更新/卸载入口 + 主程序（运行时复制为 `Protect.exe`）。 |
| `SysDispatch.exe` | `Sys_Dispatch_Main.py` | "不公平调度"：焦点窗口进程 → 高优先级 + P 核；后台进程 → 低于正常 + E 核；可自定义高/低/忽略进程列表。 |
| `file_server.exe` | `file_server.py` | HTTP 简易文件服务器（默认端口 18080，可改 `file_server_port.txt`）。 |
| `Traffic_Killer.exe` | `Traffic_Killer.py` | 流量消耗器：持续下载指定 URL 消耗流量。 |
| `WifiMobileTool.exe` | `WifiMobileTool.py` | 移动热点自动启动配置工具：创建 SYSTEM 计划任务每 3 分钟保证热点开启，可指定 SSID/密码/频段。 |
| `Zhang_PE_Tool.exe` | `Zhang_PE_Tool_Main.py` | PE 工具箱：PE 下向目标 Windows 安装 ZhangProtect、移除冰点、写注册表。 |
| `WindowDebugTool.exe` | `WindowDebugTool.py` | 窗口调试：记录焦点窗口进程、隐藏/挂起/结束非白名单窗口。 |
| `format_changer_tool.exe` | `format_changer_tool.py` | 格式转换（ffmpeg 批量转码），`/h` 查看帮助。 |
| `Zhang_ip_helper.exe` | `Zhang_IPhelper.py` | 断网自动换 IP（`/a` 自动模式）。 |
| `Zhang_lan_scan.exe` | `Zhang_lan_scan.py` | 简易 HTTP 端口/路径扫描（学习用途）。 |
| `RestoreConf.exe` | `restoreconfs.py` | 恢复配置：还原热点 SSID/密码、恢复时钟栏信息、清理 JetBrains 历史、恢复桌面右键菜单。 |
| `Awake.exe` | `awakekeeper.py` 携带 | 保持系统唤醒。 |
| `Disable_Safety.exe` | `remove_safe.py` | 一键关闭/恢复：防火墙、Hyper-V、驱动签名校验（测试签名）、系统更新服务、杀毒相关等（生成 `disable_safety.bat` 计划任务）。 |

### 5.3 内置第三方便携工具

> 以下工具由作者收集并 base64 内嵌，随程序释放，作用均为常见便携软件，供主程序或用户手动调用：

| 程序/包 | 作用 |
| --- | --- |
| `7z.exe` / `7z.dll` | 7-Zip 命令行压缩（程序内部解压 7z 包）。 |
| `7-zip-installer.exe` / `WinRAR-installer.exe` | 7-Zip / WinRAR 安装包。 |
| `CCleaner.7z` | CCleaner 清理工具（主程序自动执行 `/AUTO` 清理并自动配置免清理 QQ/微信记录）。 |
| `Everything.7z` | Everything 文件秒搜。 |
| `DesktopOK.exe` | 桌面图标布局保存/恢复。 |
| `memreduct.exe` | 内存自动清理。 |
| `MoveMouse.exe` | 自动移动鼠标（防挂机）。 |
| `Fraps.7z` | 游戏录屏/帧数显示。 |
| `Speccy.7z` | 硬件温度/信息查看。 |
| `simplewall.exe` / `simplewall.lng` | 轻量防火墙。 |
| `PopBlock.7z` | 弹窗拦截工具。 |
| `AutoScreenshot.7z` | 自动截图工具。 |
| `DeskDisp.7z` | 桌面显示文字工具。 |
| `Digital_Clock_4.7z` | 桌面数字时钟。 |
| `DesktopGoose.7z` | 桌面宠物大鹅。 |
| `FreeFileSync.7z` | 免费文件同步（含 RealTimeSync）。 |
| `WinSCP.7z` | SFTP/FTP 客户端。 |
| `XYplorer.7z` | 便携文件管理器。 |
| `WinDbg.7z` | Windows 调试器（内核调试）。 |
| `WinHex.exe` | 十六进制编辑器/磁盘编辑器。 |
| `WizTree.exe` | 磁盘空间分析（秒扫）。 |
| `FastCopy.exe` | 高速文件复制。 |
| `ProcessMonitor.exe` / `procexp64.exe` | Sysinternals 进程监控 / 进程资源管理器。 |
| `Autoruns64.exe` | 启动项/自启管理。 |
| `ContextMenuManager.exe` | 右键菜单管理器。 |
| `DefaultAppLocker.exe` | 默认应用锁定/管理。 |
| `SetUserFTA.exe` | 文件类型关联设置。 |
| `shexview.exe` / `shexview_lng.ini` | Shell 扩展查看器。 |
| `RegistryFinder.7z` | 注册表搜索工具。 |
| `Optimizer.exe` | 系统优化工具（优化服务/隐私等）。 |
| `PrivaZer.7z` | 深度隐私清理。 |
| `ProcessLasso.7z` | 进程调度优化（ProBalance）。 |
| `LockHunter.7z` | 文件/进程解锁。 |
| `UltraISO.exe` | 光盘镜像工具。 |
| `rufus.exe` | 启动盘制作。 |
| `xorriso.7z` | ISO 制作工具。 |
| `NetTime.exe` / `Timesync.exe` / `timesync.ini` | 网络校时工具。 |
| `NewFileTime.exe` | 批量修改文件时间。 |
| `h2testw.exe` | U 盘/存储卡扩容测试。 |
| `iperf3.exe` / `cygwin1.dll` | 网络带宽测试。 |
| `nircmd.exe` / `nircmdc.exe` | NirSoft 命令行系统控制工具。 |
| `NSudo.exe` / `NSudoL.exe` | SYSTEM/TrustedInstaller 权限提权工具。 |
| `ntsd.exe` | Windows 用户态调试器。 |
| `BlueScreenView.exe` | 蓝屏转储查看。 |
| `SystemInfoChanger.exe` | 修改系统 OEM 信息。 |
| `MacManager.exe` | 网卡 MAC 修改。 |
| `Autologon.exe` | 自动登录配置。 |
| `KMSActivator.exe` / `MAS.7z` | Windows/Office 激活工具（KMS / Microsoft Activation Scripts）。 |
| `IDM.7z` | Internet Download Manager 下载器。 |
| `aria2.7z` | 命令行多线程下载器。 |
| `RDPWrap.7z` | 远程桌面多用户补丁。 |
| `EfiGuard.7z` | EFI 引导时禁用驱动签名校验（含 EfiDSEFix、BOOTICE、DiskGenius）。 |
| `install_wim_tweak.exe` | WIM 镜像 Appx 集成/移除工具。 |
| `NpCapInstaller.exe` | WinPcap/Npcap 抓包库（供 scapy 等使用）。 |
| `nvidiaopenglrdp.exe` | RDP 下 NVIDIA OpenGL 支持。 |
| `ByeByeJY.exe` | 隐藏/清理类小工具（随 WindowDebugTool 白名单使用）。 |
| `uwd.exe` | Windows 更新禁用辅助工具。 |
| `DataLgloo.exe` | 文件夹/注册表重定向工具（用于 WiFi 信息持久化）。 |
| `WeiWeiFont.exe` | 字体管理工具（修改中文字体/替换雅黑）。 |
| `PingFangTTF.7z` | 苹方字体包。 |
| `FontTools.7z` | 字体工具集。 |
| `NewTemplate.7z` | 右键新建模板。 |
| `iKun_icon.7z` / `iKun_Sound.wav` / `TransparentIcon.ico` | 图标/音效资源包。 |
| `APInstaller.exe` | 360 随身 Wi-Fi 驱动/AP 安装器（配合 `use_360_ap_flag`）。 |
| `DGuardInstall.exe` | 某网管/还原软件卸载或安装辅助工具。 |
| `AutoPowerOptionsOK.exe` | 电源选项增强工具。 |
| `DontSleep.exe` | 防休眠工具。 |
| `nmyu.7z` | 内置便携工具包（源码未标注具体用途）。 |
| `PasswordSecEdit.inf` | 安全策略导入模板。 |
| `Packages.txt` | 包清单文件。 |
| `ZhangProtect火绒安全设置导入.dat` | 火绒安全软件设置导入数据。 |

---

## 6. 程序对系统所做的具体优化修改汇总

> 以下内容全部来自源码中实际执行的命令/注册表操作，按类别整理。**执行后果不可逆**，请谨慎评估。

### 6.1 注册表修改

| 位置 | 修改内容 |
| --- | --- |
| `HKLM\SOFTWARE\Policies\Microsoft\OneDrive` | 批量写入 OneDrive 策略：禁用删除对话框、暂停同步（按流量计费/电池）、静默迁移文件夹、禁用自动配置等。 |
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System` | `EnableLUA=0/1`（按 `DisableLUA` 开关）、`VerboseStatus=1`。 |
| `HKLM\SYSTEM\CurrentControlSet\Control\Bluetooth\Audio\AVRCP\CT` | `DisableAbsoluteVolume=1`（蓝牙绝对音量）。 |
| `HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\Start` | `HideShutDown/HideRestart/HideSleep/HideHibernate`（电源菜单隐藏）。 |
| `HKCU/HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced` | `ShowSecondsInSystemClock`（任务栏秒）。 |
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Icons` | `29 = TransparentIcon.ico`（去快捷方式箭头）。 |
| `HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer` | `TaskbarNoPinnedList`、`HideRecommendedSection`、`DisableSearchBoxSuggestions`、`HideRecommendedPersonalizedSites` 等。 |
| `HKLM\...\Explorer\HideDesktopIcons\NewStartPanel` | 隐藏桌面系统图标；`HideMyPC` 控制"此电脑"。 |
| `HKLM\SYSTEM\CurrentControlSet\Control\FileSystem` | `LongPathsEnabled=1`（启用长路径）。 |
| `HKLM\SYSTEM\CurrentControlSet\Control` | `WaitToKillServiceTimeout=1500`（加速关机）。 |
| `HKLM\SYSTEM\CurrentControlSet\Control\Keyboard Layout` | `Scancode Map`（屏蔽 PgUp/PgDn，可选）。 |
| `HKLM\SYSTEM\CurrentControlSet\Control\Update` | `UpdateMode=0`。 |
| `HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters` | `RequireSecuritySignature=0`、`AllowInsecureGuestAuth=1`。 |
| `HKLM\SYSTEM\CurrentControlSet\Control\Lsa` | `RunAsPPL=0`、`RunAsPPLBoot=0`、`limitblankpassworduse=0`。 |
| `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender...` | 关闭实时保护、禁用通知、隐藏安全中心各模块（UILockdown）。 |
| `HKLM\SOFTWARE\Policies\Microsoft\Windows\System` | `EnableSmartScreen=0`、`DisableAcrylicBackgroundOnLogon=1`。 |
| `HKLM\SOFTWARE\Policies\Microsoft\Windows\Psched` / `EdgeUI` | `NonBestEffortLimit=0`（解除 QoS 限速）、`AllowEdgeSwipe=0`。 |
| `HKLM\SYSTEM\CurrentControlSet\Control\CI` / `DeviceGuard` | `FeatureSetState=0`、`VulnerableDriverBlocklistEnable=0`、`HypervisorEnforcedCodeIntegrity=0`。 |
| `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\PasswordLess\Device` | `DevicePasswordLessBuildVersion=0`（启用密码登录）。 |
| `HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers` | 显示器缩放 `Scaling=3`。 |
| `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore` | 还原点创建频率 `1440`。 |
| `HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services` | RDP 优化：WDDM 驱动、AVC444、硬件编码、RemoteFX、`SelectTransport=2` 等（`RDP_Display_Cha`）。 |
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer` | `NoDriveTypeAutoRun=255`（禁止所有盘符自动运行）、隐藏移动热点设置页。 |
| `HKLM\SOFTWARE\Policies\Microsoft\Edge` | 删除 Edge 策略、禁用 Edge 更新服务。 |
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\DriveIcons` | 写入各盘符图标（iKun 图标，每日更换）。 |
| `HKLM\SOFTWARE\Classes\Directory\background\shell` | 桌面右键"ZhangProtect选项"子菜单 + 自定义命令。 |
| 用户 Shell 文件夹 | `User Shell Folders` / `ProfileImagePath` 重定向到数据盘（存储重定向）。 |

### 6.2 服务 / 计划任务修改

| 类型 | 内容 |
| --- | --- |
| 服务禁用 | `wuauserv`、`UsoSvc`、`WaaSMedicSvc`、`BITS`、`DiagTrack`、`sih`、`edgeupdate`、`edgeupdatem`、`MicrosoftEdgeElevationService`、`EasiUpdate`/`EasiUpdate3`/`EasiUpdate3Protect`、`DusmSvc`、`Winmgmt`（可选）、`8021x`/`suservice`（按开关）等。 |
| 服务启用 | `msiserver`、`TrustedInstaller`、`Winmgmt`（默认恢复）。 |
| 计划任务（`ZhangProtect\` 命名空间） | `Protect`（主程序，SYSTEM/登录）、`ProtectPot`、`ProtectKeeper`（每 5 分钟自愈）、`AutoPreD`、`KeepWifi`/`KeepWifi_Fast`、`ReturnIcon`、`Run_ON_Power_Troubleshooter`、`AutoRemoveUDrivers`、`UsbChanger`、`BatKeeperRun`、`MainTain_Mode`、`CCleaner-Auto`、`Fuck8021X`（可选）。 |
| 计划任务禁用 | 扫描并禁用所有名称/路径含 update/upgrade/orchestrator/medic/delivery/bits 等关键字的任务（白名单 ZhangProtect）。 |
| 计划任务（Microsoft\Windows\Zhang） | `WifiMobileTool`（每 3 分钟保热点）、`Disable_Safe`（每小时执行安全禁用脚本）。 |
| 启动项 | 主程序常驻计划任务；不写传统 Run 启动项。 |

### 6.3 文件系统 / 权限修改

| 类型 | 内容 |
| --- | --- |
| 目录创建 | 在数据盘创建 `Users`、`Files\Data`、`Files\Develop`、`Important\System_Backup\Drivers_Backup`、`StorageRedirect\{Program,Wlansvc,Registry,Vault,HuoRongData,Data}`、`学科文件夹` 等目录。 |
| 权限授予 | 对数据盘各目录执行 `icacls /grant SYSTEM|Users|Administrators|Everyone:(OI)(CI)(F)`；安装时对 `%systemroot%` takeown + Everyone 完全控制；重定向后用户数据目录全权限。 |
| 权限剥夺 | 对 `%AppData%\Tencent\xwechat\update`、`QQ\packages\full` 及自定义列表执行 `icacls /deny Everyone`，阻止更新下载。 |
| 文件操作 | 清空事件日志（`wevtutil cl`）；重新注册 system32 全部 DLL/OCX；修改全盘文件时间为 3000-01-01；删除 `Default.rdp`；删除 `USBSTOR` 枚举键；`VoiceAccess.exe`/`Narrator.exe` 替换为 `cmd.exe`（辅助功能后门式入口）。 |
| 系统文件 | 写入 hosts（默认 localhost）；安装苹方字体到 `%systemroot%\Fonts`；创建 `ls.bat`（`dir /A /B`）；释放全部工具到 `C:\Windows\Protect\`。 |
| 账户 | 创建隐藏管理员账户 `ZhangProtectAdmin`，密码 `Zhang<机器码前6位>`，从登录界面隐藏（`SpecialAccounts\UserList=0`），加入 Administrators。 |
| U 盘 | 可移动盘自动清理/隐藏 autorun.inf、创建陷阱目录、可选共享 `USBDiskShare`、设置完整性级别 Medium。 |

### 6.4 电源 / 系统配置修改

| 类型 | 内容 |
| --- | --- |
| bcdedit | `disabledynamictick yes`；可选 `hypervisorlaunchtype off`（关闭 Hyper-V）、`testsigning on/off`、`nointegritychecks on/off`（`Disable_Safety` 工具）。 |
| 电源计划 | 在节能/平衡/高性能/卓越性能之间自动切换（API + CMD 双保险，保留亮度设置）；游戏时强制高性能并还原。 |
| 网络 | 所有网络接口 IPv4/IPv6 metric 设为 1；可选多网卡组 Team 负载均衡；自动换 IP；随机/恢复 MAC。 |
| 系统行为 | 关闭 UAC、禁用 SmartScreen、解除 QoS 限速、禁用 Edge 更新、关闭 Windows 更新相关服务、任务栏/开始菜单清理策略等。 |

---

## 7. 目录结构与构建方法

### 7.1 源码目录结构（核心文件）

```
Zhang多功能整合程序/
├── main.py                     # 主程序（安装/配置/守护/全部功能）
├── main_imports.py             # 核心函数库（路径、任务计划、重定向、备份等）
├── main_paths.py               # 全局路径/标记文件定义
├── configure_tags.py           # 功能开关清单（config_tags）
├── ControlMain.py              # ZhangProtectControl 配置管理器
├── config.py / logger.py / version.py   # 配置、日志、版本
├── cmd_runner.py               # 非阻塞命令执行器（线程池）
├── reg_reader.py               # 注册表读写（自动提权/所有权）
├── smart_open.py               # 智能编码文件打开
├── thread_monitor.py           # 看门狗线程
├── powercfg.py                 # 电源计划切换（powrprof API）
├── remove_safe.py              # Disable_Safety 安全禁用工具
├── windows_update_blocker.py / task_update_scanner.py  # 更新禁用
├── Zhang_IPhelper.py / Zhang_lan_scan.py / Traffic_Killer.py  # 网络工具
├── WifiMobileTool.py / file_server.py / format_changer_tool.py  # 工具
├── WindowDebugTool.py / Sys_Dispatch_Main.py / Zhang_PE_Tool_Main.py  # 工具
├── files/                      # 所有内嵌 exe/7z/资源（119 个文件）
├── C++_Files/                  # 自研 C++ 工具源码
├── makefile.py                 # base64 打包清单（files → .py 模块）
├── make.bat / make_C_files.bat / make_pythontools_files.bat  # 构建脚本
├── 构建项目.bat / 构建项目并打包.bat / 格式化全部Python文件.bat
└── Release/                    # 打包输出目录
```

### 7.2 构建流程

```bat
:: 1. 编译 C++ 小工具（输出到 files\）
make_C_files.bat

:: 2. 将 files\ 下资源打包为 base64 Python 模块（makefile.py 清单）
python makefile.py

:: 3. 构建主程序（PyInstaller 类打包，输出到 Release\）
make.bat          （或 构建项目.bat）

:: 4. 一键整合并压缩为 7z 分发包（带密码 123456）
构建项目并打包.bat
```

### 7.3 运行依赖

- Windows 10/11（部分功能依赖 Win11 电源/显示 API）；
- Python 3.13 + pywin32、psutil、requests、wmi、py7zr、scapy、colorama、chardet 等（见 `安装项目依赖PIP模块.bat`）；
- 管理员权限（主程序自动请求提权）。

---

## 8. 风险与注意事项

1. **SYSTEM 级常驻**：程序以 SYSTEM 最高权限运行，可执行任意命令、修改任意注册表/文件。请仅在可信、受控的机器上使用。
2. **不可逆修改**：存储重定向（`use_storage_redirect`）、文件时间修改（`change_all_filetime_flag`）、关闭 UAC、替换系统文件（Narrator/VoiceAccess）等操作**没有一键还原机制**，卸载不会还原。
3. **安全软件冲突**：程序会关闭/绕过防火墙、Defender 实时保护、驱动签名校验、Hyper-V，并禁用 Windows 更新相关服务；会显著降低系统安全等级。
4. **隐藏管理账户**：程序会创建 `ZhangProtectAdmin`（密码基于机器码），请妥善保管或移除该账户，避免安全隐患。
5. **第三方工具版权**：内置大量第三方便携软件/激活工具（KMS/MAS 等），请自行确认使用合法性。
6. **"不公平调度"与游戏暂停**：`SysDispatch` 会频繁修改进程优先级/核心绑定，可能与反作弊软件冲突；游戏暂停功能会杀掉 memreduct/desktopok 等进程。
7. **实验性代码**：`ddos()`（HTTP/SYN/Ping 压力测试）与 `Zhang_lan_scan` 为源码保留的实验代码，控制台已标注"弃用"，默认关闭（`Disable`），请勿用于非法用途。
8. **备份建议**：开启自动系统备份（`SystemBackup`）前请确认数据盘有足够空间；备份使用 SnapShot 镜像，恢复需在 PE 下操作。
9. **日志与排障**：`C:\Windows\Protect\` 下存在 `[PID][时间].log` 日志文件（默认启用，`lowerlog` 可关闭），排障时可查看。
10. **源码保护**：所有内嵌资源在 `makefile.py` 中映射，修改 `files\` 目录内容后需重新运行 `makefile.py` 才能生效。

---

*本文档由源码分析自动生成，具体行为以实际版本源码为准。*
