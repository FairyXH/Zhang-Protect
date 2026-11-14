// AutoDisplayConfig.cpp
// C++17 单文件 Windows 多显示器配置优化工具
#include <windows.h>
#include <shellscalingapi.h>

#include <algorithm>
#include <cmath>
#include <cstdio>
#include <string>
#include <utility>
#include <vector>

#pragma comment(lib, "user32.lib")
#pragma comment(lib, "Shcore.lib")

namespace {

std::string ToUtf8(const std::wstring& w) {
    if (w.empty()) return {};
    const int n = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), static_cast<int>(w.size()),
                                      nullptr, 0, nullptr, nullptr);
    if (n <= 0) return {};
    std::string s(n, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), static_cast<int>(w.size()), &s[0], n, nullptr, nullptr);
    return s;
}

std::wstring Widen(const std::string& s) {
    if (s.empty()) return {};
    const int n = MultiByteToWideChar(CP_ACP, 0, s.c_str(), static_cast<int>(s.size()), nullptr, 0);
    if (n <= 0) return {};
    std::wstring w(n, L'\0');
    MultiByteToWideChar(CP_ACP, 0, s.c_str(), static_cast<int>(s.size()), &w[0], n);
    return w;
}

bool StartsWithIgnoreCase(const std::wstring& s, const std::wstring& p) {
    if (s.size() < p.size()) return false;
    for (size_t i = 0; i < p.size(); ++i) {
        wchar_t a = s[i], b = p[i];
        if (a >= L'A' && a <= L'Z') a += 32;
        if (b >= L'A' && b <= L'Z') b += 32;
        if (a != b) return false;
    }
    return true;
}

struct DisplayInfo {
    HMONITOR hmon = nullptr;
    std::string deviceName;
    bool primary = false;
    RECT rc{};
};

BOOL CALLBACK MonitorEnumProc(HMONITOR hMonitor, HDC, LPRECT, LPARAM lp) {
    auto* list = reinterpret_cast<std::vector<DisplayInfo>*>(lp);
    MONITORINFOEXW mi{};
    mi.cbSize = sizeof(mi);
    if (!GetMonitorInfoW(hMonitor, &mi)) return TRUE;
    DisplayInfo di;
    di.hmon = hMonitor;
    di.primary = (mi.dwFlags & MONITORINFOF_PRIMARY) != 0;
    di.rc = mi.rcMonitor;
    di.deviceName = ToUtf8(mi.szDevice);
    list->push_back(std::move(di));
    return TRUE;
}

struct VideoMode {
    int width = 0;
    int height = 0;
    int freq = 0;
    DEVMODEW dm{};
};

// 枚举驱动暴露的全部显示模式（含 NVIDIA DSR / AMD VSR 等虚拟分辨率），
// 按像素面积排序，同面积取最高刷新率。
void EnumerateModes(const std::wstring& device, std::vector<VideoMode>& modes) {
    for (int pass = 0; pass < 2; ++pass) {
        const DWORD flags = (pass == 0) ? 0 : EDS_RAWMODE;
        for (DWORD i = 0;; ++i) {
            DEVMODEW dm{};
            dm.dmSize = sizeof(dm);
            if (!EnumDisplaySettingsExW(device.c_str(), i, &dm, flags)) break;
            if (dm.dmPelsWidth == 0 || dm.dmPelsHeight == 0) continue;
            bool dup = false;
            for (const auto& m : modes) {
                if (m.width == static_cast<int>(dm.dmPelsWidth) &&
                    m.height == static_cast<int>(dm.dmPelsHeight) &&
                    m.freq == static_cast<int>(dm.dmDisplayFrequency)) {
                    dup = true;
                    break;
                }
            }
            if (dup) continue;
            VideoMode vm;
            vm.width = static_cast<int>(dm.dmPelsWidth);
            vm.height = static_cast<int>(dm.dmPelsHeight);
            vm.freq = static_cast<int>(dm.dmDisplayFrequency);
            vm.dm = dm;
            modes.push_back(std::move(vm));
        }
    }
    std::sort(modes.begin(), modes.end(), [](const VideoMode& a, const VideoMode& b) {
        const unsigned long long aa =
            static_cast<unsigned long long>(a.width) * static_cast<unsigned long long>(a.height);
        const unsigned long long bb =
            static_cast<unsigned long long>(b.width) * static_cast<unsigned long long>(b.height);
        if (aa != bb) return aa > bb;
        return a.freq > b.freq;
    });
}

VideoMode GetCurrentMode(const std::wstring& device) {
    DEVMODEW dm{};
    dm.dmSize = sizeof(dm);
    VideoMode cur;
    if (EnumDisplaySettingsExW(device.c_str(), ENUM_CURRENT_SETTINGS, &dm, 0)) {
        cur.width = static_cast<int>(dm.dmPelsWidth);
        cur.height = static_cast<int>(dm.dmPelsHeight);
        cur.freq = static_cast<int>(dm.dmDisplayFrequency);
        cur.dm = dm;
    }
    return cur;
}

// 依次尝试应用显示模式。扩展显示器优先使用主显示器的分辨率（同步），
// 否则使用该显示器自己的最大模式。用 CDS_UPDATEREGISTRY 保存。
bool ApplyBestMode(const std::wstring& device, std::vector<VideoMode> modes,
                   int syncWidth, int syncHeight, VideoMode& applied) {
    std::stable_sort(modes.begin(), modes.end(),
                     [syncWidth, syncHeight](const VideoMode& a, const VideoMode& b) {
                         const bool sa = a.width == syncWidth && a.height == syncHeight;
                         const bool sb = b.width == syncWidth && b.height == syncHeight;
                         if (sa != sb) return sa;
                         const unsigned long long aa =
                             static_cast<unsigned long long>(a.width) * static_cast<unsigned long long>(a.height);
                         const unsigned long long bb =
                             static_cast<unsigned long long>(b.width) * static_cast<unsigned long long>(b.height);
                         if (aa != bb) return aa > bb;
                         return a.freq > b.freq;
                     });
    for (const auto& m : modes) {
        DEVMODEW dm = m.dm;
        dm.dmSize = sizeof(dm);
        dm.dmFields = DM_PELSWIDTH | DM_PELSHEIGHT | DM_DISPLAYFREQUENCY | DM_BITSPERPEL;
        const LONG r = ChangeDisplaySettingsExW(device.c_str(), &dm, nullptr,
                                                CDS_UPDATEREGISTRY, nullptr);
        if (r == DISP_CHANGE_SUCCESSFUL) {
            applied = m;
            return true;
        }
        if (r == DISP_CHANGE_RESTART) {
            printf("  (模式已保存到注册表；需要重启后生效)\n");
            applied = m;
            return true;
        }
    }
    return false;
}

UINT GetEffectiveDpi(HMONITOR hmon) {
    UINT dpiX = 96, dpiY = 96;
    if (GetDpiForMonitor(hmon, MDT_EFFECTIVE_DPI, &dpiX, &dpiY) != S_OK) {
        dpiX = 96;
    }
    return dpiX;
}

// 从显示器设备实例 ID 提取短 EDID ID（如 "PHL0000"）。
// 兼容多种格式：\\?\DISPLAY#<ID>#...、DISPLAY\<ID>\...、
// \\?\MONITOR#<ID>#...、MONITOR\<ID>\...
std::string MonitorRegistryId(const std::string& deviceName) {
    const std::wstring target = Widen(deviceName);
    DISPLAY_DEVICEW dd{};
    dd.cb = sizeof(dd);
    for (DWORD i = 0; EnumDisplayDevicesW(nullptr, i, &dd, 0); ++i) {
        if (lstrcmpiW(dd.DeviceName, target.c_str()) != 0) continue;
        DISPLAY_DEVICEW md{};
        md.cb = sizeof(md);
        for (DWORD j = 0; EnumDisplayDevicesW(dd.DeviceName, j, &md, 0); ++j) {
            const std::wstring id = md.DeviceID;
            std::wstring out;
            static const wchar_t* markers[] = {L"DISPLAY#", L"DISPLAY\\",
                                                L"MONITOR#", L"MONITOR\\"};
            for (const wchar_t* marker : markers) {
                const size_t mlen = wcslen(marker);
                const size_t p = id.find(marker);
                if (p == std::wstring::npos) continue;
                const size_t s = p + mlen;
                const size_t e = id.find_first_of(L"\\#", s);
                if (e != std::wstring::npos && e > s) {
                    out = id.substr(s, e - s);
                    break;
                }
            }
            if (!out.empty()) return ToUtf8(out);
            std::wstring sane = id;
            for (auto& ch : sane) {
                if (ch == L'\\' || ch == L'#' || ch == L'{' || ch == L'}' || ch == L'/') ch = L'_';
            }
            return ToUtf8(sane);
        }
        break;
    }
    return {};
}

// ---- PerMonitorSettings 缩放同步 ----
// Windows 11 键名是 <EDID ID><实例>_<连接器>_...^<哈希>，实测值含义：
//   0 = 系统推荐/100%，v(1..8) = 100%+25v，即 DPI = 96 + 24v
//   （1=125%, 2=150%, 3=175%, 4=200%, 5=225%, 6=250%, 7=275%, 8=300%）
// 旧格式（短 ID / MONITOR_ 前缀）值为原始 DPI（如 96、120、144、192）。

struct DpiKey {
    std::wstring keyName;
    bool newFormat;  // 键名含 '^' -> Windows 11 新格式（档位索引）
};

std::vector<DpiKey> FindDpiRegistryKeys(const std::string& shortId) {
    std::vector<DpiKey> out;
    if (shortId.empty()) return out;
    const std::wstring id = Widen(shortId);
    const std::wstring legacyPrefix = L"MONITOR_" + id;
    HKEY root = nullptr;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Control Panel\\Desktop\\PerMonitorSettings",
                      0, KEY_READ, &root) != ERROR_SUCCESS) {
        return out;
    }
    for (DWORD i = 0;; ++i) {
        wchar_t name[512];
        DWORD nameLen = 512;
        FILETIME ft{};
        if (RegEnumKeyExW(root, i, name, &nameLen, nullptr, nullptr, nullptr, &ft) != ERROR_SUCCESS) {
            break;
        }
        const std::wstring key(name, nameLen);
        if (StartsWithIgnoreCase(key, id) || StartsWithIgnoreCase(key, legacyPrefix)) {
            out.push_back({key, key.find(L'^') != std::wstring::npos});
        }
    }
    RegCloseKey(root);
    return out;
}

// 新格式键实测映射: 0=系统推荐/100%，v(1..8)=100%+25v，即 DPI=96+24v
int Win11ScaleIndex(UINT dpi) {
    const int pct = static_cast<int>(std::lround(dpi * 100.0 / 96.0));
    int v = (pct + 12) / 25 - 4;
    if (v < 0) v = 0;
    if (v > 8) v = 8;
    return v;
}

bool WritePerMonitorDpiKey(const std::wstring& keyName, DWORD value) {
    const wchar_t* rootPath = L"Control Panel\\Desktop\\PerMonitorSettings";
    HKEY root = nullptr;
    LONG r = RegOpenKeyExW(HKEY_CURRENT_USER, rootPath, 0, KEY_READ | KEY_WRITE, &root);
    if (r != ERROR_SUCCESS) {
        r = RegCreateKeyExW(HKEY_CURRENT_USER, rootPath, 0, nullptr, 0,
                            KEY_READ | KEY_WRITE, nullptr, &root, nullptr);
    }
    if (r != ERROR_SUCCESS || !root) return false;

    HKEY sub = nullptr;
    r = RegCreateKeyExW(root, keyName.c_str(), 0, nullptr, 0,
                        KEY_SET_VALUE | KEY_QUERY_VALUE, nullptr, &sub, nullptr);
    if (r != ERROR_SUCCESS) {
        RegCloseKey(root);
        return false;
    }
    r = RegSetValueExW(sub, L"DpiValue", 0, REG_DWORD,
                       reinterpret_cast<const BYTE*>(&value), sizeof(value));
    DWORD readBack = 0;
    DWORD sz = sizeof(readBack);
    if (r == ERROR_SUCCESS) {
        r = RegQueryValueExW(sub, L"DpiValue", nullptr, nullptr,
                             reinterpret_cast<BYTE*>(&readBack), &sz);
    }
    RegCloseKey(sub);
    RegCloseKey(root);
    return r == ERROR_SUCCESS && readBack == value;
}

void NotifyDpiChanged() {
    DWORD_PTR unused = 0;
    SendMessageTimeoutW(HWND_BROADCAST, WM_SETTINGCHANGE, 0,
                        reinterpret_cast<LPARAM>(L"EsaSettings"),
                        SMTO_ABORTIFHUNG, 2000, &unused);
    SendMessageTimeoutW(HWND_BROADCAST, WM_SETTINGCHANGE, 0,
                        reinterpret_cast<LPARAM>(L"DisplaySettings"),
                        SMTO_ABORTIFHUNG, 2000, &unused);
}

// ---- DisplayConfig：保持桌面坐标稳定 ----

struct PathSnapshot {
    std::string monitorId;
    DISPLAYCONFIG_MODE_INFO sourceMode{};
};

std::string TargetMonitorId(const DISPLAYCONFIG_PATH_INFO& path) {
    DISPLAYCONFIG_TARGET_DEVICE_NAME t{};
    t.header.type = DISPLAYCONFIG_DEVICE_INFO_GET_TARGET_NAME;
    t.header.size = sizeof(t);
    t.header.adapterId = path.targetInfo.adapterId;
    t.header.id = path.targetInfo.id;
    if (DisplayConfigGetDeviceInfo(&t.header) == ERROR_SUCCESS) {
        return ToUtf8(t.monitorDevicePath);
    }
    return {};
}

bool QueryActiveConfig(std::vector<DISPLAYCONFIG_PATH_INFO>& paths,
                       std::vector<DISPLAYCONFIG_MODE_INFO>& modes,
                       std::vector<PathSnapshot>* snapshots) {
    UINT32 numPaths = 0, numModes = 0;
    if (GetDisplayConfigBufferSizes(QDC_ONLY_ACTIVE_PATHS, &numPaths, &numModes) != ERROR_SUCCESS) {
        return false;
    }
    paths.resize(numPaths);
    modes.resize(numModes);
    const LONG r = QueryDisplayConfig(QDC_ONLY_ACTIVE_PATHS, &numPaths, paths.data(),
                                      &numModes, modes.data(), nullptr);
    if (r != ERROR_SUCCESS) return false;
    paths.resize(numPaths);
    modes.resize(numModes);

    if (snapshots) {
        snapshots->clear();
        for (const auto& p : paths) {
            PathSnapshot s;
            s.monitorId = TargetMonitorId(p);
            if (p.sourceInfo.modeInfoIdx < modes.size()) {
                s.sourceMode = modes[p.sourceInfo.modeInfoIdx];
            }
            snapshots->push_back(std::move(s));
        }
    }
    return true;
}

// 每个活动路径都有独立 source 即为扩展模式；两个路径共享 source 为镜像。
bool TopologyIsExtend(const std::vector<DISPLAYCONFIG_PATH_INFO>& paths) {
    if (paths.size() <= 1) return true;
    for (size_t i = 0; i < paths.size(); ++i) {
        for (size_t j = i + 1; j < paths.size(); ++j) {
            const auto& a = paths[i].sourceInfo;
            const auto& b = paths[j].sourceInfo;
            if (a.adapterId.HighPart == b.adapterId.HighPart &&
                a.adapterId.LowPart == b.adapterId.LowPart &&
                a.id == b.id) {
                return false;
            }
        }
    }
    return true;
}

// 模式变更后恢复变更前的桌面排列，保证窗口坐标连续。
// 若恢复失败则保留系统当前排列（不破坏现有桌面）。
void RestoreLayoutPositions(const std::vector<PathSnapshot>& snapshots) {
    std::vector<DISPLAYCONFIG_PATH_INFO> paths;
    std::vector<DISPLAYCONFIG_MODE_INFO> modes;
    if (!QueryActiveConfig(paths, modes, nullptr)) return;

    std::vector<DISPLAYCONFIG_MODE_INFO> adjusted = modes;
    for (auto& p : paths) {
        const std::string id = TargetMonitorId(p);
        if (id.empty()) continue;
        for (const auto& s : snapshots) {
            if (id == s.monitorId) {
                if (p.sourceInfo.modeInfoIdx < adjusted.size()) {
                    adjusted[p.sourceInfo.modeInfoIdx].sourceMode.position =
                        s.sourceMode.sourceMode.position;
                }
                break;
            }
        }
    }

    LONG r = SetDisplayConfig(static_cast<UINT32>(paths.size()), paths.data(),
                              static_cast<UINT32>(adjusted.size()), adjusted.data(),
                              SDC_APPLY | SDC_USE_SUPPLIED_DISPLAY_CONFIG);
    if (r != ERROR_SUCCESS) {
        printf("  (恢复原排列失败 0x%lX，保留系统当前排列)\n",
               static_cast<unsigned long>(r));
        SetDisplayConfig(static_cast<UINT32>(paths.size()), paths.data(),
                         static_cast<UINT32>(modes.size()), modes.data(),
                         SDC_APPLY | SDC_USE_SUPPLIED_DISPLAY_CONFIG);
    }
}

// 立即生效的关键：用当前活动路径重放 SetDisplayConfig，让显示子系统
// 重新读取 PerMonitorSettings，再广播 WM_SETTINGCHANGE。
void ForceDpiRefresh() {
    std::vector<DISPLAYCONFIG_PATH_INFO> paths;
    std::vector<DISPLAYCONFIG_MODE_INFO> modes;
    if (QueryActiveConfig(paths, modes, nullptr)) {
        const LONG r = SetDisplayConfig(static_cast<UINT32>(paths.size()), paths.data(),
                                        static_cast<UINT32>(modes.size()), modes.data(),
                                        SDC_APPLY | SDC_USE_SUPPLIED_DISPLAY_CONFIG);
        printf("  (SetDisplayConfig 重放 rc=%ld)\n", static_cast<long>(r));
    } else {
        printf("  (无法查询显示配置)\n");
    }
    NotifyDpiChanged();
}

void PrintMonitorsDpi(const char* label) {
    printf("%s:\n", label);
    std::vector<DisplayInfo> mons;
    EnumDisplayMonitors(nullptr, nullptr, MonitorEnumProc, reinterpret_cast<LPARAM>(&mons));
    for (const auto& m : mons) {
        const UINT d = GetEffectiveDpi(m.hmon);
        const int pct = static_cast<int>(std::lround(d * 100.0 / 96.0));
        printf("  %s  DPI=%u (%d%%)\n", m.deviceName.c_str(), d, pct);
    }
    printf("\n");
}

}  // namespace

int main() {
    // 控制台使用 UTF-8，保证中文输出正常
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);

    // 按显示器感知模式运行，GetDpiForMonitor 才能返回真实 DPI
    if (FAILED(SetProcessDpiAwareness(PROCESS_PER_MONITOR_DPI_AWARE))) {
        SetProcessDPIAware();
    }

    std::vector<DisplayInfo> monitors;
    EnumDisplayMonitors(nullptr, nullptr, MonitorEnumProc, reinterpret_cast<LPARAM>(&monitors));

    printf("================================\n\n");
    printf("自动显示配置\n\n");

    if (monitors.empty()) {
        printf("未找到活动显示器。\n\n");
        printf("================================\n");
        return 1;
    }

    // 通过 MONITORINFOF_PRIMARY 识别真实主显示器
    DisplayInfo* primary = nullptr;
    for (auto& m : monitors) {
        if (m.primary) {
            primary = &m;
            break;
        }
    }
    if (!primary) primary = &monitors[0];

    printf("主显示器:\n%s\n\n", primary->deviceName.c_str());

    std::vector<DISPLAYCONFIG_PATH_INFO> paths;
    std::vector<DISPLAYCONFIG_MODE_INFO> modes;
    QueryActiveConfig(paths, modes, nullptr);

    // 保证扩展桌面拓扑，禁止镜像
    // 注意：不能调用 SetDisplayConfig(0,0,0,0, SDC_TOPOLOGY_EXTEND|SDC_APPLY)，
    // 在多 GPU / 虚拟显示适配器机器上会禁用其他显示器。
    if (!TopologyIsExtend(paths)) {
        printf("警告: 当前是镜像/克隆拓扑。为避免禁用显示器，程序不会自动切换拓扑；\n");
        printf("请先在系统设置中开启“扩展这些显示器”后重新运行。\n\n");
    }

    // 变更前保存桌面排列
    std::vector<PathSnapshot> snapshots;
    QueryActiveConfig(paths, modes, &snapshots);

    const std::wstring primaryDev = Widen(primary->deviceName);
    const VideoMode current = GetCurrentMode(primaryDev);

    std::vector<VideoMode> primaryModes;
    EnumerateModes(primaryDev, primaryModes);
    if (primaryModes.empty()) {
        printf("没有可用的显示模式。\n\n");
        printf("================================\n");
        return 1;
    }

    // 最大像素面积，同面积取最高刷新率
    const VideoMode selected = primaryModes.front();
    const UINT dpi = GetEffectiveDpi(primary->hmon);
    const int scalePct = static_cast<int>(std::lround(dpi * 100.0 / 96.0));

    printf("当前:\n%dx%d %dHz\n\n", current.width, current.height, current.freq);
    printf("已选择:\n%dx%d %dHz\n\n", selected.width, selected.height, selected.freq);
    printf("推荐缩放:\n%d%%\n\n", scalePct);

    VideoMode appliedPrimary;
    if (ApplyBestMode(primaryDev, primaryModes, 0, 0, appliedPrimary)) {
        Sleep(700);
    } else {
        printf("  (主显示器模式设置失败)\n");
    }

    // 同步所有扩展显示器：分辨率、刷新率、DPI 缩放
    for (auto& m : monitors) {
        if (m.primary) continue;
        const std::wstring dev = Widen(m.deviceName);
        std::vector<VideoMode> ms;
        EnumerateModes(dev, ms);
        VideoMode applied;
        const bool ok = !ms.empty() &&
                        ApplyBestMode(dev, ms, selected.width, selected.height, applied);
        printf("同步显示器:\n%s\n", m.deviceName.c_str());
        if (ok) {
            printf("%dx%d\n%dHz\n%d%%\n\n", applied.width, applied.height, applied.freq, scalePct);
            Sleep(700);
        } else {
            printf("失败\n\n");
        }
    }

    // 恢复桌面排列
    Sleep(500);
    RestoreLayoutPositions(snapshots);

    // 把主显示器的缩放同步到扩展显示器。
    // 没有公开的 SetDisplayScale API，只能写 PerMonitorSettings 并广播 WM_SETTINGCHANGE。
    printf("缩放注册表:\n");
    bool dpiWritten = false;
    for (auto& m : monitors) {
        if (m.primary) continue;
        const std::string shortId = MonitorRegistryId(m.deviceName);
        if (shortId.empty()) {
            printf("  (警告: 无法识别显示器 %s 的注册表 ID)\n", m.deviceName.c_str());
            continue;
        }
        std::vector<DpiKey> keys = FindDpiRegistryKeys(shortId);
        if (keys.empty()) {
            printf("  (警告: 显示器 %s 没有现有缩放键，创建旧格式键 %s)\n",
                   m.deviceName.c_str(), shortId.c_str());
            if (WritePerMonitorDpiKey(Widen(shortId), static_cast<DWORD>(dpi))) {
                dpiWritten = true;
            }
            continue;
        }
        for (const auto& k : keys) {
            const DWORD value = k.newFormat
                                    ? static_cast<DWORD>(Win11ScaleIndex(dpi))
                                    : static_cast<DWORD>(dpi);
            if (WritePerMonitorDpiKey(k.keyName, value)) {
                dpiWritten = true;
                printf("  HKCU\\Control Panel\\Desktop\\PerMonitorSettings\\%s\n",
                       ToUtf8(k.keyName).c_str());
                printf("    DpiValue = %u (%d%%)\n", value, scalePct);
            } else {
                printf("  (写入失败: %s)\n", ToUtf8(k.keyName).c_str());
            }
        }
    }

    if (dpiWritten) {
        printf("\n正在触发立即刷新...\n");
        ForceDpiRefresh();
        Sleep(1500);
        PrintMonitorsDpi("刷新后 DPI");
        printf("缩放设置已保存并立即刷新。若个别应用未跟随，请重新打开该应用。\n\n");
    } else {
        printf("\n缩放设置注册表写入失败。\n\n");
    }

    printf("已完成。\n\n");
    printf("================================\n");
    return 0;
}
