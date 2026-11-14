#include <windows.h>
#include <vector>
#include <cwchar>
#include <string>
#ifndef LLKHF_SHIFT
#define LLKHF_SHIFT     0x0001
#endif
#ifndef LLKHF_CONTROL
#define LLKHF_CONTROL   0x0002
#endif
#ifndef LLKHF_ALT
#define LLKHF_ALT       0x0004
#endif
#ifndef LLKHF_EXTENDED
#define LLKHF_EXTENDED  0x0010
#endif
#ifndef LLKHF_UP
#define LLKHF_UP        0x0080
#endif
struct HotKeyRule
{
    DWORD modMask;
    DWORD vkCode;
    const wchar_t* desc;
};
// ======== 屏蔽规则===========
std::vector<HotKeyRule> g_BlockList = {
    // Ctrl+Shift
    //{MOD_CONTROL | MOD_SHIFT, 0, L"Ctrl + Shift"},
    // Alt+Shift
    //{MOD_ALT | MOD_SHIFT, 0, L"Alt + Shift"},
    // Ctrl+空格
    //{MOD_CONTROL, VK_SPACE, L"Ctrl + Space"},
    // 拦截 Alt+F4
    {MOD_ALT, VK_F4, L"Alt + F4"},
};
// =========
HHOOK        g_hook = nullptr;
HWND         g_hwndNotify = nullptr;
HINSTANCE    g_hInst = nullptr;
UINT         g_uTaskbarMsg = 0;
NOTIFYICONDATAW g_nid;
HANDLE g_hConsoleOut = INVALID_HANDLE_VALUE;
bool g_bLctrl  = false, g_bRctrl  = false;
bool g_bLalt   = false, g_bRalt   = false;
bool g_bLshift = false, g_bRshift = false;
int g_NormalKeyDown = 0;
bool g_KeyState[256]={0};
std::wstring GetExitFlagPath()
{
    wchar_t sysRoot[MAX_PATH] = {0};
    GetEnvironmentVariableW(L"SystemRoot", sysRoot, MAX_PATH);

    std::wstring path = sysRoot;
    path += L"\\Protect\\keyboard_filter_exit_flag";

    return path;
}
void ClearExitFlag()
{
    std::wstring path = GetExitFlagPath();
    DeleteFileW(path.c_str());
}
bool CheckExitFlag()
{
    std::wstring path = GetExitFlagPath();

    DWORD attr = GetFileAttributesW(path.c_str());
    return (attr != INVALID_FILE_ATTRIBUTES &&
            !(attr & FILE_ATTRIBUTE_DIRECTORY));
}
void EnsureProtectDir()
{
    wchar_t sysRoot[MAX_PATH] = {0};
    GetEnvironmentVariableW(L"SystemRoot", sysRoot, MAX_PATH);

    std::wstring dir = sysRoot;
    dir += L"\\Protect";

    CreateDirectoryW(dir.c_str(), nullptr);
}
void BroadcastSettingsChange()
{
    SendMessageTimeoutW(
        HWND_BROADCAST,
        WM_SETTINGCHANGE,
        0,
        (LPARAM)L"Keyboard Layout",
        SMTO_ABORTIFHUNG,
        100,
        nullptr
    );
}
void RefreshIME()
{
    // 让系统重新加载输入设置
    SystemParametersInfoW(SPI_SETLANGTOGGLE, 0, nullptr, SPIF_SENDCHANGE);
}
void RefreshExplorer()
{
    HWND hwnd = FindWindowW(L"Shell_TrayWnd", nullptr);
    if (hwnd)
    {
        SendMessageTimeoutW(hwnd, WM_SETTINGCHANGE, 0, 0,
            SMTO_ABORTIFHUNG, 100, nullptr);
    }
}
void ApplyIMEHotkeyImmediately()
{
    BroadcastSettingsChange();
    RefreshIME();
    RefreshExplorer();
}
bool RestoreIMEHotkeys()
{
    auto write_enable = [](HKEY root, const wchar_t* path)
    {
        HKEY hKey;
        if (RegCreateKeyExW(root, path, 0, nullptr, 0,
            KEY_SET_VALUE, nullptr, &hKey, nullptr) == ERROR_SUCCESS)
        {
            const wchar_t* enable = L"2"; // 2 = Ctrl+Shift / Alt+Shift enable

            RegSetValueExW(hKey, L"Hotkey", 0, REG_SZ,
                (const BYTE*)enable, (DWORD)(wcslen(enable) + 1) * sizeof(wchar_t));

            RegSetValueExW(hKey, L"Language Hotkey", 0, REG_SZ,
                (const BYTE*)enable, (DWORD)(wcslen(enable) + 1) * sizeof(wchar_t));

            RegSetValueExW(hKey, L"Layout Hotkey", 0, REG_SZ,
                (const BYTE*)enable, (DWORD)(wcslen(enable) + 1) * sizeof(wchar_t));

            RegCloseKey(hKey);
        }
    };

    write_enable(HKEY_CURRENT_USER, L"Keyboard Layout\\Toggle");

    write_enable(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Control\\Keyboard Layout");
	ApplyIMEHotkeyImmediately();
    return true;
}
bool DisableIMEHotkeys()
{
    HKEY hKey;

    const wchar_t* subKey = L"Keyboard Layout\\Toggle";

    auto write_disable = [](HKEY root, const wchar_t* path)
    {
        HKEY hKey;
        if (RegCreateKeyExW(root, path, 0, nullptr, 0,
            KEY_SET_VALUE, nullptr, &hKey, nullptr) == ERROR_SUCCESS)
        {
            const wchar_t* disable = L"3"; // 3 = Disabled

            RegSetValueExW(hKey, L"Hotkey", 0, REG_SZ,
                (const BYTE*)disable, (DWORD)(wcslen(disable) + 1) * sizeof(wchar_t));

            RegSetValueExW(hKey, L"Language Hotkey", 0, REG_SZ,
                (const BYTE*)disable, (DWORD)(wcslen(disable) + 1) * sizeof(wchar_t));

            RegSetValueExW(hKey, L"Layout Hotkey", 0, REG_SZ,
                (const BYTE*)disable, (DWORD)(wcslen(disable) + 1) * sizeof(wchar_t));

            RegCloseKey(hKey);
        }
    };

    // HKCU
    write_disable(HKEY_CURRENT_USER, subKey);

    // HKLM（需要管理员权限）
    write_disable(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Keyboard Layout");
	ApplyIMEHotkeyImmediately();
    return true;
}
void ApplyRegIMEHotkeys_CtrlSpace()
{
    HKEY hKey;

    // HKCU\...\00000010
    if (RegCreateKeyExW(HKEY_CURRENT_USER,
        L"Control Panel\\Input Method\\Hot Keys\\00000010",
        0, nullptr, 0, KEY_SET_VALUE, nullptr, &hKey, nullptr) == ERROR_SUCCESS)
    {
        const BYTE km1[] = { 0x00, 0xC0, 0x00, 0x00 };
        const BYTE vk1[] = { 0xFF, 0x00, 0x00, 0x00 };

        RegSetValueExW(hKey, L"Key Modifiers", 0, REG_BINARY, km1, sizeof(km1));
        RegSetValueExW(hKey, L"Virtual Key", 0, REG_BINARY, vk1, sizeof(vk1));

        RegCloseKey(hKey);
    }

    // HKCU\...\00000070
    if (RegCreateKeyExW(HKEY_CURRENT_USER,
        L"Control Panel\\Input Method\\Hot Keys\\00000070",
        0, nullptr, 0, KEY_SET_VALUE, nullptr, &hKey, nullptr) == ERROR_SUCCESS)
    {
        const BYTE km1[] = { 0x00, 0xC0, 0x00, 0x00 };
        const BYTE vk1[] = { 0xFF, 0x00, 0x00, 0x00 };

        RegSetValueExW(hKey, L"Key Modifiers", 0, REG_BINARY, km1, sizeof(km1));
        RegSetValueExW(hKey, L"Virtual Key", 0, REG_BINARY, vk1, sizeof(vk1));

        RegCloseKey(hKey);
    }

    // HKU\.DEFAULT\...\00000010
    if (RegCreateKeyExW(HKEY_USERS,
        L".DEFAULT\\Control Panel\\Input Method\\Hot Keys\\00000010",
        0, nullptr, 0, KEY_SET_VALUE, nullptr, &hKey, nullptr) == ERROR_SUCCESS)
    {
        const BYTE km2[] = { 0x02, 0xC0, 0x00, 0x00 };
        const BYTE ti[]  = { 0x00, 0x00, 0x00, 0x00 };
        const BYTE vk2[] = { 0xFF, 0x00, 0x00, 0x00 };

        RegSetValueExW(hKey, L"Key Modifiers", 0, REG_BINARY, km2, sizeof(km2));
        RegSetValueExW(hKey, L"Target IME", 0, REG_BINARY, ti, sizeof(ti));
        RegSetValueExW(hKey, L"Virtual Key", 0, REG_BINARY, vk2, sizeof(vk2));

        RegCloseKey(hKey);
    }

    // HKU\.DEFAULT\...\00000070
    if (RegCreateKeyExW(HKEY_USERS,
        L".DEFAULT\\Control Panel\\Input Method\\Hot Keys\\00000070",
        0, nullptr, 0, KEY_SET_VALUE, nullptr, &hKey, nullptr) == ERROR_SUCCESS)
    {
        const BYTE km2[] = { 0x02, 0xC0, 0x00, 0x00 };
        const BYTE ti[]  = { 0x00, 0x00, 0x00, 0x00 };
        const BYTE vk2[] = { 0xFF, 0x00, 0x00, 0x00 };

        RegSetValueExW(hKey, L"Key Modifiers", 0, REG_BINARY, km2, sizeof(km2));
        RegSetValueExW(hKey, L"Target IME", 0, REG_BINARY, ti, sizeof(ti));
        RegSetValueExW(hKey, L"Virtual Key", 0, REG_BINARY, vk2, sizeof(vk2));

        RegCloseKey(hKey);
    }
}
void ConsoleLog(const wchar_t* text)
{
#ifdef _DEBUG
    if (g_hConsoleOut == INVALID_HANDLE_VALUE) return;
    DWORD write;
    WriteConsoleW(g_hConsoleOut, text, lstrlenW(text), &write, nullptr);
#endif
}
DWORD GetCurrentModifierMask()
{
    DWORD mask = 0;
    if (g_bLctrl  || g_bRctrl)  mask |= MOD_CONTROL;
    if (g_bLalt   || g_bRalt)   mask |= MOD_ALT;
    if (g_bLshift || g_bRshift) mask |= MOD_SHIFT;
    return mask;
}
void UpdateModifierCache(DWORD vk, bool isDown)
{
    switch (vk)
    {
    case VK_LCONTROL: g_bLctrl  = isDown; break;
    case VK_RCONTROL: g_bRctrl  = isDown; break;
    case VK_LMENU:    g_bLalt   = isDown; break;
    case VK_RMENU:    g_bRalt   = isDown; break;
    case VK_LSHIFT:   g_bLshift = isDown; break;
    case VK_RSHIFT:   g_bRshift = isDown; break;
    }
}
void UpdateKeyCache(DWORD vk, bool isDown)
{
    UpdateModifierCache(vk, isDown);

    bool isModifier =
        vk == VK_LCONTROL || vk == VK_RCONTROL ||
        vk == VK_LMENU || vk == VK_RMENU ||
        vk == VK_LSHIFT || vk == VK_RSHIFT;

    if (!isModifier && vk < 256)
    {
        if (isDown)
        {
            if (!g_KeyState[vk])
            {
                g_KeyState[vk] = true;
                g_NormalKeyDown++;
            }
        }
        else
        {
            if (g_KeyState[vk])
            {
                g_KeyState[vk] = false;
                g_NormalKeyDown--;
            }
        }
        if (g_NormalKeyDown < 0)
            g_NormalKeyDown = 0;
    }
}

const wchar_t* VKToString(DWORD vk)
{
    switch(vk)
    {
        case VK_SHIFT:    return L"Shift";
        case VK_CONTROL:  return L"Ctrl";
        case VK_MENU:     return L"Alt";
        case VK_ESCAPE:   return L"Esc";
        case VK_LCONTROL: return L"LCtrl";
        case VK_RCONTROL: return L"RCtrl";
        case VK_LMENU:    return L"LAlt";
        case VK_RMENU:    return L"RAlt";
        case VK_LSHIFT:   return L"LShift";
        case VK_RSHIFT:   return L"RShift";
        case VK_SPACE:    return L"Space";
        default:          return L"Other";
    }
}
bool CheckBlock(DWORD curMask, DWORD vkNow, wchar_t* outLog)
{
    for (const auto& rule : g_BlockList)
    {
        if(rule.vkCode==0)
        {
            if(curMask!=rule.modMask)
                continue;
            if(g_NormalKeyDown>0)
                continue;
        }
        else
        {	
            if(curMask!=rule.modMask)
                continue;
            if(rule.vkCode!=vkNow)
                continue;
        }
        wsprintfW(outLog, L"== 拦截 %s ==\r\n", rule.desc);
        return true;
    }
    wsprintfW(outLog, L"无匹配，放行\r\n");
    return false;
}
LRESULT CALLBACK NotifyWndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch (msg)
    {
    case WM_CREATE:
    {
        ZeroMemory(&g_nid, sizeof(g_nid));
        g_nid.cbSize = sizeof(NOTIFYICONDATAW);
        g_nid.hWnd = hWnd;
        g_nid.uID = 1001;
        g_nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
        g_nid.uCallbackMessage = g_uTaskbarMsg;
        g_nid.hIcon = LoadIconA(NULL, IDI_APPLICATION);
        wcscpy_s(g_nid.szTip, L"快捷键过滤器");
        Shell_NotifyIconW(NIM_ADD, &g_nid);
        break;
    }
    case WM_DESTROY:
        Shell_NotifyIconW(NIM_DELETE, &g_nid);
        PostQuitMessage(0);
        break;
    case WM_COMMAND:
        if (LOWORD(wParam) == 1000)
        {
            ConsoleLog(L"退出，释放钩子\r\n");
            DestroyWindow(hWnd);
        }
        break;
    default:
		if (msg == g_uTaskbarMsg && lParam == WM_RBUTTONUP)
		{
			POINT pt;
			GetCursorPos(&pt);
			HMENU hMenu = CreatePopupMenu();
			AppendMenuW(hMenu, MF_STRING, 1000, L"退出程序");
			AppendMenuW(hMenu, MF_SEPARATOR, 0, nullptr);
			int id = 2000;
			AppendMenuW(hMenu, MF_GRAYED, 0, L"===低级钩子===");
			for (const auto& r : g_BlockList)
			{
				wchar_t line[256] = {0};
				wsprintfW(line, L"屏蔽: %s", r.desc);
				AppendMenuW(hMenu, MF_STRING | MF_GRAYED, id++, line);
			}
			AppendMenuW(hMenu, MF_GRAYED, 0, L"===注册表===");
			AppendMenuW(hMenu, MF_GRAYED, 0, L"屏蔽: Ctrl+Shift");
			AppendMenuW(hMenu, MF_GRAYED, 0, L"屏蔽: Alt+Shift");
			AppendMenuW(hMenu, MF_GRAYED, 0, L"屏蔽: Ctrl+Space");
			AppendMenuW(hMenu, MF_SEPARATOR, 0, nullptr);

			// 底部提示
			AppendMenuW(hMenu, MF_GRAYED, 0, L"退出程序自动恢复注册表");
			SetForegroundWindow(hWnd);
			TrackPopupMenu(
				hMenu,
				TPM_RIGHTBUTTON | TPM_BOTTOMALIGN | TPM_LEFTALIGN,
				pt.x,
				pt.y,
				0,
				hWnd,
				nullptr
			);
			PostMessage(hWnd, WM_NULL, 0, 0);
			DestroyMenu(hMenu);
		}
		return DefWindowProcW(hWnd, msg, wParam, lParam);
    }
    return DefWindowProcW(hWnd, msg, wParam, lParam);
}
LRESULT CALLBACK LowLevelKbProc(int nCode, WPARAM wParam, LPARAM lParam)
{
    if (nCode < 0)
        return CallNextHookEx(g_hook, nCode, wParam, lParam);

    KBDLLHOOKSTRUCT* kbd = (KBDLLHOOKSTRUCT*)lParam;
    DWORD vk = kbd->vkCode;
    bool isDown = (wParam == WM_KEYDOWN || wParam == WM_SYSKEYDOWN);
    bool isKeyUp = ((kbd->flags & LLKHF_UP) != 0);
    bool isFirstDown = isDown && !isKeyUp && !g_KeyState[vk];

    if (isFirstDown || isKeyUp)
    {
        UpdateKeyCache(vk, isDown);
    }
    auto IsModifierKey = [](DWORD v) -> bool {
        return v == VK_LCONTROL || v == VK_RCONTROL ||
               v == VK_LMENU || v == VK_RMENU ||
               v == VK_LSHIFT || v == VK_RSHIFT;
    };
    bool curIsMod = IsModifierKey(vk);

    DWORD mask = GetCurrentModifierMask();
    wchar_t logBuf[512] = { 0 };
    wchar_t blockLog[256] = { 0 };

    if (isFirstDown)
    {
        wsprintfW(logBuf, L"按下键: %s(%d) mask=%08X ", VKToString(vk), vk, mask);
        ConsoleLog(logBuf);

        bool block = CheckBlock(mask, vk, blockLog);
        ConsoleLog(blockLog);
        if (block)
            return 1;
    }

    return CallNextHookEx(g_hook, nCode, wParam, lParam);
}
void InstallHook()
{
    g_hook = SetWindowsHookExW(WH_KEYBOARD_LL, LowLevelKbProc, g_hInst, 0);
    if (!g_hook)
    {
        DWORD err = GetLastError();
        wchar_t buf[256];
        wsprintfW(buf, L"钩子安装失败，错误码: %d\r\n", err);
        ConsoleLog(buf);
    }
    else
    {
        ConsoleLog(L"====程序启动成功 ====\r\n");
        ConsoleLog(L"当前屏蔽规则列表:\r\n");
        for (auto& r : g_BlockList)
        {
            wchar_t line[256];
            wsprintfW(line, L" - %s\r\n", r.desc);
            ConsoleLog(line);
        }
        ConsoleLog(L"===================\r\n");
    }
}
void UninstallHook()
{
    if (g_hook)
    {
        UnhookWindowsHookEx(g_hook);
        g_hook = nullptr;
        ConsoleLog(L"钩子已卸载\r\n");
    }
    g_bLctrl = false; g_bRctrl = false;
    g_bLalt = false; g_bRalt = false;
    g_bLshift = false; g_bRshift = false;
    g_NormalKeyDown = 0;
    ZeroMemory(g_KeyState, sizeof(g_KeyState));
}
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd)
{
#ifdef _DEBUG
    AllocConsole();
    g_hConsoleOut = GetStdHandle(STD_OUTPUT_HANDLE);
#else
    g_hConsoleOut = INVALID_HANDLE_VALUE;
#endif
    SetConsoleTitleW(L"控制台");
    g_hInst = hInstance;
    g_uTaskbarMsg = RegisterWindowMessageW(L"TaskbarNotifyMsg");

    WNDCLASSEXW wc = { 0 };
    wc.cbSize = sizeof(WNDCLASSEXW);
    wc.lpfnWndProc = NotifyWndProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = L"NotifyWindowClass";
    RegisterClassExW(&wc);

    g_hwndNotify = CreateWindowExW(
        0,
        L"NotifyWindowClass",
        L"KeyBlock Hidden Window",
        0,
        CW_USEDEFAULT, CW_USEDEFAULT, 0, 0,
        nullptr, nullptr, hInstance, nullptr
    );

    EnsureProtectDir();
    ClearExitFlag();
    ApplyRegIMEHotkeys_CtrlSpace();
    DisableIMEHotkeys();
    InstallHook();

    MSG msg;
    const DWORD LOOP_TIMEOUT = 30;
    while (true)
    {
        DWORD waitRet = MsgWaitForMultipleObjects(0, nullptr, FALSE, LOOP_TIMEOUT, QS_ALLINPUT);
        if (waitRet == WAIT_OBJECT_0)
        {
            while (PeekMessageW(&msg, nullptr, 0, 0, PM_REMOVE))
            {
                if (msg.message == WM_QUIT)
                    goto EXIT;
                TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
        }
        else if (waitRet == WAIT_TIMEOUT)
        {
            if (CheckExitFlag())
            {
                ConsoleLog(L"检测到退出flag\r\n");
                RestoreIMEHotkeys();
                UninstallHook();
                goto EXIT;
            }
        }
    }

EXIT:
    RestoreIMEHotkeys();
    UninstallHook();
#ifdef _DEBUG
    ConsoleLog(L"程序即将退出，3秒后关闭控制台\r\n");
    Sleep(3000);
    FreeConsole();
#endif
    return static_cast<int>(msg.wParam);
}