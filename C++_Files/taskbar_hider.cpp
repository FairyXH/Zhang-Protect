// taskbar_hider_fixed.cpp
#define _WIN32_WINNT 0x0600
#include <windows.h>
#include <shellapi.h>
#include <iostream>
#include <thread>
#include <atomic>
#include <vector>

#pragma comment(lib, "user32.lib")
#pragma comment(lib, "shell32.lib")

// Global variables
std::atomic<bool> g_running(true);
HHOOK g_keyboardHook = nullptr;
HHOOK g_mouseHook = nullptr;
NOTIFYICONDATA g_notifyIconData = { 0 };
HMENU g_hPopupMenu = nullptr;
HWND g_hWnd = nullptr;
const UINT WM_TRAYICON = WM_USER + 1;
UINT g_taskbarCreatedMsg = 0;

// Forward declarations
void HideAllTaskbars();
void RestoreTaskbars();
LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam);

// Find all taskbar windows
std::vector<HWND> FindAllTaskbars() {
    std::vector<HWND> taskbars;
    
    // Main taskbar
    HWND hMainTaskbar = FindWindow("Shell_TrayWnd", nullptr);
    if (hMainTaskbar) {
        taskbars.push_back(hMainTaskbar);
    }
    
    // Enumerate windows to find secondary taskbars (multi-monitor)
    EnumWindows([](HWND hwnd, LPARAM lParam) -> BOOL {
        auto& taskbars = *reinterpret_cast<std::vector<HWND>*>(lParam);
        
        char className[256];
        GetClassName(hwnd, className, 256);
        
        // Secondary taskbar class name
        if (strcmp(className, "Shell_SecondaryTrayWnd") == 0) {
            taskbars.push_back(hwnd);
        }
        return TRUE;
    }, reinterpret_cast<LPARAM>(&taskbars));
    
    return taskbars;
}

// Hide all taskbars
void HideAllTaskbars() {
    auto taskbars = FindAllTaskbars();
    for (HWND hTaskbar : taskbars) {
        ShowWindow(hTaskbar, SW_HIDE);
        SetWindowPos(hTaskbar, HWND_BOTTOM, 0, 0, 0, 0,
                    SWP_NOACTIVATE | SWP_NOMOVE | SWP_NOSIZE | SWP_NOOWNERZORDER);
        EnableWindow(hTaskbar, FALSE);
    }
}

// Restore all taskbars
void RestoreTaskbars() {
    auto taskbars = FindAllTaskbars();
    for (HWND hTaskbar : taskbars) {
        EnableWindow(hTaskbar, TRUE);
        ShowWindow(hTaskbar, SW_SHOW);
        SetWindowPos(hTaskbar, HWND_NOTOPMOST, 0, 0, 0, 0,
                    SWP_NOACTIVATE | SWP_NOMOVE | SWP_NOSIZE | SWP_NOOWNERZORDER);
    }
    SendMessage(FindWindow("Shell_TrayWnd", nullptr), WM_SIZE, 0, 0);
}

// Set taskbar auto-hide mode
void SetTaskbarAutoHide(bool autoHide) {
    APPBARDATA abd = { sizeof(APPBARDATA) };
    abd.hWnd = FindWindow("Shell_TrayWnd", nullptr);
    
    if (abd.hWnd) {
        abd.lParam = autoHide ? ABS_AUTOHIDE : ABS_ALWAYSONTOP;
        SHAppBarMessage(ABM_SETSTATE, &abd);
    }
}

// Keyboard hook procedure
LRESULT CALLBACK LowLevelKeyboardProc(int nCode, WPARAM wParam, LPARAM lParam) {
    if (nCode >= 0) {
        KBDLLHOOKSTRUCT* pKeyInfo = reinterpret_cast<KBDLLHOOKSTRUCT*>(lParam);
        
        if (pKeyInfo->vkCode == VK_LWIN || pKeyInfo->vkCode == VK_RWIN) {
            if (wParam == WM_KEYDOWN || wParam == WM_SYSKEYDOWN) {
                std::thread([]() {
                    std::this_thread::sleep_for(std::chrono::milliseconds(5));
                    HideAllTaskbars();
                    SetTaskbarAutoHide(true);
                }).detach();
            }
        }
    }
    return CallNextHookEx(g_keyboardHook, nCode, wParam, lParam);
}

// Mouse hook procedure
LRESULT CALLBACK LowLevelMouseProc(int nCode, WPARAM wParam, LPARAM lParam) {
    if (nCode >= 0) {
        MSLLHOOKSTRUCT* pMouseInfo = reinterpret_cast<MSLLHOOKSTRUCT*>(lParam);
        
        if (pMouseInfo->pt.x <= 2 || 
            pMouseInfo->pt.y <= 2 ||
            pMouseInfo->pt.x >= GetSystemMetrics(SM_CXSCREEN) - 2 ||
            pMouseInfo->pt.y >= GetSystemMetrics(SM_CYSCREEN) - 2) {
            HideAllTaskbars();
        }
    }
    return CallNextHookEx(g_mouseHook, nCode, wParam, lParam);
}

// Create hidden window for message processing
bool CreateMessageWindow() {
    WNDCLASS wc = { 0 };
    wc.lpfnWndProc = WindowProc;
    wc.hInstance = GetModuleHandle(nullptr);
    wc.lpszClassName = "TaskbarHiderWindowClass";
    
    if (!RegisterClass(&wc)) {
        return false;
    }
    
    g_hWnd = CreateWindowEx(
        0,
        wc.lpszClassName,
        "Taskbar Hider",
        0, 0, 0, 0, 0,
        HWND_MESSAGE,
        nullptr,
        wc.hInstance,
        nullptr
    );
    
    return g_hWnd != nullptr;
}

// Window procedure
LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
        case WM_CREATE:
            g_taskbarCreatedMsg = RegisterWindowMessage("TaskbarCreated");
            break;
            
        case WM_DESTROY:
            PostQuitMessage(0);
            break;
            
        case WM_COMMAND:
            if (LOWORD(wParam) == 1001) {
                g_running = false;
                PostMessage(hwnd, WM_QUIT, 0, 0);
            }
            break;
            
        default:
            if (uMsg == g_taskbarCreatedMsg) {
                std::thread([]() {
                    std::this_thread::sleep_for(std::chrono::milliseconds(500));
                    HideAllTaskbars();
                }).detach();
            }
            break;
    }
    
    if (uMsg == WM_TRAYICON) {
        if (lParam == WM_RBUTTONDOWN || lParam == WM_CONTEXTMENU) {
            POINT pt;
            GetCursorPos(&pt);
            SetForegroundWindow(hwnd);
            
            TrackPopupMenu(g_hPopupMenu, 
                          TPM_RIGHTBUTTON | TPM_BOTTOMALIGN,
                          pt.x, pt.y, 0, hwnd, nullptr);
            
            PostMessage(hwnd, WM_NULL, 0, 0);
            return 0;
        } else if (lParam == WM_LBUTTONDBLCLK) {
            g_running = false;
            PostMessage(hwnd, WM_QUIT, 0, 0);
        }
    }
    
    return DefWindowProc(hwnd, uMsg, wParam, lParam);
}

// Create system tray icon
bool CreateTrayIcon() {
    g_hPopupMenu = CreatePopupMenu();
    if (!g_hPopupMenu) return false;
    
    AppendMenu(g_hPopupMenu, MF_STRING, 1001, "Exit(&X)");
    
    g_notifyIconData.cbSize = sizeof(NOTIFYICONDATA);
    g_notifyIconData.hWnd = g_hWnd;
    g_notifyIconData.uID = 1;
    g_notifyIconData.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
    g_notifyIconData.uCallbackMessage = WM_TRAYICON;
    g_notifyIconData.hIcon = LoadIcon(nullptr, IDI_APPLICATION);
    strcpy(g_notifyIconData.szTip, "Taskbar Hider Tool\nRight-click to exit");
    
    if (!Shell_NotifyIcon(NIM_ADD, &g_notifyIconData)) {
        return false;
    }
    
    return true;
}

// Remove system tray icon
void RemoveTrayIcon() {
    Shell_NotifyIcon(NIM_DELETE, &g_notifyIconData);
    
    if (g_hPopupMenu) {
        DestroyMenu(g_hPopupMenu);
        g_hPopupMenu = nullptr;
    }
    
    if (g_notifyIconData.hIcon) {
        DestroyIcon(g_notifyIconData.hIcon);
        g_notifyIconData.hIcon = nullptr;
    }
}

// Install system hooks
bool SetHooks() {
    g_keyboardHook = SetWindowsHookEx(WH_KEYBOARD_LL, LowLevelKeyboardProc, 
                                     GetModuleHandle(nullptr), 0);
    if (!g_keyboardHook) {
        std::cerr << "Failed to install keyboard hook! Error: " << GetLastError() << std::endl;
        return false;
    }
    
    g_mouseHook = SetWindowsHookEx(WH_MOUSE_LL, LowLevelMouseProc,
                                  GetModuleHandle(nullptr), 0);
    if (!g_mouseHook) {
        std::cerr << "Failed to install mouse hook! Error: " << GetLastError() << std::endl;
        UnhookWindowsHookEx(g_keyboardHook);
        return false;
    }
    
    return true;
}

// Cleanup hooks
void CleanupHooks() {
    if (g_keyboardHook) {
        UnhookWindowsHookEx(g_keyboardHook);
        g_keyboardHook = nullptr;
    }
    if (g_mouseHook) {
        UnhookWindowsHookEx(g_mouseHook);
        g_mouseHook = nullptr;
    }
}

// Hide console window
void HideConsole() {
    HWND hConsole = GetConsoleWindow();
    if (hConsole) {
        ShowWindow(hConsole, SW_HIDE);
    }
}

// Taskbar monitoring thread
void TaskbarMonitorThread() {
    while (g_running) {
        HideAllTaskbars();
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }
}

// Main entry point
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    // Check for administrator privileges
    BOOL isAdmin = FALSE;
    HANDLE hToken = nullptr;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        TOKEN_ELEVATION elevation;
        DWORD size = sizeof(TOKEN_ELEVATION);
        if (GetTokenInformation(hToken, TokenElevation, &elevation, size, &size)) {
            isAdmin = elevation.TokenIsElevated;
        }
        CloseHandle(hToken);
    }
    
    HideConsole();
    
    if (!CreateMessageWindow()) {
        MessageBox(nullptr, "Failed to create message window", "Error", MB_ICONERROR);
        return 1;
    }
    
    if (!CreateTrayIcon()) {
        MessageBox(nullptr, "Failed to create system tray icon", "Error", MB_ICONERROR);
        return 1;
    }
    
    HideAllTaskbars();
    SetTaskbarAutoHide(true);
    
    std::thread monitor(TaskbarMonitorThread);
    
    bool hooksInstalled = SetHooks();
    
    if (!hooksInstalled && !isAdmin) {
        char exePath[MAX_PATH];
        GetModuleFileName(nullptr, exePath, MAX_PATH);
        
        SHELLEXECUTEINFO sei = { sizeof(sei) };
        sei.lpVerb = "runas";
        sei.lpFile = exePath;
        sei.nShow = SW_SHOW;
        
        if (ShellExecuteEx(&sei)) {
            g_running = false;
        }
    }
    
    MSG msg;
    while (g_running && GetMessage(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    
    g_running = false;
    
    if (monitor.joinable()) {
        monitor.join();
    }
    
    RestoreTaskbars();
    SetTaskbarAutoHide(false);
    
    CleanupHooks();
    RemoveTrayIcon();
    
    if (g_hWnd) {
        DestroyWindow(g_hWnd);
    }
    
    return 0;
}

#ifdef _CONSOLE
int main() {
    return WinMain(GetModuleHandle(nullptr), nullptr, GetCommandLine(), SW_SHOW);
}
#endif