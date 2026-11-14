#include <windows.h>
#include <iostream>
#include <string>
#include <map>
#include <vector>
#include <unordered_set>

using namespace std;

// 全局变量：是否隐藏控制台
bool g_bHideConsole = false;

// 互斥锁名称（确保唯一性）
const wchar_t* MUTEX_NAME = L"Global\\KeyLauncher_Mutex_{D5F6A5E4-7A1E-4F3A-9B8D-2C7E8F9A0B1C}";

struct EnumData {
    DWORD pid;
    unordered_set<HWND> hwnds;
};

BOOL CALLBACK EnumWindowsProc(HWND hWnd, LPARAM lParam) {
    EnumData* data = (EnumData*)lParam;
    DWORD curPid;
    GetWindowThreadProcessId(hWnd, &curPid);
    if (curPid == data->pid && data->hwnds.find(hWnd) == data->hwnds.end()) {
        data->hwnds.insert(hWnd);
    }
    return TRUE;
}

unordered_set<HWND> findWindowsByPID(DWORD pid) {
    EnumData data = { pid };
    EnumWindows(EnumWindowsProc, (LPARAM)&data);
    return data.hwnds;
}

BOOL CALLBACK EnumChildProc(HWND hWnd, LPARAM lParam) {
    unordered_set<HWND>* hwnds = (unordered_set<HWND>*)lParam;
    bool bVisible = (::GetWindowLong(hWnd, GWL_STYLE) & WS_VISIBLE) != 0;
    if (bVisible && GetWindowTextLength(hWnd) > 0 && hwnds->find(hWnd) == hwnds->end()) {
        hwnds->insert(hWnd);
        char buf[512];
        GetWindowTextA(hWnd, buf, sizeof(buf));
        if (!g_bHideConsole) {
            cout << "       找到子窗口: 句柄=" << hWnd << ", 标题=" << buf << endl;
        }
    }
    return TRUE;
}

vector<HWND> waitForReadyWindows(DWORD pid, int timeoutMs) {
    int elapsed = 0;
    unordered_set<HWND> allFoundWindows;
    
    while (elapsed < timeoutMs) {
        unordered_set<HWND> processWindows = findWindowsByPID(pid);
        bool foundNewWindows = false;
        
        for (HWND hwnd : processWindows) {
            if (allFoundWindows.find(hwnd) == allFoundWindows.end()) {
                allFoundWindows.insert(hwnd);
                foundNewWindows = true;
                bool bVisible = (::GetWindowLong(hwnd, GWL_STYLE) & WS_VISIBLE) != 0;
                char buf[512];
                GetWindowTextA(hwnd, buf, sizeof(buf));
                if (!g_bHideConsole) {
                    cout << "       找到新窗口: 句柄=" << hwnd << ", 标题=" << buf 
                         << ", 可见=" << (bVisible ? "是" : "否") << endl;
                }
                EnumChildWindows(hwnd, EnumChildProc, (LPARAM)&allFoundWindows);
            }
        }
        
        vector<HWND> validHwnds;
        for (HWND hwnd : allFoundWindows) {
            bool bVisible = (::GetWindowLong(hwnd, GWL_STYLE) & WS_VISIBLE) != 0;
            if (bVisible && GetWindowTextLength(hwnd) > 0) {
                validHwnds.push_back(hwnd);
            }
        }
        
        if (!validHwnds.empty()) {
            if (!g_bHideConsole) {
                cout << "[信息] 共找到 " << validHwnds.size() << " 个有效窗口" << endl;
            }
            return validHwnds;
        }
        
        if (!foundNewWindows) {
            if (!g_bHideConsole) {
                cout << "[信息] 未找到新窗口，等待中... (" << elapsed << "/" << timeoutMs << "ms)" << endl;
            }
            Sleep(500);
            elapsed += 500;
        } else {
            Sleep(200);
            elapsed += 200;
        }
    }
    
    if (!g_bHideConsole) {
        cout << "[警告] 超时未找到有效窗口" << endl;
    }
    return {};
}

bool aggressiveActivateWindow(HWND hwnd, int maxAttempts = 10) {
    if (!IsWindow(hwnd)) {
        if (!g_bHideConsole) {
            cout << "[错误] 窗口句柄无效" << endl;
        }
        return false;
    }

    RECT originalRect;
    GetWindowRect(hwnd, &originalRect);
    LONG originalStyle = GetWindowLong(hwnd, GWL_STYLE);
    LONG originalExStyle = GetWindowLong(hwnd, GWL_EXSTYLE);

    for (int attempt = 1; attempt <= maxAttempts; attempt++) {
        if (!g_bHideConsole) {
            cout << "[激活] 第 " << attempt << " 次尝试激活窗口 " << hwnd << endl;
        }

        ShowWindow(hwnd, SW_RESTORE);
        SetWindowPos(hwnd, HWND_TOPMOST, 0, 0, 0, 0, 
                   SWP_NOMOVE | SWP_NOSIZE | SWP_SHOWWINDOW);
        BringWindowToTop(hwnd);
        SetForegroundWindow(hwnd);
        Sleep(100);

        DWORD curThread = GetCurrentThreadId();
        DWORD targetThread = GetWindowThreadProcessId(hwnd, NULL);
        bool attached = AttachThreadInput(curThread, targetThread, TRUE);

        SetForegroundWindow(hwnd);
        SetFocus(hwnd);
        SetActiveWindow(hwnd);
        SendMessage(hwnd, WM_ACTIVATE, WA_ACTIVE, 0);
        SendMessage(hwnd, WM_ACTIVATEAPP, TRUE, 0);
        SendMessage(hwnd, WM_SETFOCUS, 0, 0);
        SendMessage(hwnd, WM_ENABLE, TRUE, 0);
        Sleep(200);

        SetWindowPos(hwnd, NULL, originalRect.left + 1, originalRect.top, 0, 0, 
                   SWP_NOSIZE | SWP_NOZORDER);
        Sleep(50);
        SetWindowPos(hwnd, NULL, originalRect.left, originalRect.top, 0, 0, 
                   SWP_NOSIZE | SWP_NOZORDER);
        Sleep(200);

        HWND fgWnd = GetForegroundWindow();
        HWND focusWnd = GetFocus();
        bool isActivated = (fgWnd == hwnd) || (focusWnd == hwnd);

        if (attached) {
            AttachThreadInput(curThread, targetThread, FALSE);
        }

        if (isActivated) {
            if (!g_bHideConsole) {
                cout << "[激活] 窗口激活成功！" << endl;
            }
            SetWindowLong(hwnd, GWL_STYLE, originalStyle);
            SetWindowLong(hwnd, GWL_EXSTYLE, originalExStyle);
            return true;
        }
    }

    SetWindowLong(hwnd, GWL_STYLE, originalStyle);
    SetWindowLong(hwnd, GWL_EXSTYLE, originalExStyle);
    SetWindowPos(hwnd, HWND_NOTOPMOST, originalRect.left, originalRect.top,
               originalRect.right - originalRect.left,
               originalRect.bottom - originalRect.top,
               SWP_SHOWWINDOW);
    
    if (!g_bHideConsole) {
        cout << "[激活] 所有激活尝试失败，但仍将尝试发送输入" << endl;
    }
    return false;
}

bool sendKeySimulate(HWND hwnd, WORD vkCode) {
    if (!g_bHideConsole) {
        cout << "[SendInput] 准备发送键码 " << vkCode << endl;
    }
    
    aggressiveActivateWindow(hwnd);

    INPUT input[2] = {};
    input[0].type = INPUT_KEYBOARD;
    input[0].ki.wVk = vkCode;
    input[0].ki.wScan = MapVirtualKey(vkCode, MAPVK_VK_TO_VSC);
    input[0].ki.dwFlags = 0;
    input[0].ki.dwExtraInfo = GetMessageExtraInfo();
    
    input[1].type = INPUT_KEYBOARD;
    input[1].ki.wVk = vkCode;
    input[1].ki.wScan = MapVirtualKey(vkCode, MAPVK_VK_TO_VSC);
    input[1].ki.dwFlags = KEYEVENTF_KEYUP;
    input[1].ki.dwExtraInfo = GetMessageExtraInfo();

    for (int i = 0; i < 2; i++) {
        UINT sent = SendInput(2, input, sizeof(INPUT));
        if (sent == 2 && !g_bHideConsole) {
            cout << "[SendInput] 第 " << (i+1) << " 次发送成功" << endl;
        }
        Sleep(100);
    }

    SetWindowPos(hwnd, HWND_NOTOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE);
    return true;
}

void sendKeyPost(HWND hwnd, WORD vkCode) {
    if (!g_bHideConsole) {
        cout << "[PostMessage] 准备发送键码 " << vkCode << endl;
    }
    
    aggressiveActivateWindow(hwnd, 3);

    LPARAM lParamDown = (MapVirtualKey(vkCode, 0) << 16) | 0x0001;
    LPARAM lParamUp = (MapVirtualKey(vkCode, 0) << 16) | 0xC001;

    for (int i = 0; i < 3; i++) {
        PostMessage(hwnd, WM_KEYDOWN, vkCode, lParamDown);
        Sleep(50);
        PostMessage(hwnd, WM_KEYUP, vkCode, lParamUp);
        Sleep(50);
    }
    if (!g_bHideConsole) {
        cout << "[PostMessage] 多轮发送完成" << endl;
    }
}

// 隐藏控制台窗口
void hideConsole() {
    HWND hConsole = GetConsoleWindow();
    if (hConsole != NULL) {
        ShowWindow(hConsole, SW_HIDE);
    }
}

void printHelp() {
    cout << "本工具用于启动exe程序并向其窗口发送键盘消息（如模拟回车键自动登录等）\n\n";
    cout << "用法:\n";
    cout << "  KeyLauncher.exe /exe <目标程序路径> [/args <参数>] [/key <键值>] [/delay <秒数>] [/hide]\n\n";
    cout << "参数说明:\n";
    cout << "  /exe       (必需) 目标程序路径\n";
    cout << "  /args      (可选) 程序参数\n";
    cout << "  /key       (可选) 键值，默认回车(13)\n";
    cout << "  /delay     (可选) 等待程序就绪的秒数，默认3秒\n";
    cout << "  /hide      (可选) 隐藏控制台窗口，静默操作\n";
    cout << "  /h 或 /?   显示本帮助\n";
    cout << "示例:\n";
    cout << "  KeyLauncher.exe /exe QQNT.exe /delay 3 /hide\n";
}

int main(int argc, char* argv[]) {
    // 先解析/hide参数，以便尽早隐藏窗口
    for (int i = 1; i < argc; i++) {
        string cur = argv[i];
        if (cur == "/hide") {
            g_bHideConsole = true;
            hideConsole();
            break;
        }
    }

    // 创建互斥锁，实现排队机制
    HANDLE hMutex = CreateMutexW(NULL, TRUE, MUTEX_NAME);
    if (hMutex == NULL) {
        if (!g_bHideConsole) {
            cerr << "错误: 创建互斥锁失败，错误码: " << GetLastError() << endl;
        }
        return 1;
    }

    // 等待互斥锁（最多等待5分钟）
    DWORD waitResult = WaitForSingleObject(hMutex, 300000); // 5分钟超时
    switch (waitResult) {
        case WAIT_OBJECT_0:
            if (!g_bHideConsole) {
                cout << "[信息] 获取互斥锁成功，开始执行操作" << endl;
            }
            break;
        case WAIT_TIMEOUT:
            if (!g_bHideConsole) {
                cerr << "错误: 等待互斥锁超时（5分钟）" << endl;
            }
            CloseHandle(hMutex);
            return 1;
        default:
            if (!g_bHideConsole) {
                cerr << "错误: 等待互斥锁失败，错误码: " << GetLastError() << endl;
            }
            CloseHandle(hMutex);
            return 1;
    }

    // 解析其他参数
    if (argc < 2) { 
        if (!g_bHideConsole) printHelp(); 
        ReleaseMutex(hMutex);
        CloseHandle(hMutex);
        return 0; 
    }

    map<string, string> args;
    for (int i = 1; i < argc; i++) {
        string cur = argv[i];
        if (cur == "/h" || cur == "/H" || cur == "/?") { 
            if (!g_bHideConsole) printHelp(); 
            ReleaseMutex(hMutex);
            CloseHandle(hMutex);
            return 0; 
        }
        if (cur == "/hide") {
            continue; // 已经处理过
        }
        if (cur[0] == '/' && i + 1 < argc) { 
            args[cur] = argv[i + 1]; 
            i++; 
        }
    }

    if (args.find("/exe") == args.end()) { 
        if (!g_bHideConsole) cerr << "错误: 必须提供 /exe 参数\n"; 
        ReleaseMutex(hMutex);
        CloseHandle(hMutex);
        return 1; 
    }

    string exePath = args["/exe"];
    string exeArgs = args.count("/args") ? args["/args"] : "";
    WORD keyCode = args.count("/key") ? stoi(args["/key"]) : VK_RETURN;
    int delaySec = args.count("/delay") ? stoi(args["/delay"]) : 3;

    if (!g_bHideConsole) {
        cout << "[信息] 程序路径: " << exePath << endl;
        cout << "[信息] 程序参数: " << exeArgs << endl;
        cout << "[信息] 键值: " << keyCode << endl;
        cout << "[信息] 延迟秒数: " << delaySec << endl;
    }

    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    string cmdLineStr = "\"" + exePath + "\" " + exeArgs;
    vector<char> cmdLine(cmdLineStr.begin(), cmdLineStr.end());
    cmdLine.push_back('\0');

    if (!CreateProcessA(NULL, cmdLine.data(), NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        if (!g_bHideConsole) {
            cerr << "错误: 启动进程失败。错误码: " << GetLastError() << endl;
        }
        ReleaseMutex(hMutex);
        CloseHandle(hMutex);
        return 1;
    }
    CloseHandle(pi.hThread);
    if (!g_bHideConsole) {
        cout << "[信息] 启动进程成功，PID=" << pi.dwProcessId << endl;
    }

    vector<HWND> hwnds = waitForReadyWindows(pi.dwProcessId, 30000);
    if (hwnds.empty()) {
        if (!g_bHideConsole) {
            cerr << "错误: 30秒内未找到有效窗口，请检查程序是否正常启动" << endl;
        }
        CloseHandle(pi.hProcess);
        ReleaseMutex(hMutex);
        CloseHandle(hMutex);
        return 1;
    }

    if (!g_bHideConsole) {
        cout << "等待 " << delaySec << " 秒后发送按键..." << endl;
    }
    Sleep(delaySec * 1000);

    if (!hwnds.empty()) {
        HWND targetHwnd = hwnds[0];
        sendKeyPost(targetHwnd, keyCode);
        Sleep(1000);
        sendKeySimulate(targetHwnd, keyCode);
    }

    if (!g_bHideConsole) {
        cout << "操作完成。" << endl;
    }
    CloseHandle(pi.hProcess);
    
    // 释放互斥锁，让下一个实例运行
    ReleaseMutex(hMutex);
    CloseHandle(hMutex);
    return 0;
}
