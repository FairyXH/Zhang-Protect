#include <windows.h>
#include <powrprof.h>
#include <stdio.h>
#include <time.h>
#include <Windows.h>
#include <cstdlib>
#include <shlwapi.h>
#include <stdarg.h>
#include <string.h>
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "powrprof.lib")
#ifndef SC_SLEEP
#define SC_SLEEP 0xF140
#endif
interface IPowerManager : IUnknown
{
    virtual HRESULT __stdcall Suspend() = 0;
    virtual HRESULT __stdcall Hibernate() = 0;
    virtual HRESULT __stdcall Reboot() = 0;
    virtual HRESULT __stdcall Shutdown() = 0;
};

const GUID GUID_LIDSWITCH_STATE_CHANGE = 
    {0xba3e0f4d, 0xb817, 0x4094, {0xa2, 0xd1, 0xd5, 0x63, 0x79, 0xe6, 0xa0, 0xf3}};
	
// {238C9FA8-0AAD-41ED-83F4-97BE242C8F20}
static const GUID GUID_SUB_SLEEP =
{ 0x238c9fa8, 0x0aad, 0x41ed, {0x83,0xf4,0x97,0xbe,0x24,0x2c,0x8f,0x20} };

// {9D7815A6-7EE4-497E-8888-515A05F02364}
static const GUID GUID_HIBERNATE_ENABLED =
{ 0x9d7815a6, 0x7ee4, 0x497e, {0x88,0x88,0x51,0x5a,0x05,0xf0,0x23,0x64} };


HPOWERNOTIFY hNotify = NULL;
BOOL lidClosed = FALSE;
ULONGLONG closeTime = 0;
HANDLE hTimer = NULL;
BOOL systemSleeping = FALSE;
BOOL hibernatePending = FALSE;

static char g_log_path[MAX_PATH] = {0};
static BOOL g_log_enabled = TRUE;

/* 检查 lowerlog 标志文件 */
static void log_check_disable_flag()
{
    char exeDir[MAX_PATH];
    GetModuleFileNameA(NULL, exeDir, MAX_PATH);
    char* p = strrchr(exeDir, '\\');
    if (p) *p = 0;

    char flagPath[MAX_PATH];
    snprintf(flagPath, MAX_PATH, "%s\\lowerlog", exeDir);

    DWORD attr = GetFileAttributesA(flagPath);
    if (attr != INVALID_FILE_ATTRIBUTES &&
        !(attr & FILE_ATTRIBUTE_DIRECTORY))
    {
        g_log_enabled = FALSE;
    }
}

/* 生成 用户专属 日志路径 */
static void log_prepare_path()
{
    if (!g_log_enabled)
        return;

    if (g_log_path[0] != '\0')
        return;

    char exePath[MAX_PATH];
    GetModuleFileNameA(NULL, exePath, MAX_PATH);

    char* dirEnd = strrchr(exePath, '\\');
    if (!dirEnd)
        return;

    char exeName[MAX_PATH];
    strcpy(exeName, dirEnd + 1);
    *dirEnd = 0;

    char* dot = strrchr(exeName, '.');
    if (dot) *dot = 0;

    char userName[256] = "unknown";
    DWORD size = sizeof(userName);
    GetUserNameA(userName, &size);

    snprintf(g_log_path, MAX_PATH,
        "%s\\%s_%s.log",
        exePath,
        exeName,
        userName);
}

/* 删除所有用户日志 */
static void log_clear_all_logs()
{
    char exeDir[MAX_PATH];
    GetModuleFileNameA(NULL, exeDir, MAX_PATH);
    char* p = strrchr(exeDir, '\\');
    if (p) *p = 0;

    char exeName[MAX_PATH];
    char* filePart = strrchr(exeDir, '\\');
    GetModuleFileNameA(NULL, exeName, MAX_PATH);
    char* name = strrchr(exeName, '\\');
    if (name) name++;
    else name = exeName;

    char* dot = strrchr(name, '.');
    if (dot) *dot = 0;

    char searchPattern[MAX_PATH];
    snprintf(searchPattern, MAX_PATH,
        "%s\\%s_*.log",
        exeDir,
        name);

    WIN32_FIND_DATAA fd;
    HANDLE hFind = FindFirstFileA(searchPattern, &fd);

    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            char filePath[MAX_PATH];
            snprintf(filePath, MAX_PATH,
                "%s\\%s",
                exeDir,
                fd.cFileName);

            DeleteFileA(filePath);

        } while (FindNextFileA(hFind, &fd));

        FindClose(hFind);
    }
}

/* ====== 在 main() 最开始调用 ====== */
void log_init()
{
    log_check_disable_flag();

    if (!g_log_enabled)
        return;

    log_clear_all_logs();   // 清空所有用户日志
    log_prepare_path();
}

/* ====== 日志函数 ====== */
void log_message(const char* fmt, ...)
{
    if (!g_log_enabled)
        return;

    log_prepare_path();

    char timebuf[64];
    char msg[512];
    char final[768];
    va_list args;
    SYSTEMTIME st;

    GetLocalTime(&st);
    snprintf(timebuf, sizeof(timebuf),
        "[INFO %04d-%02d-%02d %02d:%02d:%02d]",
        st.wYear, st.wMonth, st.wDay,
        st.wHour, st.wMinute, st.wSecond);

    va_start(args, fmt);
    vsnprintf(msg, sizeof(msg), fmt, args);
    va_end(args);

    snprintf(final, sizeof(final), "%s %s\n", timebuf, msg);

    printf("%s", final);

    FILE* f = fopen(g_log_path, "a");
    if (f) {
        fputs(final, f);
        fclose(f);
    }
}


// 检查文件是否存在
bool FileExists(const char* path)
{
    DWORD attr = GetFileAttributesA(path);
    return (attr != INVALID_FILE_ATTRIBUTES && !(attr & FILE_ATTRIBUTE_DIRECTORY));
}

// 获取程序目录
void GetModuleDir(char* dir, size_t size)
{
    char path[MAX_PATH];
    GetModuleFileNameA(NULL, path, MAX_PATH);
    char* p = strrchr(path, '\\');
    if (p) *p = 0;
    strncpy(dir, path, size);
    dir[size-1] = 0;
}

bool EnableShutdownPrivilege()
{
    HANDLE hToken;
    TOKEN_PRIVILEGES tp;

    if (!OpenProcessToken(GetCurrentProcess(),
        TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return false;

    LookupPrivilegeValue(nullptr, SE_SHUTDOWN_NAME, &tp.Privileges[0].Luid);
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    AdjustTokenPrivileges(hToken, FALSE, &tp, 0, nullptr, nullptr);
    CloseHandle(hToken);

    return GetLastError() == ERROR_SUCCESS;
}

// 调用 PsShutdown 或回退 SendMessage
bool EnterSleepPSX()
{
    char exeDir[MAX_PATH];
    GetModuleDir(exeDir, MAX_PATH);

    char psExe[MAX_PATH];
    snprintf(psExe, MAX_PATH, "%s\\PSTools\\psshutdown64.exe", exeDir);
    if (!FileExists(psExe))
        snprintf(psExe, MAX_PATH, "%s\\PSTools\\psshutdown.exe", exeDir);

    if (FileExists(psExe)) {
        char cmd[MAX_PATH + 32];
        snprintf(cmd, sizeof(cmd), "\"%s\" -x -accepteula", psExe);
        log_message("调用 PsShutdown: %s", cmd);
        int ret = system(cmd);
        if (ret == 0) {
            log_message("PsShutdown 执行完成");
        } else {
            log_message("PsShutdown 执行失败, code=%d，回退SendMessage", ret);
            SendMessage(HWND_BROADCAST, WM_SYSCOMMAND, 0xF170, 2);
            log_message("已发送S0睡眠请求（显示器关闭模式）");
        }
        return true;
    } else {
        log_message("PsShutdown 不存在，回退SendMessage模式");
        SendMessage(HWND_BROADCAST, WM_SYSCOMMAND, 0xF170, 2);
        log_message("已发送S0睡眠请求（显示器关闭模式）");
        return true;
    }
}


bool EnterSleep()
{
    EnableShutdownPrivilege();
    SYSTEM_POWER_CAPABILITIES caps = {};
    if (!GetPwrCapabilities(&caps))
    {
        DWORD err = GetLastError();
        log_message("获取电源能力失败，错误=%lu，回退使用S0模式", err);
		EnterSleepPSX();
		log_message("已发送睡眠请求（S0模式）");
        return true;
    }
    if (caps.SystemS3)
    {
        log_message("检测到系统支持 S3，进入睡眠(SetSuspendState)");
        BOOL res = SetSuspendState(
            FALSE,  // FALSE = Sleep，TRUE = Hibernate
            FALSE,  // 不强制
            TRUE    // 禁用唤醒事件
        );

        if (res)
        {
            log_message("系统已请求进入 S3 睡眠");
            return true;
        }
        else
        {
            DWORD err = GetLastError();
            log_message("SetSuspendState 失败，错误=%lu，尝试S0模式", err);
            EnterSleepPSX();
            log_message("已发送睡眠请求（S0模式）");
            return true;
        }
    }
    else
    {
        log_message("系统不支持 S3（Modern Standby）");
        EnterSleepPSX();
        log_message("已发送睡眠请求（S0模式）");
        return true;
    }
}


bool EnterHibernate()
{
	EnableShutdownPrivilege(); //获取特权
    SYSTEM_POWER_CAPABILITIES spc;
    if (!GetPwrCapabilities(&spc)) {
        log_message("无法获取电源能力");
        return false;
    }
    if (!spc.HiberFilePresent) {
        log_message("系统不支持休眠或休眠文件未创建");
        return false;
    }
    log_message("进入休眠");
    BOOL res = SetSuspendState(TRUE, FALSE, TRUE); // 第一个参数FALSE睡眠，TRUE休眠
    if (res) {
        log_message("系统已请求进入休眠");
        return true;
    } else {
        log_message("无法进入休眠");
        return false;
    }
}

BOOL MouseMovedWithinTolerance() {
    static POINT lastPos = {0};
    static BOOL firstCall = TRUE;
    POINT curPos;
    GetCursorPos(&curPos);
    if (firstCall) {
        lastPos = curPos;
        firstCall = FALSE;
        return FALSE;
    }
    int dx = abs(curPos.x - lastPos.x);
    int dy = abs(curPos.y - lastPos.y);
    lastPos = curPos;
    return (dx > 10 || dy > 10);
}

VOID CALLBACK TimerProc(PVOID lpParameter, BOOLEAN TimerOrWaitFired) {
    ULONGLONG now = GetTickCount64();
    ULONGLONG elapsed = now - closeTime;

    LASTINPUTINFO lii = { sizeof(LASTINPUTINFO) };
    GetLastInputInfo(&lii);

    DWORD idleSec = (GetTickCount() - lii.dwTime) / 1000;

    log_message("Timer check: elapsed=%llu ms, idleSec=%lu, lidClosed=%d, systemSleeping=%d, hibernatePending=%d",
        elapsed, idleSec, lidClosed, systemSleeping, hibernatePending);
		
	
	if ((idleSec < 5 && elapsed > 1000) || !lidClosed)
	{
		log_message("检测到系统唤醒");
		hibernatePending = FALSE;
		systemSleeping = FALSE;
		closeTime = GetTickCount64();
	}
	
	if (!lidClosed || systemSleeping){
        return;
	}
	
    if (elapsed >= 15000 && idleSec >= 15 && !hibernatePending) {
        log_message("盖下盖子无操作15秒，进入睡眠。");
        systemSleeping = TRUE;
        EnterSleep();
        systemSleeping = FALSE;
        closeTime = GetTickCount64();
        hibernatePending = TRUE;
    }
    //else if (elapsed >= 1800000 && idleSec >= 1800) {
    //    log_message("盖下盖子无操作30分钟，进入休眠。");
    //    systemSleeping = TRUE;
    //    EnterHibernate();
    //    systemSleeping = FALSE;
    //    hibernatePending = FALSE;
    //}
}

LRESULT CALLBACK WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_CREATE: {
            hNotify = RegisterPowerSettingNotification(hWnd, &GUID_LIDSWITCH_STATE_CHANGE, 
                DEVICE_NOTIFY_WINDOW_HANDLE);
            
            CreateTimerQueueTimer(&hTimer, NULL, TimerProc, NULL, 5000, 5000, WT_EXECUTEDEFAULT);
            log_message("正在监听屏幕盖子事件");
            break;
        }
        case WM_POWERBROADCAST:
            if (wParam == PBT_POWERSETTINGCHANGE) {
                POWERBROADCAST_SETTING* pbs = (POWERBROADCAST_SETTING*)lParam;
                if (IsEqualGUID(pbs->PowerSetting, GUID_LIDSWITCH_STATE_CHANGE)) {
                    DWORD state = *(DWORD*)pbs->Data;
                    log_message("屏幕盖子 %s", state ? "打开" : "关闭");
                    lidClosed = (state == 0);
                    if (lidClosed) {
                        closeTime = GetTickCount64();
                        hibernatePending = FALSE;
                    }
                }
            }
			if (wParam == PBT_APMRESUMEAUTOMATIC || wParam == PBT_APMRESUMESUSPEND) {
				log_message("系统唤醒");
				systemSleeping = FALSE;
				hibernatePending = FALSE;
				closeTime = GetTickCount64();
			}
            return TRUE;
        case WM_DESTROY:
            if (hTimer) DeleteTimerQueueTimer(NULL, hTimer, NULL);
            if (hNotify) UnregisterPowerSettingNotification(hNotify);
            log_message("正在关闭");
            PostQuitMessage(0);
            break;
    }
    return DefWindowProc(hWnd, msg, wParam, lParam);
}

int WINAPI WinMain(HINSTANCE hInst, HINSTANCE, LPSTR, int nCmdShow) {
	log_init();
    WNDCLASS wc = {0};
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInst;
    wc.lpszClassName = "LidMonitor";
    RegisterClass(&wc);
    HWND hWnd = CreateWindow("LidMonitor", NULL, 0, 0, 0, 0, 0, HWND_MESSAGE, NULL, hInst, NULL);
    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    return 0;
}