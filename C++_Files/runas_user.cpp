
#include <windows.h>
#include <taskschd.h>
#include <comdef.h>
#include <string>
#include <sstream>
#include <iostream>
#include <ctime>

// ======================
// 控制台输出
// ======================
void print_console(const wchar_t* text) {
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    if (!hOut || hOut == INVALID_HANDLE_VALUE) return;
    DWORD written = 0;
    WriteConsoleW(hOut, text, lstrlenW(text), &written, NULL);
}

// ======================
// 帮助信息
// ======================
void print_help() {
    print_console(
        L"用法:\n"
        L"  runas_user.exe /user <用户名> /command <命令> [/highest]\n\n"
        L"参数:\n"
        L"  /user <用户名>     运行用户（如 Administrator）\n"
        L"  /command <命令>    要执行的命令或脚本\n"
        L"  /highest           以最高权限运行\n"
        L"  /h, /?             显示帮助\n\n"
        L"说明:\n"
        L"  使用 Task Scheduler COM API 在指定用户当前会话启动程序\n"
        L"  API 失败时自动回退 schtasks\n"
    );
}

// ======================
// 打印 HRESULT 错误
// ======================
std::wstring hr_to_wstring(HRESULT hr) {
    _com_error err(hr);
    return err.ErrorMessage();
}

// ======================
// 生成 GUID 字符串
// ======================
std::wstring new_guid() {
    GUID g;
    CoCreateGuid(&g);
    wchar_t buf[64];
    StringFromGUID2(g, buf, 64);
    return buf;
}

// ======================
// 获取合法 StartBoundary
// ======================
std::wstring get_start_boundary() {
    // 返回当前时间 + 1 分钟，格式 YYYY-MM-DDTHH:MM:SS
    time_t t = time(nullptr) + 60;
    struct tm tm_now;
    localtime_s(&tm_now, &t);
    wchar_t buf[64];
    swprintf(buf, 64, L"%04d-%02d-%02dT%02d:%02d:%02d",
             tm_now.tm_year + 1900, tm_now.tm_mon + 1, tm_now.tm_mday,
             tm_now.tm_hour, tm_now.tm_min, tm_now.tm_sec);
    return buf;
}

// ======================
// Task Scheduler API 执行
// ======================
bool run_via_api(const std::wstring& user, const std::wstring& command, bool highest) {
    HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    if (FAILED(hr)) { print_console(L"[RunAs][ERROR] CoInitializeEx 失败\n"); return false; }

    ITaskService* service = nullptr;
    hr = CoCreateInstance(CLSID_TaskScheduler, nullptr, CLSCTX_INPROC_SERVER,
                          IID_ITaskService, (void**)&service);
    if (FAILED(hr)) { print_console(L"[RunAs][ERROR] CoCreateInstance TaskService 失败\n"); CoUninitialize(); return false; }

    hr = service->Connect(_variant_t(), _variant_t(), _variant_t(), _variant_t());
    if (FAILED(hr)) {
        std::wstringstream ss;
        ss << L"[RunAs][ERROR] Connect 失败 HRESULT=0x" << std::hex << hr
           << L" (" << hr_to_wstring(hr) << L")\n";
        print_console(ss.str().c_str());
        service->Release(); CoUninitialize(); return false;
    }

    ITaskFolder* root = nullptr;
    hr = service->GetFolder(_bstr_t(L"\\"), &root);
    if (FAILED(hr)) { service->Release(); CoUninitialize(); return false; }

    ITaskFolder* folder = nullptr;
    hr = root->GetFolder(_bstr_t(L"ZhangProtect"), &folder);
    if (FAILED(hr)) {
        hr = root->CreateFolder(_bstr_t(L"ZhangProtect"), _variant_t(), &folder);
        if (FAILED(hr)) {
            std::wstringstream ss;
            ss << L"[RunAs][ERROR] CreateFolder 失败 HRESULT=0x" << std::hex << hr
               << L" (" << hr_to_wstring(hr) << L")\n";
            print_console(ss.str().c_str());
            root->Release(); service->Release(); CoUninitialize();
            return false;
        }
    }

    ITaskDefinition* task = nullptr;
    hr = service->NewTask(0, &task);
    if (FAILED(hr)) { folder->Release(); root->Release(); service->Release(); CoUninitialize(); return false; }

    // ====== RegistrationInfo ======
    IRegistrationInfo* regInfo = nullptr;
    task->get_RegistrationInfo(&regInfo);
    if (regInfo) {
        regInfo->put_Author(_bstr_t(L"SYSTEM"));
        regInfo->put_Description(_bstr_t(L"ZhangProtect RunAs Task"));
        regInfo->Release();
    }

    // ====== Settings ======
    ITaskSettings* settings = nullptr;
    task->get_Settings(&settings);
    if (settings) {
        settings->put_Enabled(VARIANT_TRUE);
        settings->put_StartWhenAvailable(VARIANT_TRUE);
        settings->put_Hidden(VARIANT_FALSE);
        settings->put_ExecutionTimeLimit(_bstr_t(L"PT0S")); // 不限制
        settings->Release();
    }

    // ====== Action ======
    IActionCollection* actions = nullptr;
    task->get_Actions(&actions);
    IAction* action = nullptr;
    actions->Create(TASK_ACTION_EXEC, &action);

    IExecAction* exec = nullptr;
    action->QueryInterface(IID_IExecAction, (void**)&exec);
    exec->put_Path(_bstr_t(L"cmd.exe"));
    std::wstring args = L"/c " + command;
    exec->put_Arguments(_bstr_t(args.c_str()));
    exec->Release();
    action->Release();
    actions->Release();

    // ====== Principal ======
    IPrincipal* principal = nullptr;
    task->get_Principal(&principal);
    principal->put_UserId(_bstr_t(user.c_str()));
    principal->put_LogonType(TASK_LOGON_INTERACTIVE_TOKEN);
    principal->put_RunLevel(highest ? TASK_RUNLEVEL_HIGHEST : TASK_RUNLEVEL_LUA);
    principal->Release();

    // ====== Trigger ======
    ITriggerCollection* triggers = nullptr;
    task->get_Triggers(&triggers);
    ITrigger* trigger = nullptr;
    triggers->Create(TASK_TRIGGER_TIME, &trigger);
    ITimeTrigger* timeTrigger = nullptr;
    trigger->QueryInterface(IID_ITimeTrigger, (void**)&timeTrigger);
    timeTrigger->put_StartBoundary(_bstr_t(get_start_boundary().c_str()));
    timeTrigger->put_Enabled(VARIANT_TRUE);
    timeTrigger->Release();
    trigger->Release();
    triggers->Release();

    // ====== 注册任务 ======
    std::wstring name = L"RunAs-" + new_guid();
    IRegisteredTask* regTask = nullptr;
    hr = folder->RegisterTaskDefinition(
        _bstr_t(name.c_str()), task,
        TASK_CREATE_OR_UPDATE, _variant_t(), _variant_t(),
        TASK_LOGON_NONE, _variant_t(L""), &regTask
    );

    if (FAILED(hr)) {
        std::wstringstream ss;
        ss << L"[RunAs][ERROR] RegisterTaskDefinition 失败 HRESULT=0x" << std::hex << hr
           << L" (" << hr_to_wstring(hr) << L")\n";
        print_console(ss.str().c_str());
        task->Release(); folder->Release(); root->Release(); service->Release(); CoUninitialize();
        return false;
    }

    // ====== Run ======
    IRunningTask* pRunningTask = nullptr;
    hr = regTask->Run(_variant_t(), &pRunningTask);
    if (FAILED(hr)) {
        std::wstringstream ss;
        ss << L"[RunAs][ERROR] Run 失败 HRESULT=0x" << std::hex << hr
           << L" (" << hr_to_wstring(hr) << L")\n";
        print_console(ss.str().c_str());
        regTask->Release(); task->Release(); folder->Release(); root->Release(); service->Release(); CoUninitialize();
        return false;
    }
    if (pRunningTask) pRunningTask->Release();

    folder->DeleteTask(_bstr_t(name.c_str()), 0);

    regTask->Release();
    task->Release();
    folder->Release();
    root->Release();
    service->Release();
    CoUninitialize();

    return true;
}

// ======================
// schtasks 兜底
// ======================
void run_via_cmd(const std::wstring& user, const std::wstring& command, bool highest) {
    std::wstring name = L"RunAsFallback";

    std::wstringstream ss;
    ss << L"schtasks /Create /F /SC ONCE /ST 00:00 "
       << L"/TN ZhangProtect\\" << name
       << L" /RU \"" << user << L"\" ";
    if (highest) ss << L"/RL HIGHEST ";
    ss << L"/TR \"cmd /c " << command << L"\"";

    _wsystem(ss.str().c_str());
    _wsystem((L"schtasks /Run /I /TN ZhangProtect\\" + name).c_str());
    _wsystem((L"schtasks /Delete /F /TN ZhangProtect\\" + name).c_str());
}

// ======================
// 入口
// ======================
int wmain(int argc, wchar_t* argv[]) {

    if (argc == 1) { print_help(); return 0; }

    for (int i = 1; i < argc; ++i)
        if (!_wcsicmp(argv[i], L"/h") || !_wcsicmp(argv[i], L"/?")) { print_help(); return 0; }

    std::wstring user, command;
    bool highest = false;
    for (int i = 1; i < argc; ++i) {
        if (!_wcsicmp(argv[i], L"/user") && i + 1 < argc) user = argv[++i];
        else if (!_wcsicmp(argv[i], L"/command") && i + 1 < argc) command = argv[++i];
        else if (!_wcsicmp(argv[i], L"/highest")) highest = true;
    }

    if (user.empty() || command.empty()) {
        print_console(L"[RunAs] 错误: 缺少 /user 或 /command 参数\n\n");
        print_help();
        return 1;
    }

    print_console(L"[RunAs] 尝试 API 执行...\n");

    if (!run_via_api(user, command, highest)) {
        print_console(L"[RunAs] API 失败，回退 schtasks...\n");
        run_via_cmd(user, command, highest);
    } else {
        print_console(L"[RunAs] 执行完成\n");
    }

    return 0;
}
