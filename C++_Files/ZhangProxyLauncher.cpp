#include <windows.h>
#include <shellapi.h>
#include <shlwapi.h>
#include <cstring>
#include <cwctype>
#include <string>
#include <vector>

std::wstring associated_executable(const std::wstring& extension) {
    wchar_t executable[32768];
    DWORD length = 32768;
    if (SUCCEEDED(AssocQueryStringW(ASSOCF_NONE, ASSOCSTR_EXECUTABLE,
                                   extension.c_str(), nullptr, executable, &length)))
        return executable;
    return L"";
}

int wmain() {
    std::vector<wchar_t> module(32768);
    DWORD size = GetModuleFileNameW(nullptr, module.data(), DWORD(module.size()));
    if (!size || size >= module.size()) return ERROR_FILENAME_EXCED_RANGE;
    HANDLE file = CreateFileW(module.data(), GENERIC_READ, FILE_SHARE_READ,
                              nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) return GetLastError();
    LARGE_INTEGER offset;
    offset.QuadPart = -12;
    DWORD length = 0, read = 0;
    char magic[8] = {};
    bool valid = SetFilePointerEx(file, offset, nullptr, FILE_END) &&
                 ReadFile(file, &length, 4, &read, nullptr) && read == 4 &&
                 ReadFile(file, magic, 8, &read, nullptr) && read == 8 &&
                 !memcmp(magic, "ZPXYv1\0\0", 8) && length &&
                 length <= 65534 && length % 2 == 0;
    std::vector<wchar_t> target(length <= 65534 ? length / 2 + 1 : 1, L'\0');
    if (valid) {
        offset.QuadPart = -12 - LONGLONG(length);
        valid = SetFilePointerEx(file, offset, nullptr, FILE_END) &&
                ReadFile(file, target.data(), length, &read, nullptr) && read == length;
    }
    CloseHandle(file);
    if (!valid) return ERROR_BAD_FORMAT;

    std::wstring target_path(target.data());
    // Preserve the original argument tail; reparsing argv loses quoting details.
    const wchar_t* args = GetCommandLineW();
    bool quoted = false;
    while (*args) {
        if (*args == L'"') quoted = !quoted;
        else if (!quoted && (*args == L' ' || *args == L'\t')) break;
        ++args;
    }
    while (*args == L' ' || *args == L'\t') ++args;
    std::wstring extension = target_path.substr(target_path.find_last_of(L'.'));
    for (wchar_t& character : extension) character = std::towlower(character);
    std::wstring exe = target_path;
    std::wstring parameters = args;
    wchar_t system_dir[MAX_PATH];
    if (!GetSystemDirectoryW(system_dir, MAX_PATH)) return GetLastError();
    std::wstring system(system_dir);
    bool association = false;
    if (extension == L".bat" || extension == L".cmd") {
        exe = system + L"\\cmd.exe";
        // CMD expands these once, so '%' in a target path is kept literally.
        if (!SetEnvironmentVariableW(L"ZhangProtectProxyTarget", target_path.c_str()) ||
            !SetEnvironmentVariableW(L"ZhangProtectProxyArguments", args)) return GetLastError();
        parameters = L"/d /v:off /s /c \"\"%ZhangProtectProxyTarget%\" %ZhangProtectProxyArguments%\"";
    } else if (extension == L".ps1") {
        exe = system + L"\\WindowsPowerShell\\v1.0\\powershell.exe";
        parameters = L"-NoLogo -NoProfile -File \"" + target_path + L"\" " + args;
    } else if (extension == L".vbs" || extension == L".vbe" || extension == L".js" ||
               extension == L".jse" || extension == L".wsf" || extension == L".wsh") {
        exe = associated_executable(extension);
        if (exe.empty()) exe = system + L"\\wscript.exe";
        std::wstring host = exe.substr(exe.find_last_of(L"\\/") + 1);
        for (wchar_t& character : host) character = std::towlower(character);
        if (host == L"wscript.exe" || host == L"cscript.exe")
            parameters = L"\"" + target_path + L"\" " + args;
        else {
            exe = target_path;
            association = true;
        }
    } else if (extension == L".py" || extension == L".pyw") {
        std::wstring proxy(module.data());
        std::wstring install = proxy.substr(0, proxy.find_last_of(L"\\/"));
        install = install.substr(0, install.find_last_of(L"\\/"));
        exe = install + (extension == L".pyw" ? L"\\Python\\pythonw.exe" : L"\\Python\\python.exe");
        parameters = L"\"" + target_path + L"\" " + args;
        if (GetFileAttributesW(exe.c_str()) == INVALID_FILE_ATTRIBUTES) {
            wchar_t interpreter[32768];
            DWORD found = SearchPathW(nullptr, extension == L".pyw" ? L"pyw.exe" : L"py.exe",
                                      nullptr, 32768, interpreter, nullptr);
            if (!found || found >= 32768) return ERROR_FILE_NOT_FOUND;
            exe = interpreter;
            parameters = L"-3 " + parameters;
        }
    } else if (extension == L".msc") {
        exe = system + L"\\mmc.exe";
        parameters = L"\"" + target_path + L"\" " + args;
    } else if (extension == L".cpl") {
        exe = system + L"\\rundll32.exe";
        parameters = L"shell32.dll,Control_RunDLL \"" + target_path + L"\" " + args;
    } else if (extension != L".exe" && extension != L".com") {
        association = true;
    }
    std::wstring command = L"\"" + exe + L"\" " + parameters;
    STARTUPINFOW startup = {};
    startup.cb = sizeof(startup);
    GetStartupInfoW(&startup);
    startup.dwFlags |= STARTF_USESTDHANDLES;
    startup.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    startup.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
    startup.hStdError = GetStdHandle(STD_ERROR_HANDLE);
    PROCESS_INFORMATION process = {};
    HANDLE child = nullptr;
    if (!association && CreateProcessW(exe.c_str(), &command[0], nullptr, nullptr, TRUE, 0,
                       nullptr, nullptr, &startup, &process)) {
        child = process.hProcess;
        CloseHandle(process.hThread);
    } else {
        DWORD error = GetLastError();
        if (!association && error != ERROR_ELEVATION_REQUIRED) return error;
        SHELLEXECUTEINFOW info = {};
        info.cbSize = sizeof(info);
        info.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC;
        info.lpVerb = association ? nullptr : L"runas";
        info.lpFile = exe.c_str();
        info.lpParameters = parameters.c_str();
        info.lpDirectory = nullptr;
        info.nShow = startup.dwFlags & STARTF_USESHOWWINDOW ? startup.wShowWindow : SW_SHOWNORMAL;
        if (!ShellExecuteExW(&info)) return GetLastError();
        child = info.hProcess;
    }
    if (!child) return association ? 0 : ERROR_INVALID_HANDLE;
    // Let the child handle Ctrl+C while the proxy waits for its exit status.
    SetConsoleCtrlHandler(nullptr, TRUE);
    DWORD result = ERROR_PROCESS_ABORTED;
    if (WaitForSingleObject(child, INFINITE) == WAIT_OBJECT_0)
        GetExitCodeProcess(child, &result);
    CloseHandle(child);
    return int(result);
}
