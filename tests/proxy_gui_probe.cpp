#include <windows.h>
#include <shellapi.h>
#include <string>
#include <vector>

int WINAPI wWinMain(HINSTANCE, HINSTANCE, PWSTR, int) {
    int count = 0;
    wchar_t** args = CommandLineToArgvW(GetCommandLineW(), &count);
    if (!args || count < 2) return ERROR_INVALID_PARAMETER;
    HANDLE file = CreateFileW(args[1], GENERIC_WRITE, FILE_SHARE_READ, nullptr,
                              CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) return GetLastError();
    wchar_t cwd[32768];
    GetCurrentDirectoryW(32768, cwd);
    STARTUPINFOW startup = {};
    startup.cb = sizeof(startup);
    GetStartupInfoW(&startup);
    std::wstring report = GetConsoleWindow() ? L"console\n" : L"no-console\n";
    report += std::wstring(cwd) + L"\n";
    report += std::to_wstring(startup.dwFlags & STARTF_USESHOWWINDOW ? startup.wShowWindow : -1) + L"\n";
    for (int index = 2; index < count; ++index) report += std::wstring(args[index]) + L"\n";
    int size = WideCharToMultiByte(CP_UTF8, 0, report.c_str(), int(report.size()), nullptr, 0, nullptr, nullptr);
    std::vector<char> output(size);
    WideCharToMultiByte(CP_UTF8, 0, report.c_str(), int(report.size()), output.data(), size, nullptr, nullptr);
    DWORD written = 0;
    WriteFile(file, output.data(), DWORD(output.size()), &written, nullptr);
    CloseHandle(file);
    LocalFree(args);
    Sleep(300);
    return 41;
}
