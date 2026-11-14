#include <windows.h>
#include <iostream>
#include <string>
#include <vector>

void print(const wchar_t* value) {
    int length = WideCharToMultiByte(CP_UTF8, 0, value, -1, nullptr, 0, nullptr, nullptr);
    std::vector<char> output(length);
    WideCharToMultiByte(CP_UTF8, 0, value, -1, output.data(), length, nullptr, nullptr);
    std::cout << output.data() << '\n';
}

int wmain(int argc, wchar_t** argv) {
    wchar_t cwd[32768];
    GetCurrentDirectoryW(32768, cwd);
    print(cwd);
    for (int i = 1; i < argc; ++i) print(argv[i]);
    std::string input;
    std::getline(std::cin, input);
    std::cout << input << '\n';
    std::cerr << "probe-stderr\n";
    return 37;
}
