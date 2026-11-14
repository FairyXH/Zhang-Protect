#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <string.h>
#include <vector>
#include <string>
#include <fstream>
#include <iostream>
#include <queue>
#include <map>
#include <unordered_set>

#define MAX_PROCESSES 256

struct CmdOptions {
    std::vector<std::string> processNames;
    std::vector<DWORD> pids;
    enum { NONE, PCORE, ECORE, ALL } coreType = NONE;
    bool highPriority = false;
    bool recursive = false;
};

static std::map<DWORD, std::vector<DWORD>> BuildProcessTree() {
    std::map<DWORD, std::vector<DWORD>> parentToChildren;

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        std::cerr << "[!] CreateToolhelp32Snapshot failed" << std::endl;
        return parentToChildren;
    }

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(hSnapshot, &pe)) {
        do {
            parentToChildren[pe.th32ParentProcessID].push_back(pe.th32ProcessID);
        } while (Process32Next(hSnapshot, &pe));
    }

    CloseHandle(hSnapshot);

    std::cerr << "[*] BuildProcessTree: total parents = " << parentToChildren.size() << std::endl;
    return parentToChildren;
}

static std::vector<DWORD> FindChildPids(DWORD parentPid) {
    std::vector<DWORD> result;
    std::map<DWORD, std::vector<DWORD>> procTree = BuildProcessTree();

    std::queue<DWORD> q;
    std::unordered_set<DWORD> visited;

    q.push(parentPid);
    visited.insert(parentPid);

    std::cerr << "[*] Start BFS from PID=" << parentPid << std::endl;

    while (!q.empty()) {
        DWORD current = q.front();
        q.pop();

        auto it = procTree.find(current);
        if (it != procTree.end()) {
            for (DWORD child : it->second) {
                if (visited.find(child) == visited.end()) {
                    std::cerr << "    [+] Found child PID=" << child 
                              << " of parent PID=" << current << std::endl;
                    result.push_back(child);
                    visited.insert(child);
                    q.push(child);
                }
            }
        }
    }

    return result;
}

static int FindProcessIdsByName(const char* processName, DWORD* pidArray, int maxCount, bool recursive) {
    int count = 0;

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        std::cerr << "[!] CreateToolhelp32Snapshot failed in FindProcessIdsByName" << std::endl;
        return 0;
    }

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(hSnapshot, &pe)) {
        do {
            if (_stricmp(pe.szExeFile, processName) == 0) {
                if (count < maxCount) {
                    pidArray[count++] = pe.th32ProcessID;
                    std::cerr << "[*] Found process: " << pe.szExeFile << " PID=" << pe.th32ProcessID << std::endl;

                    if (recursive) {
                        std::vector<DWORD> children = FindChildPids(pe.th32ProcessID);
                        for (DWORD child : children) {
                            if (count < maxCount) {
                                pidArray[count++] = child;
                            }
                        }
                    }
                }
            }
        } while (Process32Next(hSnapshot, &pe));
    }

    CloseHandle(hSnapshot);
    return count;
}

DWORD_PTR GetPerformanceCoreAffinity() {
    DWORD_PTR mask = 0;
    DWORD len = 0;
    GetLogicalProcessorInformationEx(RelationProcessorCore, NULL, &len);
    if (len == 0) {
        SYSTEM_INFO si; GetSystemInfo(&si);
        for (DWORD i = 0; i < si.dwNumberOfProcessors; i++) mask |= (1ULL << i);
        return mask;
    }

    SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX* info = (SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX*)malloc(len);
    if (!info) return 0;

    if (!GetLogicalProcessorInformationEx(RelationProcessorCore, info, &len)) {
        SYSTEM_INFO si; GetSystemInfo(&si);
        for (DWORD i = 0; i < si.dwNumberOfProcessors; i++) mask |= (1ULL << i);
        free(info); return mask;
    }

    char* ptr = (char*)info;
    char* end = ptr + len;
    while (ptr < end) {
        SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX* coreInfo = (SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX*)ptr;
        DWORD logicalCount = 0;
        for (DWORD i = 0; i < sizeof(DWORD_PTR)*8; i++) {
            if (coreInfo->Processor.GroupMask[0].Mask & ((DWORD_PTR)1 << i)) logicalCount++;
        }
        if (logicalCount > 1) mask |= coreInfo->Processor.GroupMask[0].Mask; // P-core
        ptr += coreInfo->Size;
    }

    free(info);
    if (mask == 0) {
        SYSTEM_INFO si; GetSystemInfo(&si);
        for (DWORD i = 0; i < si.dwNumberOfProcessors; i++) mask |= (1ULL << i);
    }
    return mask;
}

DWORD_PTR GetEfficiencyCoreAffinity() {
    DWORD_PTR mask = 0;
    DWORD len = 0;
    GetLogicalProcessorInformationEx(RelationProcessorCore, NULL, &len);
    if (len == 0) {
        SYSTEM_INFO si; GetSystemInfo(&si);
        for (DWORD i = 0; i < si.dwNumberOfProcessors; i++) mask |= (1ULL << i);
        return mask;
    }

    SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX* info = (SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX*)malloc(len);
    if (!info) return 0;

    if (!GetLogicalProcessorInformationEx(RelationProcessorCore, info, &len)) {
        SYSTEM_INFO si; GetSystemInfo(&si);
        for (DWORD i = 0; i < si.dwNumberOfProcessors; i++) mask |= (1ULL << i);
        free(info); return mask;
    }

    char* ptr = (char*)info;
    char* end = ptr + len;
    while (ptr < end) {
        SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX* coreInfo = (SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX*)ptr;
        DWORD logicalCount = 0;
        for (DWORD i = 0; i < sizeof(DWORD_PTR)*8; i++) {
            if (coreInfo->Processor.GroupMask[0].Mask & ((DWORD_PTR)1 << i)) logicalCount++;
        }
        if (logicalCount == 1) mask |= coreInfo->Processor.GroupMask[0].Mask; // E-core
        ptr += coreInfo->Size;
    }

    free(info);
    if (mask == 0) {
        SYSTEM_INFO si; GetSystemInfo(&si);
        for (DWORD i = 0; i < si.dwNumberOfProcessors; i++) mask |= (1ULL << i);
    }
    return mask;
}

bool SetAffinityAndPriority(DWORD pid, DWORD_PTR mask, bool highPriority) {
    HANDLE hProcess = OpenProcess(PROCESS_SET_INFORMATION | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProcess) { printf("OpenProcess 失败, PID=%lu\n", pid); return false; }

    if (!SetProcessAffinityMask(hProcess, mask)){ printf("SetProcessAffinityMask 失败, PID=%lu\n", pid);CloseHandle(hProcess); return false;}
    else{printf("PID=%lu: 已绑定核心\n", pid);}

    if (highPriority) {
        if (!SetPriorityClass(hProcess, HIGH_PRIORITY_CLASS)) {printf("SetPriorityClass 失败, PID=%lu\n", pid);CloseHandle(hProcess); return false;}
        else printf("PID=%lu: 已设置高优先级\n", pid);
    }
    CloseHandle(hProcess);
    return true;
}

void PrintHelp(const char* exeName) {
    printf("本工具用于快速设置指定进程的CPU亲和性。可用于游戏绑定大核心等场景。\n\n");
    printf("用法: %s [选项]\n", exeName);
    printf("选项:\n");
    printf("  -h, --help, /?, /h        显示帮助\n");
    printf("  -n \"进程名\"              指定进程名\n");
    printf("  -r                        处理子进程\n");
    printf("  -x pid                    指定pid\n");
    printf("  -p                        使用大核心(P-core)\n");
    printf("  -e                        使用小核心(E-core)\n");
    printf("  -a                        使用全部核心\n");
    printf("  -g                        设置高优先级\n");
    printf("  -t \"txt文件路径\"          从txt文件读取进程名(支持批量,每行一个, #开头注释)\n");
}

bool ReadProcessNamesFromFile(const char* filePath, std::vector<std::string>& names) {
    std::ifstream file(filePath, std::ios::binary);
    if (!file.is_open()) return false;

    std::string line;
    while (std::getline(file, line)) {
        if (line.empty() || line[0] == '#') continue;
        while (!line.empty() && (line.back() == '\r' || line.back() == '\n')) line.pop_back();
        names.push_back(line);
    }

    file.close();
    return true;
}

bool ParseCmdLine(int argc, char* argv[], CmdOptions& opt) {
    for (int i = 1; i < argc; i++) {
        if (!_stricmp(argv[i], "-h") || !_stricmp(argv[i], "--help") ||
            !_stricmp(argv[i], "/?") || !_stricmp(argv[i], "/h")) {
            PrintHelp(argv[0]);
            return false;
        } else if (!_stricmp(argv[i], "-n")) {
            if (i + 1 >= argc) { printf("缺少进程名参数\n"); return false; }
            opt.processNames.push_back(argv[++i]);
        } else if (!_stricmp(argv[i], "-t")) {
            if (i + 1 >= argc) { printf("缺少txt文件路径\n"); return false; }
            if (!ReadProcessNamesFromFile(argv[++i], opt.processNames)) {
                printf("无法读取文件\n");
            }
        } else if (!_stricmp(argv[i], "-p")) {
            if (opt.coreType != CmdOptions::NONE) { printf("只能选择一个核心类型\n"); return false; }
            opt.coreType = CmdOptions::PCORE;
        } else if (!_stricmp(argv[i], "-e")) {
            if (opt.coreType != CmdOptions::NONE) { printf("只能选择一个核心类型\n"); return false; }
            opt.coreType = CmdOptions::ECORE;
        } else if (!_stricmp(argv[i], "-a")) {
            if (opt.coreType != CmdOptions::NONE) { printf("只能选择一个核心类型\n"); return false; }
            opt.coreType = CmdOptions::ALL;
        } else if (!_stricmp(argv[i], "-g")) {
            opt.highPriority = true;
        } else if (!_stricmp(argv[i], "-x")) {
            if (i + 1 >= argc) { 
                printf("缺少PID参数\n"); 
                return false; 
            }
            DWORD pid = (DWORD)atoi(argv[++i]);
            if (pid == 0) { printf("无效PID: %s\n", argv[i]); return false; }
            opt.pids.push_back(pid);
        } else if (!_stricmp(argv[i], "-r")) {
            opt.recursive = true;
        } else {
            printf("未知参数: %s\n", argv[i]);
            return false;
        }
    }

    if (opt.processNames.empty() && opt.pids.empty()) {
        printf("必须指定进程名或pid或txt文件\n");
        return false;
    }

    if (opt.coreType == CmdOptions::NONE) opt.coreType = CmdOptions::PCORE;
    return true;
}

extern "C" __declspec(dllexport)
int SetAffinityByName(const char* processName, bool recursive, bool highPriority, int coreType) {
    if (!processName) return -1;

    DWORD_PTR mask = 0;
    switch (coreType) {
        case 1: mask = GetPerformanceCoreAffinity(); break; // P-core
        case 2: mask = GetEfficiencyCoreAffinity(); break;  // E-core
        case 3: {
            SYSTEM_INFO si; GetSystemInfo(&si);
            for (DWORD i = 0; i < si.dwNumberOfProcessors; i++) mask |= (1ULL << i);
            break;
        }
        default: return -2;
    }

    DWORD pidList[MAX_PROCESSES] = {0};
    int count = FindProcessIdsByName(processName, pidList, MAX_PROCESSES, recursive);
    if (count == 0) return 0;

    int success = 0;
    for (int i = 0; i < count; i++) {
        if (SetAffinityAndPriority(pidList[i], mask, highPriority)) success++;
    }
    return success;
}

extern "C" __declspec(dllexport)
int SetAffinityByPid(DWORD pid, bool recursive, bool highPriority, int coreType) {
    if (pid == 0) return -1;

    DWORD_PTR mask = 0;
    switch (coreType) {
        case 1: mask = GetPerformanceCoreAffinity(); break; // P-core
        case 2: mask = GetEfficiencyCoreAffinity(); break;  // E-core
        case 3: {
            SYSTEM_INFO si; GetSystemInfo(&si);
            for (DWORD i = 0; i < si.dwNumberOfProcessors; i++) mask |= (1ULL << i);
            break;
        }
        default: return -2;
    }

    int success = 0;
    if (SetAffinityAndPriority(pid, mask, highPriority)) success++;

    if (recursive) {
        std::vector<DWORD> childPids = FindChildPids(pid);
        for (DWORD cpid : childPids) {
            if (SetAffinityAndPriority(cpid, mask, highPriority)) success++;
        }
    }
    return success;
}

int main(int argc, char* argv[]) {
    CmdOptions opt;
    if (!ParseCmdLine(argc, argv, opt)) return 1;

    DWORD_PTR mask = 0;
    switch (opt.coreType) {
        case CmdOptions::PCORE: mask = GetPerformanceCoreAffinity(); break;
        case CmdOptions::ECORE: mask = GetEfficiencyCoreAffinity(); break;
        case CmdOptions::ALL: {
            SYSTEM_INFO si; GetSystemInfo(&si);
            for (DWORD i = 0; i < si.dwNumberOfProcessors; i++) mask |= (1ULL << i);
            break;
        }
        default: break;
    }

    for (size_t i = 0; i < opt.pids.size(); i++) {
        SetAffinityAndPriority(opt.pids[i], mask, opt.highPriority); 

        if (opt.recursive) {
            std::vector<DWORD> childPids = FindChildPids(opt.pids[i]);
            for (DWORD pid : childPids) {
                bool childOk = SetAffinityAndPriority(pid, mask, opt.highPriority);
                if (!childOk) {
                    std::cerr << "[!] Warning: failed to set child PID=" << pid << ", ignoring." << std::endl;
                }
            }
        }
    }
    for (size_t idx = 0; idx < opt.processNames.size(); idx++) {
        const char* pname = opt.processNames[idx].c_str();
        DWORD pidList[MAX_PROCESSES] = {0};
        int count = FindProcessIdsByName(pname, pidList, MAX_PROCESSES, opt.recursive);

        if (count == 0) {
            printf("未找到进程: %s\n", pname);
            continue;
        }

        for (int i = 0; i < count; i++) {
            SetAffinityAndPriority(pidList[i], mask, opt.highPriority);

            if (opt.recursive) {
                std::vector<DWORD> childPids = FindChildPids(pidList[i]);
                for (DWORD pid : childPids) {
                    bool childOk = SetAffinityAndPriority(pid, mask, opt.highPriority);
                    if (!childOk) {
                        std::cerr << "[!] Warning: failed to set child PID=" << pid << ", ignoring." << std::endl;
                    }
                }
            }
        }
    }

    return 0;
}
