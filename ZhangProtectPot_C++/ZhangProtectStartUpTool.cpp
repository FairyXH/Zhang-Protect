#include <iostream>
#include <stdio.h>
#include <windows.h>
#include <tlhelp32.h>
#include <stdlib.h>
#include <winbase.h>
#include <WtsApi32.h>
#pragma comment(lib, "Wtsapi32.lib")
using namespace std;

bool isFileExists_fopen(string& name) {
    if (FILE *file = fopen(name.c_str(), "r")) {
        fclose(file);
        return true;
    } else {
        return false;
    }   
}

bool getProcess(const char *procressName)                //此函数进程名不区分大小写
{
    char pName[MAX_PATH];                                //和PROCESSENTRY32结构体中的szExeFile字符数组保持一致，便于比较
    strcpy(pName,procressName);                            //拷贝数组
    CharLowerBuff(pName,MAX_PATH);                        //将名称转换为小写
    PROCESSENTRY32 currentProcess;                        //存放快照进程信息的一个结构体
    currentProcess.dwSize = sizeof(currentProcess);        //在使用这个结构之前，先设置它的大小
    HANDLE hProcess = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);//给系统内的所有进程拍一个快照
 
    if (hProcess == INVALID_HANDLE_VALUE)
    {
        printf("CreateToolhelp32Snapshot()调用失败!\n");
        return false;
    }
 
    bool bMore=Process32First(hProcess,&currentProcess);        //获取第一个进程信息
    while(bMore)
    {
        CharLowerBuff(currentProcess.szExeFile,MAX_PATH);        //将进程名转换为小写
        if (strcmp(currentProcess.szExeFile,pName)==0)            //比较是否存在此进程
        {
            CloseHandle(hProcess);                                //清除hProcess句柄
            return true;
        }
        bMore=Process32Next(hProcess,&currentProcess);            //遍历下一个
    }
 
    CloseHandle(hProcess);    //清除hProcess句柄
    return false;
}

bool IsInteractiveSessionReady() {
    DWORD sessionId = WTSGetActiveConsoleSessionId();
    if (sessionId == 0xFFFFFFFF) return false;

    WTS_CONNECTSTATE_CLASS* pState = nullptr;
    DWORD bytesReturned = 0;
    BOOL success = WTSQuerySessionInformationA(
        nullptr, sessionId, WTSConnectState,
        (LPSTR*)&pState, &bytesReturned
    );

    bool result = false;
    if (success && pState) {
        result = (*pState == WTSActive);
        WTSFreeMemory(pState);
    }

    return result;
}

bool IsInputDesktopReady() {
    HDESK hDesk = OpenInputDesktop(0, FALSE, DESKTOP_SWITCHDESKTOP);
    if (hDesk) {
        CloseDesktop(hDesk);
        return true;
    }
    return false;
}

int main(int argc, CHAR* argv[])
{
    try{
        HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
        DWORD mode;
        GetConsoleMode(hStdin, &mode);
        mode &= ~ENABLE_QUICK_EDIT_MODE; //移除快速编辑模式
        mode &= ~ENABLE_INSERT_MODE; //移除插入模式
        mode &= ~ENABLE_MOUSE_INPUT;
        SetConsoleMode(hStdin, mode);
        SYSTEM_POWER_STATUS sysPowerStatus;
        GetSystemPowerStatus(&sysPowerStatus);
        int ACLineStatus = (int)sysPowerStatus.ACLineStatus; //返回 1:电源 0:电池 255:未知
        int BatteryFlags = (int)sysPowerStatus.BatteryFlag; //返回 128:没有电池
        char *SysDir;
        SysDir=getenv("systemroot"); //第一个字符串"C:\\Windows"
        char ProtectExe[1000];
        char *temp=ProtectExe;
        strcpy(temp,SysDir);
        temp += strlen(SysDir);
        strcpy(temp,"\\Protect\\Protect.exe"); 

        char LockWorkStation_OnStartUp[1000];
        char *L0_temp=LockWorkStation_OnStartUp;
        strcpy(L0_temp,SysDir);
        L0_temp+=strlen(SysDir);
        strcpy(L0_temp,"\\Protect\\LockWorkStation_OnStartUp");  //自启后锁定工作站的开关文件

        char fuck_8021x[1000];
        char *L1_temp=fuck_8021x;
        strcpy(L1_temp,SysDir);
        L1_temp+=strlen(SysDir);
        strcpy(L1_temp,"\\Protect\\fuck_8021x");  //自启后锁定工作站的开关文件
        
        string LockWorkStation_Flag;
        LockWorkStation_Flag=LockWorkStation_OnStartUp;
        string fuck_8021x_Flag;
        fuck_8021x_Flag=fuck_8021x;
        if(isFileExists_fopen(fuck_8021x_Flag)){
            //有网络自动结束认证客户端
            WinExec("cmd /c \"ping -n 1 www.baidu.com && taskkill /f /im 8021x.exe /t && taskkill /f /im suservice.exe /t\"",SW_HIDE);
        }

        //关闭腾讯游戏安全自启动
        WinExec("cmd /c \"taskkill /f /im ACE-Tray.exe /t\"",SW_HIDE);
        
        //关闭命令行快速编辑模式
        WinExec("cmd /c \"reg add HKEY_CURRENT_USER\\Console /v QuickEdit /t REG_DWORD /d 00000000 /f\"",SW_HIDE);

        if(isFileExists_fopen(LockWorkStation_Flag)){
            printf("已开启自启动后锁屏,执行锁屏\n");
            const int maxWaitSeconds = 6000;
            int waitedSeconds = 0;
            while (!(IsInteractiveSessionReady() && IsInputDesktopReady())) {
                printf("等待会话准备完毕后锁屏。\n");
                if (waitedSeconds >= maxWaitSeconds) {
                    printf("Timeout reached. Exit without locking.\n");
                    break;
                }
                Sleep(10);  // 每十毫秒检查一次
                waitedSeconds++;
            }
            LockWorkStation();
        } else {
            printf("未开启自启动锁屏,不锁屏\n");
        }

        printf("电源状态：%d\n",ACLineStatus);
        printf("电池状态：%d\n",BatteryFlags);
        printf("获取到系统目录：%s\n",SysDir);
        printf("ZhangProtect可执行文件位置：%s\n",ProtectExe);
        if (ACLineStatus==1 || BatteryFlags == 128){
            printf("无电池机器或已接通交流电源,延迟10秒后执行\n");
            Sleep(10000);
        } else {
            printf("使用电池的机器,立即执行\n");
        }
        char Script_Head[100]="schtasks /create /F /tn ZhangProtect\\Protect /ru SYSTEM /RL HIGHEST /SC ONLOGON /TR ";
        char TasksChd_Script[1000];
        char *Script_Temp=TasksChd_Script;
        strcpy(Script_Temp,Script_Head);
        Script_Temp += strlen(Script_Head);
        strcpy(Script_Temp,ProtectExe); 
        while (! getProcess("protect.exe"))
        {
            printf("进程不存在,执行启动\n");
            WinExec(TasksChd_Script,SW_HIDE);
            WinExec("schtasks /change /tn ZhangProtect\\Protect /enable",SW_HIDE);
            WinExec("schtasks /run /tn ZhangProtect\\Protect /I",SW_HIDE);
            Sleep(10000);
        }
        return 0;
    } catch(...){
        return 0;
    }
}

