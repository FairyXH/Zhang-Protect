#define UNICODE
#define _UNICODE
#include <windows.h>
#include <cfgmgr32.h>
#include <setupapi.h>
#include <iostream>
#include <string>
#pragma comment(lib,"setupapi.lib")
#pragma comment(lib,"cfgmgr32.lib")
//
// 禁用服务
//
void DisableService(
    const wchar_t* service
)
{
    std::wstring stop =
        L"sc stop " + std::wstring(service);
    _wsystem(stop.c_str());
    std::wstring reg =
        L"reg add HKLM\\SYSTEM\\CurrentControlSet\\Services\\"
        + std::wstring(service)
        +
        L" /v Start /t REG_DWORD /d 4 /f";
    _wsystem(reg.c_str());
    std::wcout
        << L"[SERVICE DISABLED] "
        << service
        << std::endl;
}
//
// 恢复服务
//
void RestoreService(
    const wchar_t* service
)
{
    std::wstring reg =
        L"reg add HKLM\\SYSTEM\\CurrentControlSet\\Services\\"
        + std::wstring(service)
        +
        L" /v Start /t REG_DWORD /d 3 /f";
    _wsystem(reg.c_str());
    std::wstring start =
        L"sc start " + std::wstring(service);
    _wsystem(start.c_str());
    std::wcout
        << L"[SERVICE RESTORED] "
        << service
        << std::endl;
}
//
// 判断HFP
//
bool IsHFP(
    const std::wstring& id
)
{
    return
        id.find(L"0000111E")
        != std::wstring::npos
        ||
        id.find(L"0000111F")
        != std::wstring::npos;
}
//
// 禁用HFP设备
//
void DisableBluetoothHFPNodes()
{
    HDEVINFO hDevInfo =
        SetupDiGetClassDevsW(
            nullptr,
            L"BTHENUM",
            nullptr,
            DIGCF_ALLCLASSES
        );
    if(
        hDevInfo == INVALID_HANDLE_VALUE
    )
    {
        return;
    }
    SP_DEVINFO_DATA devInfo{};
    devInfo.cbSize =
        sizeof(SP_DEVINFO_DATA);
    for(
        DWORD index=0;
        SetupDiEnumDeviceInfo(
            hDevInfo,
            index,
            &devInfo
        );
        index++
    )
    {
        WCHAR id[1024]{};
        if(
            CM_Get_Device_IDW(
                devInfo.DevInst,
                id,
                1024,
                0
            )
            != CR_SUCCESS
        )
        {
            continue;
        }
        std::wstring deviceId=id;
        if(
            IsHFP(deviceId)
        )
        {
            std::wcout
                << L"[HFP DISABLE] "
                << deviceId
                << std::endl;
            CONFIGRET ret =
                CM_Disable_DevNode(
                    devInfo.DevInst,
                    0
                );
            if(
                ret != CR_SUCCESS
            )
            {
                std::wcout
                    << L"Disable failed: "
                    << ret
                    << std::endl;
            }
        }
    }
    SetupDiDestroyDeviceInfoList(
        hDevInfo
    );
}
//
// 恢复HFP设备
//
void RestoreBluetoothHFPNodes()
{
    HDEVINFO hDevInfo =
        SetupDiGetClassDevsW(
            nullptr,
            L"BTHENUM",
            nullptr,
            DIGCF_ALLCLASSES
        );
    if(
        hDevInfo == INVALID_HANDLE_VALUE
    )
    {
        return;
    }
    SP_DEVINFO_DATA devInfo{};
    devInfo.cbSize =
        sizeof(SP_DEVINFO_DATA);
    for(
        DWORD index=0;
        SetupDiEnumDeviceInfo(
            hDevInfo,
            index,
            &devInfo
        );
        index++
    )
    {
        WCHAR id[1024]{};
        if(
            CM_Get_Device_IDW(
                devInfo.DevInst,
                id,
                1024,
                0
            )
            != CR_SUCCESS
        )
        {
            continue;
        }
        std::wstring deviceId=id;
        if(
            IsHFP(deviceId)
        )
        {
            std::wcout
                << L"[HFP ENABLE] "
                << deviceId
                << std::endl;
            CONFIGRET ret =
                CM_Enable_DevNode(
                    devInfo.DevInst,
                    0
                );
            if(
                ret != CR_SUCCESS
            )
            {
                std::wcout
                    << L"Enable failed: "
                    << ret
                    << std::endl;
            }
        }
    }
    SetupDiDestroyDeviceInfoList(
        hDevInfo
    );
}
void DisableAll()
{
    DisableService(L"BthHFSrv");
    DisableService(L"BthHFEnum");
    DisableService(L"BthHFAud");
}
void RestoreAll()
{
    RestoreBluetoothHFPNodes();
    RestoreService(L"BthHFSrv");
    RestoreService(L"BthHFEnum");
    RestoreService(L"BthHFAud");
}
void PrintHelp()
{
    std::wcout
        << L"BluetoothHFPGuard\n\n"
        << L"Usage:\n\n"
        << L"  BluetoothHFPGuard.exe\n"
        << L"      Disable Bluetooth HFP\n\n"
        << L"  BluetoothHFPGuard.exe -restore\n"
        << L"      Restore Bluetooth HFP\n\n"
        << L"  BluetoothHFPGuard.exe /?\n"
        << L"      Show help\n"
        << std::endl;
}
int main(
    int argc,
    char* argv[]
)
{
    //
    // 参数处理
    //
    if(argc > 1)
    {
        std::string arg =
            argv[1];
        if(
            arg == "/?"
            ||
            arg == "-?"
            ||
            arg == "--help"
        )
        {
            PrintHelp();
            return 0;
        }
        if(
            arg == "-restore"
        )
        {
            std::wcout
                << L"Restoring..."
                << std::endl;
            RestoreAll();
            std::wcout
                << L"Restore complete."
                << std::endl;
            return 0;
        }
    }
    //
    // 守护模式
    //
    std::wcout
        << L"Bluetooth HFP Guard Started"
        << std::endl;
    std::wcout.flush();
    DisableAll();
    while(true)
    {
        try
        {
            DisableBluetoothHFPNodes();
        }
        catch(...)
        {
            std::wcout
                << L"[ERROR]"
                << std::endl;
        }
        Sleep(1000);
    }
    return 0;
}