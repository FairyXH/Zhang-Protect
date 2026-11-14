#define UNICODE
#define _UNICODE

#include <windows.h>
#include <shellapi.h>
#include <powrprof.h>
#include <string>

#pragma comment(lib,"PowrProf.lib")
#pragma comment(lib,"Shell32.lib")
#pragma comment(lib,"Advapi32.lib")


#define WM_TRAY (WM_USER+1)

#define IDM_ON     1001
#define IDM_OFF    1002
#define IDM_EXIT   1003


//================================================
// GUID
//================================================


// Processor subgroup

static const GUID SUB_PROCESSOR =
{
    0x54533251,
    0x82be,
    0x4824,
    {0x96,0xc1,0x47,0xb6,0x0b,0x74,0x0d,0x00}
};


// Processor performance boost mode

static const GUID PERFBOOSTMODE =
{
    0xbe337238,
    0x0d82,
    0x4146,
    {
        0xa9,
        0x60,
        0x4f,
        0x37,
        0x49,
        0xd4,
        0x70,
        0xc7
    }
};


// Maximum processor state

static const GUID PROCTHROTTLEMAX =
{
    0xbc5038f7,
    0x23e0,
    0x4960,
    {0x96,0xda,0x33,0xab,0xaf,0x59,0x35,0xec}
};



NOTIFYICONDATAW tray{};



//================================================
// HKLM 状态
//================================================


bool ReadTurboState()
{
    HKEY key;

    DWORD value=1;
    DWORD size=sizeof(value);


    if(RegOpenKeyExW(
        HKEY_LOCAL_MACHINE,
        L"Software\\TurboSwitch",
        0,
        KEY_READ,
        &key
    )==ERROR_SUCCESS)
    {

        RegQueryValueExW(
            key,
            L"TurboEnabled",
            nullptr,
            nullptr,
            (BYTE*)&value,
            &size
        );


        RegCloseKey(key);
    }


    return value!=0;
}



void WriteTurboState(bool enable)
{
    HKEY key;


    if(RegCreateKeyExW(
        HKEY_LOCAL_MACHINE,
        L"Software\\TurboSwitch",
        0,
        nullptr,
        0,
        KEY_WRITE,
        nullptr,
        &key,
        nullptr
    )==ERROR_SUCCESS)
    {

        DWORD value=
            enable?1:0;


        RegSetValueExW(
            key,
            L"TurboEnabled",
            0,
            REG_DWORD,
            (BYTE*)&value,
            sizeof(value)
        );


        RegCloseKey(key);
    }
}



//================================================
// Flag文件
//================================================


void UpdateFlag(bool turbo)
{

    wchar_t windir[MAX_PATH];


    DWORD len =
        GetEnvironmentVariableW(
            L"WINDIR",
            windir,
            MAX_PATH
        );


    if(len==0 || len>=MAX_PATH)
        return;



    std::wstring dir =
        std::wstring(windir)
        +
        L"\\Protect";


    std::wstring file =
        dir
        +
        L"\\TurboDisabled";



    // 创建目录

    CreateDirectoryW(
        dir.c_str(),
        nullptr
    );



    if(!turbo)
    {

        HANDLE h =
        CreateFileW(
            file.c_str(),
            GENERIC_WRITE,
            0,
            nullptr,
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_HIDDEN,
            nullptr
        );


        if(h!=INVALID_HANDLE_VALUE)
        {
            CloseHandle(h);
        }

    }
    else
    {

        DeleteFileW(
            file.c_str()
        );

    }

}



//================================================
// 电源值读取
//================================================


bool ReadValue(
    const GUID& scheme,
    const GUID& subgroup,
    const GUID& setting,
    DWORD& value)
{

    DWORD size=
        sizeof(DWORD);



    DWORD ret=
    PowerReadACValue(
        nullptr,
        &scheme,
        &subgroup,
        &setting,
        nullptr,
        (UCHAR*)&value,
        &size
    );


    return ret==ERROR_SUCCESS;
}



//================================================
// 修改单个计划
//================================================


bool ApplyScheme(
    const GUID& scheme,
    bool turbo)
{

    DWORD boost=turbo?1:0;

    DWORD throttle=turbo?100:99;


    bool changed=false;



    DWORD old;



    if(!ReadValue(
        scheme,
        SUB_PROCESSOR,
        PERFBOOSTMODE,
        old)
        ||
        old!=boost)
    {

        PowerWriteACValueIndex(
            nullptr,
            &scheme,
            &SUB_PROCESSOR,
            &PERFBOOSTMODE,
            boost
        );


        PowerWriteDCValueIndex(
            nullptr,
            &scheme,
            &SUB_PROCESSOR,
            &PERFBOOSTMODE,
            boost
        );


        changed=true;
    }



    if(!ReadValue(
        scheme,
        SUB_PROCESSOR,
        PROCTHROTTLEMAX,
        old)
        ||
        old!=throttle)
    {

        PowerWriteACValueIndex(
            nullptr,
            &scheme,
            &SUB_PROCESSOR,
            &PROCTHROTTLEMAX,
            throttle
        );


        PowerWriteDCValueIndex(
            nullptr,
            &scheme,
            &SUB_PROCESSOR,
            &PROCTHROTTLEMAX,
            throttle
        );


        changed=true;
    }


    return changed;
}



//================================================
// 同步全部计划
//================================================


void SyncPowerPlan()
{

    bool turbo=
        ReadTurboState();



    UpdateFlag(turbo);



    bool changed=false;



    DWORD index=0;



    while(true)
    {

        GUID scheme;


        DWORD size=
            sizeof(GUID);



        DWORD ret=
        PowerEnumerate(
            nullptr,
            nullptr,
            nullptr,
            ACCESS_SCHEME,
            index,
            (UCHAR*)&scheme,
            &size
        );


        if(ret!=ERROR_SUCCESS)
            break;



        if(ApplyScheme(
            scheme,
            turbo))
        {
            changed=true;
        }



        index++;
    }



    if(changed)
    {

        GUID* active=nullptr;


        if(PowerGetActiveScheme(
            nullptr,
            &active)
            ==
            ERROR_SUCCESS)
        {

            PowerSetActiveScheme(
                nullptr,
                active
            );


            LocalFree(active);
        }
    }
}



//================================================
// 托盘
//================================================


void AddTray(HWND hwnd)
{

    tray.cbSize=
        sizeof(tray);

    tray.hWnd=
        hwnd;

    tray.uID=
        1;

    tray.uFlags=
        NIF_ICON|
        NIF_MESSAGE|
        NIF_TIP;

    tray.uCallbackMessage=
        WM_TRAY;


    tray.hIcon=
        LoadIcon(
            nullptr,
            IDI_APPLICATION
        );


    wcscpy_s(
        tray.szTip,
        L"TurboSwitch"
    );


    Shell_NotifyIconW(
        NIM_ADD,
        &tray
    );
}



void RemoveTray()
{
    Shell_NotifyIconW(
        NIM_DELETE,
        &tray
    );
}



//================================================
// 菜单
//================================================


void ShowMenu(HWND hwnd)
{

    POINT pt;

    GetCursorPos(&pt);



    HMENU menu=
        CreatePopupMenu();


    HMENU turbo=
        CreatePopupMenu();

	bool currentTurbo = ReadTurboState();

    AppendMenuW(
        turbo,
        MF_STRING,
        IDM_ON,
        L"开启睿频"
    );


    AppendMenuW(
        turbo,
        MF_STRING,
        IDM_OFF,
        L"关闭睿频"
    );
	
	AppendMenuW(
        menu,
        MF_GRAYED,
        IDM_OFF,
        L"基于电源计划控制睿频"
    );
	AppendMenuW(
        menu,
        MF_GRAYED,
        IDM_OFF,
        L"================"
    );

	std::wstring title =
    currentTurbo ?
    L"当前状态:启用睿频" :
    L"当前状态:禁用睿频";
	
	
	
	AppendMenuW(
        menu,
        MF_GRAYED,
        IDM_OFF,
        title.c_str()
    );
	
	AppendMenuW(
        menu,
        MF_GRAYED,
        IDM_OFF,
        L"================"
    );

    AppendMenuW(
        menu,
        MF_POPUP,
        (UINT_PTR)turbo,
        L"睿频控制"
    );


    AppendMenuW(
        menu,
        MF_SEPARATOR,
        0,
        nullptr
    );


    AppendMenuW(
        menu,
        MF_STRING,
        IDM_EXIT,
        L"退出"
    );



    SetForegroundWindow(hwnd);



    TrackPopupMenu(
        menu,
        TPM_RIGHTBUTTON,
        pt.x,
        pt.y,
        0,
        hwnd,
        nullptr
    );


    DestroyMenu(menu);
}



//================================================
// Window
//================================================


LRESULT CALLBACK WndProc(
HWND hwnd,
UINT msg,
WPARAM w,
LPARAM l)
{

switch(msg)
{

case WM_CREATE:

    SyncPowerPlan();


    AddTray(hwnd);


    SetTimer(
        hwnd,
        1,
        3000,
        nullptr
    );

break;



case WM_TIMER:

    SyncPowerPlan();

break;



case WM_TRAY:

    if(l==WM_RBUTTONUP)
        ShowMenu(hwnd);

break;



case WM_COMMAND:

    switch(LOWORD(w))
    {

    case IDM_ON:

        WriteTurboState(true);

        SyncPowerPlan();

        break;


    case IDM_OFF:

        WriteTurboState(false);

        SyncPowerPlan();

        break;


    case IDM_EXIT:

        RemoveTray();

        PostQuitMessage(0);

        break;

    }

break;



case WM_DESTROY:

    RemoveTray();

    PostQuitMessage(0);

break;

}


return DefWindowProcW(
    hwnd,
    msg,
    w,
    l
);

}



//================================================
// main
//================================================


int WINAPI WinMain(
HINSTANCE h,
HINSTANCE,
LPSTR,
int)
{


WNDCLASSW wc{};


wc.lpfnWndProc=
    WndProc;


wc.hInstance=
    h;


wc.lpszClassName=
    L"TurboSwitch";



RegisterClassW(&wc);



HWND hwnd=
CreateWindowExW(
    0,
    wc.lpszClassName,
    L"",
    0,
    0,0,0,0,
    nullptr,
    nullptr,
    h,
    nullptr
);



MSG msg{};


while(GetMessageW(
    &msg,
    nullptr,
    0,
    0))
{

TranslateMessage(&msg);

DispatchMessageW(&msg);

}


return 0;
}