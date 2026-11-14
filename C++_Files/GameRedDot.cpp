#include <windows.h>
#include <stdio.h>
#include <math.h>

#define ID_EXIT 1001  // 退出菜单ID

HINSTANCE hInst;
HWND hWndGlobal;
NOTIFYICONDATA nid;  // 托盘图标数据

int GetAutoScaledRadius(int screenWidth, int screenHeight) {
    const int baseWidth = 1920;
    const int baseHeight = 1080;
    const int baseRadius = 3;
    double currentDiagonal = sqrt((double)screenWidth * screenWidth + (double)screenHeight * screenHeight);
    double baseDiagonal = sqrt((double)baseWidth * baseWidth + (double)baseHeight * baseHeight);
    int scaledRadius = (int)(baseRadius * (currentDiagonal / baseDiagonal) + 0.5);
    return (scaledRadius < 2) ? 2 : scaledRadius;
}

RECT GetCurrentMonitorArea() {
    POINT mousePos;
    GetCursorPos(&mousePos);
    
    HMONITOR hMonitor = MonitorFromPoint(mousePos, MONITOR_DEFAULTTONEAREST);
    MONITORINFOEX miex;
    miex.cbSize = sizeof(MONITORINFOEX);
    GetMonitorInfoA(hMonitor, (LPMONITORINFO)&miex);
    
    return miex.rcMonitor;
}

void CreateTrayIcon() {
    nid.cbSize = sizeof(NOTIFYICONDATA);
    nid.hWnd = hWndGlobal;
    nid.uID = 1;
    nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
    nid.uCallbackMessage = WM_USER + 1;  // 托盘消息
    
    // 使用系统默认图标
    nid.hIcon = LoadIcon(NULL, IDI_APPLICATION);
    
    // 托盘提示文本
    strcpy(nid.szTip, "Crosshair");
    
    // 添加图标到系统托盘
    Shell_NotifyIcon(NIM_ADD, &nid);
}

// 移除托盘图标
void RemoveTrayIcon() {
    Shell_NotifyIcon(NIM_DELETE, &nid);
}

// 显示右键菜单
void ShowTrayMenu() {
    POINT pt;
    GetCursorPos(&pt);  // 获取鼠标位置
    
    // 创建菜单
    HMENU hMenu = CreatePopupMenu();
    AppendMenu(hMenu, MF_STRING, ID_EXIT, "退出");  // 退出选项
    
    // 设置菜单默认项
    SetMenuDefaultItem(hMenu, ID_EXIT, FALSE);
    
    // 显示菜单
    SetForegroundWindow(hWndGlobal);
    TrackPopupMenu(hMenu, TPM_BOTTOMALIGN | TPM_LEFTBUTTON, pt.x, pt.y, 0, hWndGlobal, NULL);
    PostMessage(hWndGlobal, WM_NULL, 0, 0);
    
    // 销毁菜单
    DestroyMenu(hMenu);
}

// 重绘红点
void RedrawCrosshair() {
    if (hWndGlobal) {
        InvalidateRect(hWndGlobal, NULL, TRUE);
        UpdateWindow(hWndGlobal);
    }
}

// 处理分辨率变化或显示器切换
void OnDisplayOrMonitorChange() {
    RECT currentMonitor = GetCurrentMonitorArea();
    int width = currentMonitor.right - currentMonitor.left;
    int height = currentMonitor.bottom - currentMonitor.top;
    
    SetWindowPos(
        hWndGlobal,
        HWND_TOPMOST,
        currentMonitor.left, currentMonitor.top,
        width, height,
        SWP_NOZORDER
    );
    
    RedrawCrosshair();
}

LRESULT CALLBACK WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_PAINT: {
            PAINTSTRUCT ps;
            HDC hdc = BeginPaint(hWnd, &ps);
            
            RECT monitorArea = GetCurrentMonitorArea();
            int screenWidth = monitorArea.right - monitorArea.left;
            int screenHeight = monitorArea.bottom - monitorArea.top;
            
            int centerX = monitorArea.left + (screenWidth / 2);
            int centerY = monitorArea.top + (screenHeight / 2);
            POINT pt = { centerX, centerY };
            ScreenToClient(hWnd, &pt);
            
            int crosshairRadius = GetAutoScaledRadius(screenWidth, screenHeight);
            
            HBRUSH hBrush = CreateSolidBrush(RGB(255, 0, 0));
            HPEN hPen = CreatePen(PS_SOLID, 1, RGB(255, 0, 0));
            SelectObject(hdc, hBrush);
            SelectObject(hdc, hPen);
            
            Ellipse(hdc,
                pt.x - crosshairRadius,
                pt.y - crosshairRadius,
                pt.x + crosshairRadius,
                pt.y + crosshairRadius);
            
            DeleteObject(hBrush);
            DeleteObject(hPen);
            EndPaint(hWnd, &ps);
            break;
        }
        
        case WM_MOUSEMOVE:
            OnDisplayOrMonitorChange();
            break;
            
        case WM_DISPLAYCHANGE:
            OnDisplayOrMonitorChange();
            break;
            
        case WM_NCHITTEST:
            return HTTRANSPARENT;  // 鼠标穿透
            
        // 托盘图标消息
        case WM_USER + 1:
            if (lParam == WM_RBUTTONUP) {
                ShowTrayMenu();  // 右键显示菜单
            }
            break;
            
        // 菜单命令
        case WM_COMMAND:
            if (LOWORD(wParam) == ID_EXIT) {
                RemoveTrayIcon();  // 移除托盘图标
                DestroyWindow(hWnd);  // 销毁窗口
            }
            break;
            
        case WM_DESTROY:
            PostQuitMessage(0);
            break;
            
        default:
            return DefWindowProcA(hWnd, msg, wParam, lParam);
    }
    return 0;
}

// 注册窗口类
BOOL RegisterWindowClass() {
    WNDCLASSEXA wc = {0};
    wc.cbSize = sizeof(WNDCLASSEXA);
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInst;
    wc.lpszClassName = "CrosshairClass";
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    
    return RegisterClassExA(&wc) != 0;
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    hInst = hInstance;
    SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
    
    if (!RegisterWindowClass()) {
        return 1;
    }
    
    RECT initMonitor = GetCurrentMonitorArea();
    int initWidth = initMonitor.right - initMonitor.left;
    int initHeight = initMonitor.bottom - initMonitor.top;
    
    hWndGlobal = CreateWindowExA(
        WS_EX_LAYERED | WS_EX_TOPMOST | WS_EX_TRANSPARENT | WS_EX_TOOLWINDOW,  // 工具窗口样式（不在任务栏显示）
        "CrosshairClass",
        "Screen Crosshair",  // 英文标题
        WS_POPUP,
        initMonitor.left, initMonitor.top,
        initWidth, initHeight,
        NULL,
        NULL,
        hInstance,
        NULL
    );
    
    if (!hWndGlobal) {
        return 1;
    }
    
    // 确保窗口不在任务栏显示
    ShowWindow(hWndGlobal, nCmdShow);
    UpdateWindow(hWndGlobal);
    
    // 设置透明色
    SetLayeredWindowAttributes(hWndGlobal, RGB(255, 255, 255), 0, LWA_COLORKEY);
    
    // 创建托盘图标
    CreateTrayIcon();
    
    // 消息循环
    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    
    return (int)msg.wParam;
}
    