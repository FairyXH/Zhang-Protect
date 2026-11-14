#include <windows.h>
#include <iostream>

bool EjectDrive(char letter) {
    char path[8];
    sprintf_s(path, "\\\\.\\%c:", letter);

    HANDLE hDevice = CreateFileA(
        path,
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        0,
        NULL
    );

    if (hDevice == INVALID_HANDLE_VALUE) {
        return false;
    }

    DWORD bytesReturned;
    BOOL result = DeviceIoControl(
        hDevice,
        IOCTL_STORAGE_EJECT_MEDIA,
        NULL, 0,
        NULL, 0,
        &bytesReturned,
        NULL
    );

    CloseHandle(hDevice);
    return result == TRUE;
}

int main() {
    for (char d = 'A'; d <= 'Z'; d++) {
        if (GetDriveTypeA((std::string(1, d) + ":\\").c_str()) == DRIVE_REMOVABLE) {
            if (EjectDrive(d)) {
                std::cout << "成功弹出 " << d << ":\\ " << std::endl;
            } else {
                std::cout << "无法弹出 " << d << ":\\ " << std::endl;
            }
        }
    }
    return 0;
}
