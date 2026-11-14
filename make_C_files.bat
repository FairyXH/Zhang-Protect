@echo off
cd /d "%~dp0"
REM 使用自带的MingW64
set mingw="%cd%\mingw64\bin"
%mingw%\g++ C++_Files\ZhangProxyLauncher.cpp -o files\ZhangProxyLauncher.exe -municode -static -Os -s -lshell32 -lshlwapi
if errorlevel 1 exit /b 1
%mingw%\windres -i "CppExe.rc" -o "CppExe.o"
%mingw%\g++ -mwindows ZhangProtectPot_C++\ZhangProtectStartUpTool.cpp CppExe.o -o files\ZhangProtectPot.exe -lwtsapi32 -static --verbose
%mingw%\g++ -mwindows C++_Files\fuck_keyboard.cpp CppExe.o -o files\FuckKeyBoardZ.exe -static --verbose
%mingw%\g++ C++_Files\GameKeyBoardTool.cpp CppExe.o -o files\GameKeyBoardTool.exe -static --verbose
%mingw%\g++ C++_Files\GameRedDot.cpp CppExe.o -o files\ZhangGameRedDot.exe -lgdi32 -mwindows -static --verbose
%mingw%\g++ C++_Files\KeyLauncher.cpp CppExe.o -o files\ZhangKeyLauncher.exe -static -luser32 -lkernel32 --verbose
%mingw%\g++ C++_Files\SetProToPcore.cpp CppExe.o -o files\SetProToPcore.exe -static -lpsapi --verbose
%mingw%\g++ -shared C++_Files\SetProToPcore.cpp -o files\SetProToPcore.dll -static -lpsapi -Wl,--kill-at --verbose
%mingw%\g++ C++_Files\AutoRemove_DRIVE_REMOVABLE.cpp CppExe.o -o files\AutoRemove_DRIVE_REMOVABLE.exe -static --verbose
%mingw%\g++ C++_Files\taskbar_hider.cpp CppExe.o -o files\taskbar_hider.exe -lgdi32 -luser32 -lshell32 -mwindows -static --verbose
%mingw%\g++ C++_Files\runas_user.cpp CppExe.o -municode -Wl,-subsystem,console -lole32 -loleaut32 -lTaskschd -luuid -o files\runas_user.exe --verbose
%mingw%\g++ C++_Files\Auto_Lid_Sleep.cpp CppExe.o -o files\Auto_Lid_Sleep.exe -luser32 -lpowrprof -mwindows --verbose
%mingw%\g++ C++_Files\keyboard_filter.cpp CppExe.o -o files\keyboard_filter.exe -mwindows --verbose
%mingw%\g++ C++_Files\TurboSwitch.cpp CppExe.o -o files\TurboSwitch.exe -mwindows --verbose -static -lPowrProf -lshell32 -ladvapi32
%mingw%\g++ C++_Files\BluetoothHFPGuard.cpp CppExe.o -o files\BluetoothHFPGuard.exe -static -lsetupapi -lcfgmgr32 --verbose
%mingw%\g++ C++_Files\AutoDisplayConfig.cpp CppExe.o -o files\AutoDisplayConfig.exe -static -luser32 -lShcore --verbose
