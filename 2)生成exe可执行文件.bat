@echo off
cd /d "%~dp0"
echo > ZhangProtectLock
echo > develop
for /f "delims=" %%i in ('where pyinstaller') do (copy /Y upx.exe %%~dpiupx.exe)
del /f /q "*.spec"
rd /s /q "build"
rd /s /q "dist"
attrib +h ".idea"
echo ������Ŀ...
title ������Ŀ...
if exist debug (echo ����ģʽ�������°汾��) else (python vercode.py)
python outicon.py
python icons.py
python mkicon.py
cls
echo ��һ�Σ����ڸ�ʽ������...
title ��һ�Σ����ڸ�ʽ������...
python -m black *.py
cls
echo �������̨����...
title �������̨����...
pyinstaller --clean --version-file=file_version_info.txt -n ZhangProtectControl -i icon.ico --onefile -w ControlMain.py
copy /Y dist\ZhangProtectControl.exe files\
timeout /t 5
cls
echo �������������...
title �������������...
pyinstaller --clean --version-file=file_version_info.txt -n SysDispatch -i icon.ico --onefile -w Sys_Dispatch_Main.py
copy /Y dist\SysDispatch.exe files\
timeout /t 5
cls
echo ���IPɨ�����...
title ���IPɨ�����...
pyinstaller --clean --version-file=file_version_info.txt -n Zhang_lan_scan -i icon.ico --onefile Zhang_lan_scan.py
copy /Y dist\Zhang_lan_scan.exe files\
timeout /t 5
cls
echo ����ļ�...
title ����ļ�...
python makefile.py
echo y | python -m pip uninstall pathlib
cls
echo �ڶ��Σ����ڸ�ʽ������...
title �ڶ��Σ����ڸ�ʽ������...
python -m black *.py
cls
echo ���ڴ��������...
title ���ڴ��������...
pyinstaller --clean --version-file=file_version_info.txt -n ZhangProtect -i icon.ico --onefile main.py
timeout /t 5
cls
echo ��������...
title ��������...
cd /d "%~dp0"
copy /Y dist\ZhangProtect.exe .
del /f /q "*.spec"
rd /s /q "build"
rd /s /q "dist"
rd /s /q "__pycache__"
cls
echo ���
title ���
%1 start mshta vbscript:Msgbox("������",4096)(window.close)
exit