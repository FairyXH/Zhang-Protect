@echo off
cd /d "%~dp0"
echo > ZhangProtectLock
echo > develop
for /f "delims=" %%i in ('where pyinstaller') do (copy /Y upx.exe %%~dpiupx.exe)
del /f /q "*.spec"
rd /s /q "build"
rd /s /q "dist"
attrib +h ".idea"
echo 测试项目...
title 测试项目...
if exist debug (echo 测试模式，不更新版本号) else (python vercode.py)
python outicon.py
python icons.py
python mkicon.py
cls
echo 第一次：正在格式化代码...
title 第一次：正在格式化代码...
python -m black *.py
cls
echo 打包控制台程序...
title 打包控制台程序...
pyinstaller --clean --version-file=file_version_info.txt -n ZhangProtectControl -i icon.ico --onefile -w ControlMain.py
copy /Y dist\ZhangProtectControl.exe files\
timeout /t 5
cls
echo 打包调度器程序...
title 打包调度器程序...
pyinstaller --clean --version-file=file_version_info.txt -n SysDispatch -i icon.ico --onefile -w Sys_Dispatch_Main.py
copy /Y dist\SysDispatch.exe files\
timeout /t 5
cls
echo 打包IP扫描程序...
title 打包IP扫描程序...
pyinstaller --clean --version-file=file_version_info.txt -n Zhang_lan_scan -i icon.ico --onefile Zhang_lan_scan.py
copy /Y dist\Zhang_lan_scan.exe files\
timeout /t 5
cls
echo 检查文件...
title 检查文件...
python makefile.py
echo y | python -m pip uninstall pathlib
cls
echo 第二次：正在格式化代码...
title 第二次：正在格式化代码...
python -m black *.py
cls
echo 正在打包主程序...
title 正在打包主程序...
pyinstaller --clean --version-file=file_version_info.txt -n ZhangProtect -i icon.ico --onefile main.py
timeout /t 5
cls
echo 正在清理...
title 正在清理...
cd /d "%~dp0"
copy /Y dist\ZhangProtect.exe .
del /f /q "*.spec"
rd /s /q "build"
rd /s /q "dist"
rd /s /q "__pycache__"
cls
echo 完成
title 完成
%1 start mshta vbscript:Msgbox("打包完成",4096)(window.close)
exit