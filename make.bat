@echo off
cd /d "%~dp0"
set "_fullbuild="
echo > ZhangProtectLock
echo > develop
if exist upx.exe copy /Y upx.exe "Python\Scripts\upx.exe"
del /f /q "*.spec"
del /f /q "*.log"
rd /s /q "build"
rd /s /q "dist"
rd /s /q "Release"
attrib +h .idea
attrib +h .venv
attrib +h __pycache__
set python="%cd%\Python\Python.exe"
rem 载荷必须在打包工具之前生成：工具的 PyInstaller hook 会读取 _resource_data
%python% makefile.py
if errorlevel 1 exit /b 1
cls
%1 echo 是否只打包主程序(调试)？(Y/N)
%1 choice /c YN /n /t 10 /d N >nul
%1 if errorlevel 2 goto skip_jump
%1 if errorlevel 1 goto only_main
:skip_jump
echo 测试项目...
title 测试项目...
%python% vercode.py
cls
echo 格式化代码
title 格式化代码
%python% -m black main.py 
%python% outicon.py
%python% icons.py
%python% mkicon.py
cls
echo 编译C程序
title 编译C程序
echo 编译C程序需要MinGW
cmd /c %cd%\make_C_files.bat
if errorlevel 1 exit /b 1
timeout /t 1
cls
echo 打包PythonTools
title 打包PythonTools
cmd /c %cd%\make_pythontools_files.bat
if errorlevel 1 exit /b 1
cls
set "_fullbuild=1"
:only_main
echo 检查文件
title 检查文件
%python% makefile.py
if errorlevel 1 exit /b 1
if not defined _fullbuild goto skip_precheck
cls
echo 构建前完整性检查
title 构建前完整性检查
%python% 构建前检查.py
if errorlevel 1 (
    echo.
    echo 构建前检查未通过，已停止打包。
    exit /b 1
)
:skip_precheck
echo y | %python% -m pip uninstall pathlib
cls
echo 格式化代码
title 格式化代码
%python% -m black main.py
cls
cls
echo 正在打包主程序...
title 正在打包主程序...
%python% -m PyInstaller --additional-hooks-dir=pyinstaller_hooks --version-file=file_version_info.txt -n ZhangProtect -i icon.ico --onefile main.py
if errorlevel 1 exit /b 1
timeout /t 1
cls
echo 正在清理...
title 正在清理...
cd /d "%~dp0"
mkdir Release
copy /Y dist\ZhangProtect.exe Release\ZhangProtect.exe
del /f /q "*.spec"
rd /s /q "build"
rd /s /q "dist"
rd /s /q "__pycache__"
cls
echo 清理临时文件...
title 清理临时文件
%python% 构建后清理.py --build-only --quiet
cls
echo 完成
title 完成
%1 start mshta vbscript:Msgbox("构建完成",4096)(window.close)
exit /b 0
