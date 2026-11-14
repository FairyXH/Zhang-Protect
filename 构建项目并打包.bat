@echo off
cd /d "%~dp0"
set "_proj=%~dp0"
echo 使用本批处理,请确保项目原有目录结构与文件名不变,方可一键整合
echo 恢复Test.py
echo from main_imports import * >Test.py
echo import config >>Test.py
echo config.is_testflag = True >>Test.py
timeout /t 1
taskkill /f /im mshta.exe /t
cls
echo 检查依赖...
title 检查依赖...
cmd /c "install_pip_modules.bat" 0 ::
timeout /t 1
cls
echo 测试主程序...
title 测试主程序...
start python main.py -h
timeout /t 5
taskkill /f /im python.exe /t
cls
echo 格式化全部Python文件...
title 格式化全部Python文件...
cmd /c "formatall.bat" ::
timeout /t 1
cls
echo 正在打包...
title 正在打包...
if exist "_build_validation\prebuild-fail.html" del /f /q "_build_validation\prebuild-fail.html"
cmd /c "make.bat" ::
if errorlevel 1 goto build_failed
rd /s /q ".idea"
timeout /t 1
taskkill /f /im mshta.exe /t
cls
echo 正在整理文件...
title 正在整理文件...
taskkill /f /im ZhangProtect.exe /t
copy /Y "Release\ZhangProtect.exe" "..\..\..\..\ZhangProtect.exe"
move /Y "Release\ZhangProtect.exe" "..\..\..\可执行文件\Python打包好\ZhangProtect.exe"
cls
cd "..\..\..\..\"
echo 测试exe可执行文件...
title 测试exe可执行文件...
start ZhangProtect.exe -h
timeout /t 15
taskkill /f /im ZhangProtect.exe /t
set changetime=0
if exist %systemroot%\Protect\change_all_filetime_flag (
del /f /q %systemroot%\Protect\change_all_filetime_flag
set changetime=1
)
powershell "Get-Childitem -path '%cd%\Zhang多功能整合程序\' -Recurse | foreach-object { $_.LastWriteTime ='01/01/3000 00:00:00' ; $_.CreationTime = '01/01/3000 00:00:00'; $_.LastWriteTime = '01/01/3000 00:00:00'  } 2>$null"
cls
echo 正在压缩为整合包...
title 正在压缩为整合包...
del /f /q Zhang多功能整合程序.7z
"%cd%\Zhang多功能整合程序\源代码\Python版本\Zhang多功能整合程序\files\7z.exe" a -t7z -r -mx9 -x@"%cd%\Zhang多功能整合程序\源代码\Python版本\Zhang多功能整合程序\exclude.txt" -p123456 Zhang多功能整合程序.7z Zhang多功能整合程序*
if %changetime% equ 1 (echo 0 > %systemroot%\Protect\change_all_filetime_flag)
echo 清理构建临时文件...
title 清理构建临时文件...
"%_proj%Python\Python.exe" "%_proj%构建后清理.py"
cls
explorer %cd%
start mshta vbscript:Msgbox("项目整合完成",4096)(window.close)

goto :eof

:build_failed
set "_failcode=%errorlevel%"
cls
echo.
echo ============================================================
echo   构建已阻止：文件校验或打包过程失败（退出码 %_failcode%）
echo   未复制、未移动任何可执行文件，也未生成整合包。
echo ============================================================
echo.
if exist "_build_validation\prebuild-fail.html" goto show_fail_page
start "" /wait mshta vbscript:Msgbox("构建失败（退出码 %_failcode%），未生成可执行文件。请查看构建窗口的报错信息。",4112+64)(window.close)
goto fail_page_done
:show_fail_page
start "" /wait mshta "%~dp0_build_validation\prebuild-fail.html"
:fail_page_done
echo.
echo 清理本次构建的中间文件...
"%_proj%Python\Python.exe" "%_proj%构建后清理.py" --build-only --quiet
del /f /q "%_proj%_build_validation\prebuild-fail.html" 2>nul
echo.
echo 按任意键退出...
pause >nul
exit /b %_failcode%
