@echo off
setlocal enabledelayedexpansion
cd /d "%~dp0"
set python="%cd%\Python\Python.exe"
set MIRROR=https://pypi.mirrors.ustc.edu.cn/simple/
set PACKAGES=altgraph astroid black brotli certifi chardet charset-normalizer click colorama dill idna inflate64 isort librt mccabe multivolumefile mypy mypy_extensions packaging pathspec pefile platformdirs psutil py7zr pybcj pycryptodomex PyInstaller PyInstaller-hooks-contrib pylint pypiwin32 pyppmd pytokens pywin32 pywin32-ctypes pyzstd requests ruff scapy setuptools texttable tomlkit typing_extensions urllib3 WMI afdko docutils fonttools importlib_resources numpy pyfakefs pygments pyperf
set "cho="

if "%~1"=="0" (
    set "cho=0"
) else if "%~1"=="1" (
    set "cho=1"
) else (
    set /p "cho=是否先卸载旧包？输入 1 卸载，留白或其它不卸载："
)

if "%cho%"=="1" (
    title 卸载旧包...
    echo 正在卸载旧包...
    for %%p in (%PACKAGES%) do (
        echo 卸载 %%p ...
        echo y | %python% -m pip uninstall %%p >nul 2>&1
    )
    echo y | %python% -m pip uninstall pathlib >nul 2>&1
)

title 正在扫描依赖模块...
echo 正在扫描依赖模块...
%python% check_imports.py
title 正在安装依赖模块...
echo 正在安装依赖模块...
if exist requirements.txt (
    %python% -m pip install -r requirements.txt -c "%~dp0constraints.txt" -i %MIRROR%
)
%python% -m pip install pip --upgrade -i %MIRROR%
for %%p in (%PACKAGES%) do (
    echo 正在安装 %%p ...
    %python% -m pip install %%p -c "%~dp0constraints.txt" -i %MIRROR%
)
title 正在更新依赖模块...
echo 正在更新依赖模块...
%python% -m pip install pip --upgrade -i %MIRROR%
for %%p in (%PACKAGES%) do (
    echo 正在升级 %%p ...
    %python% -m pip install %%p --upgrade -c "%~dp0constraints.txt" -i %MIRROR%
)
start mshta vbscript:Msgbox("依赖模块更新完毕",4096)(window.close)
exit
