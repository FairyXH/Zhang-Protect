@echo off
cd /d "%~dp0"
set python="%cd%\Python\Python.exe"
%python% -m PyInstaller --additional-hooks-dir=pyinstaller_hooks --version-file=file_version_info.txt -n ZhangProtectControl -i icon.ico --onefile -w ControlMain.py
%python% -m PyInstaller --additional-hooks-dir=pyinstaller_hooks --version-file=file_version_info.txt -n SysDispatch -i icon.ico --onefile -w Sys_Dispatch_Main.py
%python% -m PyInstaller --additional-hooks-dir=pyinstaller_hooks --version-file=file_version_info.txt -n Traffic_Killer -i icon.ico --onefile Traffic_Killer.py
%python% -m PyInstaller --additional-hooks-dir=pyinstaller_hooks --version-file=file_version_info.txt -n Zhang_lan_scan -i icon.ico --onefile Zhang_lan_scan.py
%python% -m PyInstaller --additional-hooks-dir=pyinstaller_hooks --version-file=file_version_info.txt -n RestoreConf -i icon.ico --onefile restoreconfs.py
%python% -m PyInstaller --additional-hooks-dir=pyinstaller_hooks --version-file=file_version_info.txt -n file_server -i icon.ico --onefile file_server.py
%python% -m PyInstaller --additional-hooks-dir=pyinstaller_hooks --version-file=file_version_info.txt -n format_changer_tool -i icon.ico --onefile format_changer_tool.py
%python% -m PyInstaller --additional-hooks-dir=pyinstaller_hooks --version-file=file_version_info.txt -n Zhang_ip_helper -i icon.ico --onefile Zhang_IPhelper.py
%python% -m PyInstaller --additional-hooks-dir=pyinstaller_hooks --version-file=file_version_info.txt -n WindowDebugTool -i icon.ico --onefile WindowDebugTool.py
%python% -m PyInstaller --additional-hooks-dir=pyinstaller_hooks --version-file=file_version_info.txt -n Disable_Safety -i icon.ico --onefile remove_safe.py
%python% -m PyInstaller --additional-hooks-dir=pyinstaller_hooks --version-file=file_version_info.txt -n WifiMobileTool -i icon.ico --onefile WifiMobileTool.py
%python% -m PyInstaller --additional-hooks-dir=pyinstaller_hooks --version-file=file_version_info.txt -n Zhang_PE_Tool -i icon.ico --onefile Zhang_PE_Tool_Main.py
%python% -m PyInstaller --additional-hooks-dir=pyinstaller_hooks --version-file=file_version_info.txt -n WeiWeiFont -i icon.ico --onefile weiwei_zhang.py
%python% -m PyInstaller --additional-hooks-dir=pyinstaller_hooks --version-file=file_version_info.txt -n StorageRedirect -i icon.ico --onefile StorageRedirect.py
copy /Y dist\ZhangProtectControl.exe files\
copy /Y dist\SysDispatch.exe files\
copy /Y dist\Traffic_Killer.exe files\
copy /Y dist\Zhang_lan_scan.exe files\
copy /Y dist\RestoreConf.exe files\
copy /Y dist\file_server.exe files\
copy /Y dist\format_changer_tool.exe files\
copy /Y dist\Zhang_ip_helper.exe files\
copy /Y dist\WindowDebugTool.exe files\
copy /Y dist\Disable_Safety.exe files\
copy /Y dist\WifiMobileTool.exe files\
copy /Y dist\Zhang_PE_Tool.exe files\
copy /Y dist\WeiWeiFont.exe files\
copy /Y dist\StorageRedirect.exe files\
