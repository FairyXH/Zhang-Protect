import ctypes
import os

import smart_open
from cmd_runner import RunWrapper


from main_imports import disable_quick_edit_mode

try:
    disable_quick_edit_mode()
except:
    pass
WindowsDir = str(os.environ.get("systemroot")).casefold()
bat_f = WindowsDir + "\\WifiMobileToolBAT.bat"
ps_f = WindowsDir + "\\WifiMobileToolPS.ps1"
runtask = (
    "schtasks /create /F /tn Microsoft\\Windows\\Zhang\\WifiMobileTool /ru"
    + " "
    + chr(34)
    + "SYSTEM"
    + chr(34)
    + " "
    + "/RL HIGHEST /SC MINUTE /mo 3 /TR"
    + " "
    + '"cmd /c '
    + bat_f
    + '"'
)
bat_w = (
    "@echo off"
    + chr(10)
    + "echo Y | Powershell Set-ExecutionPolicy -ExecutionPolicy Bypass -Force  -Scope CurrentUser"
    + chr(10)
    + "echo Y | Powershell Set-ExecutionPolicy -ExecutionPolicy Bypass -Force  -Scope LocalMachine"
    + chr(10)
    + "reg add HKLM\\SOFTWARE\\Microsoft\\PowerShell\\1\\ShellIds\\Microsoft.PowerShell /t REG_SZ /v ExecutionPolicy /d Bypass /f"
    + chr(10)
    + "reg add HKCU\\SOFTWARE\\Microsoft\\PowerShell\\1\\ShellIds\\Microsoft.PowerShell /t REG_SZ /v ExecutionPolicy /d Bypass /f"
    + chr(10)
    + "reg add HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell /t REG_DWORD /v EnableScripts /d 1 /f"
    + chr(10)
    + "reg add HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell /t REG_SZ /v ExecutionPolicy /d Bypass /f"
    + chr(10)
    + "reg add HKEY_CURRENT_USER\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell /t REG_DWORD /v EnableScripts /d 1 /f"
    + chr(10)
    + "reg add HKEY_CURRENT_USER\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell /t REG_SZ /v ExecutionPolicy /d Bypass /f"
    + chr(10)
    + "reg add HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\icssvc\\Settings /t REG_DWORD /v WifiMaxPeers /d 128 /f"
    + chr(10)
    + "reg add HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\icssvc\\Settings /t REG_DWORD /v PeerlessTimeoutEnabled /d 0 /f"
    + chr(10)
    + "reg add HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\icssvc\\Settings /t REG_DWORD /v PeerlessTimeout /d 120 /f"
    + chr(10)
    + "reg add HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\icssvc\\Settings /t REG_DWORD /v PublicConnectionTimeout /d 60 /f"
    + chr(10)
    + 'powershell "%s"' % ps_f
    + chr(10)
    + "powershell -command \"Get-ScheduledTask -TaskPath '\\Microsoft\\Windows\\Zhang\\*' | ForEach-Object { try { $task=$_; $_.Settings.ExecutionTimeLimit='PT0S'; $_.Settings.DisallowStartIfOnBatteries=$false; $_.Settings.StopIfGoingOnBatteries=$false; $_.Settings.StartWhenAvailable=$true; $_.Settings.Hidden=$false; $_.Settings.RestartCount=0; Set-ScheduledTask -InputObject $_; Write-Host '成功修改: '+$_.TaskName } catch { Write-Host '修改失败: '+$_.TaskName+' ('+$_+')' } }\""
    + chr(10)
    + "rem GBK中文编码支持"
)

user_result = input(
    "本程序用于配置移动热点自动启动，仅适用于Windows 10以上的系统\n是否配置并自动应用热点SSID与密码？请输入对应数字并按下回车\n1)仅自动打开移动热点\n2)开启时自动修改指定的热点SSID和密码\n请选择:"
)
if user_result == "2":
    while True:
        wifiid = input("请输入指定热点SSID并按下回车: ")
        if len(wifiid) > 32 or len(wifiid) == 0:
            print(
                "您输入的SSID不符合规范,请重新输入。SSID长度超出规范:%s(1-32)"
                % len(wifiid)
            )
            continue
        else:
            print("设置的SSID: %s" % wifiid)
            break

    while True:
        wifipw = input("请输入指定热点密码并按下回车: ")
        if len(wifipw) < 8:
            print(
                "您输入的密码不符合规范,请重新输入。密码长度超出规范:%s(>8)"
                % len(wifipw)
            )
            continue
        else:
            print("设置的密码: %s" % wifipw)
            break

    wifibd = input("请输入指定热点频段并按下回车(0->Auto ; 1->2.4G ; 2->5G): ")
    if not wifibd in ["0", "1", "2"]:
        wifibd = "0"
    wifibd_ls = ["Auto", "2.4G", "5G"]
    print("设置的频段:%s" % wifibd_ls[int(wifibd)])

else:
    user_result = "1"
    wifiid = ""
    wifipw = ""
    wifibd = "0"
    print("您选择了:仅自动打开移动热点")

WifiShareStart = (
    "Add-Type -AssemblyName System.Runtime.WindowsRuntime"
    + chr(10)
    + "$asTaskGeneric = ([System.WindowsRuntimeSystemExtensions].GetMethods() | ? { $_.Name -eq 'AsTask' -and $_.GetParameters().Count -eq 1 -and $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation`1' })[0]"
    + chr(10)
    + "Function Await($WinRtTask, $ResultType) {"
    + chr(10)
    + "$asTask = $asTaskGeneric.MakeGenericMethod($ResultType)"
    + chr(10)
    + "$netTask = $asTask.Invoke($null, @($WinRtTask))"
    + chr(10)
    + "$netTask.Wait(-1) | Out-Null"
    + chr(10)
    + "$netTask.Result"
    + chr(10)
    + "}"
    + chr(10)
    + "Function AwaitAction($WinRtAction) {"
    + chr(10)
    + "$asTask = ([System.WindowsRuntimeSystemExtensions].GetMethods() | ? { $_.Name -eq 'AsTask' -and $_.GetParameters().Count -eq 1 -and !$_.IsGenericMethod })[0]"
    + chr(10)
    + "$netTask = $asTask.Invoke($null, @($WinRtAction))"
    + chr(10)
    + "$netTask.Wait(-1) | Out-Null"
    + chr(10)
    + "}"
    + chr(10)
    + "$connectionProfile = [Windows.Networking.Connectivity.NetworkInformation,Windows.Networking.Connectivity,ContentType=WindowsRuntime]::GetInternetConnectionProfile()"
    + chr(10)
    + "$tetheringManager = [Windows.Networking.NetworkOperators.NetworkOperatorTetheringManager,Windows.Networking.NetworkOperators,ContentType=WindowsRuntime]::CreateFromConnectionProfile($connectionProfile)"
    + chr(10)
    + "$setting=$tetheringManager.GetCurrentAccessPointConfiguration()"
    + chr(10)
    + "$ssid="
    + chr(34)
    + str(wifiid)
    + chr(34)
    + ""
    + chr(10)
    + "$password="
    + chr(34)
    + str(wifipw)
    + chr(34)
    + ""
    + chr(10)
    + "if ($tetheringManager.TetheringOperationalState -eq 1) {"
    + chr(10)
    + "$nssid=$setting.Ssid"
    + chr(10)
    + "$npassword=$setting.passphrase"
    + chr(10)
    + "if ($nssid -ceq $ssid) {"
    + chr(10)
    + ""
    + chr(34)
    + ""
    + chr(34)
    + ""
    + chr(10)
    + "}"
    + chr(10)
    + "else{"
    + chr(10)
    + (
        "Await ($tetheringManager.StopTetheringAsync()) ([Windows.Networking.NetworkOperators.NetworkOperatorTetheringOperationResult])"
        if user_result == "2"
        else '""'
    )
    + chr(10)
    + "}"
    + chr(10)
    + "if ($npassword -ceq $password) {"
    + chr(10)
    + ""
    + chr(34)
    + ""
    + chr(34)
    + ""
    + chr(10)
    + "}"
    + chr(10)
    + "else{"
    + chr(10)
    + (
        "Await ($tetheringManager.StopTetheringAsync()) ([Windows.Networking.NetworkOperators.NetworkOperatorTetheringOperationResult])"
        if user_result == "2"
        else '""'
    )
    + chr(10)
    + "}"
    + chr(10)
    + "}"
    + chr(10)
    + "else{"
    + chr(10)
    + (
        (
            "$setting.Ssid = $ssid"
            + chr(10)
            + "$setting.passphrase = $password"
            + chr(10)
            + "$setting.Band = "
            + chr(34)
            + str(wifibd)
            + chr(34)
            + ""
            + chr(10)
            + "$tetheringManager.ConfigureAccessPointAsync($setting)"
        )
        if user_result == "2"
        else '""'
    )
    + chr(10)
    + "Await ($tetheringManager.StartTetheringAsync()) ([Windows.Networking.NetworkOperators.NetworkOperatorTetheringOperationResult])"
    + chr(10)
    + "}"
)
with smart_open.smart_opens(
    ps_f,
    "w",
) as f:
    f.write(WifiShareStart)
with smart_open.smart_opens(
    bat_f,
    "w",
) as f:
    f.write(bat_w)
print("正在执行...")
RunWrapper(runtask).read()
RunWrapper(
    "powershell -command \"Get-ScheduledTask -TaskPath '\\Microsoft\\Windows\\Zhang\\*' | ForEach-Object { try { $task=$_; $_.Settings.ExecutionTimeLimit='PT0S'; $_.Settings.DisallowStartIfOnBatteries=$false; $_.Settings.StopIfGoingOnBatteries=$false; $_.Settings.StartWhenAvailable=$true; $_.Settings.Hidden=$false; $_.Settings.RestartCount=0; Set-ScheduledTask -InputObject $_; Write-Host '成功修改: '+$_.TaskName } catch { Write-Host '修改失败: '+$_.TaskName+' ('+$_+')' } }\""
).read()
RunWrapper("schtasks /Run /tn Microsoft\\Windows\\Zhang\\WifiMobileTool /I").read()
RunWrapper('cmd /c "%s"' % bat_f).read()
input("执行完毕。请按下回车键结束。")
