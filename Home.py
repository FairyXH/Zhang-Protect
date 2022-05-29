#该Python程序仅适用于Windows10以上的系统
#本程序主要功能大量调用系统功能
#请确保系统各个功能可用
#使用前请右键以管理员身份运行

#以管理员身份运行ctypes.windll.shell32.ShellExecuteW(None,"runas", sys.executable,"cmd", None, 1)
import os,sys,time,psutil,logging,ctypes,shutil,pathlib
import tkinter as tk
from tkinter import messagebox
#获取自身位置，后面方便复制进运行文件夹
selffullname=sys.executable
#获取一些系统变量的值
ProtectDir=str(os.environ.get( "systemroot" ))
SystemDir=str(os.environ.get( "systemdrive" ))
#定义一些变量，后面需要用到
ProtectDir = ProtectDir + "\\Protect\\"
ProtectBAT = ProtectDir + "BINRD.bat"
ProtectWifi = ProtectDir + "WifiShare.ps1"
ProtectKeeper = ProtectDir + "ProtectKeeper.bat"
Protectconf = ProtectDir + "ProtectConf.conf"
ProtectExe = ProtectDir + "Protect.exe"
UsbChanger = ProtectDir + "UsbChang.bat"
AllRunCommand = ProtectDir + "AllCommand.bat"
AllSchrunBA = ProtectDir + "AllSchrunBA.bat"
BATKEEPER = ProtectDir + "BatKeeper.vbs"
UNINST = ProtectDir + "Uninstaller.bat"
VBAllRunF=ProtectDir + "VBAllRun.vbs"
#判断管理员权限
if not selffullname ==  ProtectExe or not os.path.isfile(ProtectExe):
    def is_admin():
        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except:
            return False


#初始化并写入配置文件
if not selffullname ==  ProtectExe or not os.path.isfile(ProtectExe):
    MsgText = "正在查看控制台" + chr(10) + "是否初始化配置？或清理环境？" + chr(10) + "单击是来初始化配置" + chr(10) + "单击否来清理环境" + chr(
        10) + "单击其他按钮取消所有操作"
    UserBackTell=(messagebox.askyesnocancel("控制台",MsgText))
    if UserBackTell == True:
        if not os.path.exists(ProtectDir):
            os.popen("cmd /c takeown /f %systemroot% /a & icacls %systemroot% /c /q /grant Everyone:(OI)(CI)(F)")
            time.sleep(3)
            os.makedirs(ProtectDir)
            shutil.copyfile(selffullname,ProtectExe)
        if not os.path.isfile(ProtectExe):
            os.popen("cmd /c takeown /f %systemroot% /a & icacls %systemroot% /c /q /grant Everyone:(OI)(CI)(F)")
            os.popen("copy /Y "+selffullname+" "+ProtectExe)
        # 创建GUI对话框完成参数输入
        root = tk.Tk()
        label1 = tk.Label(root, text='输入第一个保护的进程名（该项以普通权限运行）')
        label1.grid(row=0, column=0)
        label2 = tk.Label(root, text='输入第一个保护的进程路径（该项以普通权限运行）')
        label2.grid(row=1, column=0)
        label3 = tk.Label(root, text='输入第二个保护的进程名（该项以管理员身份运行）')
        label3.grid(row=2, column=0)
        label4 = tk.Label(root, text='输入第二个保护的进程路径（该项以管理员身份运行）')
        label4.grid(row=3, column=0)
        label5 = tk.Label(root, text='输入需要定期运行的进程路径（该项以普通权限运行）')
        label5.grid(row=4, column=0)
        label6 = tk.Label(root, text='输入数据盘盘符，直接输入字母')
        label6.grid(row=5, column=0)
        label7 = tk.Label(root, text='输入Onedrive同步目录路径，后面不加反斜杠')
        label7.grid(row=6, column=0)
        label8 = tk.Label(root, text='输入关机时间（该版本下该项设置无效）')
        label8.grid(row=7, column=0)
        # 创建输入框
        entry1 = tk.Entry(root)
        entry1.grid(row=0, column=1, padx=10, pady=5)
        entry2 = tk.Entry(root)
        entry2.grid(row=1, column=1, padx=10, pady=5)
        entry3 = tk.Entry(root)
        entry3.grid(row=2, column=1, padx=10, pady=5)
        entry4 = tk.Entry(root)
        entry4.grid(row=3, column=1, padx=10, pady=5)
        entry5 = tk.Entry(root)
        entry5.grid(row=4, column=1, padx=10, pady=5)
        entry6 = tk.Entry(root)
        entry6.grid(row=5, column=1, padx=10, pady=5)
        entry7 = tk.Entry(root)
        entry7.grid(row=6, column=1, padx=10, pady=5)
        entry8 = tk.Entry(root)
        entry8.grid(row=7, column=1, padx=10, pady=5)
        #写入配置文件
        def show():
            global UserBackA,UserBackB,UserBackC,UserBackD,UserBackE,UserBackF,UserBackG,UserBackH
            UserBackA=entry1.get()
            UserBackB=entry2.get()
            UserBackC=entry3.get()
            UserBackD=entry4.get()
            UserBackE=entry5.get()
            UserBackF=entry6.get()
            UserBackG=entry7.get()
            UserBackH=entry8.get()
            #判断输入值是不是空的，是空的就给一个默认值，防止后面报错
            if not UserBackA:
                UserBackA="explorer.exe"
            if not UserBackB:
                UserBackB="echo."
            if not UserBackC:
                UserBackC="explorer.exe"
            if not UserBackD:
                UserBackD="echo."
            if not UserBackE:
                UserBackE="echo."
            if not UserBackF:
                UserBackF="X"
            if not UserBackG:
                UserBackG="C:\\ProgramData\\Onedrive"
            if not UserBackH:
                UserBackH="00:00"
            #如果配置文件已经存在就先删除，避免重复
            if os.path.isfile(Protectconf):
                os.remove(Protectconf)
            Writeini = (UserBackA + chr(10) + UserBackB + chr(10) + UserBackC + chr(10) + UserBackD + chr(10) + UserBackE + chr(10) + UserBackF + chr(10) + UserBackG + chr(10) + UserBackH + chr(10))
            time.sleep(1)
            conf = open(Protectconf, 'w')
            conf.write(Writeini)
            conf.close
            messagebox.showinfo("完成","配置保存成功")
            root.quit
        button1 = tk.Button(root, text='应用', command=show).grid(row=9, column=0,sticky=tk.W, padx=30, pady=5)
        button2 = tk.Button(root, text='编辑完成', command=root.quit).grid(row=9, column=1,sticky=tk.E, padx=30, pady=5)
        tk.mainloop()
    elif UserBackTell == False:
        os.popen("cmd /c "+UNINST)
        os.popen("cmd /c shutdown -r -t 30")
        os._exit(0)
    else:
        messagebox.showinfo("已终止","已取消所有操作")
        os._exit(0)

#先判断是否存在配置文件，不存在用默认值，防止后面报错
if os.path.isfile(Protectconf):
    #从配置文件里面读取，并赋值给变量
    allini = []
    iniread=open(Protectconf, "r")
    for line in iniread: # 设置文件对象并读取每一行文件
        line = line[:-1]
        allini.append(line)  # 将每一行文件加入到list中
    iniread.close
    proname,tdir0,proname1,tdir1,tdir2,datadir,Onedriveupdatedir,autoshutdowntime = allini
else:
    if not UserBackA:
        UserBackA = "explorer.exe"
    if not UserBackB:
        UserBackB = "echo."
    if not UserBackC:
        UserBackC = "explorer.exe"
    if not UserBackD:
        UserBackD = "echo."
    if not UserBackE:
        UserBackE = "echo."
    if not UserBackF:
        UserBackF = "X"
    if not UserBackG:
        UserBackG = "C:\\ProgramData\\Onedrive"
    if not UserBackH:
        UserBackH = "00:00"
#初始化变量
#这里的大部分变量都是根据配置文件定义的
ztimeoutA = 0
ztimeoutB = 0
pronamesys = "cmd.exe"
USBWrite1 = "@echo off" + chr(10) + "set HereIs=0" + chr(10) + "set Udir=" + chr(10) + ":start" + chr(10) + "Timeout /t 1" + chr(10) + "cls" + chr(10) + "@echo off" + chr(10) + "    for /f " + chr(34) + "tokens=2 delims==" + chr(34) + " %%a in (" + chr(39) + "wmic LogicalDisk where " + chr(34) + "DriveType=" + chr(39) + "2" + chr(39) + "" + chr(34) + " get DeviceID /value" + chr(39) + ") do (" + chr(10) + "      set DriveU=%%a" + chr(10) + " )" + chr(10) + "set Udir=%DriveU%" + chr(10) + "if exist %Udir% (echo.) else (Set HereIs=0 & Set Udir=)" + chr(10) + "if %HereIs%==0 (if exist %Udir% (goto Work) else goto start) else goto start" + chr(10) + "goto start" + chr(10) + ":Work" + chr(10) + "Set HereIs=1" + chr(10) + "icacls %Udir%\\* /t /c /q /inheritance:e"
USBWrite2 = "takeown /f %Udir%\\* /a /r /d y" + chr(10) + "icacls %Udir%\\* /t /c /grant:r Everyone:(OI)(CI)(F)" + chr(10) + "del /f /q %Udir%\\autorun.inf" + chr(10) + "rd /s /q %Udir%\\autorun.inf" + chr(10) + "mkdir %Udir%\\autorun.inf\\protect..\\" + chr(10) + "attrib %Udir%\\autorun.inf +s +h +r" + chr(10) + "goto start"
USBWrite = USBWrite1 + chr(10) + USBWrite2
Uninstaller = "@echo off" + chr(10) + "schtasks /delete /F /tn AppProtectA" + chr(10) + "schtasks /delete /F /tn AppProtectB" + chr(10) + "schtasks /delete /F /tn AppProtectC" + chr(10) + "schtasks /delete /F /tn AutoPreA" + chr(10) + "schtasks /delete /F /tn AutoPreB" + chr(10) + "schtasks /delete /F /tn AutoPreC" + chr(10) + "schtasks /delete /F /tn AutoPreD" + chr(10) + "schtasks /delete /F /tn AutoShutdown" + chr(10) + "schtasks /delete /F /tn KeepWifi" + chr(10) + "schtasks /delete /F /tn Protect" + chr(10) + "schtasks /delete /F /tn ProtectKeeperBat" + chr(10) + "schtasks /delete /F /tn KeeperRun" + chr(10) + "schtasks /delete /F /tn UsbChanger" + chr(10) + "taskkill /f /im Protect.exe /t" + chr(10) + "rd /s /q %systemroot%\\Protect" + chr(10) + "shutdown -r -t 30" + chr(10) + "taskkill /f /im cmd.exe /t" + chr(10) + "exit"
BatComA1 = "@echo off" + chr(10) + ":start" + chr(10) + "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Applets\\SysTray /v Services /t reg_dword /d 29 /f" + chr(10) + "mklink /d %appdata%\\Roaming\\KuGou8 D:\\StorageRedirect\\KuGou" + chr(10) + "systray" + chr(10) + "rd /s /q %systemdrive%\\$RECYCLE.BIN >>nul" + chr(10) + "rd /s /q" + " " + datadir + ":\\$RECYCLE.BIN >>nul" + chr(10) + "reg delete HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\BitBucket /f" + chr(10) + "reg delete HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\BitBucket /f" + chr(10) + "reg add HKCU\\Softwares\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer /t REG_DWORD /v NoRecycleFiles /d 1 /f" + chr(10) + "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Applets\\SysTray /v Services /t reg_dword /d 29 /f" + chr(10) + "reg add HKLM\\SOFTWARE\\Microsoft\\PowerShell\\1\\ShellIds\\Microsoft.PowerShell /t REG_SZ /v ExecutionPolicy /d RemoteSigned /f"
BatComA2 = "echo y|Reg add " + chr(34) + "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders" + chr(34) + " /t REG_SZ /v Desktop /d " + chr(34) + datadir + ":\\Desktop" + chr(34) + " /f " + chr(10) + "echo y|Reg add " + chr(34) + "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders" + chr(34) + " /t REG_SZ /v {374DE290-123F-4565-9164-39C4925E467B} /d " + chr(34) + datadir + ":\\Download" + chr(34) + " /f " + chr(10) + "echo y|Reg add " + chr(34) + "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders" + chr(34) + " /t REG_SZ /v Personal /d " + chr(34) + datadir + ":\\Documents" + chr(34) + " /f " + chr(10) + "echo y|Reg add " + chr(34) + "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders" + chr(34) + " /t REG_SZ /v " + chr(34) + "My Music" + chr(34) + " /d " + chr(34) + datadir + ":\\Music" + chr(34) + " /f "
BatComA3 = "echo y|Reg add " + chr(34) + "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders" + chr(34) + " /t REG_SZ /v " + chr(34) + "My Video" + chr(34) + " /d " + chr(34) + datadir + ":\\Videos" + chr(34) + " /f " + chr(10) + "echo y|Reg add " + chr(34) + "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders" + chr(34) + " /t REG_SZ /v " + chr(34) + "My Pictures" + chr(34) + " /d " + chr(34) + datadir + ":\\Pictures" + chr(34) + " /f " + chr(10) + "echo y|Reg add " + chr(34) + "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders" + chr(34) + " /t REG_EXPAND_SZ /v Desktop /d " + chr(34) + datadir + ":\\Desktop" + chr(34) + " /f " + chr(10) + "echo y|Reg add " + chr(34) + "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders" + chr(34) + " /t REG_EXPAND_SZ /v {374DE290-123F-4565-9164-39C4925E467B} /d " + chr(34) + datadir + ":\\Download" + chr(34) + " /f "
BatComA4 = "echo y|Reg add " + chr(34) + "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders" + chr(34) + " /t REG_EXPAND_SZ /v Personal /d " + chr(34) + datadir + ":\\Documents" + chr(34) + " /f " + chr(10) + "echo y|Reg add " + chr(34) + "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders" + chr(34) + " /t REG_EXPAND_SZ /v " + chr(34) + "My Music" + chr(34) + " /d " + chr(34) + datadir + ":\\Music" + chr(34) + " /f " + chr(10) + "echo y|Reg add " + chr(34) + "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders" + chr(34) + " /t REG_EXPAND_SZ /v " + chr(34) + "My Video" + chr(34) + " /d " + chr(34) + datadir + ":\\Videos" + chr(34) + " /f " + chr(10) + "echo y|Reg add " + chr(34) + "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders" + chr(34) + " /t REG_EXPAND_SZ /v " + chr(34) + "My Pictures" + chr(34) + " /d " + chr(34) + datadir + ":\\Pictures" + chr(34) + " /f "
BatComA5 = "echo y|reg add " + chr(34) + "HKLM\\system\\CurrentControlSet\\Control\\terminal server" + chr(34) + " /v AllowRemoteRPC /d 1 /f" + chr(10) + "cls"
BatComA6 = "label "+datadir+":数据盘"+chr(10)+"label %systemdrive%系统盘"+chr(10)+"timeout /t 10" + chr(10) + "Goto start"
BatComA = BatComA1 + chr(10) + BatComA2 + chr(10) + BatComA3 + chr(10) + BatComA4 + chr(10) + BatComA5 + chr(10) + BatComA6
BATRUNVBS =  "CreateObject" + chr(40) + chr(34) + "Shell.Application" + chr(34) + chr(41) + ".ShellExecute" + chr(34) + "cmd" + chr(34) + chr(44) + chr(34) + "/c %systemroot%\\Protect\\BINRD.bat" + chr(34) + chr(44) + chr(34) + chr(34) + chr(44) + "runas" + chr(44) + "0" + chr(10) + "CreateObject" + chr(40) + chr(34) + "Shell.Application" + chr(34) + chr(41) + ".ShellExecute" + chr(34) + "cmd" + chr(34) + chr(44) + chr(34) + "/c powershell %systemroot%\\Protect\\WifiShare.ps1" + chr(34) + chr(44) + chr(34) + chr(34) + chr(44) + "runas" + chr(44) + "0"
VBAllRun="CreateObject" + chr(40) + chr(34) + "Shell.Application" + chr(34) + chr(41) + ".ShellExecute" + chr(34) + "cmd" + chr(34) + chr(44) + chr(34) + "/c %systemroot%\\Protect\\AllCommand.bat" + chr(34) + chr(44) + chr(34) + chr(34) + chr(44) + "runas" + chr(44) + "0"
ProtectKeeperBAT = "qprocess|findstr /i Protect.exe" + chr(10) + "if %errorlevel% NEQ 0 schtasks /run /tn Protect" + chr(10) + "exit"
WifiShareStart = "$connectionProfile = [Windows.Networking.Connectivity.NetworkInformation,Windows.Networking.Connectivity,ContentType=WindowsRuntime]::GetInternetConnectionProfile()" + chr(10) + "$tetheringManager = [Windows.Networking.NetworkOperators.NetworkOperatorTetheringManager,Windows.Networking.NetworkOperators,ContentType=WindowsRuntime]::CreateFromConnectionProfile($connectionProfile)" + chr(10) + "while (1)" + chr(10) + "{" + chr(10) + "start-sleep -s 10" + chr(10) + "clear" + chr(10) + "if ($tetheringManager.TetheringOperationalState -eq 1) " + chr(10) + "{" + chr(10) + "}" + chr(10) + "else{" + chr(10) + "Await ($tetheringManager.StartTetheringAsync()) ([Windows.Networking.NetworkOperators.NetworkOperatorTetheringOperationResult])" + chr(10) + "}" + chr(10) + "}"
ProtectTest = "/c" + " " + "Schtasks /Run /TN Protect & shutdown -r -t 30"
Regset = "reg delete HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\BitBucket /f & reg delete HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\BitBucket /f & reg add HKCU\\Softwares\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer /t REG_DWORD /v NoRecycleFiles /d 1 /f  & reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Applets\\SysTray /v Services /t reg_dword /d 29 /f & reg add HKLM\\SOFTWARE\\Microsoft\\PowerShell\\1\\ShellIds\\Microsoft.PowerShell /t REG_SZ /v ExecutionPolicy /d RemoteSigned /f"
ProtectSchTask = "/c" + " " + "schtasks /create /F /TN Protect /ru" + " " + chr(34) + "NT SERVICE\\TrustedInstaller" + chr(34) + " " + "/RL HIGHEST /SC ONSTART /TR" + " " + ProtectExe
ProtectInstaller = "/c" + " " + "schtasks /create /F /TN ProtectInstaller /RU Users /RL HIGHEST /SC ONCE /ST 00:00 /TR" + " " + ProtectExe + " " + "& schtasks /run /I /tn ProtectInstaller & timeout /t 5 & schtasks /delete /F /tn ProtectInstaller"
BINDIR = str(os.environ.get( "systemdrive" ))
UsbChange = "schtasks /create /F /TN UsbChanger /ru" + " " + chr(34) + "NT SERVICE\\TrustedInstaller" + chr(34) + " " + "/RL HIGHEST /SC ONSTART /TR" + " " + UsbChanger
Onedriveupdate = Onedriveupdatedir + "\\update"
OnedirveprecomA = "icacls" + " " + chr(39) + Onedriveupdatedir + "\\*" + chr(39) + " " + "/t /c /q /inheritance:e"
OnedirveprecomB = "takeown /f" + " " + chr(39) + Onedriveupdatedir + "\\*" + chr(39) + " " + "/a /r /d y"
OnedirveprecomC = "icacls" + " " + chr(39) + Onedriveupdatedir + "\\*" + chr(39) + " " + "/t /c /grant:r Everyone:(OI)(CI)(F)"
datadircomA = "icacls" + " " + chr(39) + datadir + ":\\*" + chr(39) + " " + "/t /c /q /inheritance:e"
datadircomB = "takeown /f" + " " + chr(39) + datadir + ":\\*" + chr(39) + " " + "/a /r /d y"
datadircomC = "icacls" + " " + chr(39) + datadir + ":\\*" + chr(39) + " " + "/t /c /grant:r Everyone:(OI)(CI)(F)"
systemdircomA = "echo."
systemdircomB = "echo."
systemdircomC = "echo."
SchTaskcomA = chr(34) + "cmd /c" + " " + OnedirveprecomA + " " + "&" + " " + OnedirveprecomB + " " + "&" + " " + OnedirveprecomC + chr(34)
SchTaskcomB = chr(34) + "cmd /c" + " " + datadircomA + " " + "&" + " " + datadircomB + " " + "&" + " " + datadircomC + chr(34)
SchTaskcomC = chr(34) + "cmd /c" + " " + systemdircomA + " " + "&" + " " + systemdircomB + " " + "&" + " " + systemdircomC + chr(34)
autoshutdown = "echo."
autochangepreA = "schtasks /create /F /ru" + " " + chr(34) + "NT SERVICE\\TrustedInstaller" + chr(34) + " " + "/RL HIGHEST /tn AutoPreA /sc ONIDLE /I 3" + " " + "/tr" + " " + SchTaskcomA
autochangepreB = "schtasks /create /F /ru" + " " + chr(34) + "NT SERVICE\\TrustedInstaller" + chr(34) + " " + "/RL HIGHEST /tn AutoPreB /sc ONIDLE /I 3" + " " + "/tr" + " " + SchTaskcomB
autochangepreC = "schtasks /create /F /ru" + " " + chr(34) + "NT SERVICE\\TrustedInstaller" + chr(34) + " " + "/RL HIGHEST /tn AutoPreC /sc ONIDLE /I 15" + " " + "/tr" + " " + SchTaskcomC
autochangepreD = "schtasks /create /F /ru" + " " + chr(34) + "NT SERVICE\\TrustedInstaller" + chr(34) + " " + "/RL HIGHEST /tn AutoPreD /sc ONSTART" + " " + "/tr" + " " + ProtectBAT
AppProtectA = "schtasks /create /F /RU Users /RL LIMITED /TN AppProtectA /SC ONLOGON /TR" + " " + chr(34) + tdir0 + chr(34)
AppProtectB = "schtasks /create /F /RU Users /RL HIGHEST /TN AppProtectB /SC ONLOGON /TR" + " " + chr(34) + tdir1 + chr(34)
AppProtectC = "schtasks /create /F /RU Users /RL LIMITED /TN AppProtectC /SC ONLOGON /TR" + " " + chr(34) + tdir2 + chr(34)
AppRunA = "/c schtasks /run /I /tn AppProtectA"
AppRunB = "/c schtasks /run /I /tn AppProtectB"
AppRunC = "/c schtasks /run /I /tn AppProtectC"
changetaskrunA = "schtasks /run /I /tn AutoPreA"
changetaskrunB = "schtasks /run /I /tn AutoPreB"
changetaskrunC = "schtasks /run /I /tn AutoPreC"
UsbChangerRun = "schtasks /run /I /tn UsbChanger"
MyComputerClean = "reg delete HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MyComputer\\NameSpace\\{088e3905-0323-4b02-9826-5d99428e115f} /f " + chr(10) + "reg delete HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MyComputer\\NameSpace\\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A} /f " + chr(10) + "reg delete HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MyComputer\\NameSpace\\{24ad3ad4-a569-4530-98e1-ab02f9417aa8} /f" + chr(10) + "reg delete HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MyComputer\\NameSpace\\{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}  /f" + chr(10) + "reg delete HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MyComputer\\NameSpace\\{d3162b92-9365-467a-956b-92703aca08af} /f" + chr(10) + "reg delete HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MyComputer\\NameSpace\\{f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a} /f"
WifiKeepersch = "schtasks /create /F /ru" + " " + chr(34) + "NT SERVICE\\TrustedInstaller" + chr(34) + " " + "/RL HIGHEST /tn KeepWifi /sc ONLOGON /tr" + " " + chr(34) + "cmd /c powershell %systemroot%\\Protect\\WifiShare.ps1" + chr(34)
ProtectKeepersch = "schtasks /create /F /ru" + " " + chr(34) + "NT SERVICE\\TrustedInstaller" + chr(34) + " " + "/RL HIGHEST /tn ProtectKeeper /sc MINUTE /MO 1 /tr" + " " + chr(34) + "%systemroot%\\Protect\\ProtectKeeper.bat" + chr(34)
BatKeeperRunsch = "schtasks /create /F /ru Users /RL HIGHEST /tn BatKeeperRun /sc ONLOGON /tr" + " " + chr(34) + "%systemroot%\\Protect\\BatKeeper.vbs" + chr(34)
AutoPreDrun = "schtasks /run /I /tn AutoPreD" + chr(10) + "schtasks /run /I /tn KeepWifi" + chr(10) + "schtasks /run /I /tn BatKeeperRun"
MaketheLink = "echo."
StorageRedirect1 = "set datadir=" + datadir + chr(10) + "taskkill /f /im Kugou.exe /t" + chr(10) + "taskkill /f /im couldmusic.exe /t" + chr(10) + "taskkill /f /im QQMusic.exe /t" + chr(10) + "Taskkill /f /im msedge.exe /t" + chr(10) + "md %datadir%:\\StorageRedirect" + chr(10) + "move /Y %userprofile%\\Appdata\\Local\\Netease  %datadir%:\\StorageRedirect\\" + chr(10) + "rd /q /s %userprofile%\\Appdata\\Local\\Netease" + chr(10) + "md %datadir%:\\StorageRedirect\\Netease" + chr(10) + "mklink /D %userprofile%\\Appdata\\Local\\Netease %datadir%:\\StorageRedirect\\Netease"
StorageRedirect2 = "move /Y %userprofile%\\Appdata\\Roaming\\KuGou8 %datadir%:\\StorageRedirect\\" + chr(10) + "rd /q /s %userprofile%\\Appdata\\Roaming\\KuGou8" + chr(10) + "md %datadir%:\\StorageRedirect\\KuGou8" + chr(10) + "mklink /D %userprofile%\\Appdata\\Roaming\\KuGou8 %datadir%:\\StorageRedirect\\KuGou8" + chr(10) + "move /Y  %userprofile%\\Appdata\\Roaming\\Tencent\\QQMusic %datadir%:\\StorageRedirect\\" + chr(10) + "rd /q /s %userprofile%\\Appdata\\Roaming\\Tencent\\QQMusicmd %datadir%:\\StorageRedirect\\QQMusic"
StorageRedirect3 = "mklink /D %userprofile%\\Appdata\\Roaming\\Tencent\\QQMusic %datadir%:\\StorageRedirect\\QQMusic" + chr(10) + "move /Y %userprofile%\\Appdata\\Local\\Microsoft\\Edge  %datadir%:\\StorageRedirect\\" + chr(10) + "rd /q /s %userprofile%\\Appdata\\Local\\Microsoft\\Edge" + chr(10) + "md %datadir%:\\StorageRedirect\\Edge" + chr(10) + "mklink /D %userprofile%\\Appdata\\Local\\Microsoft\\Edge %datadir%:\\StorageRedirect\\Edge"
StorageRedirect = StorageRedirect1 + chr(10) + StorageRedirect2 + chr(10) + StorageRedirect3
AllCommands = BatKeeperRunsch + chr(10) + ProtectKeepersch + chr(10) + WifiKeepersch + chr(10) + UsbChange + chr(10) + AppProtectA + chr(10) + AppProtectB + chr(10) + AppProtectC + chr(10) + autoshutdown + chr(10) + autochangepreA + chr(10) + autochangepreB + chr(10) + autochangepreC + chr(10) + autochangepreD + chr(10) + MaketheLink + chr(10) + MyComputerClean + chr(10) + StorageRedirect
AllSchrun = changetaskrunA + chr(10) + changetaskrunB + chr(10) + changetaskrunC + chr(10) + AutoPreDrun + chr(10) + UsbChangerRun
if not selffullname ==  ProtectExe or not os.path.isfile(ProtectExe):
    if not os.path.exists:
        os.mkdir(ProtectDir)
    print(AllCommands)
    ComSMakeA = open(AllRunCommand,'w')
    ComSMakeA.write(AllCommands)
    ComSMakeA.close()
    ComSMakeB = open(AllSchrunBA,'w')
    ComSMakeB.write(AllSchrun)
    ComSMakeB.close()
    ComSMakeC = open(ProtectBAT,'w')
    ComSMakeC.write(BatComA)
    ComSMakeC.close()
    ComSMakeD = open(ProtectWifi,'w')
    ComSMakeD.write(WifiShareStart)
    ComSMakeD.close()
    ComSMakeE = open(ProtectKeeper,'w')
    ComSMakeE.write(ProtectKeeperBAT)
    ComSMakeE.close()
    ComSMakeF = open(BATKEEPER,'w')
    ComSMakeF.write(BATRUNVBS)
    ComSMakeF.close()
    ComSMakeG = open(UNINST,'w')
    ComSMakeG.write(Uninstaller)
    ComSMakeG.close()
    ComSMakeH = open(UsbChanger,'w')
    ComSMakeH.write(USBWrite)
    ComSMakeH.close()
    ComSMakeI = open(VBAllRunF, 'w')
    ComSMakeI.write(VBAllRun)
    ComSMakeI.close()
    #配置脚本写入完成，配置系统设置
    os.popen("cmd "+ProtectSchTask)
    os.popen("wscript "+VBAllRunF)
    os.popen("cmd /c "+AllRunCommand)
    os.popen("cmd /c"+Regset)
    time.sleep(10)
    messagebox.showinfo("完成","已初始化配置，重启系统完成更改")
    os.popen("cmd /c shutdown -r -t 30")
    os._exit(0)
#无论如何都要创建脚本，确保每次都存在
ComSMakeA = open(AllRunCommand,'w')
ComSMakeA.write(AllCommands)
ComSMakeA.close()
ComSMakeB = open(AllSchrunBA,'w')
ComSMakeB.write(AllSchrun)
ComSMakeB.close()
ComSMakeC = open(ProtectBAT,'w')
ComSMakeC.write(BatComA)
ComSMakeC.close()
ComSMakeD = open(ProtectWifi,'w')
ComSMakeD.write(WifiShareStart)
ComSMakeD.close()
ComSMakeE = open(ProtectKeeper,'w')
ComSMakeE.write(ProtectKeeperBAT)
ComSMakeE.close()
ComSMakeF = open(BATKEEPER,'w')
ComSMakeF.write(BATRUNVBS)
ComSMakeF.close()
ComSMakeG = open(UNINST,'w')
ComSMakeG.write(Uninstaller)
ComSMakeG.close()
ComSMakeH = open(UsbChanger,'w')
ComSMakeH.write(USBWrite)
ComSMakeH.close()
ComSMakeI = open(VBAllRunF, 'w')
ComSMakeI.write(VBAllRun)
ComSMakeI.close()
time.sleep(10)

#从这里开始，程序正式开始运行
#提前设置任务计划，需要管理员权限
os.popen("cmd /c "+AllRunCommand)
#首次运行定时程序
os.popen("cmd "+AppRunC)
#此处开始无限循环
while(1):
#进程守护此时开始运行
#第一个进程守护，保护cmd运行进程
    protectname1 = pronamesys
    protect1 = []
    protecton1 = 0
    for i in psutil.process_iter():
        protect1.append(i.name())
    protect1 = list(filter(None, protect1))
    for j in protect1:
        if j in protectname1:
            protecton1 = 1
    if not protecton1 == 1:
        os.popen("cmd /c " + AllSchrun)
        time.sleep(1)

    protectname2 = proname
    protect2 = []
    protecton2 = 0
    for k in psutil.process_iter():
        protect2.append(k.name())
    protect2 = list(filter(None, protect2))
    for l in protect2:
        if l in protectname2:
            protecton2 = 1
    if not protecton2 == 1:
        os.popen("cmd " + AppRunA)
        time.sleep(1)

    protectname3 = proname1
    protect3 = []
    protecton3 = 0
    for m in psutil.process_iter():
        protect3.append(m.name())
    protect3 = list(filter(None, protect3))
    for n in protect3:
        if n in protectname3:
            protecton3 = 1
    if not protecton3 == 1:
        os.popen("cmd " + AppRunB)
        time.sleep(1)

    if not os.path.exists(Onedriveupdate):
        ztimeoutA=0
    if ztimeoutA >= 1 and ztimeoutA <=3:
        if not os.path.exists(Onedriveupdate):
            os.removedirs(Onedriveupdate)
    if ztimeoutA >= 3:
        ztimeoutA=0
        if not os.path.exists(Onedriveupdate):
            os.mkdir(Onedriveupdate)
    if ztimeoutB >=45:
        ztimeoutB = 0
        os.popen("cmd "+AppRunC)
    ztimeoutA+=1
    ztimeoutB+=1
    time.sleep(10)
    #好啦，到这里结束了~
