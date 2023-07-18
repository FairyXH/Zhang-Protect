from file2base import mode2_make
import os


def main():
    print("正在更新文件")
    files = [
        ("ZhangProtectControl.exe", "ZhangProtectControl", "ZhangProtectControl_File"),
        ("SysDispatch.exe", "SysDispatch", "SysDispatch_File"),
        ("Zhang_lan_scan.exe", "Zhang_lan_scan_e", "Zhang_lan_scan_f"),
        ("RDPWrap.zip", "RDPWrapZip", "RDPWrapZip"),
        ("DesktopOK.exe", "DesktopOK", "DesktopOKFile"),
        ("memreduct.exe", "memreduct", "memreductFile"),
        ("NpCapInstaller.exe", "npcap", "npcapzip"),
        ("NSudo.exe", "NSudoZip", "NSudoZipf"),
        ("CCleaner.zip", "CCleaner", "CCleanerZip"),
        ("SnapShot.zip", "SnapShot", "SnapShotf"),
        ("7z.exe", "xzzip7", "zip7f"),
        ("7z.dll", "xzzip7dll", "zip7dllf"),
        ("动态壁纸示例.mp4", "examplemp4", "examplemp4f"),
        ("动态壁纸示例静态图.png", "examplemp4photo", "examplemp4photof"),
        ("奶酪陷阱体.ttf", "nlxjt", "nlxjtf"),
        ("苹方字体.ttf", "pingfang", "pingfangf"),
        ("nmyu.zip", "nmyu", "nmyuf"),
        ("iKun_icon.zip", "iKun_icon_zip", "iKun_icon_zip_f"),
        ("iKun动态壁纸.mp4", "iKun_wallpaper_mp4", "iKun_wallpaper_mp4_f"),
        ("iKun动态壁纸静态图.png", "iKun_wallpaper_photo", "iKun_wallpaper_photo_f"),
        ("KMSActivator.exe", "KMSActivator", "KMSActivatorf"),
        ("APInstaller.exe", "APInstaller", "APInstallerf"),
        ("DGuardInstall.exe", "DGuardInstall", "DGuardInstallf"),
    ]
    for i in files:
        file_name = i[0]
        py_name = i[1]
        py_var = i[2]
        abs_path = os.path.abspath(".\\files\\" + file_name)
        print("更新文件：", abs_path)
        mode2_make(abs_path, py_name, py_var)
        print("***" * 15)


if __name__ == "__main__":
    main()
