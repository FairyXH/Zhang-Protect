from main_imports import *

# 获取一些系统变量的值
try:
    os.chdir(os.path.dirname(sys.executable))
except Exception as e:
    pass

with smart_open.smart_opens(
    Protectconf,
    "r",
) as f:
    pro_conf = f.read().splitlines()
wifi_conf = pro_conf[9].split("*")
wifi_ssid = wifi_conf[0]
wifi_pwd = wifi_conf[1]


try:
    disable_quick_edit_mode()
except:
    pass


def str_to_hex(str):
    str_encode = ""
    for i in str:
        str_encode += "\\" + hex(ord(i))[1::]
    return str_encode


def restore_wifi():
    if os.path.isfile(ProtectWifi):
        with smart_open.smart_opens(
            ProtectWifi,
            "r",
        ) as f:
            wifi_txt = f.read()
        wifi_txt_c = []
        for i in wifi_txt.splitlines():
            if "$password=" in i:
                wifi_txt_c.append('$password="' + wifi_pwd + '"\n')
            elif "$ssid=" in i:
                wifi_txt_c.append('$ssid="' + wifi_ssid + '"\n')
            else:
                wifi_txt_c.append(i + "\n")
        with smart_open.smart_opens(
            ProtectWifi,
            "w",
        ) as f:
            f.writelines(wifi_txt_c)
        for i in range(2):
            RunWrapper("powershell %s" % ProtectWifi).read()
            time.sleep(1)
        print("热点信息已还原为配置文件指定项")


def restore_background_shell():
    reg_read = reg_reader.reg_read(background_reg_path)
    for i in reg_read["Folders"]:
        if any(j in i["name"] for j in ("ZhangProtect", "RDP")):
            reg_reader.reg_delete_key(f"{background_reg_path}\\{i['name']}")


def main():
    try:
        restore_wifi()
    except:
        pass

    try:
        if os.path.isfile(Digital_Clock_4_flag) and os.path.isfile(clock_show_wifiinfo):
            clock_show_mobilehospd_info(
                wifi_ssid, wifi_pwd, Digital_Clock_4_dir + "\\settings.ini"
            )
    except:
        pass

    try:
        if not os.path.isfile(user_show_clock_info):
            if os.path.isfile(do_no_show_clock_info):
                clock_show_info("热点:" + wifi_ssid, "密码:" + wifi_pwd)
            else:
                clock_show_info()
    except:
        pass

    if os.path.isfile(AutoClearJetBrainsHistory):
        try:
            print("清理JetBrains历史")
            clear_JetBrains_History()
        except:
            pass


if __name__ == "__main__":
    argvs = sys.argv
    if len(argvs) == 1:
        main()
    else:
        if "--restore_background_shell" in argvs:
            restore_background_shell()
