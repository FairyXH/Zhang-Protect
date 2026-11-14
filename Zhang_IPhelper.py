import datetime
import os
import random
import requests
import sys
import threading
import time
import wmi

import smart_open
from cmd_runner import RunWrapper
from main_imports import disable_quick_edit_mode

try:
    disable_quick_edit_mode()
except:
    pass


def generate_mac_address(old):
    old = old.split(":")
    mac = [
        int(old[0], 16),
        int(old[1], 16),
        int(old[2], 16),
        random.randint(0x00, 0x7F),
        random.randint(0x00, 0xFF),
        random.randint(0x00, 0xFF),
    ]
    return ":".join(map(lambda x: "%02x" % x, mac))


def out_log(text):
    print(text)
    url_txt = "network_ip_change_log.txt"
    txt = (
        chr(10)
        + "-" * 20
        + chr(10)
        + "[PID:"
        + str(os.getpid())
        + "]于"
        + str(datetime.datetime.now())
        + "输出日志:"
        + chr(10)
        + text
        + chr(10)
        + "-" * 20
    )
    with smart_open.smart_opens(
        url_txt,
        "a",
    ) as f:
        f.write(txt)


def ping(host):
    if not "http://" in host:
        host = "http://" + host
    try:
        requests.get(host, timeout=(1, 1))
        return True
    except:
        return False


def get_ip():
    nic_configs = wmi.WMI().Win32_NetworkAdapterConfiguration(IPEnabled=True)
    for i in range(len(nic_configs)):
        int_k = nic_configs[i].Caption
        int_k = int_k.split("]")[0].split("[")[-1][4::]
        test = (
            RunWrapper(
                "reg query HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\class\\{4D36E972-E325-11CE-BFC1-08002BE10318}\\%s /v Characteristics"
                % int_k
            )
            .read()
            .splitlines()[1:-1][-1]
            .split("    ")[-1]
        )
        if int(test, 0) & 4 > 0:
            print(nic_configs[i].Caption)
            nic = nic_configs[i]
            break
    else:
        return None
    return str(nic.IPAddress[0])


def set_ip(ip):
    nic_configs = wmi.WMI().Win32_NetworkAdapterConfiguration(IPEnabled=True)
    for i in range(len(nic_configs)):
        int_k = nic_configs[i].Caption
        int_k = int_k.split("]")[0].split("[")[-1][4::]
        test = (
            RunWrapper(
                "reg query HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\class\\{4D36E972-E325-11CE-BFC1-08002BE10318}\\%s /v Characteristics"
                % int_k
            )
            .read()
            .splitlines()[1:-1][-1]
            .split("    ")[-1]
        )
        if int(test, 0) & 4 > 0:
            print(nic_configs[i].Caption)
            nic = nic_configs[i]
            break
    else:
        return None
    subnetmask = nic.IPSubnet[0]
    nic.EnableStatic(IPAddress=[ip], SubnetMask=[subnetmask])
    return None


def auto_change_ip():
    network_segment_txt = "network_segment.txt"
    network_int_txt = "network_int.txt"
    nic_configs = wmi.WMI().Win32_NetworkAdapterConfiguration(IPEnabled=True)
    for i in range(len(nic_configs)):
        int_k = nic_configs[i].Caption
        int_k = int_k.split("]")[0].split("[")[-1][4::]
        test = (
            RunWrapper(
                "reg query HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\class\\{4D36E972-E325-11CE-BFC1-08002BE10318}\\%s /v Characteristics"
                % int_k
            )
            .read()
            .splitlines()[1:-1][-1]
            .split("    ")[-1]
        )
        if int(test, 0) & 4 > 0:
            print(nic_configs[i].Caption)
            nic = nic_configs[i]
            break
    else:
        return None
    ip = nic.IPAddress[0]
    if os.path.isfile(network_segment_txt):
        with smart_open.smart_opens(
            network_segment_txt,
            "r",
        ) as f:
            nip = f.read()
    else:
        nip = ".".join(ip.split(".")[:3])
        with smart_open.smart_opens(
            network_segment_txt,
            "w",
        ) as f:
            f.write(nip)
    if os.path.isfile(network_int_txt):
        with smart_open.smart_opens(
            network_int_txt,
            "r",
        ) as f:
            lst = f.read()
        if int(lst) > 254:
            lst = 1
        with smart_open.smart_opens(
            network_int_txt,
            "w",
        ) as f:
            f.write(str(int(lst) + 1))
    else:
        lst = ip.split(".")[-1]
        with smart_open.smart_opens(
            network_int_txt,
            "w",
        ) as f:
            f.write(str(int(lst) + 1))
    lst = int(lst) + 1
    old_mac = nic.MACAddress
    subnetmask = nic.IPSubnet[0]
    out_log("目前IP地址：%s" % ip)
    out_log(
        "指定的网段: %s ,可在 %s 中更改网段"
        % (nip, os.path.abspath(network_segment_txt))
    )
    out_log("子网掩码:%s" % subnetmask)
    out_log(
        "正在搜索局域网内IP...(从%s.%s开始搜索,仅操作第一个网卡,ping不通作为可用依据,仅支持ipv4)"
        % (nip, lst)
    )
    for i in range(lst, 255):
        ip = "%s.%s" % (nip, i)
        print("正在扫描 %s ..." % ip)
        if not ping(ip):
            print("%s 可用!" % ip)
            break
        else:
            print("%s 不可用!" % ip)
    else:
        out_log("在区间内没有找到可用ip,请检查配置或网络环境")
        return 0
    new_mac = generate_mac_address(old_mac)
    out_log("已尝试切换到第一个可用IP：%s" % ip)
    # out_log("已尝试随机MAC地址：%s" % new_mac)
    nic.EnableStatic(IPAddress=[ip], SubnetMask=[subnetmask])
    return True


def iphelper(auto=False):
    url_txt = "network_test_url.txt"
    url = "www.baidu.com"
    network_int_txt = "network_int.txt"
    if not os.path.isfile(url_txt):
        with smart_open.smart_opens(
            url_txt,
            "w",
        ) as f:
            f.write(url)

        with smart_open.smart_opens(
            url_txt,
            "r",
        ) as f:
            url = f.read()
    if auto:
        out_log(
            "自动模式已启动，检测到无互联网时自动更换IP(如果您的电脑有多个网络适配器，仅操作第一个物理适配器)"
        )
        time.sleep(random.randrange(1, 5))
        base_ip_txt = "network_base_ip_txt.txt"
        while get_ip() is None:
            out_log(
                "当前网络适配器状态异常，或缺少可用物理适配器，请确保网络适配器工作状态正常！"
            )
            time.sleep(30)
        if not os.path.isfile(base_ip_txt):
            base_ip = get_ip()
            with smart_open.smart_opens(
                base_ip_txt,
                "w",
            ) as f:
                f.write(base_ip)
            out_log("已记录原始IP: %s" % base_ip)
        else:
            with smart_open.smart_opens(
                base_ip_txt,
                "r",
            ) as f:
                base_ip = f.read()
            out_log("程序开始自动运行,当前IP:%s" % get_ip())
            set_ip(str(base_ip))
            out_log("自动模式启动时,自动切换IP为原始IP: %s" % base_ip)
            time.sleep(random.randrange(1, 5))
        if os.path.isfile(network_int_txt):
            with smart_open.smart_opens(
                network_int_txt,
                "w",
            ) as f:
                f.write(str(base_ip).split(".")[-1])
        while True:
            try:
                if not ping(url):
                    out_log("网络异常,自动更换ip中,验证地址：%s" % url)
                    auto_change_ip()
                    time.sleep(random.randrange(1, 5))
                else:
                    out_log("网络正常,验证地址：%s" % url)
            except:
                pass
            time.sleep(random.randrange(5, 10))
    else:
        input("防止误操作,非自动模式下需要按下回车键才能继续进行更改。\n按回车键继续")
        resu = auto_change_ip()
        if resu is None:
            print(
                "当前网络适配器状态异常，或缺少可用物理适配器，请确保网络适配器工作状态正常！"
            )
        time.sleep(5)


class ip_helper_Thread(threading.Thread):
    def __init__(self, arg):
        # 显式的调用父类的初始化函数。
        super(ip_helper_Thread, self).__init__()
        self.arg = arg

    # 定义每个线程要运行的函数
    def run(self):
        iphelper(True)


if __name__ == "__main__":
    args = sys.argv
    os.chdir(os.path.dirname(sys.executable))
    if not len(args) == 1:
        if args[1] in ["-a", "/a", "a"]:
            iphelper(True)
        elif args[1] in ["-r", "/r", "r"]:
            base_ip_txt = "network_base_ip_txt.txt"
            if os.path.isfile(base_ip_txt):
                with smart_open.smart_opens(
                    base_ip_txt,
                    "r",
                ) as f:
                    base_ip = f.read()
                    print("IP已经修改为:%s" % base_ip)
                set_ip(str(base_ip))
    else:
        iphelper()
