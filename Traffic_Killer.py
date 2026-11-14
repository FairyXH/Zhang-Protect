import datetime
import os
import requests
import time

import smart_open
from main_imports import disable_quick_edit_mode


def log(text):
    text = "%s %s" % (datetime.datetime.now(), text)
    with smart_open.smart_opens(
        "Traffic_Killer_%s.log" % os.getpid(),
        "a",
    ) as f:
        f.write("\n%s" % text)
    print(text)


def Traffic_Killer(url):
    all = 0
    log("开始消耗流量,请通过任务管理器查看速率，url:%s" % url)
    a_time = time.time()
    while True:
        try:
            response = requests.get(url, stream=True)
            start_time = time.time()
            for i in response.iter_content(chunk_size=1024):
                all += len(i)
                if time.time() - start_time > 10:
                    log(
                        "已消耗流量： %s GB , 平均: %s MB/s"
                        % (
                            round(all / 1024**3, 3),
                            round((all / 1024**2) / (time.time() - a_time), 3),
                        )
                    )
                    start_time = time.time()
        except:
            time.sleep(10)


def main():
    URL_txt = "Traffic_Killer_url.txt"
    if os.path.isfile(URL_txt):
        with smart_open.smart_opens(
            URL_txt,
            "r",
        ) as f:
            Traffic_Killer(f.read())
    else:
        base_url = "https://cesubao.chinaunicom.cn/1000.bin"
        with smart_open.smart_opens(
            URL_txt,
            "w",
        ) as f:
            f.write(base_url)
        Traffic_Killer(base_url)


try:
    disable_quick_edit_mode()
except:
    pass

if __name__ == "__main__":
    Traffic_Killer(input("输入用于消耗流量的Url(如下载直链)："))
