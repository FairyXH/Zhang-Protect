import os, sys, time, random, requests, itertools, threading


def go(long, ip, words, file):
    global nownum, allnum
    for i in ("", itertools.product(words, repeat=long)):
        headers = {
            "User-Agent": "Mozilla/%s.0 (Windows NT %s.0; Win64; x64; rv:%s.0) Gecko/20100101 Firefox/%s.0"
            % (
                random.randrange(0, 114514),
                random.randrange(0, 114514),
                random.randrange(0, 114514),
                random.randrange(0, 114514),
            )
        }
        for port in range(1, 65536):
            try:
                nownum += 1
                str = "".join(i)
                url = "%s:%s/%s" % (ip, port, str)
                result = requests.get(url, headers=headers).status_code
                if result // 100 in [1, 2, 3]:
                    print(url)
                    with open(file, "a", encoding="gbk") as f:
                        f.write(url + "\n")
                print(
                    f"正在多线程扫描 %s:%s : 完成 %s ,共 %s --> %s\n"
                    % (ip, port, nownum, allnum, result),
                    end="",
                )
                print(url)
                sys.stdout.flush()
            except:
                print(
                    f"正在多线程扫描 %s:%s : 完成 %s ,共 %s --> %s\n"
                    % (ip, port, nownum, allnum, "错误"),
                    end="",
                )


def scan(min, max, ip, type, file, floor=3):
    global nownum, allnum
    nownum = 0
    allnum = 0
    words = (
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890-_ ."
        + "/" * floor
    )
    if type == "http":
        ip = "http://%s" % ip
    for i in range(min, max + 1):
        allnum += len(words) ** i
    allnum *= 65536
    for long in range(min, max + 1):
        threading.Thread(target=go, args=(long, ip, words, file)).start()


if __name__ == "__main__":
    ip = "1.1.1.3"
    min = 1
    max = 10
    floor = 3
    arg = sys.argv
    if len(arg) == 1:
        print(
            "本程序不是专业工具，只能进行简单扫描，且效率低下,每次都只能重头来，并且每个单词都会遍历所有端口(1-65535)。结果保存在scan_result.txt。支持命令行参数。"
        )
        ip = input("目标地址(-ip=):")
        min = int(input("最小单词长度(-min=):"))
        max = int(input("最大单词长度(-max=):"))
        floor = int(input("最大层数(-floor=):"))
    else:
        for i in arg[1::]:
            try:
                exec(i[1::])
            except:
                i = '%s="%s"' % (i.split("=")[0], i.split("=")[1])
                exec(i[1::])
    print("参数已接受，3秒后开始运行")
    time.sleep(3)
    print("开始扫描")
    try:
        scan(min, max, ip, "http", "scan_result.txt", floor)
    except:
        os._exit(0)
