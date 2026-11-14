import os
import random
import sys
from math import ceil, floor, sqrt
import config
import smart_open
from icons import *
from tkinter import *
from tkinter import ttk
from base64 import b64decode
from configure_tags import *
from tkinter import messagebox
from main_imports import debug_mode
from cmd_runner import RunWrapper

ls = config_tags


def optimal_row(ls):
    n = len(ls)
    if n == 0:
        return 0

    widths = [len(item[0]) for item in ls]
    avg_width = sum(widths) / n

    min_row = max(1, int(sqrt(n)))
    max_row = min(n, int(sqrt(n) * 2))

    best_row = min_row
    best_score = float("inf")

    for row in range(min_row, max_row + 1):
        col = ceil(n / row)
        last_col_count = n - (col - 1) * row
        empty_count = row - last_col_count

        # 最大允许空白数量：绝对数量或比例
        max_empty = min(2, int(row / 3))  # 可以调整为绝对值限制

        # 如果空白超过限制，可以尝试 row +1
        penalty = 0
        if empty_count > max_empty:
            penalty = empty_count - max_empty

        # 方正度 + 空白惩罚 + 字符串长度权重
        score = abs(row - col * avg_width) + penalty

        if score < best_score:
            best_score = score
            best_row = row

    return best_row


def get_pic(pic_code, pic_name):
    image = smart_open.smart_opens(pic_name, "wb")
    image.write(b64decode(pic_code))
    image.close()


def check(file):
    return os.path.isfile(file)


def create(file):
    if not os.path.isfile(file):
        with smart_open.smart_opens(file, "w") as f:
            f.write("0")
    return 0


def delete(file):
    if os.path.isfile(file):
        os.remove(file)
    return 0


def test():
    if (
        (
            os.path.isdir(protectdir)
            and os.path.isfile(protectexe)
            and os.path.isfile(protectconf)
        )
        or config.is_test_mode()
        or debug_mode
    ):
        os.chdir(protectdir)
        return 0
    else:
        messagebox.showerror("程序错误", "程序未安装，无法使用配置工具")
        return sys.exit(0)


def main():
    global windir, protectdir, protectexe, protectconf
    windir = os.getenv("systemroot")
    protectdir = "%s\\Protect\\" % windir
    protectexe = "%sProtect.exe" % protectdir
    protectconf = "%sProtectConf.conf" % protectdir
    try:
        os.chdir(protectdir)
    except:
        pass
    if not os.path.isfile("develop"):
        test()
    tk = Tk()
    tk.title("ZhangProtect配置管理器")
    frame = ttk.Frame(tk)
    frame.grid()
    tk.attributes("-topmost", 1)
    icon = "icon.ico"
    if not os.path.isfile(icon):
        get_pic(icon_ico, "icon.ico")
    if os.path.isfile(icon):
        tk.iconbitmap(icon)
        os.remove(icon)
    global ls
    lsb = []
    long = len(ls)
    x, j = 0, 0
    pai = optimal_row(ls)
    for i in range(long):
        lsb.append(BooleanVar())
        c = ttk.Checkbutton(
            frame, text=ls[i][0], variable=lsb[i], onvalue=1, offvalue=0
        )
        if x >= pai:
            x = 0
            j += 1
        c.grid(row=x, column=j, sticky="w")
        x += 1

    def on_check():
        for i in range(len(ls)):
            if os.path.isfile(ls[i][1]):
                lsb[i].set(True)

    on_check()

    def finished():
        for i in range(len(ls)):
            if lsb[i].get():
                create(ls[i][1])
            else:
                delete(ls[i][1])
        on_check()
        messagebox.showinfo(
            "完成", "新策略应用成功。可能需要刷新ZhangProtect进程后生效。"
        )

    def change():
        RunWrapper(protectexe + " -c")
        messagebox.showinfo(
            "完成",
            "已打开配置修改页，如未成功运行，您可执行命令行：\r\n%s -c" % protectexe,
        )

    def fresh():
        RunWrapper(
            """cmd /c schtasks /End /TN ZhangProtect\\Protect & taskkill /f /im Protect.exe /t & powershell \"Get-Process -Name Protect | Stop-Process -Force\" & schtasks /Run /TN ZhangProtect\\Protect /I"""
        ).read()
        messagebox.showinfo("完成", "ZhangProtect刷新成功")

    but = ttk.Button(frame, text="写入设置", command=finished)
    but.grid()

    rpr = ttk.Button(frame, text="刷新进程", command=fresh)
    rpr.grid()
    tk.mainloop()


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        messagebox.showinfo("错误", f"{e}")
