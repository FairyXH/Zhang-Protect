import os
from icons import *
from tkinter import *
from tkinter import ttk
from base64 import b64decode
from configure_tags import *
from tkinter import messagebox

ls = config_tags


def get_pic(pic_code, pic_name):
    image = open(pic_name, "wb")
    image.write(b64decode(pic_code))
    image.close()


def check(file):
    return os.path.isfile(file)


def create(file):
    if not os.path.isfile(file):
        with open(file, "w") as f:
            f.write("0")
    return 0


def delete(file):
    if os.path.isfile(file):
        os.remove(file)
    return 0


def test():
    if (
        os.path.isdir(protectdir)
        and os.path.isfile(protectexe)
        and os.path.isfile(protectconf)
    ):
        os.chdir(protectdir)
        return 0
    else:
        messagebox.showerror("程序错误", "程序未安装，无法使用配置工具")
        return os._exit(0)


def main():
    global windir, protectdir, protectexe, protectconf
    windir = os.getenv("systemroot")
    protectdir = "%s\\Protect\\" % windir
    protectexe = "%sProtect.exe" % protectdir
    protectconf = "%sProtectConf.conf" % protectdir
    if not os.path.isfile("develop"):
        test()
    tk = Tk()
    tk.title("ZhangProtect开关控制台")
    frame = ttk.Frame(tk)
    frame.pack()
    tk.attributes("-topmost", 1)
    icon = "icon.ico"
    if not os.path.isfile(icon):
        get_pic(icon_ico, "icon.ico")
    if os.path.isfile(icon):
        tk.iconbitmap(icon)
        os.remove(icon)
    global ls
    lsb = []
    for i in range(len(ls)):
        lsb.append(BooleanVar())
        C = ttk.Checkbutton(
            frame, text=ls[i][0], variable=lsb[i], onvalue=1, offvalue=0
        )
        C.pack()

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
        messagebox.showinfo("完成", "新策略应用成功,重启系统或刷新ZhangProtect后生效")

    def change():
        os.popen(protectexe + " -c")
        messagebox.showinfo("完成", "已打开配置修改页，如未成功运行，您可执行命令行：\r\n%s -c" % protectexe)

    def fresh():
        os.popen(
            """cmd /c schtasks /End /TN ZhangProtect\Protect & taskkill /f /im Protect.exe /t & schtasks /Run /TN ZhangProtect\Protect /I"""
        ).read()
        messagebox.showinfo("完成", "ZhangProtect刷新成功")

    but = ttk.Button(frame, text="写入设置", command=finished)
    but.pack()

    ccf = ttk.Button(frame, text="修改配置", command=change)
    ccf.pack()

    rpr = ttk.Button(frame, text="刷新进程", command=fresh)
    rpr.pack()
    tk.mainloop()


if __name__ == "__main__":
    try:
        main()
    except:
        pass
