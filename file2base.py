import base64


def mode1():
    file = input("输入待转换文件绝对路径：")
    if '"' in file:
        file = file.replace('"', "")

    with open(file, "rb") as f:
        file_bit = f.read()
        f.close()
    file_b64 = base64.b64encode(file_bit)
    with open("output.txt", "wb") as f:
        f.write(file_b64)
        f.close()
    print("完成，保存至output.txt中")


def mode2_make(file, name, var):
    if '"' in file:
        file = file.replace('"', "")
    with open(file, "rb") as f:
        file_bit = f.read()
        f.close()

    file_b64 = base64.b64encode(file_bit)
    with open(name + ".py", "w") as f:
        f.write(var + " = " + str(file_b64) + "\n")
        f.close()
    print("源文件：", file, "\n文件名：", name, "\n变量名：", var, "\n状态：成功")


def mode2():
    file = input("输入待转换文件绝对路径：")
    name = input("输出名称：")
    var = input("变量名：")
    mode2_make(file, name, var)
    print("完成")


def main():
    print("输入1：直接将文件转换为Base64后存储为txt文本")
    print("输入2：将文件转换为Base64后输出为一个可导入的py文件")
    mode = input("请选择：")
    if mode == "1":
        mode1()
    elif mode == "2":
        mode2()
    else:
        print("输入错误")


if __name__ == "__main__":
    main()
