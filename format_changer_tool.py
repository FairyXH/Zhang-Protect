import os
import sys
import config
from cmd_runner import RunWrapper

HELP_FLAGS = ["/h", "-h", "/?", "--help"]

config.is_testflag = True


def print_help():
    help_text = (
        "用法:\n"
        + "    FormatTool.exe 原后缀 目标后缀 [要去除的字符串]\n\n"
        + "说明:\n"
        + "    当前系统需要有ffmpeg。\n"
        + "    将当前目录下所有指定后缀的文件使用 ffmpeg 转换为另一种格式。\n"
        + "    所有转换后文件保存在 “原后缀_to_目标后缀” 文件夹中。\n\n"
        + "参数:\n"
        + "    原后缀             要转换的原始文件后缀名（不带点）\n"
        + "    目标后缀           要转换成的目标文件后缀名（不带点）\n"
        + '    要去除的字符串      （可选）转换时去除文件名中的某个字符串，默认是 "_kgg-dec"\n\n'
        + "示例:\n"
        + "    FormatTool.exe mp4 mp3\n"
        + "    FormatTool.exe wav ogg __temp\n"
        + "    FormatTool.exe /h\n"
    )
    print(help_text)


def main():
    args = sys.argv[1:]

    if any(arg in HELP_FLAGS for arg in args):
        print_help()
        return

    if len(args) < 2 or len(args) > 3:
        print("参数数量不正确，使用 /h 查看帮助。")
        return

    src_ext = args[0].lower()
    dst_ext = args[1].lower()
    remove_str = args[2] if len(args) == 3 else "_kgg-dec"

    output_dir = f"{src_ext}_to_{dst_ext}"
    os.makedirs(output_dir, exist_ok=True)

    for filename in os.listdir("."):
        if filename.lower().endswith(f".{src_ext}"):
            base_name = filename[: -len(src_ext) - 1]
            if remove_str:
                base_name = base_name.replace(remove_str, "")
            output_path = os.path.join(output_dir, f"{base_name}.{dst_ext}")

            print(f"正在转换: {filename} -> {output_path}")
            try:
                RunWrapper(f'ffmpeg -i "{filename}" "{output_path}"').read()
            except:
                print(f"转换失败: {filename}")


if __name__ == "__main__":
    try:
        main()
    except:
        pass
