def main():
    verfile = "version.py"
    infofile = "file_version_info.txt"
    with open(verfile, "r") as f:
        code = f.read()
        f.close()
        code = code.replace(" ", "")
        code = code.split("=")[1].replace('"', "")
        code = list(map(int, code.split(".")))
        badnum = [2, 4, 5, 7]
        code[2] += 1
        while (
            code[2] > 9
            or code[1] > 9
            or code[0] in badnum
            or code[1] in badnum
            or code[2] in badnum
            or any(int(i) in badnum for i in str(code[0]))
        ):
            code[2] += 1
            if code[2] > 9:
                code[2] = 0
                code[1] += 1
            if code[1] > 9:
                code[1] = 0
                code[0] += 1
        code = list(map(str, code))
        code = ".".join(code)
        code2 = code.replace(".", ",") + ",1"
        info = (
            """# UTF-8
#
# For more details about fixed file info 'ffi' see:
# http://msdn.microsoft.com/en-us/library/ms646997.aspx
VSVersionInfo(
  ffi=FixedFileInfo(
    # filevers and prodvers should be always a tuple with four items: (1, 2, 3, 4)
    # Set not needed items to zero 0.
    filevers=("""
            + code2
            + """),
    prodvers=("""
            + code2
            + """),
    # Contains a bitmask that specifies the valid bits 'flags'r
    mask=0x3f,
    # Contains a bitmask that specifies the Boolean attributes of the file.
    flags=0x0,
    # The operating system for which this file was designed.
    # 0x4 - NT and there is no need to change it.
    OS=0x40004,
    # The general type of file.
    # 0x1 - the file is an application.
    fileType=0x1,
    # The function of the file.
    # 0x0 - the function is not defined for this fileType
    subtype=0x0,
    # Creation date and time stamp.
    date=(0, 0)
    ),
  kids=[
    StringFileInfo(
      [
      StringTable(
        '040904B0',
        [StringStruct('CompanyName', 'Zhang'),
        StringStruct('FileDescription', 'ZhangProtet-由个人编写的Windows系统优化软件，支持最新系统,内置多款工具，故文件较大。对系统改动较大，建议关闭安全软件安装，并添加白名单。优化倾向于纯净系统优化,是锁定式优化，即循环保持优化状态，系统资源占用低。'),
        StringStruct('FileVersion', '"""
            + code
            + """'),
        StringStruct('InternalName', 'Protect'),
        StringStruct('LegalCopyright', '© Zhang'),
        StringStruct('OriginalFilename', 'Protect.EXE'),
        StringStruct('ProductName', 'ZhangProtect'),
        StringStruct('ProductVersion', '"""
            + code
            + """')])
      ]), 
    VarFileInfo([VarStruct('Translation', [1033, 1200])])
  ]
)"""
        )
        with open(infofile, "w+", encoding="utf-8") as h:
            h.write(info)
        code = 'version = "' + code + '"\n'
        print(code)
        with open(verfile, "w+") as g:
            g.write(code)
            g.close()


if __name__ == "__main__":
    main()
