import datetime

import smart_open


def main():
    verfile = "version.py"
    infofile = "file_version_info.txt"
    date = datetime.datetime.now()
    year = date.year
    month = date.month
    day = date.day
    code = "%s.%s.%s.0" % (year, month, day)
    code2 = "%s,%s,%s,0" % (year, month, day)
    info = (
        """# UTF-8
#
# For more details about fixed file info 'ffi' see:
# https://msdn.microsoft.com/en-us/library/ms646997.aspx
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
    StringStruct('FileDescription', 'ZhangProtect'),
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
    with smart_open.smart_opens(
        infofile,
        "w",
    ) as h:
        h.write(info)
    with smart_open.smart_opens(
        verfile,
        "w",
    ) as h:
        h.write('version = "%s"\n' % code)
    print(code)


if __name__ == "__main__":
    main()
