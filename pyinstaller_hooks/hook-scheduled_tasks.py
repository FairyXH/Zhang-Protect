"""让 PyInstaller 一并收集 win32timezone。

pywin32 的 IRegisteredTask.LastRunTime / NextRunTime 返回的是带时区的 datetime，
需要 win32timezone 模块才能构造，否则访问这些属性会抛
"No module named 'win32timezone'"。窗口化的独立 exe 里没人会手动装它，所以在这里补上。
"""

hiddenimports = ["win32timezone"]
