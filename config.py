is_testflag = False  # 测试模式
log_writetofile = False  # 日志是否写入文件
log_dir = ""  # 日志目录
max_log_size = 10  # 单个日志大小限制，MB
low_cpu_flag = False  # 开发测试标志,限制输出测试真实cpu True-->不执行log()等占IO命令 False-->无作用


def is_test_mode():
    return is_testflag
