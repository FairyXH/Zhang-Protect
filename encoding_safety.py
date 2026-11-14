"""
最小化编码安全修复
只解决print编码问题，不做任何流重定向
"""

import sys
import os
import builtins


def fix_print():
    os.environ["PYTHONIOENCODING"] = "utf-8"
    os.environ["PYTHONUTF8"] = "1"
    _original_print = builtins.print

    def _safe_print(*args, **kwargs):
        try:
            _original_print(*args, **kwargs)
        except (UnicodeEncodeError, UnicodeDecodeError, ValueError) as e:
            try:
                file = kwargs.get("file", sys.stdout)
                sep = kwargs.get("sep", " ")
                end = kwargs.get("end", "\n")
                safe_args = []
                for arg in args:
                    if isinstance(arg, bytes):
                        try:
                            safe_args.append(arg.decode("utf-8", errors="replace"))
                        except:
                            safe_args.append("[BYTES]")
                    else:
                        safe_args.append(str(arg))
                text = sep.join(safe_args) + end
                if hasattr(file, "buffer"):
                    file.buffer.write(text.encode("utf-8", errors="replace"))
                    file.buffer.flush()
            except:
                pass

    builtins.print = _safe_print
    return True


fix_print()
