import http.server
import os
import socketserver
import sys
import time

import smart_open
from main_imports import disable_quick_edit_mode


def file_server(dir):
    while True:
        time.sleep(1)
        try:
            port_txt = "file_server_port.txt"
            os.chdir(os.path.abspath(os.path.dirname(sys.executable)))
            if os.path.isfile(port_txt):
                with smart_open.smart_opens(
                    port_txt,
                    "r",
                ) as f:
                    port = int(f.read())
                    if port == "":
                        port = 18080
                        os.remove(port_txt)
            else:
                port = 18080
                with smart_open.smart_opens(
                    port_txt,
                    "w",
                ) as f:
                    f.write(str(port))
            os.chdir(dir)
            handler = http.server.SimpleHTTPRequestHandler
            with socketserver.TCPServer(("", port), handler) as httpd:
                print(f"Serving at port {port}")
                httpd.serve_forever()
        except:
            pass


try:
    disable_quick_edit_mode()
except:
    pass

if __name__ == "__main__":
    try:
        file_server(sys.argv[1])
    except:
        for i in [chr(y) for y in range(97, 123)]:
            path = "%s:\\" % i
            if os.path.exists(path):
                file_server(path)
