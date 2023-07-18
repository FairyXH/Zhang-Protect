import os
from icons import *
from base64 import b64decode

icon = "icon.ico"


def get_pic(pic_code, pic_name):
    image = open(pic_name, "wb")
    image.write(b64decode(pic_code))
    image.close()


if not os.path.isfile(icon):
    get_pic(icon_ico, "icon.ico")
