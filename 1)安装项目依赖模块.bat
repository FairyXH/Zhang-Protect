@echo off
echo ���ڰ�װ����ģ��...
title ���ڰ�װ����ģ��...
python -m pip install pip --upgrade
python -m pip install pyinstaller
python -m pip install psutil
python -m pip install ctypes
python -m pip install shutil
python -m pip install requests
python -m pip install scapy
python -m pip install black
python -m pip install pypiwin32
echo y | python -m pip uninstall pathlib
cls
echo ���ڸ�������ģ��...
title ���ڸ�������ģ��...
python -m pip install pyinstaller --upgrade
python -m pip install psutil --upgrade
python -m pip install ctypes --upgrade
python -m pip install shutil --upgrade
python -m pip install requests --upgrade
python -m pip install scapy --upgrade
python -m pip install black --upgrade
python -m pip install pypiwin32 --upgrade
%1 start mshta vbscript:Msgbox("����ģ��������",4096)(window.close)
exit