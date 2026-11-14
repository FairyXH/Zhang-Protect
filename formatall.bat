@echo off
cd /d "%~dp0"
set python="%cd%\Python\Python.exe"
for %%i in (*.py) do (if %%~zi leq 3072000 %python% -m black "%%i")