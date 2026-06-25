@echo off
REM Run SecChat client on Windows
cd /d "%~dp0"
if exist ".venv\Scripts\activate.bat" (
    call .venv\Scripts\activate.bat
)
REM Ensure liboqs DLL is findable (liboqs-python looks in _oqs\bin on Windows)
set PATH=%USERPROFILE%\_oqs\bin;%USERPROFILE%\_oqs\lib;%PATH%
python run_client.py
if errorlevel 1 pause
