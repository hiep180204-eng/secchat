@echo off
REM ============================================================
REM  SecChat Client - Windows Setup
REM  Run this from the project folder (Desktop\secchat)
REM  Requires: Python 3.10+, Git, CMake, Visual Studio Build Tools
REM ============================================================

echo ============================================
echo   SecChat Client - Windows Setup
echo ============================================
echo.

REM Check Python
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python not found!
    echo Install Python 3.10+ from https://www.python.org/downloads/
    echo Make sure to check "Add Python to PATH"
    pause
    exit /b 1
)

REM Check Git
git --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Git not found!
    echo Install Git from https://git-scm.com/download/win
    pause
    exit /b 1
)

REM Check CMake
cmake --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] CMake not found!
    echo Install CMake from https://cmake.org/download/
    echo Or: pip install cmake
    pause
    exit /b 1
)

echo [1/5] Creating virtual environment...
if not exist ".venv" (
    python -m venv .venv
)
call .venv\Scripts\activate.bat

echo [2/5] Installing Python packages...
pip install --upgrade pip
pip install PyQt5 cryptography cmake ninja

echo [3/5] Building liboqs from source...
set OQS_DIR=%USERPROFILE%\_oqs
if not exist "%OQS_DIR%\lib\oqs.dll" (
    echo Cloning liboqs...
    if exist "%OQS_DIR%\src" rmdir /s /q "%OQS_DIR%\src"
    mkdir "%OQS_DIR%\src" 2>nul
    git clone --depth 1 https://github.com/open-quantum-safe/liboqs.git "%OQS_DIR%\src"
    if errorlevel 1 (
        echo [ERROR] Failed to clone liboqs
        pause
        exit /b 1
    )
    echo Building liboqs (this may take a few minutes)...
    cmake -S "%OQS_DIR%\src" -B "%OQS_DIR%\build" -DOQS_DIST_BUILD=ON -DBUILD_SHARED_LIBS=ON -DOQS_BUILD_ONLY_LIB=ON
    if errorlevel 1 (
        echo [ERROR] CMake configure failed. Make sure Visual Studio Build Tools are installed.
        echo Download from: https://visualstudio.microsoft.com/visual-cpp-build-tools/
        pause
        exit /b 1
    )
    cmake --build "%OQS_DIR%\build" --config Release
    if errorlevel 1 (
        echo [ERROR] Build failed
        pause
        exit /b 1
    )
    mkdir "%OQS_DIR%\lib" 2>nul
    mkdir "%OQS_DIR%\bin" 2>nul
    mkdir "%OQS_DIR%\include" 2>nul
    copy "%OQS_DIR%\build\lib\Release\oqs.dll" "%OQS_DIR%\lib\" 2>nul
    copy "%OQS_DIR%\build\lib\Release\oqs.lib" "%OQS_DIR%\lib\" 2>nul
    REM liboqs-python on Windows looks in _oqs\bin\oqs.dll
    copy "%OQS_DIR%\build\lib\Release\oqs.dll" "%OQS_DIR%\bin\" 2>nul
    REM Also copy to build dir for liboqs-python to find
    copy "%OQS_DIR%\build\lib\Release\oqs.dll" "%OQS_DIR%\build\lib\" 2>nul
    xcopy /s /y "%OQS_DIR%\src\src\oqs\*.h" "%OQS_DIR%\include\oqs\" 2>nul
    echo liboqs built successfully!
) else (
    echo liboqs already built, skipping...
)

echo [4/5] Installing liboqs-python...
set LIBOQS_INSTALL_PATH=%OQS_DIR%
set PATH=%OQS_DIR%\lib;%PATH%
pip install liboqs-python

echo [5/5] Copying DLL to venv for runtime...
copy "%OQS_DIR%\lib\oqs.dll" ".venv\Scripts\" 2>nul
copy "%OQS_DIR%\lib\oqs.dll" ".venv\Lib\site-packages\" 2>nul
REM Also place in _oqs\bin which is where liboqs-python actually looks on Windows
copy "%OQS_DIR%\lib\oqs.dll" "%OQS_DIR%\bin\" 2>nul

echo.
echo ============================================
echo   Setup complete!
echo.
echo   To run the client:
echo     Double-click run_client.bat
echo.
echo   On the login screen:
echo     SERVER: localhost
echo     PORT:   8888
echo ============================================
pause
