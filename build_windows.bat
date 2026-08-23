@echo off
REM ============================================================
REM  SpiderPhish - Windows build script
REM  Produces: dist\SpiderPhish.exe
REM ============================================================
setlocal enabledelayedexpansion
cd /d "%~dp0"

echo.
echo [1/5] Checking Python environment...
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python not found in PATH. Install Python 3.10+ first.
    pause & exit /b 1
)

echo [2/5] Installing dependencies...
python -m pip install -r requirements.txt pyinstaller --quiet --disable-pip-version-check
if errorlevel 1 (
    echo ERROR: dependency installation failed.
    pause & exit /b 1
)

echo [3/5] Generating application icon...
if not exist assets\spiderphish.ico (
    python scripts\generate_icon.py
    if errorlevel 1 (
        echo WARNING: icon generation failed, building without custom icon.
    )
)

echo [4/5] Cleaning previous builds...
if exist build rmdir /s /q build
if exist dist rmdir /s /q dist

echo [5/5] Building executable with PyInstaller...
python -m PyInstaller spiderphish.spec --noconfirm
if errorlevel 1 (
    echo ERROR: PyInstaller build failed.
    pause & exit /b 1
)

echo.
echo ============================================================
echo  BUILD OK
echo  Output: dist\SpiderPhish.exe
echo ============================================================
pause

