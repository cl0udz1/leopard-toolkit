@echo off
echo [*] Starting the build process for Leopard...

:: Activate virtual environment if it exists
IF EXIST .\\venv\\Scripts\\activate.bat (
    echo [*] Activating virtual environment...
    call .\\venv\\Scripts\\activate.bat
) ELSE (
    echo [!] Virtual environment not found. Please run setup_win.bat first.
    pause
    exit /b
)

echo [*] Running PyInstaller to create the executable...

pyinstaller --name Leopard ^
    --onefile ^
    --windowed ^
    --icon=icon.ico ^
    --add-data="C:\\Windows\\System32\\netsh.exe;." ^
    leopard.py

echo [*] Build process complete.
echo [*] You can find the executable (Leopard.exe) in the 'dist' folder.
pause