@echo off
echo [*] Setting up Python environment for Leopard...

echo [*] Creating virtual environment in '.\venv\'...
python -m venv venv

echo [*] Activating virtual environment and installing dependencies...
call .\\venv\\Scripts\\activate.bat
pip install -r requirements.txt

echo.
echo [*] Setup complete!
echo [*] You can now run the build script (build_windows_exe.bat) to create the .exe
echo [*] or run the GUI directly for testing with: python leopard.py
pause