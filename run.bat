@echo off
:: Request admin privileges automatically
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Requesting Administrator privileges...
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

title MACalypse [ADMIN]
echo.
echo   ================================================
echo      MACalypse - Network Identity Toolkit [ADMIN]
echo   ================================================
echo.
echo   Running as Administrator - all features available!
echo.
echo   Opening window...
echo.
cd /d "%~dp0"
python "%~dp0app.py"
echo.
echo   App closed.
pause
