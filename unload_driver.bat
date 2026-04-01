@echo off
NET SESSION >nul 2>&1
IF %ERRORLEVEL% NEQ 0 (
    echo Error: Please run as Administrator
    pause
    exit /b 1
)

set DRIVER_NAME=AntiCheat

echo Stopping driver...
sc stop %DRIVER_NAME%
timeout /t 2 /nobreak >nul

echo Removing driver...
sc delete %DRIVER_NAME%

echo Driver unloaded successfully
pause