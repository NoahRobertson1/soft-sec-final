@echo off
NET SESSION >nul 2>&1
IF %ERRORLEVEL% NEQ 0 (
    echo Error: Please run as Administrator
    pause
    exit /b 1
)

set DRIVER_NAME=AntiCheat
set DRIVER_PATH=%~dp0anti-cheat.sys

:: Check if driver file exists
IF NOT EXIST "%DRIVER_PATH%" (
    echo Error: anti-cheat.sys not found in %~dp0
    pause
    exit /b 1
)

:: Check if already registered
sc query %DRIVER_NAME% >nul 2>&1
IF %ERRORLEVEL% EQU 0 (
    echo Driver already registered, stopping and removing first...
    sc stop %DRIVER_NAME% >nul 2>&1
    sc delete %DRIVER_NAME% >nul 2>&1
    timeout /t 2 /nobreak >nul
)

echo Registering driver...
sc create %DRIVER_NAME% type= kernel binPath= "%DRIVER_PATH%"
IF %ERRORLEVEL% NEQ 0 (
    echo Error: Failed to register driver
    pause
    exit /b 1
)

echo Starting driver...
sc start %DRIVER_NAME%
IF %ERRORLEVEL% NEQ 0 (
    echo Error: Failed to start driver
    sc delete %DRIVER_NAME% >nul 2>&1
    pause
    exit /b 1
)

echo.
echo Driver loaded successfully
echo   Device:  \\Device\\AntiCheat
echo   SymLink: \\.\AntiCheat
echo.
pause