@echo off
NET SESSION >nul 2>&1
IF %ERRORLEVEL% NEQ 0 (
    echo Error: Please run as Administrator
    pause
    exit /b 1
)

:: Check current test signing status
bcdedit /enum | find "testsigning" | find "Yes" >nul 2>&1
IF %ERRORLEVEL% EQU 0 (
    echo Test signing is currently: ENABLED
    echo.
    choice /C YN /M "Do you want to DISABLE test signing?"
    IF %ERRORLEVEL% EQU 1 (
        bcdedit /set testsigning off
        bcdedit /set nointegritychecks off
        echo Test signing DISABLED - reboot required
    )
) ELSE (
    echo Test signing is currently: DISABLED
    echo.
    choice /C YN /M "Do you want to ENABLE test signing?"
    IF %ERRORLEVEL% EQU 1 (
        bcdedit /set testsigning on
        bcdedit /set nointegritychecks on
        echo Test signing ENABLED - reboot required
    )
)

echo.
choice /C YN /M "Reboot now?"
IF %ERRORLEVEL% EQU 1 (
    shutdown /r /t 5 /c "Rebooting to apply test signing changes"
)

pause