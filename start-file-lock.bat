@echo off
setlocal
powershell.exe -NoProfile -ExecutionPolicy Bypass -STA -File "%~dp0FileLockApp.ps1"
if errorlevel 1 (
    echo.
    echo File Lock could not start. Check that Windows PowerShell is available.
    pause
)
endlocal
