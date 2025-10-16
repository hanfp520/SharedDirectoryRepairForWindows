@echo off
chcp 65001 >nul
echo ========================================
echo Advanced SMB Fix Tool Launcher
echo ========================================
echo.
echo Starting advanced SMB repair tool...
echo This tool is designed to fix error 0x80004005 and credential issues.
echo.
powershell -ExecutionPolicy Bypass -File "%~dp0Fix-SMBAccess-Advanced.ps1"
echo.
echo Repair process completed!
echo It is recommended to restart your computer to ensure all changes take effect.
echo.
pause
