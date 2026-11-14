@echo off
rem DSC-Sync — Local PC (the PC where the USB DSC token is plugged in). No administrator rights needed.
setlocal
set "TARGET=%LOCALAPPDATA%\Programs\DSC-Sync"
taskkill /im DSC-Sync.exe /f >nul 2>&1
if not exist "%TARGET%" mkdir "%TARGET%"
copy /y "%~dp0DSC-Sync.exe" "%TARGET%\" >nul || goto :error
copy /y "%~dp0DSC-Sync-RdpPlugin.dll" "%TARGET%\" >nul || goto :error
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v DSC-Sync /t REG_SZ /d "\"%TARGET%\DSC-Sync.exe\" --minimized" /f >nul
reg add "HKCU\Software\Microsoft\Terminal Server Client\Default\AddIns\DSCSync" /v Name /t REG_SZ /d "%TARGET%\DSC-Sync-RdpPlugin.dll" /f >nul
start "" "%TARGET%\DSC-Sync.exe" --mode Local
echo.
echo DSC-Sync (Local PC) installed to %TARGET%
echo It starts automatically when you sign in. Now connect to your server with Remote Desktop.
pause
exit /b 0
:error
echo Installation failed. Close DSC-Sync and try again.
pause
exit /b 1
