@echo off
rem DSC-Sync — Remote Desktop / cloud server, for the CURRENT user only. No administrator rights needed.
setlocal
set "TARGET=%LOCALAPPDATA%\Programs\DSC-Sync"
taskkill /im DSC-Sync.exe /fi "USERNAME eq %USERNAME%" /f >nul 2>&1
if not exist "%TARGET%" mkdir "%TARGET%"
copy /y "%~dp0DSC-Sync.exe" "%TARGET%\" >nul || goto :error
copy /y "%~dp0DSC-Sync-P11-*.dll" "%TARGET%\" >nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v DSC-Sync /t REG_SZ /d "\"%TARGET%\DSC-Sync.exe\" --minimized" /f >nul
start "" "%TARGET%\DSC-Sync.exe" --mode Remote
echo.
echo DSC-Sync (Remote) installed to %TARGET%
echo PKCS#11 module for Adobe Acrobat: %TARGET%\DSC-Sync-P11-x64.dll
pause
exit /b 0
:error
echo Installation failed.
pause
exit /b 1
