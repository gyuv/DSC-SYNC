@echo off
rem Removes DSC-Sync for the current user.
taskkill /im DSC-Sync.exe /fi "USERNAME eq %USERNAME%" /f >nul 2>&1
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v DSC-Sync /f >nul 2>&1
reg delete "HKCU\Software\Microsoft\Terminal Server Client\Default\AddIns\DSCSync" /f >nul 2>&1
rmdir /s /q "%LOCALAPPDATA%\Programs\DSC-Sync" >nul 2>&1
echo DSC-Sync removed for %USERNAME%. Settings remain in %APPDATA%\DSC-Sync (delete manually if wanted).
pause
