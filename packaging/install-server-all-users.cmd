@echo off
rem DSC-Sync — install ONCE on the Windows Server 2019 for ALL users (run as Administrator).
net session >nul 2>&1 || (echo Please right-click and "Run as administrator". & pause & exit /b 1)
setlocal
set "TARGET=%ProgramFiles%\DSC-Sync"
if not exist "%TARGET%" mkdir "%TARGET%"
copy /y "%~dp0DSC-Sync.exe" "%TARGET%\" >nul || (echo Close DSC-Sync in all sessions first. & pause & exit /b 1)
copy /y "%~dp0DSC-Sync-P11-*.dll" "%TARGET%\" >nul
rem Start for every user at sign-in (each user gets their own instance and their own Local PC token).
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v DSC-Sync /t REG_SZ /d "\"%TARGET%\DSC-Sync.exe\" --minimized --mode Remote" /f >nul
rem Shared usage-report folder: every user can add their own records and read the reports.
if not exist "%ProgramData%\DSC-Sync\audit" mkdir "%ProgramData%\DSC-Sync\audit"
icacls "%ProgramData%\DSC-Sync\audit" /grant *S-1-5-32-545:(OI)(CI)(RX,WD,AD) /T >nul
rem emSigner cannot see USB tokens on the server and blocks the ports: disable its service if present.
for /f "tokens=2 delims=: " %%s in ('sc query state^= all ^| findstr /i "SERVICE_NAME:.*emsigner"') do (sc stop %%s >nul 2>&1 & sc config %%s start= disabled >nul 2>&1)
echo.
echo DSC-Sync installed for all users in %TARGET%.
echo Each user: install DSC-Sync-Local on their own PC, then connect with Remote Desktop.
echo Adobe Acrobat PKCS#11 module: %TARGET%\DSC-Sync-P11-x64.dll
pause
