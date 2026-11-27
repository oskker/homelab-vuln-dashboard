@echo off
rem Starts the dashboard on this PC. Double-click it, or run it from a terminal.
setlocal
cd /d "%~dp0"

where docker >nul 2>nul
if errorlevel 1 goto no_docker

if exist .env goto have_env
echo Creating .env with a random database password...
powershell -NoProfile -Command "$b = New-Object byte[] 24; [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($b); $p = -join ($b | ForEach-Object { $_.ToString('x2') }); (Get-Content .env.example) -replace 'change-me', $p | Set-Content -Encoding ascii .env"
if errorlevel 1 goto failed
:have_env

echo Starting the dashboard. The first run downloads and builds for a few minutes.
docker compose up -d --build
if errorlevel 1 goto failed

echo Waiting for the dashboard to answer...
powershell -NoProfile -Command "for ($i = 0; $i -lt 60; $i++) { try { Invoke-WebRequest -UseBasicParsing -Uri http://127.0.0.1:8000/healthz | Out-Null; exit 0 } catch { Start-Sleep -Seconds 2 } }; exit 1"
if errorlevel 1 goto failed

start "" http://localhost:8000
echo.
echo The dashboard is open at http://localhost:8000
echo To stop it later, double-click stop.bat.
pause
exit /b 0

:no_docker
echo Docker Desktop was not found. Install it from docker.com, start it, then run this again.
pause
exit /b 1

:failed
echo.
echo Something went wrong. Check that Docker Desktop is running, then run this again.
pause
exit /b 1
