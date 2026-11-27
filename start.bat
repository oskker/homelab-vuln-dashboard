@echo off
rem Starts the dashboard, and OpenVAS next to it, on this PC. Double-click it, or run it
rem from a terminal. Run it again at any time: it only changes what needs changing.
setlocal
cd /d "%~dp0"

where docker >nul 2>nul
if errorlevel 1 goto no_docker

if exist .env goto have_env
echo Creating .env with random passwords...
powershell -NoProfile -Command "function New-Secret { $b = New-Object byte[] 24; [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($b); -join ($b | ForEach-Object { $_.ToString('x2') }) }; (Get-Content .env.example) -replace '^POSTGRES_PASSWORD=change-me$', ('POSTGRES_PASSWORD=' + (New-Secret)) -replace '^OPENVAS_PASSWORD=change-me$', ('OPENVAS_PASSWORD=' + (New-Secret)) | Set-Content -Encoding ascii .env"
if errorlevel 1 goto failed
:have_env

rem A .env from version 0.1 has no OpenVAS settings yet. Add them; nothing else changes.
findstr /b /c:"OPENVAS_PASSWORD=" .env >nul
if not errorlevel 1 goto have_openvas_password
echo Adding OpenVAS settings to .env...
powershell -NoProfile -Command "$b = New-Object byte[] 24; [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($b); $p = -join ($b | ForEach-Object { $_.ToString('x2') }); Add-Content -Encoding ascii .env ([Environment]::NewLine + 'OPENVAS=on' + [Environment]::NewLine + 'OPENVAS_PASSWORD=' + $p)"
if errorlevel 1 goto failed
:have_openvas_password

set FILES=-f docker-compose.yml -f docker-compose.openvas.yml
set WITH_OPENVAS=1
findstr /b /i /c:"OPENVAS=off" .env >nul
if errorlevel 1 goto start
set FILES=-f docker-compose.yml
set WITH_OPENVAS=0

:start
echo Starting. The first run downloads and builds for several minutes.
docker compose %FILES% up -d --build
if errorlevel 1 goto failed

echo Waiting for the dashboard to answer...
powershell -NoProfile -Command "for ($i = 0; $i -lt 90; $i++) { try { Invoke-WebRequest -UseBasicParsing -Uri http://127.0.0.1:8000/healthz | Out-Null; exit 0 } catch { Start-Sleep -Seconds 2 } }; exit 1"
if errorlevel 1 goto failed

start "" http://localhost:8000
echo.
echo The dashboard is open at http://localhost:8000
if "%WITH_OPENVAS%"=="0" goto done
echo.
echo OpenVAS is starting next to it. On the first start it loads its vulnerability
echo feed, which can take 30 minutes or more. The Scans tab shows when it is ready.
echo The Greenbone web interface is optional: https://127.0.0.1 (user admin, password
echo OPENVAS_PASSWORD in the .env file).
:done
echo.
echo To stop everything, double-click stop.bat. Your data is kept for next time.
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
