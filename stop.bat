@echo off
rem Stops the dashboard and OpenVAS. Your data stays in Docker volumes for next time.
setlocal
cd /d "%~dp0"
set FILES=-f docker-compose.yml -f docker-compose.openvas.yml
findstr /b /c:"OPENVAS_PASSWORD=" .env >nul 2>nul
if errorlevel 1 set FILES=-f docker-compose.yml
docker compose %FILES% down
pause
