@echo off
rem Stops the dashboard. Your data stays in the Docker volume and is there next time.
setlocal
cd /d "%~dp0"
docker compose down
pause
