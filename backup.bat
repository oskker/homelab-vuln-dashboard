@echo off
rem Saves the dashboard's database to the backups folder: every scan, every finding and
rem its history, and the original reports. Run it while the dashboard is running.
rem The backup describes your network in detail. Keep it somewhere private.
setlocal
cd /d "%~dp0"

for /f %%t in ('powershell -NoProfile -Command "Get-Date -Format yyyyMMdd-HHmmss"') do set STAMP=%%t
if not exist backups mkdir backups
set NAME=backups\vulndash-%STAMP%.dump

docker compose exec -T db pg_dump -U vulndash -d vulndash --format=custom --file=/tmp/backup.dump
if errorlevel 1 goto failed
docker compose cp db:/tmp/backup.dump "%NAME%"
if errorlevel 1 goto failed
docker compose exec -T db rm -f /tmp/backup.dump

echo.
echo Saved %NAME%
echo To restore it later, drag the file onto restore.bat.
pause
exit /b 0

:failed
echo.
echo The backup failed. Start the dashboard with start.bat first, then run this again.
pause
exit /b 1
