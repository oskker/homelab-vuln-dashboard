@echo off
rem Restores a backup made by backup.bat. Drag a .dump file onto this script, or run
rem   restore.bat backups\vulndash-20261126-210000.dump
rem Everything currently in the dashboard is replaced by the backup.
setlocal
cd /d "%~dp0"

if "%~1"=="" goto usage
if not exist "%~1" goto usage

echo This replaces everything in the dashboard with the backup %~nx1.
choice /c YN /m "Continue"
if errorlevel 2 exit /b 1

docker compose stop app
if errorlevel 1 goto failed
docker compose cp "%~1" db:/tmp/restore.dump
if errorlevel 1 goto failed
docker compose exec -T db pg_restore -U vulndash -d vulndash --clean --if-exists --no-owner /tmp/restore.dump
if errorlevel 1 goto failed
docker compose exec -T db rm -f /tmp/restore.dump
docker compose start app

echo.
echo Restored. Reload the dashboard in your browser.
pause
exit /b 0

:usage
echo Drag a .dump file from the backups folder onto restore.bat.
pause
exit /b 1

:failed
echo.
echo The restore did not finish. Check that the dashboard is running (start.bat), then
echo try again. Starting the app again...
docker compose start app
pause
exit /b 1
