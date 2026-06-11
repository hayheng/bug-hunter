@echo off
cd /d "%~dp0"
echo.
echo ================================
echo   Auto Bug Hunter v2.0
echo ================================
echo.

:input
set /p target="Enter target domain (q to quit): "

if "%target%"=="q" goto end
if "%target%"=="" goto input

echo.
echo Scanning: %target%
echo.
python main.py %target%
echo.
echo Scan complete!
echo.
goto input

:end
exit /b 0
