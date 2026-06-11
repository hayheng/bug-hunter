@echo off
chcp 65001 >nul
title 自动化漏洞挖掘系统

cd /d "%~dp0"

echo.
echo ╔════════════════════════════════════════════════════════════╗
echo ║           🎯 自动化漏洞挖掘系统                           ║
echo ╚════════════════════════════════════════════════════════════╝
echo.

:input
set /p target="请输入目标域名 (输入q退出): "

if "%target%"=="q" (
    exit /b 0
)

if "%target%"=="" (
    echo [错误] 请输入目标域名
    goto input
)

echo.
echo [开始扫描] %target%
echo.
python main.py %target%

echo.
echo [完成] 扫描结束
echo.
goto input
