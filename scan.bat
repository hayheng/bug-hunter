@echo off
chcp 65001 >nul
title 自动化漏洞挖掘系统
echo.
echo ╔════════════════════════════════════════════════════════════╗
echo ║           🎯 自动化漏洞挖掘系统                           ║
echo ╚════════════════════════════════════════════════════════════╝
echo.

cd /d "%~dp0"

python --version >nul 2>&1
if errorlevel 1 (
    echo [错误] 未找到 Python，请先安装 Python
    echo 下载地址: https://www.python.org/downloads/
    pause
    exit /b 1
)

echo [✓] Python 已安装
echo.

if "%1"=="" (
    echo 用法:
    echo   scan.bat example.com              - 完整扫描
    echo   scan.bat example.com subdomain    - 只枚举子域名
    echo   scan.bat example.com alive        - 只检测存活
    echo   scan.bat example.com scan         - 只扫描漏洞
    echo.
    set /p target="请输入目标域名: "
    if "!target!"=="" (
        echo 未输入目标，退出
        pause
        exit /b 1
    )
    echo.
    echo [开始扫描] !target!
    echo.
    python main.py !target!
) else (
    if "%2"=="" (
        echo [开始扫描] %1
        echo.
        python main.py %1
    ) else (
        echo [开始扫描] %1 -m %2
        echo.
        python main.py %1 -m %2
    )
)

echo.
echo [完成] 扫描结束
echo.
pause
