# -*- coding: utf-8 -*-
"""
软件漏洞扫描统一入口
支持: Android APK, iOS IPA, Windows EXE, Electron, 小程序, .NET
"""

import os
import sys
from pathlib import Path
from typing import List, Dict


def detect_software_type(path: str) -> str:
    """检测软件类型"""
    p = Path(path)

    # 检查是否是文件
    if p.is_file():
        suffix = p.suffix.lower()
        if suffix == '.apk':
            return 'android'
        elif suffix == '.ipa':
            return 'ios'
        elif suffix == '.exe':
            # 检查是否是 .NET
            try:
                with open(path, 'rb') as f:
                    content = f.read(1024)
                if b'mscoree.dll' in content or b'_CorExeMain' in content:
                    return 'dotnet'
            except:
                pass
            return 'windows'
        elif suffix == '.dll':
            return 'dotnet'
        elif suffix == '.asar':
            return 'electron'
        elif suffix == '.wxapkg':
            return 'wechat_miniapp'
        elif suffix == '.jar':
            return 'java'
        elif suffix == '.pyc':
            return 'python'

    # 检查是否是目录
    elif p.is_dir():
        # 检查 Android
        if (p / "AndroidManifest.xml").exists():
            return 'android'

        # 检查 Electron
        if (p / "resources" / "app.asar").exists():
            return 'electron'
        if (p / "package.json").exists():
            try:
                import json
                with open(p / "package.json", 'r') as f:
                    config = json.load(f)
                if 'electron' in config.get('devDependencies', {}):
                    return 'electron'
                if 'nw' in config.get('dependencies', {}):
                    return 'nwjs'
            except:
                pass

        # 检查微信小程序
        if (p / "app.json").exists() and (p / "app.wxss").exists():
            return 'wechat_miniapp'
        if (p / "app.json").exists() and (p / "pages").exists():
            for file in os.listdir(p):
                if file.endswith('.wxml'):
                    return 'wechat_miniapp'

        # 检查支付宝小程序
        if (p / "app.json").exists() and (p / "app.acss").exists():
            return 'alipay_miniapp'

        # 检查 Windows 应用
        for file in os.listdir(p):
            if file.endswith('.exe'):
                return 'windows'

    return 'unknown'


def scan_software(path: str, deep: bool = False) -> List[Dict]:
    """扫描软件"""
    software_type = detect_software_type(path)
    print(f"[*] 检测到软件类型: {software_type}")

    vulnerabilities = []

    if software_type == 'android':
        if deep:
            from apk_decompiler import APKDecompiler
            decompiler = APKDecompiler(path)
            if decompiler.decompile():
                vulnerabilities = decompiler.scan()
        else:
            from apk_scanner import APKScanner
            scanner = APKScanner(path)
            vulnerabilities = scanner.scan()

    elif software_type in ['electron', 'nwjs']:
        from desktop_scanner import DesktopScanner
        scanner = DesktopScanner(path)
        vulnerabilities = scanner.scan()

    elif software_type == 'windows':
        from desktop_scanner import DesktopScanner
        scanner = DesktopScanner(path)
        vulnerabilities = scanner.scan()

        # 增强字符串分析
        from enhanced_strings import EnhancedStringAnalyzer
        analyzer = EnhancedStringAnalyzer(path)
        result = analyzer.analyze()
        vulnerabilities.extend(result['vulnerabilities'])

    elif software_type == 'dotnet':
        from dotnet_scanner import DotNetScanner
        scanner = DotNetScanner(path)
        vulnerabilities = scanner.scan()

    elif software_type in ['wechat_miniapp', 'alipay_miniapp']:
        from miniapp_scanner import MiniAppScanner
        scanner = MiniAppScanner(path)
        vulnerabilities = scanner.scan()

    elif software_type == 'java':
        print("[*] Java JAR 文件扫描")
        print("[*] 请使用 jadx 反编译后扫描")

    elif software_type == 'python':
        print("[*] Python 字节码扫描")
        print("[*] 请使用 uncompyle6 反编译后扫描")

    else:
        print(f"[!] 不支持的软件类型: {software_type}")
        print("[*] 支持的类型:")
        print("    - Android APK (.apk)")
        print("    - Windows EXE (.exe)")
        print("    - .NET 程序 (.exe, .dll)")
        print("    - Electron应用 (目录或.asar)")
        print("    - 微信小程序 (.wxapkg或目录)")
        print("    - 支付宝小程序 (目录)")

    return vulnerabilities


def main():
    if len(sys.argv) < 2:
        print("软件漏洞扫描工具")
        print()
        print("用法:")
        print("  python software_scanner.py <软件路径> [--deep]")
        print()
        print("支持的软件类型:")
        print("  - Android APK (.apk)")
        print("  - Windows EXE (.exe)")
        print("  - .NET 程序 (.exe, .dll)")
        print("  - Electron应用 (目录或.asar文件)")
        print("  - 微信小程序 (.wxapkg文件或小程序目录)")
        print("  - 支付宝小程序 (小程序目录)")
        print()
        print("选项:")
        print("  --deep    深度扫描（反编译分析）")
        print()
        print("示例:")
        print("  python software_scanner.py app.apk")
        print("  python software_scanner.py app.apk --deep")
        print("  python software_scanner.py app.exe")
        print("  python software_scanner.py ./electron-app/")
        print("  python software_scanner.py app.wxapkg")
        return

    path = sys.argv[1]
    deep = "--deep" in sys.argv

    if not os.path.exists(path):
        print(f"[错误] 路径不存在: {path}")
        return

    vulns = scan_software(path, deep)

    if vulns:
        print(f"\n[*] 发现 {len(vulns)} 个漏洞:")
        for vuln in vulns:
            print(f"  [{vuln['severity']}] {vuln['type']}: {vuln['description']}")
    else:
        print("\n[*] 未发现漏洞")


if __name__ == "__main__":
    main()
