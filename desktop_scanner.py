# -*- coding: utf-8 -*-
"""
桌面应用漏洞扫描模块
支持: Windows EXE, Electron, NW.js
"""

import os
import re
import json
import subprocess
import tempfile
from typing import List, Dict
from pathlib import Path


class DesktopScanner:
    """桌面应用漏洞扫描器"""

    def __init__(self, app_path: str):
        self.app_path = app_path
        self.app_name = Path(app_path).stem
        self.app_type = self._detect_app_type()
        self.vulnerabilities = []

    def scan(self) -> List[Dict]:
        """执行扫描"""
        print(f"[*] 开始扫描桌面应用: {self.app_name}")
        print(f"[*] 应用类型: {self.app_type}")

        if self.app_type == "electron":
            self._scan_electron()
        elif self.app_type == "nwjs":
            self._scan_nwjs()
        elif self.app_type == "windows":
            self._scan_windows_exe()
        else:
            print(f"[!] 不支持的应用类型: {self.app_type}")

        print(f"[*] 扫描完成，发现 {len(self.vulnerabilities)} 个漏洞")
        return self.vulnerabilities

    def _detect_app_type(self) -> str:
        """检测应用类型"""
        path = Path(self.app_path)

        # 检查是否是目录
        if path.is_dir():
            # 检查Electron
            if (path / "resources" / "app.asar").exists():
                return "electron"
            if (path / "package.json").exists():
                return "electron"
            # 检查NW.js
            if (path / "package.json").exists() and (path / "nw.exe").exists():
                return "nwjs"

        # 检查文件扩展名
        if path.suffix.lower() == '.exe':
            return "windows"
        if path.suffix.lower() == '.asar':
            return "electron"

        return "unknown"

    def _scan_electron(self):
        """扫描Electron应用"""
        print("[*] 扫描Electron应用...")

        # 提取asar文件
        asar_path = self._find_asar()
        if not asar_path:
            print("[!] 未找到asar文件")
            return

        # 解包asar
        extracted_dir = self._extract_asar(asar_path)
        if not extracted_dir:
            return

        try:
            # 扫描源码
            self._scan_source_code(extracted_dir)

            # 扫描配置文件
            self._scan_electron_config(extracted_dir)

            # 扫描敏感信息
            self._scan_sensitive_info(extracted_dir)

        finally:
            # 清理
            import shutil
            shutil.rmtree(extracted_dir, ignore_errors=True)

    def _find_asar(self) -> str:
        """查找asar文件"""
        path = Path(self.app_path)

        if path.is_dir():
            # 常见asar位置
            possible_paths = [
                path / "resources" / "app.asar",
                path / "resources" / "app" / "app.asar",
                path / "app.asar",
            ]
            for p in possible_paths:
                if p.exists():
                    return str(p)
        elif path.suffix == '.asar':
            return str(path)

        return None

    def _extract_asar(self, asar_path: str) -> str:
        """解包asar文件"""
        try:
            temp_dir = tempfile.mkdtemp()
            subprocess.run(
                ["npx", "asar", "extract", asar_path, temp_dir],
                capture_output=True,
                timeout=60
            )
            return temp_dir
        except Exception as e:
            print(f"[!] 解包asar失败: {e}")
            return None

    def _scan_nwjs(self):
        """扫描NW.js应用"""
        print("[*] 扫描NW.js应用...")

        path = Path(self.app_path)
        if path.is_dir():
            self._scan_source_code(str(path))
            self._scan_sensitive_info(str(path))

    def _scan_windows_exe(self):
        """扫描Windows EXE"""
        print("[*] 扫描Windows EXE...")

        # 使用strings提取字符串
        try:
            result = subprocess.run(
                ["strings", self.app_path],
                capture_output=True,
                text=True,
                timeout=30
            )
            content = result.stdout

            # 扫描敏感信息
            self._scan_strings(content)

        except FileNotFoundError:
            print("[!] strings命令未安装，跳过字符串分析")

    def _scan_source_code(self, directory: str):
        """扫描源码"""
        # 敏感信息模式
        patterns = {
            "API Key": r'["\'](?:api[_-]?key|apikey)["\']?\s*[:=]\s*["\'][a-zA-Z0-9]{20,}["\']',
            "Secret Key": r'["\'](?:secret[_-]?key|secretkey)["\']?\s*[:=]\s*["\'][a-zA-Z0-9]{20,}["\']',
            "Password": r'["\'](?:password|passwd|pwd)["\']?\s*[:=]\s*["\'][^"\']{6,}["\']',
            "Token": r'["\'](?:token|access_token|auth_token)["\']?\s*[:=]\s*["\'][a-zA-Z0-9]{20,}["\']',
            "AWS Key": r'(?:AKIA|ASIA)[A-Z0-9]{16}',
            "Private Key": r'-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----',
            "Database URL": r'(?:mysql|postgres|mongodb|redis)://[^\s]+',
            "Internal URL": r'https?://(?:10\.|172\.(?:1[6-9]|2[0-9]|3[01])\.|192\.168\.)[^\s]+',
        }

        for root, dirs, files in os.walk(directory):
            for file in files:
                if file.endswith(('.js', '.json', '.html', '.css', '.ts')):
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()

                        for vuln_type, pattern in patterns.items():
                            matches = re.findall(pattern, content, re.IGNORECASE)
                            if matches:
                                self.vulnerabilities.append({
                                    "type": "信息泄露",
                                    "severity": "High",
                                    "url": file_path,
                                    "description": f"发现{vuln_type}硬编码",
                                    "evidence": matches[0][:100],
                                    "remediation": "使用环境变量或安全存储"
                                })
                    except Exception:
                        continue

    def _scan_electron_config(self, directory: str):
        """扫描Electron配置"""
        package_json_path = os.path.join(directory, "package.json")
        if not os.path.exists(package_json_path):
            return

        try:
            with open(package_json_path, 'r', encoding='utf-8') as f:
                config = json.load(f)

            # 检查nodeIntegration
            if config.get("nodeIntegration") == True:
                self.vulnerabilities.append({
                    "type": "配置错误",
                    "severity": "High",
                    "url": package_json_path,
                    "description": "Electron开启了nodeIntegration",
                    "evidence": "nodeIntegration: true",
                    "remediation": "设置nodeIntegration: false，使用contextBridge"
                })

            # 检查webSecurity
            if config.get("webSecurity") == False:
                self.vulnerabilities.append({
                    "type": "配置错误",
                    "severity": "High",
                    "url": package_json_path,
                    "description": "Electron禁用了webSecurity",
                    "evidence": "webSecurity: false",
                    "remediation": "设置webSecurity: true"
                })

            # 检查allowRunningInsecureContent
            if config.get("allowRunningInsecureContent") == True:
                self.vulnerabilities.append({
                    "type": "配置错误",
                    "severity": "High",
                    "url": package_json_path,
                    "description": "Electron允许运行不安全内容",
                    "evidence": "allowRunningInsecureContent: true",
                    "remediation": "设置allowRunningInsecureContent: false"
                })

        except Exception as e:
            pass

    def _scan_sensitive_info(self, directory: str):
        """扫描敏感信息"""
        # 扫描.env文件
        env_files = [".env", ".env.local", ".env.production"]
        for env_file in env_files:
            env_path = os.path.join(directory, env_file)
            if os.path.exists(env_path):
                self.vulnerabilities.append({
                    "type": "信息泄露",
                    "severity": "Critical",
                    "url": env_path,
                    "description": "发现.env配置文件",
                    "evidence": "文件存在",
                    "remediation": "删除.env文件，使用环境变量"
                })

        # 扫描配置文件
        config_files = ["config.json", "config.yml", "config.yaml", "settings.json"]
        for config_file in config_files:
            config_path = os.path.join(directory, config_file)
            if os.path.exists(config_path):
                try:
                    with open(config_path, 'r', encoding='utf-8') as f:
                        content = f.read()

                    # 检查是否包含敏感信息
                    sensitive_patterns = [
                        r'password', r'secret', r'key', r'token',
                        r'api[_-]?key', r'access[_-]?key'
                    ]

                    for pattern in sensitive_patterns:
                        if re.search(pattern, content, re.IGNORECASE):
                            self.vulnerabilities.append({
                                "type": "信息泄露",
                                "severity": "High",
                                "url": config_path,
                                "description": f"配置文件包含敏感信息",
                                "evidence": f"包含关键词: {pattern}",
                                "remediation": "使用环境变量或加密存储"
                            })
                            break

                except Exception:
                    continue

    def _scan_strings(self, content: str):
        """扫描字符串"""
        patterns = {
            "URL": r'https?://[^\s]+',
            "IP Address": r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
            "Email": r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
            "AWS Key": r'(?:AKIA|ASIA)[A-Z0-9]{16}',
            "Private Key": r'-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----',
        }

        for vuln_type, pattern in patterns.items():
            matches = re.findall(pattern, content)
            if matches:
                self.vulnerabilities.append({
                    "type": "信息泄露",
                    "severity": "Medium",
                    "url": self.app_path,
                    "description": f"发现{vuln_type}",
                    "evidence": matches[0][:100],
                    "remediation": "移除敏感信息"
                })


def scan_desktop_app(app_path: str) -> List[Dict]:
    """便捷函数：扫描桌面应用"""
    scanner = DesktopScanner(app_path)
    return scanner.scan()


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        vulns = scan_desktop_app(sys.argv[1])
        for vuln in vulns:
            print(f"[{vuln['severity']}] {vuln['type']}: {vuln['description']}")
    else:
        print("用法: python desktop_scanner.py <app_path>")
        print("支持: Electron应用目录, .exe文件, .asar文件")
