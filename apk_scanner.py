# -*- coding: utf-8 -*-
"""
Android APK 漏洞扫描模块
"""

import os
import re
import json
import subprocess
import tempfile
from typing import List, Dict
from pathlib import Path


class APKScanner:
    """APK漏洞扫描器"""

    def __init__(self, apk_path: str):
        self.apk_path = apk_path
        self.apk_name = Path(apk_path).stem
        self.temp_dir = None
        self.vulnerabilities = []

    def scan(self) -> List[Dict]:
        """执行APK扫描"""
        print(f"[*] 开始扫描APK: {self.apk_name}")

        # 创建临时目录
        self.temp_dir = tempfile.mkdtemp()

        try:
            # 1. 反编译APK
            print("[*] 反编译APK...")
            self._decompile_apk()

            # 2. 扫描敏感信息
            print("[*] 扫描敏感信息...")
            self._scan_sensitive_info()

            # 3. 扫描不安全配置
            print("[*] 扫描不安全配置...")
            self._scan_insecure_config()

            # 4. 扫描硬编码凭证
            print("[*] 扫描硬编码凭证...")
            self._scan_hardcoded_credentials()

            # 5. 扫描不安全网络通信
            print("[*] 扫描不安全网络通信...")
            self._scan_insecure_network()

            # 6. 扫描组件暴露
            print("[*] 扫描组件暴露...")
            self._scan_exposed_components()

            # 7. 扫描WebView漏洞
            print("[*] 扫描WebView漏洞...")
            self._scan_webview_vulnerabilities()

        except Exception as e:
            print(f"[!] 扫描失败: {e}")
        finally:
            # 清理临时目录
            self._cleanup()

        print(f"[*] 扫描完成，发现 {len(self.vulnerabilities)} 个漏洞")
        return self.vulnerabilities

    def _decompile_apk(self):
        """反编译APK"""
        output_dir = os.path.join(self.temp_dir, "decompiled")

        # 使用apktool反编译
        try:
            subprocess.run(
                ["apktool", "d", self.apk_path, "-o", output_dir, "-f"],
                capture_output=True,
                timeout=120
            )
        except FileNotFoundError:
            print("[!] apktool未安装，跳过反编译")
            return

        self.decompiled_dir = output_dir

    def _scan_sensitive_info(self):
        """扫描敏感信息泄露"""
        if not hasattr(self, 'decompiled_dir'):
            return

        # 敏感信息模式
        patterns = {
            "API Key": r'["\'](?:api[_-]?key|apikey)["\']?\s*[:=]\s*["\'][a-zA-Z0-9]{20,}["\']',
            "Secret Key": r'["\'](?:secret[_-]?key|secretkey)["\']?\s*[:=]\s*["\'][a-zA-Z0-9]{20,}["\']',
            "AWS Key": r'(?:AKIA|ASIA)[A-Z0-9]{16}',
            "Private Key": r'-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----',
            "Password": r'["\'](?:password|passwd|pwd)["\']?\s*[:=]\s*["\'][^"\']{6,}["\']',
            "Token": r'["\'](?:token|access_token|auth_token)["\']?\s*[:=]\s*["\'][a-zA-Z0-9]{20,}["\']',
            "Database URL": r'(?:mysql|postgres|mongodb|redis)://[^\s]+',
        }

        for root, dirs, files in os.walk(self.decompiled_dir):
            for file in files:
                if file.endswith(('.java', '.xml', '.json', '.properties', '.yml')):
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

    def _scan_insecure_config(self):
        """扫描不安全配置"""
        if not hasattr(self, 'decompiled_dir'):
            return

        manifest_path = os.path.join(self.decompiled_dir, "AndroidManifest.xml")
        if not os.path.exists(manifest_path):
            return

        try:
            with open(manifest_path, 'r', encoding='utf-8') as f:
                content = f.read()

            # 检查debug模式
            if 'android:debuggable="true"' in content:
                self.vulnerabilities.append({
                    "type": "配置错误",
                    "severity": "High",
                    "url": manifest_path,
                    "description": "应用开启了debug模式",
                    "evidence": 'android:debuggable="true"',
                    "remediation": "发布时关闭debug模式"
                })

            # 检查allowBackup
            if 'android:allowBackup="true"' in content:
                self.vulnerabilities.append({
                    "type": "配置错误",
                    "severity": "Medium",
                    "url": manifest_path,
                    "description": "应用允许备份",
                    "evidence": 'android:allowBackup="true"',
                    "remediation": "设置android:allowBackup=\"false\""
                })

            # 检查usesCleartextTraffic
            if 'android:usesCleartextTraffic="true"' in content:
                self.vulnerabilities.append({
                    "type": "配置错误",
                    "severity": "Medium",
                    "url": manifest_path,
                    "description": "应用允许明文传输",
                    "evidence": 'android:usesCleartextTraffic="true"',
                    "remediation": "设置android:usesCleartextTraffic=\"false\""
                })

        except Exception as e:
            pass

    def _scan_hardcoded_credentials(self):
        """扫描硬编码凭证"""
        if not hasattr(self, 'decompiled_dir'):
            return

        # 硬编码凭证模式
        patterns = {
            "Hardcoded Password": r'password\s*=\s*["\'][^"\']{6,}["\']',
            "Hardcoded Token": r'token\s*=\s*["\'][a-zA-Z0-9]{20,}["\']',
            "Hardcoded API Key": r'api[_-]?key\s*=\s*["\'][a-zA-Z0-9]{20,}["\']',
            "Hardcoded Secret": r'secret\s*=\s*["\'][a-zA-Z0-9]{20,}["\']',
        }

        for root, dirs, files in os.walk(self.decompiled_dir):
            for file in files:
                if file.endswith(('.java', '.kt')):
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()

                        for vuln_type, pattern in patterns.items():
                            matches = re.findall(pattern, content, re.IGNORECASE)
                            if matches:
                                self.vulnerabilities.append({
                                    "type": "信息泄露",
                                    "severity": "Critical",
                                    "url": file_path,
                                    "description": f"发现{vuln_type}",
                                    "evidence": matches[0][:100],
                                    "remediation": "使用安全存储或环境变量"
                                })
                    except Exception:
                        continue

    def _scan_insecure_network(self):
        """扫描不安全网络通信"""
        if not hasattr(self, 'decompiled_dir'):
            return

        # 检查network_security_config
        nsc_path = os.path.join(self.decompiled_dir, "res", "xml", "network_security_config.xml")
        if os.path.exists(nsc_path):
            try:
                with open(nsc_path, 'r', encoding='utf-8') as f:
                    content = f.read()

                # 检查是否允许明文传输
                if 'cleartextTrafficPermitted="true"' in content:
                    self.vulnerabilities.append({
                        "type": "配置错误",
                        "severity": "High",
                        "url": nsc_path,
                        "description": "网络安全配置允许明文传输",
                        "evidence": 'cleartextTrafficPermitted="true"',
                        "remediation": "设置cleartextTrafficPermitted=\"false\""
                    })

                # 检查是否禁用证书验证
                if 'trust-anchors' in content and 'user-certificates' in content:
                    self.vulnerabilities.append({
                        "type": "配置错误",
                        "severity": "High",
                        "url": nsc_path,
                        "description": "网络安全配置信任用户证书",
                        "evidence": "trust-anchors包含user-certificates",
                        "remediation": "移除user-certificates信任"
                    })

            except Exception:
                pass

    def _scan_exposed_components(self):
        """扫描暴露的组件"""
        if not hasattr(self, 'decompiled_dir'):
            return

        manifest_path = os.path.join(self.decompiled_dir, "AndroidManifest.xml")
        if not os.path.exists(manifest_path):
            return

        try:
            with open(manifest_path, 'r', encoding='utf-8') as f:
                content = f.read()

            # 检查exported组件
            exported_pattern = r'<(?:activity|service|receiver|provider)[^>]*android:exported="true"[^>]*>'
            matches = re.findall(exported_pattern, content)

            if matches:
                self.vulnerabilities.append({
                    "type": "配置错误",
                    "severity": "Medium",
                    "url": manifest_path,
                    "description": f"发现{len(matches)}个导出的组件",
                    "evidence": matches[0][:100],
                    "remediation": "设置android:exported=\"false\"或添加权限验证"
                })

        except Exception:
            pass

    def _scan_webview_vulnerabilities(self):
        """扫描WebView漏洞"""
        if not hasattr(self, 'decompiled_dir'):
            return

        # WebView漏洞模式
        patterns = {
            "JavaScript启用": r'setJavaScriptEnabled\s*\(\s*true\s*\)',
            "文件访问启用": r'setAllowFileAccess\s*\(\s*true\s*\)',
            "通用文件访问": r'setAllowUniversalAccessFromFileURLs\s*\(\s*true\s*\)',
            "内容访问启用": r'setAllowContentAccess\s*\(\s*true\s*\)',
            "SSL错误忽略": r'onReceivedSslError.*?handler\.proceed',
        }

        for root, dirs, files in os.walk(self.decompiled_dir):
            for file in files:
                if file.endswith(('.java', '.kt')):
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()

                        for vuln_type, pattern in patterns.items():
                            matches = re.findall(pattern, content, re.IGNORECASE | re.DOTALL)
                            if matches:
                                self.vulnerabilities.append({
                                    "type": "配置错误",
                                    "severity": "High" if "SSL" in vuln_type else "Medium",
                                    "url": file_path,
                                    "description": f"WebView存在{vuln_type}漏洞",
                                    "evidence": matches[0][:100],
                                    "remediation": "禁用不必要的WebView功能"
                                })

                    except Exception:
                        continue

    def _cleanup(self):
        """清理临时文件"""
        if self.temp_dir and os.path.exists(self.temp_dir):
            import shutil
            shutil.rmtree(self.temp_dir, ignore_errors=True)


def scan_apk(apk_path: str) -> List[Dict]:
    """便捷函数：扫描APK"""
    scanner = APKScanner(apk_path)
    return scanner.scan()


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        vulns = scan_apk(sys.argv[1])
        for vuln in vulns:
            print(f"[{vuln['severity']}] {vuln['type']}: {vuln['description']}")
    else:
        print("用法: python apk_scanner.py <apk_path>")
