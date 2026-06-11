# -*- coding: utf-8 -*-
"""
APK 反编译模块
支持: apktool, jadx, dex2jar
"""

import os
import re
import json
import subprocess
import tempfile
import shutil
from typing import List, Dict, Optional
from pathlib import Path


class APKDecompiler:
    """APK 反编译器"""

    def __init__(self, apk_path: str, tools_dir: str = None):
        self.apk_path = apk_path
        self.apk_name = Path(apk_path).stem
        self.tools_dir = tools_dir or os.path.join(os.path.dirname(__file__), "tools")
        self.temp_dir = None
        self.decompiled_dir = None
        self.vulnerabilities = []

    def decompile(self, method: str = "apktool") -> str:
        """反编译 APK"""
        print(f"[*] 反编译 APK: {self.apk_name}")
        print(f"[*] 使用方法: {method}")

        # 创建临时目录
        self.temp_dir = tempfile.mkdtemp()

        try:
            if method == "apktool":
                self._decompile_with_apktool()
            elif method == "jadx":
                self._decompile_with_jadx()
            elif method == "dex2jar":
                self._decompile_with_dex2jar()
            else:
                print(f"[!] 不支持的反编译方法: {method}")
                return None

            return self.decompiled_dir

        except Exception as e:
            print(f"[!] 反编译失败: {e}")
            self._cleanup()
            return None

    def _decompile_with_apktool(self):
        """使用 apktool 反编译"""
        apktool_path = os.path.join(self.tools_dir, "apktool.jar")

        # 检查 apktool 是否存在
        if not os.path.exists(apktool_path):
            # 尝试系统 PATH
            try:
                subprocess.run(["apktool", "--version"], capture_output=True, check=True)
                apktool_cmd = ["apktool"]
            except (subprocess.CalledProcessError, FileNotFoundError):
                print("[!] apktool 未安装")
                print("[*] 请下载 apktool.jar 到 tools 目录")
                print("[*] 下载地址: https://ibotpeaches.github.io/Apktool/")
                return
        else:
            apktool_cmd = ["java", "-jar", apktool_path]

        # 执行反编译
        self.decompiled_dir = os.path.join(self.temp_dir, "decompiled")
        cmd = apktool_cmd + ["d", self.apk_path, "-o", self.decompiled_dir, "-f"]

        print(f"[*] 执行命令: {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

        if result.returncode == 0:
            print(f"[+] 反编译成功: {self.decompiled_dir}")
        else:
            print(f"[!] 反编译失败: {result.stderr}")

    def _decompile_with_jadx(self):
        """使用 jadx 反编译"""
        jadx_path = os.path.join(self.tools_dir, "jadx", "bin", "jadx")

        # 检查 jadx 是否存在
        if not os.path.exists(jadx_path):
            # 尝试系统 PATH
            try:
                subprocess.run(["jadx", "--version"], capture_output=True, check=True)
                jadx_cmd = ["jadx"]
            except (subprocess.CalledProcessError, FileNotFoundError):
                print("[!] jadx 未安装")
                print("[*] 请下载 jadx 到 tools 目录")
                print("[*] 下载地址: https://github.com/skylot/jadx/releases")
                return
        else:
            jadx_cmd = [jadx_path]

        # 执行反编译
        self.decompiled_dir = os.path.join(self.temp_dir, "jadx_output")
        cmd = jadx_cmd + ["-d", self.decompiled_dir, self.apk_path]

        print(f"[*] 执行命令: {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

        if result.returncode == 0:
            print(f"[+] 反编译成功: {self.decompiled_dir}")
        else:
            print(f"[!] 反编译失败: {result.stderr}")

    def _decompile_with_dex2jar(self):
        """使用 dex2jar 反编译"""
        d2j_path = os.path.join(self.tools_dir, "dex2jar", "d2j-dex2jar.bat")

        # 检查 dex2jar 是否存在
        if not os.path.exists(d2j_path):
            print("[!] dex2jar 未安装")
            print("[*] 请下载 dex2jar 到 tools 目录")
            print("[*] 下载地址: https://github.com/pxb1988/dex2jar/releases")
            return

        # 提取 dex 文件
        dex_dir = os.path.join(self.temp_dir, "dex")
        os.makedirs(dex_dir, exist_ok=True)

        import zipfile
        with zipfile.ZipFile(self.apk_path, 'r') as zip_ref:
            for file in zip_ref.namelist():
                if file.endswith('.dex'):
                    zip_ref.extract(file, dex_dir)

        # 转换 dex 到 jar
        self.decompiled_dir = os.path.join(self.temp_dir, "jars")
        os.makedirs(self.decompiled_dir, exist_ok=True)

        for dex_file in os.listdir(dex_dir):
            if dex_file.endswith('.dex'):
                dex_path = os.path.join(dex_dir, dex_file)
                jar_path = os.path.join(self.decompiled_dir, dex_file.replace('.dex', '.jar'))

                cmd = [d2j_path, dex_path, "-o", jar_path]
                print(f"[*] 执行命令: {' '.join(cmd)}")
                subprocess.run(cmd, capture_output=True, timeout=120)

        print(f"[+] 转换完成: {self.decompiled_dir}")

    def scan(self) -> List[Dict]:
        """扫描反编译后的代码"""
        if not self.decompiled_dir or not os.path.exists(self.decompiled_dir):
            print("[!] 未找到反编译结果")
            return []

        print(f"[*] 扫描反编译结果: {self.decompiled_dir}")

        # 扫描敏感信息
        self._scan_sensitive_info()

        # 扫描配置文件
        self._scan_config_files()

        # 扫描 AndroidManifest.xml
        self._scan_manifest()

        # 扫描源码
        self._scan_source_code()

        print(f"[*] 扫描完成，发现 {len(self.vulnerabilities)} 个漏洞")
        return self.vulnerabilities

    def _scan_sensitive_info(self):
        """扫描敏感信息"""
        patterns = {
            "API Key": r'["\'](?:api[_-]?key|apikey)["\']?\s*[:=]\s*["\'][a-zA-Z0-9]{20,}["\']',
            "Secret Key": r'["\'](?:secret[_-]?key|secretkey)["\']?\s*[:=]\s*["\'][a-zA-Z0-9]{20,}["\']',
            "AWS Key": r'(?:AKIA|ASIA)[A-Z0-9]{16}',
            "Private Key": r'-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----',
            "Password": r'["\'](?:password|passwd|pwd)["\']?\s*[:=]\s*["\'][^"\']{6,}["\']',
            "Token": r'["\'](?:token|access_token|auth_token)["\']?\s*[:=]\s*["\'][a-zA-Z0-9]{20,}["\']',
            "Database URL": r'(?:mysql|postgres|mongodb|redis)://[^\s"\']+',
            "Internal IP": r'\b(?:10\.|172\.(?:1[6-9]|2[0-9]|3[01])\.|192\.168\.)\d{1,3}\.\d{1,3}\b',
        }

        for root, dirs, files in os.walk(self.decompiled_dir):
            for file in files:
                if file.endswith(('.java', '.kt', '.xml', '.json', '.properties', '.yml')):
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

    def _scan_config_files(self):
        """扫描配置文件"""
        config_files = [
            "AndroidManifest.xml",
            "res/xml/network_security_config.xml",
            "res/values/strings.xml",
            "assets/config.json",
            "assets/config.properties",
        ]

        for config_file in config_files:
            config_path = os.path.join(self.decompiled_dir, config_file)
            if os.path.exists(config_path):
                try:
                    with open(config_path, 'r', encoding='utf-8') as f:
                        content = f.read()

                    # 检查敏感配置
                    if 'debuggable="true"' in content:
                        self.vulnerabilities.append({
                            "type": "配置错误",
                            "severity": "High",
                            "url": config_path,
                            "description": "应用开启了debug模式",
                            "evidence": 'debuggable="true"',
                            "remediation": "发布时关闭debug模式"
                        })

                    if 'allowBackup="true"' in content:
                        self.vulnerabilities.append({
                            "type": "配置错误",
                            "severity": "Medium",
                            "url": config_path,
                            "description": "应用允许备份",
                            "evidence": 'allowBackup="true"',
                            "remediation": "设置allowBackup=\"false\""
                        })

                except Exception:
                    continue

    def _scan_manifest(self):
        """扫描 AndroidManifest.xml"""
        manifest_path = os.path.join(self.decompiled_dir, "AndroidManifest.xml")
        if not os.path.exists(manifest_path):
            return

        try:
            with open(manifest_path, 'r', encoding='utf-8') as f:
                content = f.read()

            # 检查权限
            permissions = re.findall(r'android:name="android.permission.(\w+)"', content)
            dangerous_permissions = [
                'READ_EXTERNAL_STORAGE',
                'WRITE_EXTERNAL_STORAGE',
                'CAMERA',
                'RECORD_AUDIO',
                'ACCESS_FINE_LOCATION',
                'ACCESS_COARSE_LOCATION',
                'READ_PHONE_STATE',
                'READ_CONTACTS',
                'READ_SMS',
                'SEND_SMS',
                'CALL_PHONE',
            ]

            found_dangerous = [p for p in permissions if p in dangerous_permissions]
            if found_dangerous:
                self.vulnerabilities.append({
                    "type": "配置错误",
                    "severity": "Medium",
                    "url": manifest_path,
                    "description": f"申请了{len(found_dangerous)}个危险权限",
                    "evidence": ', '.join(found_dangerous[:5]),
                    "remediation": "只申请必要的权限"
                })

            # 检查导出组件
            exported_pattern = r'<(?:activity|service|receiver|provider)[^>]*android:exported="true"[^>]*>'
            exported_matches = re.findall(exported_pattern, content)
            if exported_matches:
                self.vulnerabilities.append({
                    "type": "配置错误",
                    "severity": "Medium",
                    "url": manifest_path,
                    "description": f"发现{len(exported_matches)}个导出的组件",
                    "evidence": exported_matches[0][:100],
                    "remediation": "设置exported=\"false\"或添加权限验证"
                })

        except Exception as e:
            pass

    def _scan_source_code(self):
        """扫描源码"""
        patterns = {
            "WebView JavaScript": r'setJavaScriptEnabled\s*\(\s*true\s*\)',
            "WebView File Access": r'setAllowFileAccess\s*\(\s*true\s*\)',
            "SSL Error Ignore": r'onReceivedSslError.*?handler\.proceed',
            "Weak Random": r'new\s+Random\s*\(',
            "Hardcoded IV": r'IvParameterSpec\s*\(\s*["\'][^"\']+["\']',
            "Hardcoded Salt": r'PBEKeySpec\s*\(\s*[^,]+,\s*["\'][^"\']+["\']',
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
                                    "type": "代码漏洞",
                                    "severity": "High" if "SSL" in vuln_type else "Medium",
                                    "url": file_path,
                                    "description": f"发现{vuln_type}",
                                    "evidence": matches[0][:100],
                                    "remediation": "修复代码漏洞"
                                })
                    except Exception:
                        continue

    def _cleanup(self):
        """清理临时文件"""
        if self.temp_dir and os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir, ignore_errors=True)


def decompile_apk(apk_path: str, method: str = "apktool") -> Optional[str]:
    """便捷函数：反编译 APK"""
    decompiler = APKDecompiler(apk_path)
    return decompiler.decompile(method)


def scan_apk(apk_path: str, method: str = "apktool") -> List[Dict]:
    """便捷函数：反编译并扫描 APK"""
    decompiler = APKDecompiler(apk_path)
    if decompiler.decompile(method):
        return decompiler.scan()
    return []


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        apk_path = sys.argv[1]
        method = sys.argv[2] if len(sys.argv) > 2 else "apktool"

        vulns = scan_apk(apk_path, method)
        for vuln in vulns:
            print(f"[{vuln['severity']}] {vuln['type']}: {vuln['description']}")
    else:
        print("用法: python apk_decompiler.py <apk_path> [method]")
        print("方法: apktool, jadx, dex2jar")
