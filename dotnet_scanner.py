# -*- coding: utf-8 -*-
"""
.NET 程序分析模块
支持: EXE, DLL, 反编译分析
"""

import os
import re
import json
import subprocess
import tempfile
import shutil
from typing import List, Dict, Optional
from pathlib import Path


class DotNetScanner:
    """.NET 程序扫描器"""

    def __init__(self, file_path: str, tools_dir: str = None):
        self.file_path = file_path
        self.file_name = Path(file_path).stem
        self.tools_dir = tools_dir or os.path.join(os.path.dirname(__file__), "tools")
        self.temp_dir = None
        self.decompiled_dir = None
        self.vulnerabilities = []

    def scan(self) -> List[Dict]:
        """执行扫描"""
        print(f"[*] 扫描 .NET 程序: {self.file_name}")

        # 检查是否是 .NET 程序
        if not self._is_dotnet():
            print("[!] 不是 .NET 程序")
            return []

        # 尝试反编译
        self._decompile()

        # 扫描敏感信息
        self._scan_sensitive_info()

        # 扫描配置
        self._scan_config()

        # 扫描代码
        self._scan_source_code()

        # 清理
        self._cleanup()

        print(f"[*] 扫描完成，发现 {len(self.vulnerabilities)} 个漏洞")
        return self.vulnerabilities

    def _is_dotnet(self) -> bool:
        """检查是否是 .NET 程序"""
        try:
            with open(self.file_path, 'rb') as f:
                content = f.read(1024)

            # 检查 .NET 特征
            # PE 文件头
            if content[:2] != b'MZ':
                return False

            # 检查 .NET 元数据
            dotnet_patterns = [
                b'_CorExeMain',
                b'_CorDllMain',
                b'mscoree.dll',
                b'.NET Framework',
                b'System.Runtime',
                b'mscorlib',
            ]

            for pattern in dotnet_patterns:
                if pattern in content:
                    return True

            return False
        except:
            return False

    def _decompile(self):
        """反编译 .NET 程序"""
        # 尝试使用 dnSpy
        dnspy_path = os.path.join(self.tools_dir, "dnSpy", "dnSpy.exe")
        ilspy_path = os.path.join(self.tools_dir, "ILSpy", "ILSpy.exe")

        if os.path.exists(dnspy_path):
            self._decompile_with_dnspy()
        elif os.path.exists(ilspy_path):
            self._decompile_with_ilspy()
        else:
            # 使用 Python 读取字符串
            print("[*] 使用内置方法分析")
            self._extract_strings()

    def _decompile_with_dnspy(self):
        """使用 dnSpy 反编译"""
        dnspy_path = os.path.join(self.tools_dir, "dnSpy", "dnSpy.exe")
        self.decompiled_dir = os.path.join(tempfile.mkdtemp(), "decompiled")

        cmd = [dnspy_path, self.file_path, "-o", self.decompiled_dir]
        try:
            subprocess.run(cmd, capture_output=True, timeout=120)
            print(f"[+] 反编译成功: {self.decompiled_dir}")
        except Exception as e:
            print(f"[!] 反编译失败: {e}")

    def _decompile_with_ilspy(self):
        """使用 ILSpy 反编译"""
        ilspy_path = os.path.join(self.tools_dir, "ILSpy", "ILSpy.exe")
        self.decompiled_dir = os.path.join(tempfile.mkdtemp(), "decompiled")

        cmd = [ilspy_path, self.file_path, "-o", self.decompiled_dir]
        try:
            subprocess.run(cmd, capture_output=True, timeout=120)
            print(f"[+] 反编译成功: {self.decompiled_dir}")
        except Exception as e:
            print(f"[!] 反编译失败: {e}")

    def _extract_strings(self):
        """提取字符串"""
        self.temp_dir = tempfile.mkdtemp()
        self.decompiled_dir = self.temp_dir

        try:
            with open(self.file_path, 'rb') as f:
                content = f.read()

            # 提取 ASCII 字符串
            strings = re.findall(b'[\x20-\x7e]{6,}', content)

            # 保存到文件
            output_file = os.path.join(self.temp_dir, "strings.txt")
            with open(output_file, 'w', encoding='utf-8') as f:
                for s in strings:
                    f.write(s.decode('ascii', errors='ignore') + '\n')

            print(f"[+] 提取了 {len(strings)} 个字符串")
        except Exception as e:
            print(f"[!] 提取字符串失败: {e}")

    def _scan_sensitive_info(self):
        """扫描敏感信息"""
        if not self.decompiled_dir or not os.path.exists(self.decompiled_dir):
            return

        patterns = {
            "API Key": r'["\'](?:api[_-]?key|apikey)["\']?\s*[:=]\s*["\'][a-zA-Z0-9]{20,}["\']',
            "Secret Key": r'["\'](?:secret[_-]?key|secretkey)["\']?\s*[:=]\s*["\'][a-zA-Z0-9]{20,}["\']',
            "Connection String": r'(?:Server|Data Source|Initial Catalog)\s*=',
            "Password": r'["\'](?:password|passwd|pwd)["\']?\s*[:=]\s*["\'][^"\']{6,}["\']',
            "AWS Key": r'(?:AKIA|ASIA)[A-Z0-9]{16}',
            "Private Key": r'-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----',
            "Internal IP": r'\b(?:10\.|172\.(?:1[6-9]|2[0-9]|3[01])\.|192\.168\.)\d{1,3}\.\d{1,3}\b',
        }

        for root, dirs, files in os.walk(self.decompiled_dir):
            for file in files:
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
                                "description": f"发现{vuln_type}",
                                "evidence": matches[0][:100],
                                "remediation": "使用安全存储或环境变量"
                            })
                except Exception:
                    continue

    def _scan_config(self):
        """扫描配置文件"""
        config_files = [
            "app.config",
            "web.config",
            "appsettings.json",
            "appsettings.Development.json",
            "appsettings.Production.json",
        ]

        for config_file in config_files:
            config_path = os.path.join(self.decompiled_dir, config_file)
            if os.path.exists(config_path):
                try:
                    with open(config_path, 'r', encoding='utf-8') as f:
                        content = f.read()

                    # 检查连接字符串
                    if 'connectionString' in content.lower():
                        self.vulnerabilities.append({
                            "type": "信息泄露",
                            "severity": "High",
                            "url": config_path,
                            "description": "配置文件包含连接字符串",
                            "evidence": "connectionString",
                            "remediation": "使用环境变量或加密存储"
                        })

                    # 检查 API 密钥
                    if 'apikey' in content.lower() or 'secret' in content.lower():
                        self.vulnerabilities.append({
                            "type": "信息泄露",
                            "severity": "High",
                            "url": config_path,
                            "description": "配置文件包含敏感信息",
                            "evidence": "包含 apikey 或 secret",
                            "remediation": "使用环境变量或加密存储"
                        })

                except Exception:
                    continue

    def _scan_source_code(self):
        """扫描源码"""
        patterns = {
            "SQL 注入": r'(?:SqlCommand|OleDbCommand|MySqlCommand)\s*\([^)]*\+',
            "命令注入": r'Process\.Start\s*\([^)]*\+',
            "路径遍历": r'File\.(?:Read|Write|Delete|Exists)\s*\([^)]*\+',
            "不安全反序列化": r'(?:BinaryFormatter|JavaScriptSerializer|XmlSerializer)\s*\(',
            "弱加密": r'(?:DES|RC2|RC4|MD5|SHA1)\s*\(',
            "硬编码密钥": r'(?:Key|IV|Salt)\s*=\s*["\'][^"\']+["\']',
        }

        for root, dirs, files in os.walk(self.decompiled_dir):
            for file in files:
                if file.endswith(('.cs', '.vb')):
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()

                        for vuln_type, pattern in patterns.items():
                            matches = re.findall(pattern, content, re.IGNORECASE)
                            if matches:
                                self.vulnerabilities.append({
                                    "type": "代码漏洞",
                                    "severity": "High",
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


def scan_dotnet(file_path: str) -> List[Dict]:
    """便捷函数：扫描 .NET 程序"""
    scanner = DotNetScanner(file_path)
    return scanner.scan()


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        vulns = scan_dotnet(sys.argv[1])
        for vuln in vulns:
            print(f"[{vuln['severity']}] {vuln['type']}: {vuln['description']}")
    else:
        print("用法: python dotnet_scanner.py <file_path>")
        print("支持: .exe, .dll 文件")
