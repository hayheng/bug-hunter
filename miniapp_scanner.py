# -*- coding: utf-8 -*-
"""
小程序漏洞扫描模块
支持: 微信小程序、支付宝小程序、百度小程序
"""

import os
import re
import json
import subprocess
import tempfile
from typing import List, Dict
from pathlib import Path


class MiniAppScanner:
    """小程序漏洞扫描器"""

    def __init__(self, app_path: str):
        self.app_path = app_path
        self.app_name = Path(app_path).stem
        self.app_type = self._detect_app_type()
        self.vulnerabilities = []

    def scan(self) -> List[Dict]:
        """执行扫描"""
        print(f"[*] 开始扫描小程序: {self.app_name}")
        print(f"[*] 小程序类型: {self.app_type}")

        if self.app_type == "wechat":
            self._scan_wechat()
        elif self.app_type == "alipay":
            self._scan_alipay()
        elif self.app_type == "baidu":
            self._scan_baidu()
        else:
            # 尝试通用扫描
            self._scan_generic()

        print(f"[*] 扫描完成，发现 {len(self.vulnerabilities)} 个漏洞")
        return self.vulnerabilities

    def _detect_app_type(self) -> str:
        """检测小程序类型"""
        path = Path(self.app_path)

        # 检查是否是目录
        if path.is_dir():
            # 微信小程序
            if (path / "app.json").exists() and (path / "app.wxss").exists():
                return "wechat"
            if (path / "app.json").exists() and (path / "pages").exists():
                # 检查是否有微信特有文件
                for root, dirs, files in os.walk(path):
                    for file in files:
                        if file.endswith('.wxml') or file.endswith('.wxss'):
                            return "wechat"
                    break

            # 支付宝小程序
            if (path / "app.json").exists() and (path / "app.acss").exists():
                return "alipay"

            # 百度小程序
            if (path / "app.json").exists() and (path / "app.css").exists():
                return "baidu"

        # 检查文件扩展名
        if path.suffix == '.wxapkg':
            return "wechat"

        return "unknown"

    def _scan_wechat(self):
        """扫描微信小程序"""
        print("[*] 扫描微信小程序...")

        path = Path(self.app_path)

        # 如果是wxapkg文件，先解包
        if path.suffix == '.wxapkg':
            extracted_dir = self._extract_wxapkg(str(path))
            if extracted_dir:
                self._scan_source_code(extracted_dir)
                import shutil
                shutil.rmtree(extracted_dir, ignore_errors=True)
        elif path.is_dir():
            self._scan_source_code(str(path))
            self._scan_config(str(path))
            self._scan_sensitive_info(str(path))

    def _scan_alipay(self):
        """扫描支付宝小程序"""
        print("[*] 扫描支付宝小程序...")

        path = Path(self.app_path)
        if path.is_dir():
            self._scan_source_code(str(path))
            self._scan_config(str(path))

    def _scan_baidu(self):
        """扫描百度小程序"""
        print("[*] 扫描百度小程序...")

        path = Path(self.app_path)
        if path.is_dir():
            self._scan_source_code(str(path))
            self._scan_config(str(path))

    def _scan_generic(self):
        """通用扫描"""
        print("[*] 执行通用扫描...")

        path = Path(self.app_path)
        if path.is_dir():
            self._scan_source_code(str(path))

    def _extract_wxapkg(self, wxapkg_path: str) -> str:
        """解包wxapkg文件"""
        try:
            temp_dir = tempfile.mkdtemp()

            # 使用wxappUnpacker解包
            unpacker_path = os.path.join(os.path.dirname(__file__), "tools", "wxappUnpacker")
            if os.path.exists(unpacker_path):
                subprocess.run(
                    ["node", os.path.join(unpacker_path, "wuWxapkg.js"), wxapkg_path, temp_dir],
                    capture_output=True,
                    timeout=60
                )
            else:
                print("[!] wxappUnpacker未安装，跳过解包")
                return None

            return temp_dir
        except Exception as e:
            print(f"[!] 解包wxapkg失败: {e}")
            return None

    def _scan_source_code(self, directory: str):
        """扫描源码"""
        # 敏感信息模式
        patterns = {
            "API Key": r'["\'](?:api[_-]?key|apikey)["\']?\s*[:=]\s*["\'][a-zA-Z0-9]{20,}["\']',
            "Secret Key": r'["\'](?:secret[_-]?key|secretkey)["\']?\s*[:=]\s*["\'][a-zA-Z0-9]{20,}["\']',
            "AppSecret": r'["\'](?:app[_-]?secret|appsecret)["\']?\s*[:=]\s*["\'][a-zA-Z0-9]{20,}["\']',
            "Password": r'["\'](?:password|passwd|pwd)["\']?\s*[:=]\s*["\'][^"\']{6,}["\']',
            "Token": r'["\'](?:token|access_token|auth_token)["\']?\s*[:=]\s*["\'][a-zA-Z0-9]{20,}["\']',
            "AWS Key": r'(?:AKIA|ASIA)[A-Z0-9]{16}',
            "Private Key": r'-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----',
            "Database URL": r'(?:mysql|postgres|mongodb|redis)://[^\s]+',
            "Internal URL": r'https?://(?:10\.|172\.(?:1[6-9]|2[0-9]|3[01])\.|192\.168\.)[^\s]+',
            "IP Address": r'\b(?:10\.|172\.(?:1[6-9]|2[0-9]|3[01])\.|192\.168\.)\d{1,3}\.\d{1,3}\b',
        }

        for root, dirs, files in os.walk(directory):
            for file in files:
                if file.endswith(('.js', '.json', '.wxml', '.wxss', '.html', '.css', '.ts')):
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
                                    "remediation": "使用云函数或后端接口获取"
                                })
                    except Exception:
                        continue

    def _scan_config(self, directory: str):
        """扫描配置文件"""
        # 扫描app.json
        app_json_path = os.path.join(directory, "app.json")
        if os.path.exists(app_json_path):
            try:
                with open(app_json_path, 'r', encoding='utf-8') as f:
                    config = json.load(f)

                # 检查是否开启了调试模式
                if config.get("debug") == True:
                    self.vulnerabilities.append({
                        "type": "配置错误",
                        "severity": "Medium",
                        "url": app_json_path,
                        "description": "小程序开启了调试模式",
                        "evidence": "debug: true",
                        "remediation": "发布时关闭调试模式"
                    })

            except Exception:
                pass

        # 扫描project.config.json
        project_config_path = os.path.join(directory, "project.config.json")
        if os.path.exists(project_config_path):
            try:
                with open(project_config_path, 'r', encoding='utf-8') as f:
                    config = json.load(f)

                # 检查appid
                appid = config.get("appid", "")
                if appid:
                    self.vulnerabilities.append({
                        "type": "信息泄露",
                        "severity": "Low",
                        "url": project_config_path,
                        "description": "小程序AppID泄露",
                        "evidence": f"appid: {appid}",
                        "remediation": "注意保护AppID"
                    })

            except Exception:
                pass

    def _scan_sensitive_info(self, directory: str):
        """扫描敏感信息"""
        # 扫描云函数配置
        cloud_dir = os.path.join(directory, "cloudfunctions")
        if os.path.exists(cloud_dir):
            for root, dirs, files in os.walk(cloud_dir):
                for file in files:
                    if file.endswith(('.js', '.json')):
                        file_path = os.path.join(root, file)
                        try:
                            with open(file_path, 'r', encoding='utf-8') as f:
                                content = f.read()

                            # 检查云函数中的敏感信息
                            if 'appsecret' in content.lower() or 'secret' in content.lower():
                                self.vulnerabilities.append({
                                    "type": "信息泄露",
                                    "severity": "High",
                                    "url": file_path,
                                    "description": "云函数包含敏感信息",
                                    "evidence": "包含secret关键词",
                                    "remediation": "使用云环境变量存储敏感信息"
                                })

                        except Exception:
                            continue

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
                    "remediation": "删除.env文件，使用云环境变量"
                })


def scan_miniapp(app_path: str) -> List[Dict]:
    """便捷函数：扫描小程序"""
    scanner = MiniAppScanner(app_path)
    return scanner.scan()


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        vulns = scan_miniapp(sys.argv[1])
        for vuln in vulns:
            print(f"[{vuln['severity']}] {vuln['type']}: {vuln['description']}")
    else:
        print("用法: python miniapp_scanner.py <app_path>")
        print("支持: 微信小程序目录, .wxapkg文件, 支付宝小程序, 百度小程序")
