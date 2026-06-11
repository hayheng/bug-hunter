# -*- coding: utf-8 -*-
"""
增强字符串分析模块
支持: ASCII, Unicode, 中文, Base64, Hex
"""

import re
import base64
import binascii
from typing import List, Dict, Set
from collections import Counter


class EnhancedStringAnalyzer:
    """增强字符串分析器"""

    def __init__(self, file_path: str):
        self.file_path = file_path
        self.strings = []
        self.vulnerabilities = []

    def analyze(self) -> Dict:
        """执行分析"""
        print(f"[*] 分析文件: {self.file_path}")

        # 读取文件
        with open(self.file_path, 'rb') as f:
            content = f.read()

        # 提取字符串
        print("[*] 提取字符串...")
        self._extract_strings(content)

        # 分析敏感信息
        print("[*] 分析敏感信息...")
        self._analyze_sensitive_info()

        # 分析加密信息
        print("[*] 分析加密信息...")
        self._analyze_encrypted_info()

        # 分析配置信息
        print("[*] 分析配置信息...")
        self._analyze_config_info()

        # 分析网络信息
        print("[*] 分析网络信息...")
        self._analyze_network_info()

        # 分析代码特征
        print("[*] 分析代码特征...")
        self._analyze_code_features()

        print(f"[*] 分析完成，提取 {len(self.strings)} 个字符串")

        return {
            "strings": self.strings,
            "vulnerabilities": self.vulnerabilities,
            "statistics": self._get_statistics()
        }

    def _extract_strings(self, content: bytes):
        """提取字符串"""
        # ASCII 字符串
        ascii_strings = re.findall(b'[\x20-\x7e]{6,}', content)
        for s in ascii_strings:
            try:
                decoded = s.decode('ascii')
                self.strings.append({
                    "type": "ascii",
                    "value": decoded,
                    "offset": content.find(s)
                })
            except:
                pass

        # Unicode 字符串 (UTF-16LE)
        unicode_strings = re.findall(b'(?:[\x20-\x7e]\x00){6,}', content)
        for s in unicode_strings:
            try:
                decoded = s.decode('utf-16-le')
                self.strings.append({
                    "type": "unicode",
                    "value": decoded,
                    "offset": content.find(s)
                })
            except:
                pass

        # 中文字符串 (UTF-8)
        chinese_pattern = b'[\xe4-\xe9][\x80-\xbf][\x80-\xbf]'
        chinese_matches = re.findall(chinese_pattern + b'{2,}', content)
        for s in chinese_matches:
            try:
                decoded = s.decode('utf-8')
                if len(decoded) >= 2:
                    self.strings.append({
                        "type": "chinese",
                        "value": decoded,
                        "offset": content.find(s)
                    })
            except:
                pass

        # Base64 字符串
        b64_pattern = b'[A-Za-z0-9+/]{20,}={0,2}'
        b64_matches = re.findall(b64_pattern, content)
        for s in b64_matches:
            try:
                decoded = base64.b64decode(s)
                if self._is_printable(decoded):
                    self.strings.append({
                        "type": "base64",
                        "value": s.decode('ascii'),
                        "decoded": decoded.decode('utf-8', errors='ignore'),
                        "offset": content.find(s)
                    })
            except:
                pass

        # Hex 字符串
        hex_pattern = b'(?:0x)?[0-9a-fA-F]{16,}'
        hex_matches = re.findall(hex_pattern, content)
        for s in hex_matches:
            try:
                hex_str = s.decode('ascii').replace('0x', '')
                if len(hex_str) % 2 == 0:
                    decoded = bytes.fromhex(hex_str)
                    if self._is_printable(decoded):
                        self.strings.append({
                            "type": "hex",
                            "value": s.decode('ascii'),
                            "decoded": decoded.decode('utf-8', errors='ignore'),
                            "offset": content.find(s)
                        })
            except:
                pass

    def _is_printable(self, data: bytes) -> bool:
        """检查是否是可打印字符串"""
        try:
            text = data.decode('utf-8', errors='ignore')
            return len(text) > 0 and all(c.isprintable() or c.isspace() for c in text)
        except:
            return False

    def _analyze_sensitive_info(self):
        """分析敏感信息"""
        patterns = {
            "API Key": r'["\'](?:api[_-]?key|apikey)["\']?\s*[:=]\s*["\'][a-zA-Z0-9]{20,}["\']',
            "Secret Key": r'["\'](?:secret[_-]?key|secretkey)["\']?\s*[:=]\s*["\'][a-zA-Z0-9]{20,}["\']',
            "AWS Key": r'(?:AKIA|ASIA)[A-Z0-9]{16}',
            "AWS Secret": r'["\']?(?:aws[_-]?secret[_-]?access[_-]?key|aws[_-]?secret)["\']?\s*[:=]\s*["\']?[A-Za-z0-9/+=]{40}["\']?',
            "Private Key": r'-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----',
            "Password": r'["\'](?:password|passwd|pwd)["\']?\s*[:=]\s*["\'][^"\']{6,}["\']',
            "Token": r'["\'](?:token|access_token|auth_token|refresh_token)["\']?\s*[:=]\s*["\'][a-zA-Z0-9]{20,}["\']',
            "JWT Token": r'eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_.+/=]+',
            "SSH Key": r'ssh-(?:rsa|dss|ed25519)\s+[A-Za-z0-9+/=]+',
            "PGP Key": r'-----BEGIN\s+PGP\s+PRIVATE\s+KEY\s+BLOCK-----',
        }

        all_strings = ' '.join([s['value'] for s in self.strings])

        for vuln_type, pattern in patterns.items():
            matches = re.findall(pattern, all_strings, re.IGNORECASE)
            if matches:
                self.vulnerabilities.append({
                    "type": "信息泄露",
                    "severity": "Critical",
                    "description": f"发现{vuln_type}",
                    "evidence": matches[0][:100],
                    "count": len(matches)
                })

    def _analyze_encrypted_info(self):
        """分析加密信息"""
        patterns = {
            "MD5 Hash": r'\b[0-9a-f]{32}\b',
            "SHA1 Hash": r'\b[0-9a-f]{40}\b',
            "SHA256 Hash": r'\b[0-9a-f]{64}\b',
            "SHA512 Hash": r'\b[0-9a-f]{128}\b',
            "bcrypt Hash": r'\$2[aby]?\$\d{2}\$[./A-Za-z0-9]{53}',
            "DES Key": r'[0-9a-fA-F]{16}',
            "3DES Key": r'[0-9a-fA-F]{48}',
            "AES Key": r'[0-9a-fA-F]{32}|[0-9a-fA-F]{48}|[0-9a-fA-F]{64}',
        }

        all_strings = ' '.join([s['value'] for s in self.strings])

        for vuln_type, pattern in patterns.items():
            matches = re.findall(pattern, all_strings)
            if matches:
                # 过滤掉常见的非密钥hash
                filtered_matches = [m for m in matches if not self._is_common_hash(m)]
                if filtered_matches:
                    self.vulnerabilities.append({
                        "type": "信息泄露",
                        "severity": "High",
                        "description": f"发现{vuln_type}",
                        "evidence": filtered_matches[0][:100],
                        "count": len(filtered_matches)
                    })

    def _is_common_hash(self, hash_str: str) -> bool:
        """检查是否是常见的非密钥hash"""
        common_hashes = [
            "d41d8cd98f00b204e9800998ecf8427e",  # 空字符串MD5
            "e99a18c428cb38d5f260853678922e03",  # "abc123" MD5
            "da39a3ee5e6b4b0d3255bfef95601890afd80709",  # 空字符串SHA1
        ]
        return hash_str.lower() in common_hashes

    def _analyze_config_info(self):
        """分析配置信息"""
        patterns = {
            "Database URL": r'(?:mysql|postgres|mongodb|redis|sqlite)://[^\s"\']+',
            "SMTP Config": r'smtp://[^\s"\']+',
            "FTP Config": r'ftp://[^\s"\']+',
            "AMQP Config": r'amqp://[^\s"\']+',
            "Internal URL": r'https?://(?:10\.|172\.(?:1[6-9]|2[0-9]|3[01])\.|192\.168\.)[^\s"\']+',
            "Localhost URL": r'https?://(?:localhost|127\.0\.0\.1):\d+[^\s"\']*',
            "Debug Mode": r'debug\s*[:=]\s*(?:true|1|yes)',
            "Test Mode": r'test[_-]?mode\s*[:=]\s*(?:true|1|yes)',
        }

        all_strings = ' '.join([s['value'] for s in self.strings])

        for vuln_type, pattern in patterns.items():
            matches = re.findall(pattern, all_strings, re.IGNORECASE)
            if matches:
                self.vulnerabilities.append({
                    "type": "配置错误",
                    "severity": "High" if "Internal" in vuln_type or "Debug" in vuln_type else "Medium",
                    "description": f"发现{vuln_type}",
                    "evidence": matches[0][:100],
                    "count": len(matches)
                })

    def _analyze_network_info(self):
        """分析网络信息"""
        patterns = {
            "URL": r'https?://[^\s"\'<>]+',
            "IP Address": r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
            "Email": r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
            "Domain": r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b',
            "Port": r':(\d{1,5})\b',
        }

        all_strings = ' '.join([s['value'] for s in self.strings])

        # 提取URL
        urls = re.findall(patterns["URL"], all_strings)
        if urls:
            unique_urls = list(set(urls))[:20]
            self.vulnerabilities.append({
                "type": "信息泄露",
                "severity": "Low",
                "description": f"发现{len(unique_urls)}个URL",
                "evidence": unique_urls[0][:100],
                "count": len(unique_urls)
            })

        # 提取IP地址
        ips = re.findall(patterns["IP Address"], all_strings)
        if ips:
            # 分类IP
            internal_ips = [ip for ip in ips if self._is_internal_ip(ip)]
            external_ips = [ip for ip in ips if not self._is_internal_ip(ip)]

            if internal_ips:
                unique_ips = list(set(internal_ips))[:10]
                self.vulnerabilities.append({
                    "type": "信息泄露",
                    "severity": "High",
                    "description": f"发现{len(unique_ips)}个内网IP",
                    "evidence": unique_ips[0],
                    "count": len(unique_ips)
                })

        # 提取邮箱
        emails = re.findall(patterns["Email"], all_strings)
        if emails:
            unique_emails = list(set(emails))[:10]
            self.vulnerabilities.append({
                "type": "信息泄露",
                "severity": "Medium",
                "description": f"发现{len(unique_emails)}个邮箱",
                "evidence": unique_emails[0],
                "count": len(unique_emails)
            })

    def _is_internal_ip(self, ip: str) -> bool:
        """检查是否是内网IP"""
        parts = ip.split('.')
        if len(parts) != 4:
            return False

        try:
            first = int(parts[0])
            second = int(parts[1])

            # 10.0.0.0/8
            if first == 10:
                return True
            # 172.16.0.0/12
            if first == 172 and 16 <= second <= 31:
                return True
            # 192.168.0.0/16
            if first == 192 and second == 168:
                return True
            # 127.0.0.0/8
            if first == 127:
                return True

            return False
        except:
            return False

    def _analyze_code_features(self):
        """分析代码特征"""
        patterns = {
            "SQL Query": r'(?:SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER)\s+',
            "Shell Command": r'(?:exec|system|popen|subprocess)\s*\(',
            "File Operation": r'(?:open|fopen|readfile|file_get_contents)\s*\(',
            "Network Operation": r'(?:socket|connect|bind|listen|accept)\s*\(',
            "Crypto Operation": r'(?:encrypt|decrypt|hash|hmac|sign|verify)\s*\(',
            "Eval Function": r'(?:eval|exec)\s*\(',
            "Deserialization": r'(?:unserialize|pickle\.loads|yaml\.load)\s*\(',
        }

        all_strings = ' '.join([s['value'] for s in self.strings])

        for vuln_type, pattern in patterns.items():
            matches = re.findall(pattern, all_strings, re.IGNORECASE)
            if matches:
                severity = "High" if vuln_type in ["Eval Function", "Deserialization", "Shell Command"] else "Medium"
                self.vulnerabilities.append({
                    "type": "代码特征",
                    "severity": severity,
                    "description": f"发现{vuln_type}",
                    "evidence": matches[0][:100],
                    "count": len(matches)
                })

    def _get_statistics(self) -> Dict:
        """获取统计信息"""
        type_counter = Counter([s['type'] for s in self.strings])

        return {
            "total_strings": len(self.strings),
            "by_type": dict(type_counter),
            "vulnerabilities": len(self.vulnerabilities)
        }


def analyze_strings(file_path: str) -> Dict:
    """便捷函数：分析字符串"""
    analyzer = EnhancedStringAnalyzer(file_path)
    return analyzer.analyze()


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        result = analyze_strings(sys.argv[1])

        print(f"\n[*] 统计信息:")
        print(f"  总字符串数: {result['statistics']['total_strings']}")
        print(f"  按类型分布: {result['statistics']['by_type']}")
        print(f"  发现漏洞: {result['statistics']['vulnerabilities']}")

        if result['vulnerabilities']:
            print(f"\n[*] 发现的漏洞:")
            for vuln in result['vulnerabilities']:
                print(f"  [{vuln['severity']}] {vuln['type']}: {vuln['description']}")
    else:
        print("用法: python enhanced_strings.py <file_path>")
