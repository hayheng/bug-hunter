# -*- coding: utf-8 -*-
"""
漏洞验证模块 - 二次验证减少误报
"""

import requests
import re
import time
from typing import List, Dict, Optional
from urllib.parse import urljoin, urlparse
from config import SCAN_CONFIG


class VulnerabilityVerifier:
    """漏洞验证器"""

    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": SCAN_CONFIG["user_agent"],
        })

    def verify_all(self, vulnerabilities: List[Dict]) -> List[Dict]:
        """验证所有漏洞（去重 + 智能过滤）"""
        print(f"[*] 开始漏洞验证，共 {len(vulnerabilities)} 个")

        verified = []
        seen = set()  # 用于去重
        evidence_seen = set()  # 用于证据去重

        # 误报关键词
        false_positive_keywords = [
            "password\"",  # 代码中的 password 字符串
            "password'",
            "password=",
            "password:",
            "password\\",
            "password\"",
            "password'",
            "password=",
            "password:",
            "password\\",
        ]

        for vuln in vulnerabilities:
            result = self.verify(vuln)
            if result and result.get("verified"):
                # 去重：相同URL和类型只保留一个
                url = vuln.get("url", "")
                vuln_type = vuln.get("type", "")
                evidence = vuln.get("evidence", "")[:50]  # 取前50个字符作为证据

                # 智能过滤误报
                is_false_positive = False
                for keyword in false_positive_keywords:
                    if keyword in evidence:
                        is_false_positive = True
                        break

                if is_false_positive:
                    print(f"  [X] {vuln_type} - 误报（代码中的字符串）")
                    continue

                # URL+类型 去重
                key = f"{url}|{vuln_type}"

                # 证据去重：相同证据的漏洞只保留一个
                evidence_key = f"{vuln_type}|{evidence}"

                if key not in seen and evidence_key not in evidence_seen:
                    seen.add(key)
                    evidence_seen.add(evidence_key)
                    verified.append(result)
                    print(f"  [OK] {vuln_type} - 已验证")
                else:
                    print(f"  [=] {vuln_type} - 重复，跳过")
            else:
                print(f"  [X] {vuln.get('type')} - 误报")

        print(f"[*] 验证完成，确认 {len(verified)}/{len(vulnerabilities)} 个漏洞")
        return verified

    def verify(self, vuln: Dict) -> Optional[Dict]:
        """验证单个漏洞"""
        vuln_type = vuln.get("type", "")

        # 根据漏洞类型选择验证方法
        if "Clickjacking" in vuln_type:
            return self._verify_clickjacking(vuln)
        elif "敏感文件" in vuln_type:
            return self._verify_sensitive_file(vuln)
        elif "信息泄露" in vuln_type:
            return self._verify_info_disclosure(vuln)
        elif "PUT方法" in vuln_type:
            return self._verify_put_method(vuln)
        elif "安全头" in vuln_type:
            return self._verify_security_headers(vuln)
        elif "弱加密" in vuln_type:
            return self._verify_weak_cipher(vuln)
        elif "SQL注入" in vuln_type:
            return self._verify_sql_injection(vuln)
        elif "XSS" in vuln_type:
            return self._verify_xss(vuln)
        elif "未授权" in vuln_type:
            return self._verify_unauthorized(vuln)
        elif "API" in vuln_type:
            return self._verify_api_endpoint(vuln)
        else:
            # 默认通过
            vuln["verified"] = True
            vuln["verify_method"] = "默认通过"
            return vuln

    def _verify_clickjacking(self, vuln: Dict) -> Optional[Dict]:
        """验证Clickjacking漏洞"""
        url = vuln.get("url", "")
        try:
            response = self.session.get(url, timeout=5, verify=False)
            headers = response.headers

            # 检查是否真的缺少防护
            x_frame = headers.get("X-Frame-Options", "").upper()
            csp = headers.get("Content-Security-Policy", "")

            has_protection = False
            if x_frame in ["DENY", "SAMEORIGIN"]:
                has_protection = True
            if "frame-ancestors" in csp:
                has_protection = True

            if not has_protection:
                vuln["verified"] = True
                vuln["verify_method"] = "确认缺少X-Frame-Options和CSP frame-ancestors"
                return vuln
            else:
                return None

        except Exception as e:
            vuln["verified"] = True
            vuln["verify_method"] = f"无法验证，默认通过: {e}"
            return vuln

    def _verify_sensitive_file(self, vuln: Dict) -> Optional[Dict]:
        """验证敏感文件泄露"""
        url = vuln.get("url", "")

        # 正常文件列表（不算漏洞）
        normal_files = [
            "robots.txt", "sitemap.xml", "favicon.ico",
            "humans.txt", "crossdomain.xml",
            "LICENSE", "README.md", "CHANGELOG.md",
            "security.txt", ".well-known/security.txt",
        ]

        # 检查是否是正常文件
        for normal_file in normal_files:
            if normal_file in url:
                return None

        try:
            response = self.session.get(url, timeout=5, verify=False)

            # 只有 200 状态码才算敏感文件泄露
            # 301/302 重定向不算
            if response.status_code == 200:
                content = response.text

                # 排除自定义404页面
                if "404" in content[:100] and "not found" in content.lower()[:100]:
                    return None

                # 检查内容是否包含敏感信息
                sensitive_patterns = [
                    r"password", r"secret", r"key", r"token",
                    r"database", r"mysql", r"redis",
                    r"\.env", r"DB_PASSWORD", r"API_KEY",
                    r"private_key", r"access_token",
                ]

                for pattern in sensitive_patterns:
                    if re.search(pattern, content, re.IGNORECASE):
                        vuln["verified"] = True
                        vuln["verify_method"] = f"确认文件存在且包含敏感内容"
                        return vuln

            return None

        except Exception as e:
            vuln["verified"] = True
            vuln["verify_method"] = f"无法验证，默认通过: {e}"
            return vuln

    def _verify_info_disclosure(self, vuln: Dict) -> Optional[Dict]:
        """验证信息泄露"""
        url = vuln.get("url", "")
        evidence = vuln.get("evidence", "")

        # 排除误报
        false_positive_patterns = [
            "password",  # 代码中的 password 字符串
            "password=",  # 代码中的 password= 字符串
            "password:",  # 代码中的 password: 字符串
            "password\"",  # 代码中的 password" 字符串
            "password'",  # 代码中的 password' 字符串
        ]

        # 检查是否是误报
        for pattern in false_positive_patterns:
            if pattern in evidence.lower():
                # 检查是否是真正的敏感信息
                if not any(kw in evidence.lower() for kw in ["db_password", "api_key", "secret_key", "token"]):
                    return None

        # 检查证据是否充分
        if evidence and len(evidence) > 20:
            # 检查是否包含真正的敏感信息
            sensitive_patterns = [
                r'DB_PASSWORD',
                r'API_KEY',
                r'SECRET_KEY',
                r'ACCESS_TOKEN',
                r'PRIVATE_KEY',
                r'AWS_SECRET',
                r'password\s*[:=]\s*["\'][^"\']{8,}["\']',
                r'secret\s*[:=]\s*["\'][^"\']{8,}["\']',
                r'token\s*[:=]\s*["\'][^"\']{8,}["\']',
            ]

            for pattern in sensitive_patterns:
                if re.search(pattern, evidence, re.IGNORECASE):
                    vuln["verified"] = True
                    vuln["verify_method"] = "确认存在信息泄露"
                    return vuln

        return None

    def _verify_put_method(self, vuln: Dict) -> Optional[Dict]:
        """验证PUT方法启用"""
        url = vuln.get("url", "")
        try:
            # 测试PUT方法
            response = self.session.request(
                "PUT",
                url,
                data="test",
                timeout=5,
                verify=False
            )

            # 如果返回200或201，说明PUT方法确实可用
            if response.status_code in [200, 201]:
                vuln["verified"] = True
                vuln["verify_method"] = f"确认PUT方法可用，返回状态码: {response.status_code}"
                return vuln

            # 如果返回405，说明PUT方法被禁用
            if response.status_code == 405:
                return None

            vuln["verified"] = True
            vuln["verify_method"] = f"PUT方法返回状态码: {response.status_code}"
            return vuln

        except Exception as e:
            vuln["verified"] = True
            vuln["verify_method"] = f"无法验证，默认通过: {e}"
            return vuln

    def _verify_security_headers(self, vuln: Dict) -> Optional[Dict]:
        """验证安全头缺失"""
        url = vuln.get("url", "")
        try:
            response = self.session.get(url, timeout=5, verify=False)
            headers = response.headers

            # 检查缺失的安全头
            missing_headers = []
            security_headers = [
                "X-Content-Type-Options",
                "X-Frame-Options",
                "X-XSS-Protection",
                "Strict-Transport-Security",
                "Content-Security-Policy",
                "Referrer-Policy",
            ]

            for header in security_headers:
                if header not in headers:
                    missing_headers.append(header)

            if missing_headers:
                vuln["verified"] = True
                vuln["verify_method"] = f"确认缺少安全头: {', '.join(missing_headers)}"
                return vuln

            return None

        except Exception as e:
            vuln["verified"] = True
            vuln["verify_method"] = f"无法验证，默认通过: {e}"
            return vuln

    def _verify_weak_cipher(self, vuln: Dict) -> Optional[Dict]:
        """验证弱加密套件"""
        # 弱加密通常通过SSL/TLS检测，这里简化处理
        vuln["verified"] = True
        vuln["verify_method"] = "SSL/TLS配置问题，需要专业工具验证"
        return vuln

    def _verify_sql_injection(self, vuln: Dict) -> Optional[Dict]:
        """验证SQL注入"""
        url = vuln.get("url", "")
        evidence = vuln.get("evidence", "")

        # 检查是否有SQL报错信息
        sql_errors = [
            "sql syntax", "mysql_fetch", "mysqli",
            "ORA-", "SQL Server", "sqlite3",
            "Syntax error", "unclosed quotation mark",
        ]

        for error in sql_errors:
            if error.lower() in evidence.lower():
                vuln["verified"] = True
                vuln["verify_method"] = f"确认存在SQL报错: {error}"
                return vuln

        # 时间盲注验证
        if "SLEEP" in evidence or "sleep" in evidence:
            vuln["verified"] = True
            vuln["verify_method"] = "时间盲注需要手动验证"
            return vuln

        return None

    def _verify_xss(self, vuln: Dict) -> Optional[Dict]:
        """验证XSS"""
        url = vuln.get("url", "")
        evidence = vuln.get("evidence", "")

        # 检查payload是否被反射
        xss_payloads = [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
        ]

        for payload in xss_payloads:
            if payload in evidence:
                vuln["verified"] = True
                vuln["verify_method"] = f"确认XSS payload被反射"
                return vuln

        return None

    def _verify_unauthorized(self, vuln: Dict) -> Optional[Dict]:
        """验证未授权访问"""
        url = vuln.get("url", "")
        try:
            response = self.session.get(url, timeout=5, verify=False)

            # 检查是否真的不需要认证
            if response.status_code == 200:
                # 排除登录页面
                if "login" not in response.text.lower()[:500]:
                    if "password" not in response.text.lower()[:500]:
                        vuln["verified"] = True
                        vuln["verify_method"] = "确认可未授权访问"
                        return vuln

            return None

        except Exception as e:
            vuln["verified"] = True
            vuln["verify_method"] = f"无法验证，默认通过: {e}"
            return vuln

    def _verify_api_endpoint(self, vuln: Dict) -> Optional[Dict]:
        """验证API端点泄露"""
        url = vuln.get("url", "")
        try:
            response = self.session.get(url, timeout=5, verify=False)

            # 检查是否真的是API
            content_type = response.headers.get("Content-Type", "")
            if "json" in content_type or "swagger" in response.text.lower():
                vuln["verified"] = True
                vuln["verify_method"] = f"确认API端点存在"
                return vuln

            return None

        except Exception as e:
            vuln["verified"] = True
            vuln["verify_method"] = f"无法验证，默认通过: {e}"
            return vuln


def verify_vulnerabilities(vulnerabilities: List[Dict]) -> List[Dict]:
    """便捷函数：验证漏洞"""
    verifier = VulnerabilityVerifier()
    return verifier.verify_all(vulnerabilities)


if __name__ == "__main__":
    import json
    import sys

    if len(sys.argv) > 1:
        # 从文件读取漏洞
        with open(sys.argv[1], "r", encoding="utf-8") as f:
            vulns = json.load(f)

        verified = verify_vulnerabilities(vulns)
        print(f"\n验证通过的漏洞:")
        for v in verified:
            print(f"  [{v.get('severity')}] {v.get('type')}: {v.get('url')}")
    else:
        print("用法: python vuln_verifier.py <vulns.json>")
