# -*- coding: utf-8 -*-
"""
高级漏洞检测模块
支持: 逻辑漏洞、业务漏洞、新漏洞类型
"""

import requests
import re
import json
import time
from typing import List, Dict
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from config import SCAN_CONFIG


class AdvancedVulnScanner:
    """高级漏洞扫描器"""

    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": SCAN_CONFIG["user_agent"],
        })
        self.vulnerabilities = []

    def scan(self, url: str) -> List[Dict]:
        """执行扫描"""
        print(f"[*] 高级漏洞扫描: {url}")

        vulns = []

        # 1. 逻辑漏洞检测
        vulns.extend(self._scan_logic_vulns(url))

        # 2. 业务漏洞检测
        vulns.extend(self._scan_business_vulns(url))

        # 3. 认证漏洞检测
        vulns.extend(self._scan_auth_vulns(url))

        # 4. 授权漏洞检测
        vulns.extend(self._scan_authz_vulns(url))

        # 5. 会话漏洞检测
        vulns.extend(self._scan_session_vulns(url))

        # 6. 输入验证漏洞检测
        vulns.extend(self._scan_input_vulns(url))

        # 7. 输出编码漏洞检测
        vulns.extend(self._scan_output_vulns(url))

        # 8. 加密漏洞检测
        vulns.extend(self._scan_crypto_vulns(url))

        # 9. 配置漏洞检测
        vulns.extend(self._scan_config_vulns(url))

        # 10. 架构漏洞检测
        vulns.extend(self._scan_arch_vulns(url))

        self.vulnerabilities.extend(vulns)
        return vulns

    def _scan_logic_vulns(self, url: str) -> List[Dict]:
        """逻辑漏洞检测"""
        vulns = []
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        # 密码重置逻辑漏洞
        reset_paths = [
            "/forgot-password", "/forgot-password/",
            "/reset-password", "/reset-password/",
            "/password/reset", "/password/reset/",
            "/api/reset-password", "/api/reset-password/",
            "/api/forgot-password", "/api/forgot-password/",
        ]

        for path in reset_paths:
            full_url = urljoin(base, path)
            try:
                response = self.session.get(full_url, timeout=3, verify=False)

                if response.status_code == 200:
                    content = response.text.lower()

                    # 检查是否有验证码
                    if "captcha" not in content and "验证码" not in content:
                        vulns.append({
                            "type": "逻辑漏洞",
                            "severity": "High",
                            "url": full_url,
                            "description": "密码重置接口缺少验证码",
                            "evidence": "未发现验证码",
                            "remediation": "添加验证码验证"
                        })

                    # 检查是否有频率限制
                    if "rate limit" not in content and "频率限制" not in content:
                        vulns.append({
                            "type": "逻辑漏洞",
                            "severity": "Medium",
                            "url": full_url,
                            "description": "密码重置接口缺少频率限制",
                            "evidence": "未发现频率限制",
                            "remediation": "添加频率限制"
                        })

            except:
                pass

        # 注册逻辑漏洞
        register_paths = [
            "/register", "/register/",
            "/signup", "/signup/",
            "/api/register", "/api/register/",
            "/api/signup", "/api/signup/",
        ]

        for path in register_paths:
            full_url = urljoin(base, path)
            try:
                response = self.session.get(full_url, timeout=3, verify=False)

                if response.status_code == 200:
                    content = response.text.lower()

                    # 检查是否有验证码
                    if "captcha" not in content and "验证码" not in content:
                        vulns.append({
                            "type": "逻辑漏洞",
                            "severity": "Medium",
                            "url": full_url,
                            "description": "注册接口缺少验证码",
                            "evidence": "未发现验证码",
                            "remediation": "添加验证码验证"
                        })

            except:
                pass

        # 登录逻辑漏洞
        login_paths = [
            "/login", "/login/",
            "/signin", "/signin/",
            "/api/login", "/api/login/",
            "/api/auth/login", "/api/auth/login/",
        ]

        for path in login_paths:
            full_url = urljoin(base, path)
            try:
                response = self.session.get(full_url, timeout=3, verify=False)

                if response.status_code == 200:
                    content = response.text.lower()

                    # 检查是否有验证码
                    if "captcha" not in content and "验证码" not in content:
                        vulns.append({
                            "type": "逻辑漏洞",
                            "severity": "Medium",
                            "url": full_url,
                            "description": "登录接口缺少验证码",
                            "evidence": "未发现验证码",
                            "remediation": "添加验证码验证"
                        })

                    # 检查是否有账户锁定
                    if "lock" not in content and "锁定" not in content:
                        vulns.append({
                            "type": "逻辑漏洞",
                            "severity": "Medium",
                            "url": full_url,
                            "description": "登录接口缺少账户锁定",
                            "evidence": "未发现账户锁定",
                            "remediation": "添加账户锁定机制"
                        })

            except:
                pass

        return vulns

    def _scan_business_vulns(self, url: str) -> List[Dict]:
        """业务漏洞检测"""
        vulns = []
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        # 支付逻辑漏洞
        pay_paths = [
            "/pay", "/pay/",
            "/payment", "/payment/",
            "/checkout", "/checkout/",
            "/order/submit", "/order/submit/",
            "/api/pay", "/api/pay/",
            "/api/payment", "/api/payment/",
        ]

        for path in pay_paths:
            full_url = urljoin(base, path)
            try:
                response = self.session.get(full_url, timeout=3, verify=False)

                if response.status_code == 200:
                    content = response.text.lower()

                    # 检查是否有金额验证
                    if "price" in content or "amount" in content:
                        vulns.append({
                            "type": "逻辑漏洞",
                            "severity": "High",
                            "url": full_url,
                            "description": "支付接口可能存在金额篡改漏洞",
                            "evidence": "发现金额相关参数",
                            "remediation": "服务端验证金额"
                        })

            except:
                pass

        # 订单逻辑漏洞
        order_paths = [
            "/order", "/order/",
            "/orders", "/orders/",
            "/api/order", "/api/order/",
            "/api/orders", "/api/orders/",
        ]

        for path in order_paths:
            full_url = urljoin(base, path)
            try:
                response = self.session.get(full_url, timeout=3, verify=False)

                if response.status_code == 200:
                    content = response.text.lower()

                    # 检查是否有订单ID遍历
                    if "order_id" in content or "orderId" in content:
                        vulns.append({
                            "type": "逻辑漏洞",
                            "severity": "High",
                            "url": full_url,
                            "description": "订单接口可能存在ID遍历漏洞",
                            "evidence": "发现订单ID参数",
                            "remediation": "验证订单归属"
                        })

            except:
                pass

        return vulns

    def _scan_auth_vulns(self, url: str) -> List[Dict]:
        """认证漏洞检测"""
        vulns = []
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        # 检查认证接口
        auth_paths = [
            "/api/auth", "/api/auth/",
            "/api/token", "/api/token/",
            "/api/refresh", "/api/refresh/",
            "/oauth", "/oauth/",
            "/oauth2", "/oauth2/",
        ]

        for path in auth_paths:
            full_url = urljoin(base, path)
            try:
                response = self.session.get(full_url, timeout=3, verify=False)

                if response.status_code == 200:
                    content = response.text.lower()

                    # 检查是否有JWT
                    if "jwt" in content or "token" in content:
                        vulns.append({
                            "type": "认证漏洞",
                            "severity": "Medium",
                            "url": full_url,
                            "description": "发现认证接口",
                            "evidence": "发现JWT/Token相关",
                            "remediation": "加强认证安全"
                        })

            except:
                pass

        return vulns

    def _scan_authz_vulns(self, url: str) -> List[Dict]:
        """授权漏洞检测"""
        vulns = []
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        # 检查管理接口
        admin_paths = [
            "/admin", "/admin/",
            "/admin/users", "/admin/users/",
            "/admin/config", "/admin/config/",
            "/api/admin", "/api/admin/",
            "/api/users", "/api/users/",
        ]

        for path in admin_paths:
            full_url = urljoin(base, path)
            try:
                response = self.session.get(full_url, timeout=3, verify=False)

                if response.status_code == 200:
                    content = response.text.lower()

                    # 检查是否需要认证
                    if "login" not in content and "登录" not in content:
                        vulns.append({
                            "type": "授权漏洞",
                            "severity": "Critical",
                            "url": full_url,
                            "description": "管理接口可能未授权访问",
                            "evidence": "无需认证即可访问",
                            "remediation": "添加认证和授权"
                        })

            except:
                pass

        return vulns

    def _scan_session_vulns(self, url: str) -> List[Dict]:
        """会话漏洞检测"""
        vulns = []

        try:
            response = self.session.get(url, timeout=3, verify=False)

            # 检查会话Cookie
            cookies = response.cookies
            for cookie in cookies:
                # 检查HttpOnly
                if not cookie.has_attr('httponly'):
                    vulns.append({
                        "type": "会话漏洞",
                        "severity": "Medium",
                        "url": url,
                        "description": f"Cookie {cookie.name} 缺少 HttpOnly",
                        "evidence": f"Cookie: {cookie.name}",
                        "remediation": "设置 HttpOnly 标志"
                    })

                # 检查Secure
                if not cookie.secure:
                    vulns.append({
                        "type": "会话漏洞",
                        "severity": "Medium",
                        "url": url,
                        "description": f"Cookie {cookie.name} 缺少 Secure",
                        "evidence": f"Cookie: {cookie.name}",
                        "remediation": "设置 Secure 标志"
                    })

        except:
            pass

        return vulns

    def _scan_input_vulns(self, url: str) -> List[Dict]:
        """输入验证漏洞检测"""
        vulns = []
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        if not params:
            return vulns

        # 测试输入验证
        test_payloads = [
            ("' OR '1'='1", "SQL注入"),
            ("<script>alert(1)</script>", "XSS"),
            ("../../../etc/passwd", "路径遍历"),
            ("; ls -la", "命令注入"),
            ("{{7*7}}", "模板注入"),
        ]

        for param_name, param_values in params.items():
            for payload, vuln_type in test_payloads:
                try:
                    test_params = params.copy()
                    test_params[param_name] = [payload]
                    test_query = urlencode(test_params, doseq=True)
                    test_url = urlunparse(parsed._replace(query=test_query))

                    response = self.session.get(test_url, timeout=3, verify=False)

                    # 检查是否有漏洞
                    if self._check_vulnerability(response, vuln_type, payload):
                        vulns.append({
                            "type": vuln_type,
                            "severity": "High",
                            "url": url,
                            "description": f"参数 {param_name} 存在{vuln_type}漏洞",
                            "evidence": f"Payload: {payload}",
                            "remediation": "验证和过滤输入"
                        })

                except:
                    pass

        return vulns

    def _check_vulnerability(self, response, vuln_type: str, payload: str) -> bool:
        """检查是否有漏洞"""
        content = response.text

        if vuln_type == "SQL注入":
            sql_errors = ["sql syntax", "mysql", "ora-", "sql server"]
            return any(error in content.lower() for error in sql_errors)

        elif vuln_type == "XSS":
            return payload in content

        elif vuln_type == "路径遍历":
            return "root:" in content or "localhost" in content

        elif vuln_type == "命令注入":
            return "uid=" in content or "root:" in content

        elif vuln_type == "模板注入":
            return "49" in content

        return False

    def _scan_output_vulns(self, url: str) -> List[Dict]:
        """输出编码漏洞检测"""
        vulns = []

        try:
            response = self.session.get(url, timeout=3, verify=False)
            headers = response.headers

            # 检查Content-Type
            content_type = headers.get("Content-Type", "")
            if "text/html" in content_type:
                # 检查X-Content-Type-Options
                if "X-Content-Type-Options" not in headers:
                    vulns.append({
                        "type": "输出编码漏洞",
                        "severity": "Low",
                        "url": url,
                        "description": "缺少 X-Content-Type-Options 头",
                        "evidence": "未设置 X-Content-Type-Options",
                        "remediation": "添加 X-Content-Type-Options: nosniff"
                    })

        except:
            pass

        return vulns

    def _scan_crypto_vulns(self, url: str) -> List[Dict]:
        """加密漏洞检测"""
        vulns = []

        try:
            response = self.session.get(url, timeout=3, verify=False)

            # 检查HTTPS
            if not url.startswith("https://"):
                vulns.append({
                    "type": "加密漏洞",
                    "severity": "High",
                    "url": url,
                    "description": "未使用HTTPS",
                    "evidence": "使用HTTP协议",
                    "remediation": "启用HTTPS"
                })

            # 检查HSTS
            if "Strict-Transport-Security" not in response.headers:
                vulns.append({
                    "type": "加密漏洞",
                    "severity": "Medium",
                    "url": url,
                    "description": "缺少HSTS头",
                    "evidence": "未设置 Strict-Transport-Security",
                    "remediation": "添加HSTS头"
                })

        except:
            pass

        return vulns

    def _scan_config_vulns(self, url: str) -> List[Dict]:
        """配置漏洞检测"""
        vulns = []
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        # 检查错误页面
        error_paths = [
            "/error", "/error/",
            "/404", "/404.html",
            "/500", "/500.html",
        ]

        for path in error_paths:
            full_url = urljoin(base, path)
            try:
                response = self.session.get(full_url, timeout=3, verify=False)

                if response.status_code == 200:
                    content = response.text

                    # 检查是否泄露敏感信息
                    if any(kw in content.lower() for kw in ["stack trace", "debug", "exception"]):
                        vulns.append({
                            "type": "配置漏洞",
                            "severity": "Medium",
                            "url": full_url,
                            "description": "错误页面泄露敏感信息",
                            "evidence": "发现调试信息",
                            "remediation": "自定义错误页面"
                        })

            except:
                pass

        return vulns

    def _scan_arch_vulns(self, url: str) -> List[Dict]:
        """架构漏洞检测"""
        vulns = []

        try:
            response = self.session.get(url, timeout=3, verify=False)

            # 检查服务器信息
            server = response.headers.get("Server", "")
            if server:
                vulns.append({
                    "type": "架构漏洞",
                    "severity": "Low",
                    "url": url,
                    "description": "服务器信息泄露",
                    "evidence": f"Server: {server}",
                    "remediation": "隐藏服务器信息"
                })

            # 检查X-Powered-By
            powered_by = response.headers.get("X-Powered-By", "")
            if powered_by:
                vulns.append({
                    "type": "架构漏洞",
                    "severity": "Low",
                    "url": url,
                    "description": "技术栈信息泄露",
                    "evidence": f"X-Powered-By: {powered_by}",
                    "remediation": "隐藏技术栈信息"
                })

        except:
            pass

        return vulns


def scan_advanced_vulns(url: str) -> List[Dict]:
    """便捷函数：高级漏洞扫描"""
    scanner = AdvancedVulnScanner()
    return scanner.scan(url)


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        vulns = scan_advanced_vulns(sys.argv[1])
        for vuln in vulns:
            print(f"[{vuln['severity']}] {vuln['type']}: {vuln['description']}")
    else:
        print("用法: python vuln_advanced.py <url>")
