# -*- coding: utf-8 -*-
"""
漏洞扫描模块
"""

import requests
import re
import time
from typing import List, Dict, Optional
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from config import (
    SCAN_CONFIG, VULN_CONFIG, SENSITIVE_PATHS,
    SQL_PAYLOADS, SQL_ERRORS, XSS_PAYLOADS, INFO_DISCLOSURE_KEYWORDS
)


class Vulnerability:
    """漏洞类"""

    def __init__(self, vuln_type: str, severity: str, url: str,
                 description: str, evidence: str = "", remediation: str = ""):
        self.vuln_type = vuln_type
        self.severity = severity  # Critical, High, Medium, Low, Info
        self.url = url
        self.description = description
        self.evidence = evidence
        self.remediation = remediation

    def to_dict(self) -> Dict:
        return {
            "type": self.vuln_type,
            "severity": self.severity,
            "url": self.url,
            "description": self.description,
            "evidence": self.evidence[:500] if self.evidence else "",
            "remediation": self.remediation,
        }


class VulnScanner:
    """漏洞扫描器"""

    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": SCAN_CONFIG["user_agent"],
        })
        self.vulnerabilities: List[Vulnerability] = []

    def scan_target(self, target: Dict) -> List[Vulnerability]:
        """扫描单个目标"""
        url = target["url"]
        print(f"[*] 扫描目标: {url}")

        vulns = []

        # 信息泄露检测
        if VULN_CONFIG["check_info_disclosure"]:
            vulns.extend(self._check_info_disclosure(url))

        # 敏感文件检测
        if VULN_CONFIG["check_sensitive_files"]:
            vulns.extend(self._check_sensitive_files(url))

        # CORS 配置检测
        if VULN_CONFIG["check_cors"]:
            vulns.extend(self._check_cors(url))

        # Clickjacking 检测
        if VULN_CONFIG["check_clickjacking"]:
            vulns.extend(self._check_clickjacking(url))

        # SQL注入检测
        if VULN_CONFIG["check_sql_injection"]:
            vulns.extend(self._check_sql_injection(url))

        # XSS检测
        if VULN_CONFIG["check_xss"]:
            vulns.extend(self._check_xss(url))

        # 开放重定向检测
        if VULN_CONFIG["check_open_redirect"]:
            vulns.extend(self._check_open_redirect(url))

        self.vulnerabilities.extend(vulns)
        return vulns

    def _check_info_disclosure(self, url: str) -> List[Vulnerability]:
        """检测信息泄露"""
        vulns = []
        try:
            response = self.session.get(url, timeout=SCAN_CONFIG["timeout"], verify=False)
            body = response.text.lower()

            # 检查敏感信息泄露
            for keyword in INFO_DISCLOSURE_KEYWORDS:
                if keyword in body:
                    # 获取上下文
                    pattern = rf".{{0,50}}{re.escape(keyword)}.{{0,50}}"
                    matches = re.findall(pattern, body)
                    if matches:
                        vulns.append(Vulnerability(
                            vuln_type="信息泄露",
                            severity="Medium",
                            url=url,
                            description=f"页面中发现敏感关键词: {keyword}",
                            evidence=matches[0],
                            remediation="移除页面中的敏感信息"
                        ))
                        break  # 只报告一次

            # 检查响应头信息泄露
            headers = response.headers
            if "X-Powered-By" in headers:
                vulns.append(Vulnerability(
                    vuln_type="信息泄露",
                    severity="Low",
                    url=url,
                    description=f"响应头泄露技术栈: {headers['X-Powered-By']}",
                    evidence=f"X-Powered-By: {headers['X-Powered-By']}",
                    remediation="移除 X-Powered-By 响应头"
                ))

            if "Server" in headers and len(headers["Server"]) > 10:
                vulns.append(Vulnerability(
                    vuln_type="信息泄露",
                    severity="Low",
                    url=url,
                    description=f"响应头泄露服务器信息: {headers['Server']}",
                    evidence=f"Server: {headers['Server']}",
                    remediation="配置服务器隐藏详细版本信息"
                ))

        except Exception as e:
            pass
        return vulns

    def _check_sensitive_files(self, url: str) -> List[Vulnerability]:
        """检测敏感文件"""
        vulns = []

        def check_path(path):
            full_url = urljoin(url, path)
            try:
                response = self.session.get(
                    full_url,
                    timeout=SCAN_CONFIG["timeout"],
                    allow_redirects=False,
                    verify=False
                )
                if response.status_code == 200:
                    # 验证不是自定义404页面
                    if len(response.text) > 0 and "404" not in response.text[:100]:
                        return Vulnerability(
                            vuln_type="敏感文件泄露",
                            severity="High" if path in ["/.env", "/.git/config", "/.htpasswd"] else "Medium",
                            url=full_url,
                            description=f"发现敏感文件: {path}",
                            evidence=response.text[:200],
                            remediation="删除或限制访问敏感文件"
                        )
            except:
                pass
            return None

        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(check_path, path) for path in SENSITIVE_PATHS]
            for future in as_completed(futures):
                result = future.result()
                if result:
                    vulns.append(result)

        return vulns

    def _check_cors(self, url: str) -> List[Vulnerability]:
        """检测CORS配置错误"""
        vulns = []
        try:
            headers = {"Origin": "https://evil.com"}
            response = self.session.get(
                url,
                headers=headers,
                timeout=SCAN_CONFIG["timeout"],
                verify=False
            )

            acao = response.headers.get("Access-Control-Allow-Origin", "")
            if acao == "*":
                vulns.append(Vulnerability(
                    vuln_type="CORS配置错误",
                    severity="Medium",
                    url=url,
                    description="CORS配置允许所有域名访问",
                    evidence=f"Access-Control-Allow-Origin: {acao}",
                    remediation="限制 CORS 允许的域名"
                ))
            elif "evil.com" in acao:
                vulns.append(Vulnerability(
                    vuln_type="CORS配置错误",
                    severity="High",
                    url=url,
                    description="CORS配置反射任意Origin",
                    evidence=f"Access-Control-Allow-Origin: {acao}",
                    remediation="验证 Origin 白名单，不要反射任意 Origin"
                ))

            # 检查是否允许携带凭证
            if acao and response.headers.get("Access-Control-Allow-Credentials") == "true":
                if acao == "*" or "evil.com" in acao:
                    vulns.append(Vulnerability(
                        vuln_type="CORS配置错误",
                        severity="Critical",
                        url=url,
                        description="CORS配置允许任意域名携带凭证",
                        evidence=f"ACAO: {acao}, ACAC: true",
                        remediation="禁止携带凭证或严格限制 Origin"
                    ))

        except Exception as e:
            pass
        return vulns

    def _check_clickjacking(self, url: str) -> List[Vulnerability]:
        """检测Clickjacking漏洞"""
        vulns = []
        try:
            response = self.session.get(url, timeout=SCAN_CONFIG["timeout"], verify=False)
            headers = response.headers

            x_frame = headers.get("X-Frame-Options", "").upper()
            csp = headers.get("Content-Security-Policy", "")

            has_protection = False
            if x_frame in ["DENY", "SAMEORIGIN"]:
                has_protection = True
            if "frame-ancestors" in csp:
                has_protection = True

            if not has_protection:
                vulns.append(Vulnerability(
                    vuln_type="Clickjacking",
                    severity="Medium",
                    url=url,
                    description="页面缺少 Clickjacking 防护",
                    evidence="未设置 X-Frame-Options 或 CSP frame-ancestors",
                    remediation="添加 X-Frame-Options: DENY 或 CSP frame-ancestors 指令"
                ))

        except Exception as e:
            pass
        return vulns

    def _check_sql_injection(self, url: str) -> List[Vulnerability]:
        """检测SQL注入"""
        vulns = []

        # 解析URL中的参数
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        if not params:
            return vulns

        for param_name, param_values in params.items():
            for payload in SQL_PAYLOADS[:5]:  # 限制payload数量
                try:
                    # 构造测试URL
                    test_params = params.copy()
                    test_params[param_name] = [payload]
                    test_query = urlencode(test_params, doseq=True)
                    test_url = urlunparse(parsed._replace(query=test_query))

                    # 发送请求
                    response = self.session.get(
                        test_url,
                        timeout=SCAN_CONFIG["timeout"] + 5,
                        verify=False
                    )

                    # 检查SQL报错
                    body = response.text.lower()
                    for error in SQL_ERRORS:
                        if error.lower() in body:
                            vulns.append(Vulnerability(
                                vuln_type="SQL注入",
                                severity="Critical",
                                url=url,
                                description=f"参数 {param_name} 存在SQL注入漏洞",
                                evidence=f"Payload: {payload}\n响应包含: {error}",
                                remediation="使用参数化查询，过滤用户输入"
                            ))
                            break

                    # 时间盲注检测
                    if "SLEEP" in payload or "WAITFOR" in payload:
                        if response.elapsed.total_seconds() > 4:
                            vulns.append(Vulnerability(
                                vuln_type="SQL注入(时间盲注)",
                                severity="Critical",
                                url=url,
                                description=f"参数 {param_name} 可能存在时间盲注",
                                evidence=f"Payload: {payload}\n响应时间: {response.elapsed.total_seconds()}s",
                                remediation="使用参数化查询，过滤用户输入"
                            ))

                except Exception as e:
                    continue

        return vulns

    def _check_xss(self, url: str) -> List[Vulnerability]:
        """检测XSS漏洞"""
        vulns = []

        # 解析URL中的参数
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        if not params:
            return vulns

        for param_name, param_values in params.items():
            for payload in XSS_PAYLOADS[:3]:  # 限制payload数量
                try:
                    # 构造测试URL
                    test_params = params.copy()
                    test_params[param_name] = [payload]
                    test_query = urlencode(test_params, doseq=True)
                    test_url = urlunparse(parsed._replace(query=test_query))

                    # 发送请求
                    response = self.session.get(
                        test_url,
                        timeout=SCAN_CONFIG["timeout"],
                        verify=False
                    )

                    # 检查payload是否被反射
                    if payload in response.text:
                        vulns.append(Vulnerability(
                            vuln_type="XSS",
                            severity="High",
                            url=url,
                            description=f"参数 {param_name} 存在反射型XSS",
                            evidence=f"Payload: {payload}\n被直接反射到页面",
                            remediation="对用户输入进行HTML编码"
                        ))

                except Exception as e:
                    continue

        return vulns

    def _check_open_redirect(self, url: str) -> List[Vulnerability]:
        """检测开放重定向"""
        vulns = []

        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        redirect_params = ["url", "redirect", "next", "return", "goto", "to", "out", "rurl", "dest"]
        test_domain = "https://evil.com"

        for param in params:
            if param.lower() in redirect_params:
                try:
                    test_params = params.copy()
                    test_params[param] = [test_domain]
                    test_query = urlencode(test_params, doseq=True)
                    test_url = urlunparse(parsed._replace(query=test_query))

                    response = self.session.get(
                        test_url,
                        timeout=SCAN_CONFIG["timeout"],
                        allow_redirects=False,
                        verify=False
                    )

                    if response.status_code in [301, 302, 303, 307, 308]:
                        location = response.headers.get("Location", "")
                        if "evil.com" in location:
                            vulns.append(Vulnerability(
                                vuln_type="开放重定向",
                                severity="Medium",
                                url=url,
                                description=f"参数 {param} 存在开放重定向漏洞",
                                evidence=f"重定向到: {location}",
                                remediation="验证重定向目标域名白名单"
                            ))

                except Exception as e:
                    continue

        return vulns


def scan_single_target(target: Dict) -> List[Vulnerability]:
    """便捷函数：扫描单个目标"""
    scanner = VulnScanner()
    return scanner.scan_target(target)


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        target = {"url": sys.argv[1]}
        vulns = scan_single_target(target)
        for vuln in vulns:
            print(f"[{vuln.severity}] {vuln.vuln_type}: {vuln.url}")
            print(f"  描述: {vuln.description}")
            print()
    else:
        print("用法: python vuln_scanner.py <url>")
