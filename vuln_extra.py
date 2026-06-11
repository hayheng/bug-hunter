# -*- coding: utf-8 -*-
"""
额外漏洞检测模块
支持: JWT、GraphQL、WebSocket、CORS增强、开放重定向增强
"""

import requests
import re
import json
import base64
from typing import List, Dict
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from config import SCAN_CONFIG


class ExtraVulnScanner:
    """额外漏洞扫描器"""

    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": SCAN_CONFIG["user_agent"],
        })
        self.vulnerabilities = []

    def scan(self, url: str) -> List[Dict]:
        """执行扫描"""
        print(f"[*] 额外漏洞扫描: {url}")

        vulns = []

        # 1. JWT 漏洞检测
        vulns.extend(self._scan_jwt(url))

        # 2. GraphQL 漏洞检测
        vulns.extend(self._scan_graphql(url))

        # 3. WebSocket 漏洞检测
        vulns.extend(self._scan_websocket(url))

        # 4. CORS 漏洞增强
        vulns.extend(self._scan_cors_enhanced(url))

        # 5. 开放重定向增强
        vulns.extend(self._scan_open_redirect_enhanced(url))

        # 6. HTTP 方法增强
        vulns.extend(self._scan_http_methods(url))

        # 7. Cookie 安全检测
        vulns.extend(self._scan_cookie_security(url))

        # 8. CSRF 漏洞检测
        vulns.extend(self._scan_csrf(url))

        # 9. 点击劫持增强
        vulns.extend(self._scan_clickjacking_enhanced(url))

        # 10. MIME 类型检测
        vulns.extend(self._scan_mime_type(url))

        self.vulnerabilities.extend(vulns)
        return vulns

    def _scan_jwt(self, url: str) -> List[Dict]:
        """JWT 漏洞检测"""
        vulns = []

        try:
            response = self.session.get(url, timeout=5, verify=False)
            content = response.text

            # 查找 JWT token
            jwt_patterns = [
                r'eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_.+/=]+',
                r'Bearer\s+eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_.+/=]+',
                r'Authorization:\s*Bearer\s+eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_.+/=]+',
            ]

            for pattern in jwt_patterns:
                matches = re.findall(pattern, content)
                for jwt_token in matches:
                    # 清理 token
                    if jwt_token.startswith("Bearer "):
                        jwt_token = jwt_token[7:]

                    # 解码 header
                    try:
                        header = jwt_token.split(".")[0]
                        header += "=" * (4 - len(header) % 4)
                        header_decoded = json.loads(base64.b64decode(header))

                        # 检查 alg: none 漏洞
                        if header_decoded.get("alg", "").lower() == "none":
                            vulns.append({
                                "type": "JWT漏洞",
                                "severity": "Critical",
                                "url": url,
                                "description": "JWT 使用 none 算法，可被伪造",
                                "evidence": f"Header: {json.dumps(header_decoded)}",
                                "remediation": "使用强算法（RS256等），验证签名"
                            })

                        # 检查弱算法
                        if header_decoded.get("alg", "").upper() in ["HS256", "HS384", "HS512"]:
                            vulns.append({
                                "type": "JWT漏洞",
                                "severity": "Medium",
                                "url": url,
                                "description": "JWT 使用对称算法，可能存在弱密钥",
                                "evidence": f"Algorithm: {header_decoded.get('alg')}",
                                "remediation": "使用非对称算法（RS256等）或强密钥"
                            })

                    except:
                        pass

        except Exception as e:
            pass

        return vulns

    def _scan_graphql(self, url: str) -> List[Dict]:
        """GraphQL 漏洞检测"""
        vulns = []
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        # GraphQL 路径
        graphql_paths = ["/graphql", "/graphiql", "/playground", "/api/graphql", "/v1/graphql", "/v2/graphql"]

        for path in graphql_paths:
            full_url = urljoin(base, path)
            try:
                # 测试 introspection
                query = {"query": "{__schema{types{name}}}"}
                response = self.session.post(full_url, json=query, timeout=5, verify=False)

                if response.status_code == 200 and "__schema" in response.text:
                    vulns.append({
                        "type": "GraphQL漏洞",
                        "severity": "High",
                        "url": full_url,
                        "description": "GraphQL 端点可访问，可能泄露 Schema",
                        "evidence": "Introspection 查询返回数据",
                        "remediation": "限制 GraphQL 访问，禁用 introspection"
                    })

                    # 测试完整 introspection
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
                    response2 = self.session.post(full_url, json=introspection_query, timeout=5, verify=False)
                    if response2.status_code == 200 and "mutationType" in response2.text:
                        vulns.append({
                            "type": "GraphQL漏洞",
                            "severity": "High",
                            "url": full_url,
                            "description": "GraphQL introspection 已启用，可获取完整 Schema",
                            "evidence": "Introspection 查询返回完整 schema",
                            "remediation": "禁用 introspection 查询"
                        })

            except:
                pass

        return vulns

    def _scan_websocket(self, url: str) -> List[Dict]:
        """WebSocket 漏洞检测"""
        vulns = []
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        # WebSocket 路径
        ws_paths = ["/ws", "/websocket", "/socket", "/socket.io", "/wss"]

        for path in ws_paths:
            ws_url = f"wss://{parsed.netloc}{path}" if parsed.scheme == "https" else f"ws://{parsed.netloc}{path}"

            try:
                # 尝试 WebSocket 连接
                import websocket
                ws = websocket.create_connection(ws_url, timeout=5)
                ws.close()

                vulns.append({
                    "type": "WebSocket漏洞",
                    "severity": "Medium",
                    "url": ws_url,
                    "description": f"发现 WebSocket 端点: {path}",
                    "evidence": "WebSocket 连接成功",
                    "remediation": "验证 WebSocket 连接来源"
                })
            except:
                pass

        return vulns

    def _scan_cors_enhanced(self, url: str) -> List[Dict]:
        """CORS 漏洞增强检测"""
        vulns = []

        # 测试不同的 Origin
        test_origins = [
            "https://evil.com",
            "https://attacker.com",
            "null",
            f"https://{urlparse(url).netloc}.evil.com",
            f"https://evil.{urlparse(url).netloc}",
        ]

        for origin in test_origins:
            try:
                headers = {"Origin": origin}
                response = self.session.get(url, headers=headers, timeout=5, verify=False)

                acao = response.headers.get("Access-Control-Allow-Origin", "")
                acac = response.headers.get("Access-Control-Allow-Credentials", "")

                if acao == origin and origin != "null":
                    severity = "Critical" if acac == "true" else "High"
                    vulns.append({
                        "type": "CORS配置错误",
                        "severity": severity,
                        "url": url,
                        "description": f"CORS 配置反射任意 Origin: {origin}",
                        "evidence": f"ACAO: {acao}, ACAC: {acac}",
                        "remediation": "验证 Origin 白名单"
                    })
                    break

            except:
                pass

        return vulns

    def _scan_open_redirect_enhanced(self, url: str) -> List[Dict]:
        """开放重定向增强检测"""
        vulns = []
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        # 重定向参数
        redirect_params = ["url", "redirect", "next", "return", "goto", "to", "out", "rurl", "dest",
                          "redirect_uri", "redirect_url", "return_url", "next_url", "continue",
                          "forward", "target", "redir", "redirect_to", "go", "link", "view"]

        # 测试 payload
        test_payloads = [
            "https://evil.com",
            "//evil.com",
            "javascript:alert(1)",
            "//evil.com/%2f..",
            "https://evil.com%00.example.com",
            "https://example.com@evil.com",
            "https://evil.com#https://example.com",
            "https://evil.com%0d%0aLocation:%20https://evil.com",
        ]

        for param_name in params:
            if param_name.lower() in redirect_params:
                for payload in test_payloads[:3]:
                    try:
                        test_params = params.copy()
                        test_params[param_name] = [payload]
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

                    except:
                        pass

        return vulns

    def _scan_http_methods(self, url: str) -> List[Dict]:
        """HTTP 方法检测"""
        vulns = []

        # 测试方法
        methods = ["OPTIONS", "TRACE", "PUT", "DELETE", "PATCH", "CONNECT"]

        for method in methods:
            try:
                response = self.session.request(method, url, timeout=5, verify=False)

                if response.status_code not in [404, 405, 501]:
                    vulns.append({
                        "type": "配置错误",
                        "severity": "Medium",
                        "url": url,
                        "description": f"服务器允许 {method} 方法",
                        "evidence": f"{method} 返回 {response.status_code}",
                        "remediation": "限制 HTTP 方法"
                    })

            except:
                pass

        return vulns

    def _scan_cookie_security(self, url: str) -> List[Dict]:
        """Cookie 安全检测"""
        vulns = []

        try:
            response = self.session.get(url, timeout=5, verify=False)

            # 检查 Set-Cookie 头
            cookies = response.headers.get("Set-Cookie", "")
            if cookies:
                # 检查 HttpOnly
                if "HttpOnly" not in cookies:
                    vulns.append({
                        "type": "配置错误",
                        "severity": "Medium",
                        "url": url,
                        "description": "Cookie 未设置 HttpOnly 标志",
                        "evidence": "Set-Cookie 缺少 HttpOnly",
                        "remediation": "设置 HttpOnly 标志"
                    })

                # 检查 Secure
                if "Secure" not in cookies:
                    vulns.append({
                        "type": "配置错误",
                        "severity": "Medium",
                        "url": url,
                        "description": "Cookie 未设置 Secure 标志",
                        "evidence": "Set-Cookie 缺少 Secure",
                        "remediation": "设置 Secure 标志"
                    })

                # 检查 SameSite
                if "SameSite" not in cookies:
                    vulns.append({
                        "type": "配置错误",
                        "severity": "Low",
                        "url": url,
                        "description": "Cookie 未设置 SameSite 标志",
                        "evidence": "Set-Cookie 缺少 SameSite",
                        "remediation": "设置 SameSite 标志"
                    })

        except:
            pass

        return vulns

    def _scan_csrf(self, url: str) -> List[Dict]:
        """CSRF 漏洞检测"""
        vulns = []

        try:
            response = self.session.get(url, timeout=5, verify=False)
            content = response.text

            # 检查表单是否有 CSRF token
            if "<form" in content.lower():
                # 检查是否有 CSRF token
                csrf_patterns = [
                    r'<input[^>]*name=["\']csrf[_-]?token["\']',
                    r'<input[^>]*name=["\']_token["\']',
                    r'<input[^>]*name=["\']authenticity_token["\']',
                    r'<meta[^>]*name=["\']csrf[_-]?token["\']',
                ]

                has_csrf = False
                for pattern in csrf_patterns:
                    if re.search(pattern, content, re.IGNORECASE):
                        has_csrf = True
                        break

                if not has_csrf:
                    vulns.append({
                        "type": "CSRF漏洞",
                        "severity": "Medium",
                        "url": url,
                        "description": "表单缺少 CSRF token",
                        "evidence": "表单未包含 CSRF token",
                        "remediation": "添加 CSRF token 验证"
                    })

        except:
            pass

        return vulns

    def _scan_clickjacking_enhanced(self, url: str) -> List[Dict]:
        """点击劫持增强检测"""
        vulns = []

        try:
            response = self.session.get(url, timeout=5, verify=False)
            headers = response.headers

            # 检查 X-Frame-Options
            x_frame = headers.get("X-Frame-Options", "").upper()
            csp = headers.get("Content-Security-Policy", "")

            has_protection = False
            if x_frame in ["DENY", "SAMEORIGIN"]:
                has_protection = True
            if "frame-ancestors" in csp:
                has_protection = True

            if not has_protection:
                # 检查是否可以被 iframe 嵌入
                vulns.append({
                    "type": "Clickjacking",
                    "severity": "Medium",
                    "url": url,
                    "description": "页面缺少 Clickjacking 防护",
                    "evidence": "未设置 X-Frame-Options 或 CSP frame-ancestors",
                    "remediation": "添加 X-Frame-Options: DENY 或 CSP frame-ancestors"
                })

        except:
            pass

        return vulns

    def _scan_mime_type(self, url: str) -> List[Dict]:
        """MIME 类型检测"""
        vulns = []

        try:
            response = self.session.get(url, timeout=5, verify=False)
            content_type = response.headers.get("Content-Type", "")

            # 检查是否缺少 X-Content-Type-Options
            if "text/html" in content_type:
                x_content_type = response.headers.get("X-Content-Type-Options", "")
                if not x_content_type:
                    vulns.append({
                        "type": "配置错误",
                        "severity": "Low",
                        "url": url,
                        "description": "缺少 X-Content-Type-Options 头",
                        "evidence": "未设置 X-Content-Type-Options",
                        "remediation": "添加 X-Content-Type-Options: nosniff"
                    })

        except:
            pass

        return vulns


def scan_extra(url: str) -> List[Dict]:
    """便捷函数：额外漏洞扫描"""
    scanner = ExtraVulnScanner()
    return scanner.scan(url)


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        vulns = scan_extra(sys.argv[1])
        for vuln in vulns:
            print(f"[{vuln['severity']}] {vuln['type']}: {vuln['description']}")
    else:
        print("用法: python vuln_extra.py <url>")
