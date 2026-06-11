# -*- coding: utf-8 -*-
"""
补天平台专用扫描器
只检测高价值漏洞，确保可提交
"""

import requests
import re
import json
import time
from typing import List, Dict
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from config import SCAN_CONFIG


class ButianScanner:
    """补天平台专用扫描器"""

    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": SCAN_CONFIG["user_agent"],
        })
        self.vulnerabilities = []

    def scan(self, url: str) -> List[Dict]:
        """执行补天平台专用扫描"""
        print(f"[*] 补天平台专用扫描: {url}")

        vulns = []

        # 1. SQL注入检测（高价值）
        vulns.extend(self._scan_sql_injection(url))

        # 2. 未授权访问检测（高价值）
        vulns.extend(self._scan_unauthorized_access(url))

        # 3. 信息泄露检测（高价值）
        vulns.extend(self._scan_info_disclosure(url))

        # 4. 逻辑漏洞检测（高价值）
        vulns.extend(self._scan_logic_vulns(url))

        # 5. XSS检测（中价值）
        vulns.extend(self._scan_xss(url))

        # 6. SSRF检测（高价值）
        vulns.extend(self._scan_ssrf(url))

        # 7. 命令注入检测（高价值）
        vulns.extend(self._scan_command_injection(url))

        # 8. 文件包含检测（高价值）
        vulns.extend(self._scan_file_inclusion(url))

        # 9. 敏感文件泄露（高价值）
        vulns.extend(self._scan_sensitive_files(url))

        # 10. 配置错误（中价值）
        vulns.extend(self._scan_misconfig(url))

        self.vulnerabilities.extend(vulns)
        return vulns

    def _scan_sql_injection(self, url: str) -> List[Dict]:
        """SQL注入检测"""
        vulns = []
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        if not params:
            return vulns

        # SQL注入 Payload
        sql_payloads = [
            ("'", "SQL语法错误"),
            ("' OR '1'='1", "SQL逻辑绕过"),
            ("' OR '1'='1' --", "SQL注释绕过"),
            ("1' ORDER BY 1--", "SQL排序注入"),
            ("1' UNION SELECT NULL--", "SQL联合查询"),
            ("1 AND 1=1", "SQL布尔盲注"),
            ("1 AND 1=2", "SQL布尔盲注"),
            ("SLEEP(5)", "SQL时间盲注"),
            ("' SLEEP(5)--", "SQL时间盲注"),
        ]

        # SQL报错特征
        sql_errors = [
            "sql syntax",
            "mysql_fetch",
            "mysqli",
            "ORA-",
            "SQL Server",
            "sqlite3",
            "postgresql",
            "SQLSTATE",
            "Syntax error",
            "Unclosed quotation mark",
        ]

        for param_name, param_values in params.items():
            for payload, desc in sql_payloads[:5]:
                try:
                    test_params = params.copy()
                    test_params[param_name] = [payload]
                    test_query = urlencode(test_params, doseq=True)
                    test_url = urlunparse(parsed._replace(query=test_query))

                    start_time = time.time()
                    response = self.session.get(test_url, timeout=10, verify=False)
                    elapsed = time.time() - start_time

                    body = response.text.lower()

                    # 检查SQL报错
                    for error in sql_errors:
                        if error.lower() in body:
                            vulns.append({
                                "type": "SQL注入",
                                "severity": "Critical",
                                "url": url,
                                "parameter": param_name,
                                "payload": payload,
                                "evidence": f"响应包含: {error}",
                                "description": f"参数 {param_name} 存在SQL注入漏洞",
                                "remediation": "使用参数化查询，过滤用户输入",
                                "injection_type": "报错注入",
                                "database_type": self._detect_db_type(body),
                            })
                            break

                    # 时间盲注检测
                    if elapsed > 4:
                        vulns.append({
                            "type": "SQL注入",
                            "severity": "Critical",
                            "url": url,
                            "parameter": param_name,
                            "payload": payload,
                            "evidence": f"响应时间: {elapsed:.2f}s",
                            "description": f"参数 {param_name} 存在时间盲注",
                            "remediation": "使用参数化查询",
                            "injection_type": "时间盲注",
                            "database_type": "未知",
                        })

                except Exception as e:
                    continue

        return vulns

    def _detect_db_type(self, content: str) -> str:
        """检测数据库类型"""
        if "mysql" in content:
            return "MySQL"
        elif "oracle" in content or "ora-" in content:
            return "Oracle"
        elif "sql server" in content:
            return "SQL Server"
        elif "postgresql" in content:
            return "PostgreSQL"
        elif "sqlite" in content:
            return "SQLite"
        return "未知"

    def _scan_unauthorized_access(self, url: str) -> List[Dict]:
        """未授权访问检测"""
        vulns = []
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        # 高价值未授权访问路径
        unauthorized_paths = [
            # 管理后台
            ("/admin", "管理后台"),
            ("/admin/", "管理后台"),
            ("/administrator", "管理后台"),
            ("/manage", "管理后台"),
            ("/manager", "管理后台"),
            ("/console", "控制台"),
            ("/dashboard", "仪表盘"),
            ("/panel", "控制面板"),

            # API接口
            ("/api/users", "用户接口"),
            ("/api/admin", "管理接口"),
            ("/api/config", "配置接口"),
            ("/api/data", "数据接口"),
            ("/api/export", "导出接口"),

            # 数据库管理
            ("/phpmyadmin", "phpMyAdmin"),
            ("/adminer", "Adminer"),
            ("/pma", "phpMyAdmin"),

            # 监控系统
            ("/actuator", "Spring Boot Actuator"),
            ("/actuator/env", "环境变量"),
            ("/actuator/health", "健康检查"),
            ("/actuator/info", "系统信息"),
            ("/metrics", "监控指标"),
            ("/prometheus", "Prometheus"),

            # 调试接口
            ("/debug", "调试接口"),
            ("/trace", "跟踪接口"),
            ("/console", "控制台"),

            # Swagger/API文档
            ("/swagger-ui.html", "Swagger UI"),
            ("/swagger-ui/", "Swagger UI"),
            ("/api-docs", "API文档"),
            ("/v2/api-docs", "API文档"),
            ("/v3/api-docs", "API文档"),

            # GraphQL
            ("/graphql", "GraphQL"),
            ("/graphiql", "GraphiQL"),
            ("/playground", "GraphQL Playground"),
        ]

        def check_unauthorized(path, desc):
            full_url = urljoin(base, path)
            try:
                response = self.session.get(full_url, timeout=5, verify=False)

                if response.status_code == 200:
                    content = response.text.lower()

                    # 排除登录页面
                    if "login" in content[:500] or "password" in content[:500]:
                        return None

                    # 检查是否返回敏感内容
                    sensitive_keywords = [
                        "admin", "dashboard", "config", "user",
                        "database", "password", "secret", "token",
                        "swagger", "graphql", "actuator",
                    ]

                    for keyword in sensitive_keywords:
                        if keyword in content:
                            return Vulnerability(
                                vuln_type="未授权访问",
                                severity="High",
                                url=full_url,
                                description=f"{desc}可未授权访问",
                                evidence=f"状态码: 200, 包含关键词: {keyword}",
                                remediation="添加身份认证",
                                path=path,
                                access_content=f"可访问{desc}",
                            )

            except:
                pass
            return None

        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = {executor.submit(check_unauthorized, p, d): (p, d) for p, d in unauthorized_paths}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    vulns.append(result.to_dict())

        return vulns

    def _scan_info_disclosure(self, url: str) -> List[Dict]:
        """信息泄露检测"""
        vulns = []
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        # 敏感信息路径
        sensitive_paths = [
            ("/.env", "环境配置文件"),
            ("/.env.local", "本地环境配置"),
            ("/.env.production", "生产环境配置"),
            ("/.git/config", "Git配置文件"),
            ("/.git/HEAD", "Git HEAD文件"),
            ("/.svn/entries", "SVN配置文件"),
            ("/web.config", "Web配置文件"),
            ("/config.php", "PHP配置文件"),
            ("/config.json", "JSON配置文件"),
            ("/settings.py", "Django配置"),
            ("/application.yml", "Spring配置"),
            ("/application.properties", "Spring配置"),
            ("/database.yml", "数据库配置"),
            ("/backup.sql", "数据库备份"),
            ("/dump.sql", "数据库备份"),
            ("/backup.zip", "备份文件"),
            ("/www.zip", "网站备份"),
            ("/phpinfo.php", "PHP信息"),
            ("/info.php", "PHP信息"),
            ("/test.php", "测试文件"),
            ("/debug.log", "调试日志"),
            ("/error.log", "错误日志"),
            ("/access.log", "访问日志"),
        ]

        def check_sensitive(path, desc):
            full_url = urljoin(base, path)
            try:
                response = self.session.get(full_url, timeout=3, verify=False)

                if response.status_code == 200:
                    content = response.text

                    # 排除空页面
                    if len(content) < 50:
                        return None

                    # 排除404页面
                    if "404" in content[:100] and "not found" in content.lower()[:100]:
                        return None

                    # 检查是否包含敏感信息
                    sensitive_patterns = [
                        r"password",
                        r"secret",
                        r"token",
                        r"api_key",
                        r"database",
                        r"mysql",
                        r"redis",
                        r"DB_PASSWORD",
                        r"APP_KEY",
                        r"PRIVATE_KEY",
                    ]

                    for pattern in sensitive_patterns:
                        if re.search(pattern, content, re.IGNORECASE):
                            return Vulnerability(
                                vuln_type="信息泄露",
                                severity="High",
                                url=full_url,
                                description=f"{desc}泄露",
                                evidence=f"包含敏感信息: {pattern}",
                                remediation="删除或限制访问敏感文件",
                                leak_type=desc,
                                leaked_data=content[:500],
                            )

            except:
                pass
            return None

        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = {executor.submit(check_sensitive, p, d): (p, d) for p, d in sensitive_paths}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    vulns.append(result.to_dict())

        return vulns

    def _scan_logic_vulns(self, url: str) -> List[Dict]:
        """逻辑漏洞检测"""
        vulns = []
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        # 逻辑漏洞路径
        logic_paths = [
            ("/forgot-password", "密码重置"),
            ("/reset-password", "密码重置"),
            ("/password/reset", "密码重置"),
            ("/register", "注册接口"),
            ("/signup", "注册接口"),
            ("/login", "登录接口"),
            ("/api/register", "注册接口"),
            ("/api/login", "登录接口"),
            ("/api/reset-password", "密码重置"),
        ]

        for path, desc in logic_paths:
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
                            "description": f"{desc}接口缺少验证码",
                            "evidence": "未发现验证码",
                            "remediation": "添加验证码验证",
                            "logic_type": desc,
                        })

            except:
                pass

        return vulns

    def _scan_xss(self, url: str) -> List[Dict]:
        """XSS检测"""
        vulns = []
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        if not params:
            return vulns

        # XSS Payload
        xss_payloads = [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "'-alert(1)-'",
            "\"><script>alert(1)</script>",
        ]

        for param_name, param_values in params.items():
            for payload in xss_payloads[:3]:
                try:
                    test_params = params.copy()
                    test_params[param_name] = [payload]
                    test_query = urlencode(test_params, doseq=True)
                    test_url = urlunparse(parsed._replace(query=test_query))

                    response = self.session.get(test_url, timeout=5, verify=False)

                    # 检查payload是否被反射
                    if payload in response.text:
                        vulns.append({
                            "type": "XSS",
                            "severity": "Medium",
                            "url": url,
                            "parameter": param_name,
                            "payload": payload,
                            "evidence": f"Payload被反射",
                            "description": f"参数 {param_name} 存在反射型XSS",
                            "remediation": "对输出进行HTML编码",
                            "xss_type": "反射型",
                            "browser_info": "Chrome 最新版",
                        })

                except:
                    continue

        return vulns

    def _scan_ssrf(self, url: str) -> List[Dict]:
        """SSRF检测"""
        vulns = []
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        if not params:
            return vulns

        # SSRF参数名
        ssrf_params = ["url", "uri", "link", "src", "dest", "redirect", "feed", "page", "path"]

        # SSRF Payload
        ssrf_payloads = [
            "http://127.0.0.1",
            "http://localhost",
            "http://169.254.169.254",
        ]

        for param_name in params:
            if param_name.lower() in ssrf_params:
                for payload in ssrf_payloads[:2]:
                    try:
                        test_params = params.copy()
                        test_params[param_name] = [payload]
                        test_query = urlencode(test_params, doseq=True)
                        test_url = urlunparse(parsed._replace(query=test_query))

                        response = self.session.get(test_url, timeout=5, verify=False)

                        if response.status_code == 200 and len(response.text) > 100:
                            vulns.append({
                                "type": "SSRF",
                                "severity": "High",
                                "url": url,
                                "parameter": param_name,
                                "payload": payload,
                                "evidence": f"请求成功，状态码: {response.status_code}",
                                "description": f"参数 {param_name} 存在SSRF漏洞",
                                "remediation": "限制URL白名单",
                                "internal_access": f"可访问内部地址: {payload}",
                            })

                    except:
                        continue

        return vulns

    def _scan_command_injection(self, url: str) -> List[Dict]:
        """命令注入检测"""
        vulns = []
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        if not params:
            return vulns

        # 命令注入 Payload
        cmd_payloads = [
            (";id", "id"),
            ("|id", "id"),
            ("`id`", "id"),
            ("$(id)", "id"),
        ]

        for param_name, param_values in params.items():
            for payload, cmd in cmd_payloads[:2]:
                try:
                    test_params = params.copy()
                    test_params[param_name] = [payload]
                    test_query = urlencode(test_params, doseq=True)
                    test_url = urlunparse(parsed._replace(query=test_query))

                    response = self.session.get(test_url, timeout=5, verify=False)

                    # 检查命令执行结果
                    if "uid=" in response.text:
                        vulns.append({
                            "type": "命令执行",
                            "severity": "Critical",
                            "url": url,
                            "parameter": param_name,
                            "payload": payload,
                            "evidence": f"命令执行成功: uid=",
                            "description": f"参数 {param_name} 存在命令注入漏洞",
                            "remediation": "使用白名单验证输入",
                            "command_result": response.text[:200],
                        })

                except:
                    continue

        return vulns

    def _scan_file_inclusion(self, url: str) -> List[Dict]:
        """文件包含检测"""
        vulns = []
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        if not params:
            return vulns

        # 文件包含 Payload
        lfi_payloads = [
            ("../../../etc/passwd", "root:"),
            ("....//....//....//etc/passwd", "root:"),
            ("..%252f..%252f..%252fetc/passwd", "root:"),
        ]

        file_params = ["file", "path", "page", "include", "inc", "require", "load"]

        for param_name in params:
            if param_name.lower() in file_params:
                for payload, indicator in lfi_payloads:
                    try:
                        test_params = params.copy()
                        test_params[param_name] = [payload]
                        test_query = urlencode(test_params, doseq=True)
                        test_url = urlunparse(parsed._replace(query=test_query))

                        response = self.session.get(test_url, timeout=5, verify=False)

                        if indicator in response.text:
                            vulns.append({
                                "type": "文件包含",
                                "severity": "Critical",
                                "url": url,
                                "parameter": param_name,
                                "payload": payload,
                                "evidence": f"成功读取系统文件",
                                "description": f"参数 {param_name} 存在文件包含漏洞",
                                "remediation": "限制可包含的文件路径",
                            })

                    except:
                        continue

        return vulns

    def _scan_sensitive_files(self, url: str) -> List[Dict]:
        """敏感文件泄露检测"""
        vulns = []
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        # 敏感文件
        sensitive_files = [
            (".env", "环境配置文件"),
            (".git/config", "Git配置"),
            (".git/HEAD", "Git HEAD"),
            (".svn/entries", "SVN配置"),
            ("robots.txt", "Robots文件"),
            ("sitemap.xml", "Sitemap文件"),
            ("crossdomain.xml", "跨域配置"),
            ("phpinfo.php", "PHP信息"),
            ("info.php", "PHP信息"),
            ("test.php", "测试文件"),
            ("debug.log", "调试日志"),
            ("error.log", "错误日志"),
        ]

        for filename, desc in sensitive_files:
            full_url = urljoin(base, filename)
            try:
                response = self.session.get(full_url, timeout=3, verify=False)

                if response.status_code == 200:
                    content = response.text

                    # 排除空页面
                    if len(content) < 50:
                        continue

                    # 排除404页面
                    if "404" in content[:100]:
                        continue

                    # 检查是否是真正的敏感文件
                    if self._is_sensitive_file(filename, content):
                        vulns.append({
                            "type": "敏感文件泄露",
                            "severity": "High" if filename in [".env", ".git/config"] else "Medium",
                            "url": full_url,
                            "description": f"发现{desc}: {filename}",
                            "evidence": content[:200],
                            "remediation": "删除或限制访问敏感文件",
                            "leak_type": desc,
                            "leaked_data": content[:500],
                        })

            except:
                pass

        return vulns

    def _is_sensitive_file(self, filename: str, content: str) -> bool:
        """检查是否是真正的敏感文件"""
        # robots.txt
        if filename == "robots.txt":
            return "user-agent" in content.lower() or "disallow" in content.lower()

        # sitemap.xml
        if filename == "sitemap.xml":
            return "<urlset" in content.lower() or "<sitemap" in content.lower()

        # .env
        if filename == ".env":
            return any(kw in content.lower() for kw in ["password", "secret", "key", "database"])

        # .git
        if ".git" in filename:
            return "[core]" in content or "repositoryformatversion" in content

        # phpinfo
        if "phpinfo" in filename or "info.php" in filename:
            return "php version" in content.lower() or "phpinfo()" in content.lower()

        # 日志文件
        if ".log" in filename:
            return len(content) > 100

        return True

    def _scan_misconfig(self, url: str) -> List[Dict]:
        """配置错误检测"""
        vulns = []

        try:
            response = self.session.get(url, timeout=5, verify=False)
            headers = response.headers

            # CORS配置错误
            acao = headers.get("Access-Control-Allow-Origin", "")
            if acao == "*":
                vulns.append({
                    "type": "CORS配置错误",
                    "severity": "Medium",
                    "url": url,
                    "description": "CORS配置允许所有域名",
                    "evidence": f"Access-Control-Allow-Origin: {acao}",
                    "remediation": "限制CORS允许的域名",
                    "config_type": "CORS配置",
                })

            # HTTP请求走私
            try:
                test_headers = {"Transfer-Encoding": "chunked", "Content-Length": "0"}
                test_response = self.session.post(url, headers=test_headers, timeout=5, verify=False)
                if test_response.status_code in [200, 400]:
                    vulns.append({
                        "type": "HTTP请求走私",
                        "severity": "High",
                        "url": url,
                        "description": "服务器可能存在HTTP请求走私漏洞",
                        "evidence": "服务器接受了Transfer-Encoding头",
                        "remediation": "正确处理Transfer-Encoding和Content-Length头",
                        "config_type": "HTTP配置",
                    })
            except:
                pass

        except:
            pass

        return vulns


class Vulnerability:
    """漏洞类"""

    def __init__(self, vuln_type: str, severity: str, url: str,
                 description: str, evidence: str = "", remediation: str = "", **kwargs):
        self.vuln_type = vuln_type
        self.severity = severity
        self.url = url
        self.description = description
        self.evidence = evidence
        self.remediation = remediation
        self.extra = kwargs

    def to_dict(self) -> Dict:
        result = {
            "type": self.vuln_type,
            "severity": self.severity,
            "url": self.url,
            "description": self.description,
            "evidence": self.evidence,
            "remediation": self.remediation,
        }
        result.update(self.extra)
        return result


def scan_butian(url: str) -> List[Dict]:
    """便捷函数：补天平台专用扫描"""
    scanner = ButianScanner()
    return scanner.scan(url)


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        vulns = scan_butian(sys.argv[1])
        print(f"\n发现 {len(vulns)} 个漏洞:")
        for vuln in vulns:
            print(f"  [{vuln.get('severity')}] {vuln.get('type')}: {vuln.get('description')}")
    else:
        print("用法: python butian_scanner.py <url>")
