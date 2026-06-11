# -*- coding: utf-8 -*-
"""
漏洞发现增强模块
专注发现高价值漏洞
"""

import requests
import re
import time
import json
from typing import List, Dict
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from config import SCAN_CONFIG


class VulnBooster:
    """漏洞发现增强器"""

    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": SCAN_CONFIG["user_agent"],
        })
        self.vulnerabilities = []

    def scan(self, url: str) -> List[Dict]:
        """执行增强扫描"""
        print(f"[*] 增强漏洞扫描: {url}")

        vulns = []

        # 1. 敏感接口探测
        vulns.extend(self._scan_sensitive_endpoints(url))

        # 2. API 接口探测
        vulns.extend(self._scan_api_endpoints(url))

        # 3. 未授权访问增强
        vulns.extend(self._scan_unauthorized_enhanced(url))

        # 4. 信息泄露增强
        vulns.extend(self._scan_info_disclosure_enhanced(url))

        # 5. 弱口令检测
        vulns.extend(self._scan_weak_passwords(url))

        # 6. 默认页面发现
        vulns.extend(self._scan_default_pages(url))

        # 7. 配置错误检测
        vulns.extend(self._scan_misconfigurations(url))

        # 8. 备份文件探测
        vulns.extend(self._scan_backup_files(url))

        # 9. 源码泄露检测
        vulns.extend(self._scan_source_code_leak(url))

        # 10. 内网信息泄露
        vulns.extend(self._scan_internal_info(url))

        self.vulnerabilities.extend(vulns)
        return vulns

    def _scan_sensitive_endpoints(self, url: str) -> List[Dict]:
        """扫描敏感接口"""
        vulns = []
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        # 高价值敏感接口
        sensitive_endpoints = [
            # 管理后台
            "/admin", "/admin/", "/admin/login", "/admin/dashboard",
            "/administrator", "/administrator/", "/manage", "/manager",
            "/console", "/console/", "/dashboard", "/dashboard/",
            "/panel", "/panel/", "/cpanel", "/cpanel/",

            # 数据库管理
            "/phpmyadmin", "/phpmyadmin/", "/pma", "/pma/",
            "/adminer", "/adminer/", "/adminer.php",
            "/dbadmin", "/dbadmin/", "/mysql", "/mysql/",

            # API 文档
            "/api-docs", "/api-docs/", "/swagger", "/swagger/",
            "/swagger-ui", "/swagger-ui/", "/swagger-ui.html",
            "/redoc", "/redoc/", "/openapi.json", "/openapi.yaml",
            "/v2/api-docs", "/v3/api-docs",

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
            "/sonarqube", "/sonarqube/", "/sonarqube/login",

            # 文件管理
            "/filemanager", "/filemanager/", "/file-manager", "/file-manager/",
            "/elfinder", "/elfinder/", "/kcfinder", "/kcfinder/",
            "/ckfinder", "/ckfinder/", "/upload", "/upload/",
            "/uploads", "/uploads/", "/files", "/files/",
            "/documents", "/documents/", "/attachments", "/attachments/",

            # 配置文件
            "/.env", "/.env.local", "/.env.production",
            "/.git/config", "/.git/HEAD",
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
            "/test1", "/test2", "/test3",

            # 内部接口
            "/internal", "/internal/", "/private", "/private/",
            "/intranet", "/intranet/", "/hidden", "/hidden/",
            "/secret", "/secret/", "/restricted", "/restricted/",
        ]

        def check_endpoint(path):
            full_url = urljoin(base, path)
            try:
                response = self.session.get(
                    full_url,
                    timeout=5,
                    allow_redirects=False,
                    verify=False
                )

                # 200 状态码且不是登录页面
                if response.status_code == 200:
                    content = response.text.lower()
                    # 排除登录页面
                    if 'login' not in content[:500] or 'password' not in content[:500]:
                        # 检查是否是敏感内容
                        if any(kw in content for kw in ['admin', 'dashboard', 'config', 'database', 'backup']):
                            return {
                                "type": "未授权访问",
                                "severity": "High",
                                "url": full_url,
                                "description": f"发现敏感接口可访问: {path}",
                                "evidence": f"状态码: {response.status_code}",
                                "remediation": "添加访问控制"
                            }

                # 403 但路径存在
                elif response.status_code == 403:
                    return {
                        "type": "信息泄露",
                        "severity": "Low",
                        "url": full_url,
                        "description": f"发现敏感接口存在但被禁止: {path}",
                        "evidence": f"状态码: 403",
                        "remediation": "确认是否需要隐藏"
                    }

            except:
                pass
            return None

        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = [executor.submit(check_endpoint, p) for p in sensitive_endpoints]
            for future in as_completed(futures):
                result = future.result()
                if result:
                    vulns.append(result)

        return vulns

    def _scan_api_endpoints(self, url: str) -> List[Dict]:
        """扫描 API 接口"""
        vulns = []
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        # API 路径
        api_paths = [
            "/api", "/api/", "/api/v1", "/api/v2", "/api/v3",
            "/api/users", "/api/user", "/api/admin",
            "/api/config", "/api/settings", "/api/info",
            "/api/data", "/api/export", "/api/import",
            "/api/search", "/api/query", "/api/execute",
            "/api/auth", "/api/login", "/api/register",
            "/api/token", "/api/refresh",
            "/rest", "/rest/", "/rest/v1", "/rest/v2",
            "/graphql", "/graphql/",
        ]

        for path in api_paths:
            full_url = urljoin(base, path)
            try:
                response = self.session.get(full_url, timeout=5, verify=False)

                if response.status_code == 200:
                    content_type = response.headers.get("Content-Type", "")

                    # JSON 响应
                    if "json" in content_type:
                        try:
                            data = response.json()
                            if isinstance(data, (list, dict)):
                                vulns.append({
                                    "type": "信息泄露",
                                    "severity": "Medium",
                                    "url": full_url,
                                    "description": f"发现 API 接口: {path}",
                                    "evidence": f"返回 JSON 数据",
                                    "remediation": "添加认证和授权"
                                })
                        except:
                            pass

            except:
                pass

        return vulns

    def _scan_unauthorized_enhanced(self, url: str) -> List[Dict]:
        """增强未授权访问检测"""
        vulns = []
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        # 高价值未授权接口
        unauthorized_paths = [
            # 管理功能
            "/admin/export", "/admin/import", "/admin/backup",
            "/admin/users", "/admin/config", "/admin/settings",
            "/admin/logs", "/admin/audit",

            # 用户数据
            "/api/users/list", "/api/users/all", "/api/users/export",
            "/api/user/info", "/api/user/profile", "/api/user/settings",
            "/api/accounts", "/api/accounts/list",

            # 配置数据
            "/api/config/all", "/api/config/export",
            "/api/settings/all", "/api/settings/export",
            "/api/env", "/api/environment",

            # 日志数据
            "/api/logs", "/api/logs/all", "/api/logs/export",
            "/api/audit", "/api/audit/all", "/api/audit/export",

            # 备份数据
            "/api/backup/list", "/api/backup/download",
            "/api/export/all", "/api/export/data",

            # 数据库
            "/api/database/list", "/api/database/export",
            "/api/table/list", "/api/table/export",

            # 文件操作
            "/api/files/list", "/api/files/download",
            "/api/upload/list", "/api/upload/download",

            # 系统信息
            "/api/system/info", "/api/system/status",
            "/api/system/config", "/api/system/env",
            "/api/system/process", "/api/system/services",

            # 调试功能
            "/api/debug/info", "/api/debug/config",
            "/api/debug/logs", "/api/debug/trace",
            "/api/test", "/api/test/execute",
        ]

        for path in unauthorized_paths:
            full_url = urljoin(base, path)
            try:
                response = self.session.get(full_url, timeout=5, verify=False)

                if response.status_code == 200:
                    content = response.text
                    content_type = response.headers.get("Content-Type", "")

                    # 检查是否返回了敏感数据
                    if any(kw in content.lower() for kw in ['password', 'secret', 'token', 'key', 'email', 'phone']):
                        vulns.append({
                            "type": "未授权访问",
                            "severity": "Critical",
                            "url": full_url,
                            "description": f"发现未授权访问敏感数据: {path}",
                            "evidence": "返回包含敏感信息",
                            "remediation": "添加认证和授权"
                        })
                    elif "json" in content_type and len(content) > 100:
                        vulns.append({
                            "type": "未授权访问",
                            "severity": "High",
                            "url": full_url,
                            "description": f"发现未授权访问 API: {path}",
                            "evidence": "返回 JSON 数据",
                            "remediation": "添加认证和授权"
                        })

            except:
                pass

        return vulns

    def _scan_info_disclosure_enhanced(self, url: str) -> List[Dict]:
        """增强信息泄露检测"""
        vulns = []
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        # 信息泄露路径
        info_paths = [
            # 错误信息
            "/error", "/error/", "/error.html", "/error.php",
            "/404", "/404.html", "/500", "/500.html",
            "/exception", "/exception/", "/trace", "/trace/",

            # 系统信息
            "/server-status", "/server-info",
            "/.well-known/openid-configuration",
            "/.well-known/jwks.json",
            "/.well-known/security.txt",
            "/favicon.ico",
            "/robots.txt",
            "/sitemap.xml",
            "/sitemap.txt",

            # 版本信息
            "/version", "/version/", "/version.txt", "/version.json",
            "/build", "/build/", "/build.json", "/build.txt",
            "/release", "/release/", "/release.json",
            "/CHANGELOG.md", "/CHANGELOG.txt",
            "/RELEASE_NOTES.md", "/RELEASE_NOTES.txt",

            # 配置信息
            "/config", "/config/", "/config.json", "/config.yml",
            "/settings", "/settings/", "/settings.json",
            "/env", "/env/", "/environment", "/environment/",

            # 调试信息
            "/debug", "/debug/", "/debug/info", "/debug/config",
            "/phpinfo.php", "/info.php", "/test.php",
            "/php_info.php", "/phpinfo.html",
        ]

        for path in info_paths:
            full_url = urljoin(base, path)
            try:
                response = self.session.get(full_url, timeout=5, verify=False)

                if response.status_code == 200:
                    content = response.text

                    # 检查敏感信息
                    sensitive_patterns = [
                        (r'password', "密码"),
                        (r'secret', "密钥"),
                        (r'token', "令牌"),
                        (r'api[_-]?key', "API Key"),
                        (r'private[_-]?key', "私钥"),
                        (r'connection[_-]?string', "连接字符串"),
                        (r'database', "数据库"),
                        (r'mysql', "MySQL"),
                        (r'redis', "Redis"),
                        (r'mongodb', "MongoDB"),
                    ]

                    for pattern, name in sensitive_patterns:
                        if re.search(pattern, content, re.IGNORECASE):
                            vulns.append({
                                "type": "信息泄露",
                                "severity": "High",
                                "url": full_url,
                                "description": f"发现{name}信息泄露: {path}",
                                "evidence": f"包含 {pattern}",
                                "remediation": "移除敏感信息"
                            })
                            break

            except:
                pass

        return vulns

    def _scan_weak_passwords(self, url: str) -> List[Dict]:
        """弱口令检测"""
        vulns = []
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        # 登录接口
        login_paths = [
            "/login", "/login/", "/admin/login", "/user/login",
            "/api/login", "/api/auth/login", "/api/signin",
            "/wp-login.php", "/administrator/login",
            "/manager/login", "/console/login",
        ]

        # 默认凭证
        default_creds = [
            ("admin", "admin"),
            ("admin", "123456"),
            ("admin", "password"),
            ("admin", "admin123"),
            ("root", "root"),
            ("root", "toor"),
            ("root", "123456"),
            ("test", "test"),
            ("test", "123456"),
            ("guest", "guest"),
            ("user", "user"),
            ("user", "123456"),
            ("admin", "12345678"),
            ("admin", "888888"),
            ("admin", "666666"),
        ]

        for path in login_paths:
            full_url = urljoin(base, path)
            try:
                # 先检查登录页面是否存在
                response = self.session.get(full_url, timeout=5, verify=False)

                if response.status_code == 200 and 'password' in response.text.lower():
                    # 尝试默认凭证
                    for username, password in default_creds[:5]:
                        try:
                            login_data = {
                                "username": username,
                                "password": password,
                                "user": username,
                                "pass": password,
                                "email": username,
                                "account": username,
                            }

                            login_response = self.session.post(
                                full_url,
                                data=login_data,
                                timeout=5,
                                allow_redirects=False,
                                verify=False
                            )

                            # 检查是否登录成功
                            if login_response.status_code in [301, 302]:
                                location = login_response.headers.get("Location", "")
                                if "dashboard" in location.lower() or "admin" in location.lower():
                                    vulns.append({
                                        "type": "弱口令",
                                        "severity": "Critical",
                                        "url": full_url,
                                        "description": f"发现默认凭证: {username}/{password}",
                                        "evidence": f"登录成功，重定向到: {location}",
                                        "remediation": "修改默认密码"
                                    })
                                    break

                        except:
                            continue

            except:
                pass

        return vulns

    def _scan_default_pages(self, url: str) -> List[Dict]:
        """扫描默认页面"""
        vulns = []
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        # 默认页面
        default_pages = [
            "/index.html", "/index.htm", "/index.php", "/index.jsp",
            "/default.html", "/default.htm", "/default.php",
            "/home.html", "/home.php",
            "/main.html", "/main.php",
            "/welcome.html", "/welcome.php",
            "/install", "/install/", "/install.php",
            "/setup", "/setup/", "/setup.php",
            "/readme.html", "/readme.txt", "/README.md",
            "/LICENSE", "/LICENSE.txt",
            "/CHANGELOG.md", "/CHANGELOG.txt",
            "/TODO.md", "/TODO.txt",
            "/CONTRIBUTING.md", "/CONTRIBUTING.txt",
        ]

        for path in default_pages:
            full_url = urljoin(base, path)
            try:
                response = self.session.get(full_url, timeout=5, verify=False)

                if response.status_code == 200:
                    content = response.text

                    # 检查是否是默认页面
                    if any(kw in content.lower() for kw in ['default', 'welcome', 'install', 'setup', 'readme']):
                        vulns.append({
                            "type": "信息泄露",
                            "severity": "Low",
                            "url": full_url,
                            "description": f"发现默认页面: {path}",
                            "evidence": "页面存在",
                            "remediation": "删除默认页面"
                        })

            except:
                pass

        return vulns

    def _scan_misconfigurations(self, url: str) -> List[Dict]:
        """扫描配置错误"""
        vulns = []
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        # 检查 CORS 配置
        try:
            headers = {"Origin": "https://evil.com"}
            response = self.session.get(url, headers=headers, timeout=5, verify=False)

            acao = response.headers.get("Access-Control-Allow-Origin", "")
            if acao == "*":
                vulns.append({
                    "type": "配置错误",
                    "severity": "Medium",
                    "url": url,
                    "description": "CORS 配置允许所有域名",
                    "evidence": f"Access-Control-Allow-Origin: {acao}",
                    "remediation": "限制 CORS 允许的域名"
                })
            elif "evil.com" in acao:
                vulns.append({
                    "type": "配置错误",
                    "severity": "High",
                    "url": url,
                    "description": "CORS 配置反射任意 Origin",
                    "evidence": f"Access-Control-Allow-Origin: {acao}",
                    "remediation": "验证 Origin 白名单"
                })
        except:
            pass

        # 检查安全头
        try:
            response = self.session.get(url, timeout=5, verify=False)
            headers = response.headers

            missing_headers = []
            if "X-Frame-Options" not in headers:
                missing_headers.append("X-Frame-Options")
            if "X-Content-Type-Options" not in headers:
                missing_headers.append("X-Content-Type-Options")
            if "X-XSS-Protection" not in headers:
                missing_headers.append("X-XSS-Protection")
            if "Content-Security-Policy" not in headers:
                missing_headers.append("Content-Security-Policy")
            if "Strict-Transport-Security" not in headers:
                missing_headers.append("Strict-Transport-Security")

            if missing_headers:
                vulns.append({
                    "type": "配置错误",
                    "severity": "Low",
                    "url": url,
                    "description": f"缺少安全头: {', '.join(missing_headers)}",
                    "evidence": f"缺少: {', '.join(missing_headers)}",
                    "remediation": "添加安全响应头"
                })
        except:
            pass

        return vulns

    def _scan_backup_files(self, url: str) -> List[Dict]:
        """扫描备份文件"""
        vulns = []
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        # 备份文件扩展名
        backup_extensions = [
            ".zip", ".tar.gz", ".tar.bz2", ".rar", ".7z",
            ".sql", ".sql.gz", ".sql.bz2",
            ".bak", ".bak.gz", ".old", ".old.gz",
            ".backup", ".backup.gz",
            ".save", ".swp", ".swo", "~",
        ]

        # 备份文件名
        backup_names = [
            "backup", "db_backup", "database_backup",
            "www", "web", "html", "public",
            "src", "source", "code",
            "config", "settings", "env",
            "1", "2", "3", "old", "new",
            "temp", "tmp", "cache",
        ]

        for name in backup_names:
            for ext in backup_extensions:
                path = f"/{name}{ext}"
                full_url = urljoin(base, path)

                try:
                    response = self.session.head(full_url, timeout=3, verify=False)

                    if response.status_code == 200:
                        content_length = int(response.headers.get("Content-Length", 0))
                        if content_length > 0:
                            vulns.append({
                                "type": "信息泄露",
                                "severity": "High",
                                "url": full_url,
                                "description": f"发现备份文件: {path}",
                                "evidence": f"文件大小: {content_length} bytes",
                                "remediation": "删除备份文件"
                            })
                except:
                    pass

        return vulns

    def _scan_source_code_leak(self, url: str) -> List[Dict]:
        """扫描源码泄露"""
        vulns = []
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        # 源码泄露路径
        source_paths = [
            "/.git/config", "/.git/HEAD", "/.gitignore",
            "/.svn/entries", "/.svn/wc.db",
            "/.hg/dirstate", "/.hg/00manifest.i",
            "/.bzr/branch-format",
            "/CVS/Root", "/CVS/Repository",
            "/.DS_Store", "/.env", "/.env.local",
            "/.env.production", "/.env.development",
            "/Thumbs.db", "/desktop.ini",
            "/.idea", "/.vscode", "/.settings",
            "/.project", "/.classpath", "/.buildpath",
        ]

        for path in source_paths:
            full_url = urljoin(base, path)
            try:
                response = self.session.get(full_url, timeout=3, verify=False)

                if response.status_code == 200:
                    content = response.text[:200]

                    # 检查是否是源码文件
                    if any(kw in content for kw in ['[core]', '[subversion]', 'repositoryformatversion', 'ref:']):
                        vulns.append({
                            "type": "信息泄露",
                            "severity": "Critical",
                            "url": full_url,
                            "description": f"发现源码泄露: {path}",
                            "evidence": content[:100],
                            "remediation": "删除源码管理文件"
                        })

            except:
                pass

        return vulns

    def _scan_internal_info(self, url: str) -> List[Dict]:
        """扫描内网信息泄露"""
        vulns = []
        parsed = urlparse(url)

        try:
            response = self.session.get(url, timeout=5, verify=False)
            content = response.text

            # 检查内网 IP
            internal_ips = re.findall(
                r'\b(?:10\.|172\.(?:1[6-9]|2[0-9]|3[01])\.|192\.168\.)\d{1,3}\.\d{1,3}\b',
                content
            )

            if internal_ips:
                unique_ips = list(set(internal_ips))[:5]
                vulns.append({
                    "type": "信息泄露",
                    "severity": "High",
                    "url": url,
                    "description": f"发现内网 IP 地址",
                    "evidence": ', '.join(unique_ips),
                    "remediation": "移除内网 IP 信息"
                })

            # 检查邮箱
            emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', content)
            if emails:
                unique_emails = list(set(emails))[:5]
                vulns.append({
                    "type": "信息泄露",
                    "severity": "Medium",
                    "url": url,
                    "description": f"发现邮箱地址",
                    "evidence": ', '.join(unique_emails),
                    "remediation": "移除邮箱信息"
                })

            # 检查手机号
            phones = re.findall(r'1[3-9]\d{9}', content)
            if phones:
                unique_phones = list(set(phones))[:5]
                vulns.append({
                    "type": "信息泄露",
                    "severity": "Medium",
                    "url": url,
                    "description": f"发现手机号码",
                    "evidence": ', '.join(unique_phones),
                    "remediation": "移除手机号信息"
                })

        except:
            pass

        return vulns


def scan_boost(url: str) -> List[Dict]:
    """便捷函数：增强扫描"""
    booster = VulnBooster()
    return booster.scan(url)


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        vulns = scan_boost(sys.argv[1])
        for vuln in vulns:
            print(f"[{vuln['severity']}] {vuln['type']}: {vuln['description']}")
    else:
        print("用法: python vuln_boost.py <url>")
