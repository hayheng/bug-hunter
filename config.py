# -*- coding: utf-8 -*-
"""
自动化漏洞挖掘系统 - 配置文件
"""

import os
from pathlib import Path

# 基础路径
BASE_DIR = Path(__file__).parent
REPORTS_DIR = BASE_DIR / "reports"
WORDLISTS_DIR = BASE_DIR / "wordlists"
TARGETS_DIR = BASE_DIR / "targets"

# 确保目录存在
REPORTS_DIR.mkdir(exist_ok=True)
WORDLISTS_DIR.mkdir(exist_ok=True)
TARGETS_DIR.mkdir(exist_ok=True)

# 扫描配置
SCAN_CONFIG = {
    "max_threads": 100,         # 最大线程数
    "timeout": 5,               # 请求超时（秒）
    "retries": 1,               # 重试次数
    "delay": 0.05,              # 请求间隔（秒）
    "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
}

# 子域名枚举配置
SUBDOMAIN_CONFIG = {
    "use_crt_sh": True,         # 使用 crt.sh 证书透明度
    "use_dns_dumpster": True,   # 使用 DNSdumpster
    "use_sublist3r": True,      # 使用 Sublist3r API
    "brute_force": False,       # 是否暴力枚举（慢）
}

# 漏洞扫描配置
VULN_CONFIG = {
    "check_sql_injection": True,
    "check_xss": True,
    "check_info_disclosure": True,
    "check_sensitive_files": True,
    "check_cors": True,
    "check_clickjacking": True,
    "check_open_redirect": True,
    "check_ssrf": True,
}

# 常见敏感路径
SENSITIVE_PATHS = [
    "/.env",
    "/.git/config",
    "/.git/HEAD",
    "/.svn/entries",
    "/.htaccess",
    "/.htpasswd",
    "/robots.txt",
    "/sitemap.xml",
    "/crossdomain.xml",
    "/clientaccesspolicy.xml",
    "/.well-known/security.txt",
    "/phpinfo.php",
    "/info.php",
    "/test.php",
    "/debug",
    "/trace",
    "/actuator",
    "/actuator/env",
    "/actuator/health",
    "/swagger-ui.html",
    "/swagger-ui/",
    "/api-docs",
    "/v2/api-docs",
    "/v3/api-docs",
    "/graphql",
    "/graphiql",
    "/console",
    "/admin",
    "/administrator",
    "/wp-admin",
    "/wp-login.php",
    "/login",
    "/api",
    "/api/v1",
    "/api/v2",
    "/backup",
    "/db",
    "/database",
    "/dump",
    "/config",
    "/settings",
    "/.DS_Store",
    "/WEB-INF/web.xml",
    "/server-status",
    "/server-info",
    "/.bash_history",
    "/.ssh",
    "/id_rsa",
    "/shadow",
    "/passwd",
]

# SQL注入检测 Payload
SQL_PAYLOADS = [
    "'",
    "\"",
    "' OR '1'='1",
    "\" OR \"1\"=\"1",
    "' OR '1'='1' --",
    "1' ORDER BY 1--",
    "1' ORDER BY 2--",
    "1' ORDER BY 3--",
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
    "1 AND 1=1",
    "1 AND 1=2",
    "1' AND '1'='1",
    "1' AND '1'='2",
    "SLEEP(5)",
    "' SLEEP(5)--",
    "1' AND SLEEP(5)--",
    "WAITFOR DELAY '0:0:5'",
]

# SQL报错特征
SQL_ERRORS = [
    "sql syntax",
    "mysql_fetch",
    "mysqli",
    "pg_query",
    "sqlite3",
    "ORA-",
    "SQL Server",
    "Microsoft OLE DB",
    "ODBC SQL Server",
    "JET Database Engine",
    "Access Database Engine",
    "SQLSTATE",
    "Syntax error",
    "Unclosed quotation mark",
    "unterminated quoted string",
]

# XSS Payload
XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "'-alert(1)-'",
    "\"><script>alert(1)</script>",
    "<details open ontoggle=alert(1)>",
    "<body onload=alert(1)>",
    "<iframe src=javascript:alert(1)>",
    "<input onfocus=alert(1) autofocus>",
    "<marquee onstart=alert(1)>",
]

# 信息泄露关键词
INFO_DISCLOSURE_KEYWORDS = [
    "password",
    "passwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "access_token",
    "auth_token",
    "private_key",
    "credentials",
    "database",
    "mysql",
    "redis",
    "mongodb",
    "aws_access",
    "aws_secret",
    "smtp",
    "ftp",
    "ssh",
]

# 报告模板
REPORT_TEMPLATE = """
# 自动化漏洞扫描报告

**目标**: {target}
**扫描时间**: {scan_time}
**扫描状态**: {status}

---

## 📊 扫描统计

| 项目 | 数量 |
|------|------|
| 子域名发现 | {subdomain_count} |
| 存活目标 | {alive_count} |
| 发现漏洞 | {vuln_count} |

---

## 🔍 发现的漏洞

{vuln_details}

---

## 📝 建议

{recommendations}

---

*报告由自动化漏洞挖掘系统生成*
"""
