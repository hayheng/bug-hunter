# -*- coding: utf-8 -*-
"""
HackerOne 专用报告生成器
"""

import json
from datetime import datetime
from typing import List, Dict
from pathlib import Path
from urllib.parse import urlparse


class HackerOneReportGenerator:
    """HackerOne 报告生成器"""

    # CVSS 评分映射
    CVSS_SCORES = {
        "Critical": "9.0-10.0",
        "High": "7.0-8.9",
        "Medium": "4.0-6.9",
        "Low": "0.1-3.9",
        "Info": "0.0",
    }

    # CWE 编号映射
    CWE_MAP = {
        "SQL注入": "CWE-89",
        "XSS": "CWE-79",
        "反射型XSS": "CWE-79",
        "存储型XSS": "CWE-79",
        "SSRF": "CWE-918",
        "命令注入": "CWE-78",
        "命令执行": "CWE-78",
        "文件包含": "CWE-98",
        "路径遍历": "CWE-22",
        "目录遍历": "CWE-22",
        "未授权访问": "CWE-284",
        "信息泄露": "CWE-200",
        "敏感文件泄露": "CWE-200",
        "逻辑漏洞": "CWE-840",
        "越权访问": "CWE-639",
        "水平越权": "CWE-639",
        "垂直越权": "CWE-269",
        "弱口令": "CWE-521",
        "默认凭证": "CWE-521",
        "配置错误": "CWE-16",
        "CORS配置错误": "CWE-942",
        "HTTP请求走私": "CWE-444",
        "Clickjacking": "CWE-1021",
        "CSRF": "CWE-352",
        "XXE": "CWE-611",
        "反序列化": "CWE-502",
        "SSTI模板注入": "CWE-1336",
        "JWT漏洞": "CWE-347",
        "开放重定向": "CWE-601",
    }

    def __init__(self, target: str):
        self.target = target
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    def generate_report(self, vuln: Dict) -> str:
        """生成 HackerOne 报告"""
        vuln_type = vuln.get("type", "")
        severity = vuln.get("severity", "Medium")
        url = vuln.get("url", "")
        evidence = vuln.get("evidence", "")
        description = vuln.get("description", "")

        # 获取 CWE 编号
        cwe = self.CWE_MAP.get(vuln_type, "CWE-2000")

        # 获取 CVSS 评分
        cvss_score = self.CVSS_SCORES.get(severity, "4.0-6.9")

        # 生成标题
        title = self._generate_title(vuln)

        # 生成报告
        report = f"""# {title}

## Summary

A {vuln_type.lower()} vulnerability was discovered in {self.target} that could allow an attacker to {self._get_impact(vuln_type)}.

**Severity**: {severity} ({cvss_score})
**CWE**: {cwe}
**Asset**: {url}

## Vulnerability Details

**Type**: {vuln_type}
**Affected URL**: {url}
**Root Cause**: {self._get_root_cause(vuln_type)}

## Steps to Reproduce

{self._generate_steps(vuln)}

## Proof of Concept

**Request**:
```http
{self._generate_request(vuln)}
```

**Response**:
```
{evidence[:500]}
```

**Evidence**:
- URL: {url}
- Finding: {description}

## Impact

{self._get_impact_detail(vuln_type)}

## Remediation

{self._get_remediation(vuln_type)}

## References

- [OWASP {vuln_type}](https://owasp.org/www-community/attacks/{vuln_type.replace(' ', '_')})
- [{cwe}](https://cwe.mitre.org/data/definitions/{cwe.split('-')[1]}.html)
- [CVSS v3.1 Calculator](https://www.first.org/cvss/calculator/3.1)

---

**Report generated**: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
**Tool**: Bug Hunter v2.0
"""
        return report

    def _generate_title(self, vuln: Dict) -> str:
        """生成标题"""
        vuln_type = vuln.get("type", "")
        url = vuln.get("url", "")
        parsed = urlparse(url)
        domain = parsed.netloc or self.target

        # 根据漏洞类型生成标题
        title_map = {
            "SQL注入": f"SQL Injection in {domain} allows database access",
            "XSS": f"Cross-Site Scripting (XSS) in {domain}",
            "反射型XSS": f"Reflected XSS in {domain}",
            "存储型XSS": f"Stored XSS in {domain} allows account takeover",
            "SSRF": f"Server-Side Request Forgery (SSRF) in {domain}",
            "命令注入": f"Command Injection in {domain} allows Remote Code Execution",
            "命令执行": f"Remote Code Execution in {domain}",
            "未授权访问": f"Unauthorized Access to {domain} admin panel",
            "信息泄露": f"Information Disclosure in {domain}",
            "敏感文件泄露": f"Sensitive File Exposure in {domain}",
            "逻辑漏洞": f"Business Logic Vulnerability in {domain}",
            "越权访问": f"Insecure Direct Object Reference (IDOR) in {domain}",
            "配置错误": f"Security Misconfiguration in {domain}",
            "HTTP请求走私": f"HTTP Request Smuggling in {domain}",
        }

        return title_map.get(vuln_type, f"{vuln_type} vulnerability in {domain}")

    def _generate_steps(self, vuln: Dict) -> str:
        """生成复现步骤"""
        vuln_type = vuln.get("type", "")
        url = vuln.get("url", "")
        payload = vuln.get("payload", "")

        steps_map = {
            "SQL注入": f"""1. Navigate to {url}
2. Identify the vulnerable parameter
3. Inject the following payload: `{payload or "' OR '1'='1"}`
4. Observe the SQL error in the response
5. Verify with sqlmap: `sqlmap -u "{url}" --dbs`""",

            "XSS": f"""1. Navigate to {url}
2. Locate the input field or parameter
3. Inject the following payload: `{payload or "<script>alert(1)</script>"}`
4. Submit the form/URL
5. Observe the JavaScript execution""",

            "SSRF": f"""1. Navigate to {url}
2. Identify the URL parameter
3. Inject internal URL: `{payload or "http://127.0.0.1"}`
4. Observe the server making request to internal resource
5. Verify with cloud metadata: `http://169.254.169.254`""",

            "未授权访问": f"""1. Open a new browser session (incognito/private mode)
2. Navigate to {url}
3. Do not provide any authentication credentials
4. Observe that the page loads successfully
5. Verify access to sensitive functionality""",

            "信息泄露": f"""1. Navigate to {url}
2. Observe the response content
3. Identify sensitive information exposed
4. Document the leaked data""",

            "敏感文件泄露": f"""1. Navigate to {url}
2. Observe the file content
3. Identify sensitive configuration data
4. Document the exposed information""",
        }

        return steps_map.get(vuln_type, f"""1. Navigate to {url}
2. Identify the vulnerability
3. Construct the payload
4. Execute the attack
5. Document the results""")

    def _generate_request(self, vuln: Dict) -> str:
        """生成HTTP请求"""
        vuln_type = vuln.get("type", "")
        url = vuln.get("url", "")
        payload = vuln.get("payload", "")
        method = "GET"

        if vuln_type in ["SQL注入", "XSS", "SSRF", "命令注入"]:
            if "?" in url:
                return f"GET {url}&test={payload or 'payload'} HTTP/1.1\nHost: {urlparse(url).netloc}\nUser-Agent: Mozilla/5.0"
            else:
                return f"GET {url}?test={payload or 'payload'} HTTP/1.1\nHost: {urlparse(url).netloc}\nUser-Agent: Mozilla/5.0"
        else:
            return f"GET {url} HTTP/1.1\nHost: {urlparse(url).netloc}\nUser-Agent: Mozilla/5.0"

    def _get_impact(self, vuln_type: str) -> str:
        """获取影响描述"""
        impact_map = {
            "SQL注入": "access and extract sensitive data from the database, potentially leading to full system compromise",
            "XSS": "execute malicious JavaScript in the context of other users' browsers, potentially leading to account takeover",
            "SSRF": "make requests to internal resources and potentially access cloud metadata services",
            "命令注入": "execute arbitrary operating system commands on the server",
            "命令执行": "execute arbitrary code on the server, leading to full system compromise",
            "未授权访问": "access sensitive functionality without proper authentication",
            "信息泄露": "obtain sensitive information about the application and its users",
            "敏感文件泄露": "access sensitive configuration files and credentials",
            "逻辑漏洞": "bypass business logic protections and perform unauthorized actions",
            "越权访问": "access other users' data and functionality",
            "配置错误": "exploit security misconfigurations to gain unauthorized access",
            "HTTP请求走私": "smuggle HTTP requests to bypass security controls and potentially hijack user sessions",
        }

        return impact_map.get(vuln_type, "exploit this vulnerability to compromise the application")

    def _get_impact_detail(self, vuln_type: str) -> str:
        """获取详细影响"""
        impact_detail_map = {
            "SQL注入": """An attacker could exploit this SQL injection vulnerability to:
- Extract sensitive data from the database (user credentials, personal information)
- Modify or delete database records
- Execute operating system commands on the database server
- Potentially gain full control of the application

**Business Impact**: Data breach, regulatory compliance violations, reputational damage""",

            "XSS": """An attacker could exploit this XSS vulnerability to:
- Steal user session cookies and hijack accounts
- Redirect users to malicious websites
- Deface the website
- Deliver malware to users

**Business Impact**: Account takeover, data theft, loss of user trust""",

            "SSRF": """An attacker could exploit this SSRF vulnerability to:
- Access internal services and APIs
- Read cloud metadata (AWS, GCP, Azure)
- Scan internal network
- Potentially achieve Remote Code Execution

**Business Impact**: Internal network exposure, cloud credentials theft""",

            "未授权访问": """An attacker could exploit this vulnerability to:
- Access sensitive administrative functions
- View/modify user data
- Perform privileged operations
- Potentially compromise the entire application

**Business Impact**: Data breach, unauthorized transactions, regulatory violations""",

            "信息泄露": """Information disclosed could be used to:
- Plan further attacks against the application
- Identify additional vulnerabilities
- Access sensitive user data
- Gain competitive intelligence

**Business Impact**: Privacy violations, competitive disadvantage, regulatory penalties""",
        }

        return impact_detail_map.get(vuln_type, "This vulnerability could be exploited to compromise the security of the application and its users.")

    def _get_root_cause(self, vuln_type: str) -> str:
        """获取根本原因"""
        root_cause_map = {
            "SQL注入": "User input is directly concatenated into SQL queries without proper sanitization or parameterized queries",
            "XSS": "User input is reflected or stored in the page without proper output encoding",
            "SSRF": "User-supplied URLs are fetched by the server without proper validation",
            "命令注入": "User input is passed directly to system commands without sanitization",
            "未授权访问": "Missing or improper authentication/authorization checks",
            "信息泄露": "Sensitive information included in responses or error messages",
            "配置错误": "Insecure default configuration or missing security controls",
            "HTTP请求走私": "Inconsistent parsing of HTTP requests between frontend and backend servers",
        }

        return root_cause_map.get(vuln_type, "Insufficient input validation and security controls")

    def _get_remediation(self, vuln_type: str) -> str:
        """获取修复建议"""
        remediation_map = {
            "SQL注入": """1. **Use Parameterized Queries**: Replace string concatenation with prepared statements
2. **Input Validation**: Implement strict input validation and whitelisting
3. **Least Privilege**: Configure database users with minimal required permissions
4. **WAF**: Deploy a Web Application Firewall as additional protection
5. **Error Handling**: Implement custom error pages that don't reveal database details""",

            "XSS": """1. **Output Encoding**: Encode all user input before rendering in HTML
2. **Content Security Policy**: Implement strict CSP headers
3. **HttpOnly Cookies**: Set HttpOnly flag on session cookies
4. **Input Validation**: Validate and sanitize all user input
5. **Framework Security**: Use modern frameworks with automatic XSS protection""",

            "SSRF": """1. **URL Whitelist**: Implement strict URL validation with whitelist
2. **Block Internal IPs**: Deny requests to internal IP ranges
3. **Disable Unnecessary Protocols**: Only allow HTTP/HTTPS
4. **DNS Validation**: Verify DNS resolution before making requests
5. **Network Segmentation**: Isolate backend services""",

            "未授权访问": """1. **Authentication**: Implement proper authentication on all sensitive endpoints
2. **Authorization**: Add role-based access control (RBAC)
3. **Session Management**: Implement secure session handling
4. **API Security**: Use API keys or OAuth for API endpoints
5. **Audit Logging**: Log all access attempts""",

            "信息泄露": """1. **Remove Sensitive Data**: Remove sensitive information from responses
2. **Custom Error Pages**: Implement generic error pages
3. **Security Headers**: Add security headers to responses
4. **Code Review**: Review code for hardcoded secrets
5. **Configuration**: Disable debug mode in production""",
        }

        return remediation_map.get(vuln_type, "Implement proper input validation and security controls.")


def generate_hackerone_report(target: str, vuln: Dict, output_dir: str = None) -> str:
    """便捷函数：生成 HackerOne 报告"""
    generator = HackerOneReportGenerator(target)

    if output_dir is None:
        output_dir = Path(__file__).parent / "reports"
    else:
        output_dir = Path(output_dir)

    output_dir.mkdir(exist_ok=True)

    # 生成报告
    report = generator.generate_report(vuln)

    # 保存报告
    vuln_type = vuln.get("type", "vulnerability").replace(" ", "_")
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"hackerone_{target}_{vuln_type}_{timestamp}.md"
    filepath = output_dir / filename

    filepath.write_text(report, encoding="utf-8")

    print(f"[*] HackerOne 报告已生成: {filepath}")
    return str(filepath)


if __name__ == "__main__":
    # 测试
    test_vuln = {
        "type": "HTTP请求走私",
        "severity": "High",
        "url": "https://playtika.com",
        "evidence": "服务器接受了Transfer-Encoding头",
        "description": "服务器可能存在HTTP请求走私漏洞",
        "payload": "Transfer-Encoding: chunked",
    }

    generate_hackerone_report("playtika.com", test_vuln)
