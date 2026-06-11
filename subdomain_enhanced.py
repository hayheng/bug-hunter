# -*- coding: utf-8 -*-
"""
增强子域名枚举模块
支持: 证书透明度、DNS暴力、搜索引擎、被动收集
"""

import requests
import re
import json
import socket
import dns.resolver
from typing import List, Dict, Set
from concurrent.futures import ThreadPoolExecutor, as_completed
from config import SCAN_CONFIG


class SubdomainEnumerator:
    """增强子域名枚举器"""

    def __init__(self, domain: str):
        self.domain = domain
        self.subdomains = set()
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": SCAN_CONFIG["user_agent"],
        })

    def enumerate_all(self) -> Set[str]:
        """执行所有枚举方法"""
        print(f"[*] 开始子域名枚举: {self.domain}")

        # 1. 证书透明度查询
        print("[*] 证书透明度查询...")
        self._enum_crt_sh()

        # 2. DNS 暴力枚举
        print("[*] DNS 暴力枚举...")
        self._enum_dns_brute()

        # 3. 搜索引擎收集
        print("[*] 搜索引擎收集...")
        self._enum_search_engines()

        # 4. 被动信息收集
        print("[*] 被动信息收集...")
        self._enum_passive()

        # 5. DNS 记录查询
        print("[*] DNS 记录查询...")
        self._enum_dns_records()

        # 6. 子域名爆破
        print("[*] 子域名爆破...")
        self._enum_wordlist()

        # 7. 子域名置换
        print("[*] 子域名置换...")
        self._enum_permutation()

        # 8. 子域名递归
        print("[*] 子域名递归...")
        self._enum_recursive()

        print(f"[*] 枚举完成，发现 {len(self.subdomains)} 个子域名")
        return self.subdomains

    def _enum_crt_sh(self):
        """证书透明度查询"""
        try:
            url = f"https://crt.sh/?q=%.{self.domain}&output=json"
            response = self.session.get(url, timeout=30)

            if response.status_code == 200:
                data = response.json()
                for entry in data:
                    name = entry.get("name_value", "")
                    for subdomain in name.split("\n"):
                        subdomain = subdomain.strip().lower()
                        if subdomain.endswith(self.domain) and "*" not in subdomain:
                            self.subdomains.add(subdomain)

                print(f"  [+] crt.sh: {len(self.subdomains)} 个子域名")
        except Exception as e:
            print(f"  [-] crt.sh 失败: {e}")

    def _enum_dns_brute(self):
        """DNS 暴力枚举"""
        # 常见子域名前缀（精简版，只保留高价值的）
        common_prefixes = [
            "www", "mail", "ftp", "api", "app", "dev", "test", "staging",
            "admin", "manage", "console", "dashboard", "panel",
            "db", "database", "mysql", "redis", "mongo",
            "cdn", "oss", "img", "static", "assets",
            "vpn", "remote", "ssh", "sftp",
            "monitor", "grafana", "zabbix", "nagios",
            "jenkins", "gitlab", "git", "svn",
            "log", "logs", "audit", "backup", "bak",
            "shop", "store", "pay", "payment",
            "blog", "news", "forum", "bbs",
            "help", "support", "ticket",
            "oa", "erp", "crm", "hr", "bi",
            "mobile", "m", "wap", "h5",
            "open", "public", "internal", "private",
            "auth", "login", "sso", "oauth",
            "gateway", "gw", "proxy", "lb",
            "search", "s", "so",
            "video", "live", "tv", "stream",
            "game", "play", "iot", "smart",
        ]

        found = []
        with ThreadPoolExecutor(max_workers=100) as executor:
            futures = {executor.submit(self._resolve_subdomain, f"{prefix}.{self.domain}"): prefix for prefix in common_prefixes}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    found.append(result)

        self.subdomains.update(found)
        print(f"  [+] DNS暴力: {len(found)} 个子域名")

    def _resolve_subdomain(self, subdomain: str) -> str:
        """解析子域名"""
        try:
            socket.gethostbyname(subdomain)
            return subdomain
        except:
            return None

    def _enum_search_engines(self):
        """搜索引擎收集"""
        # Bing 搜索
        try:
            url = f"https://www.bing.com/search?q=site:{self.domain}&count=50"
            response = self.session.get(url, timeout=10)

            # 提取子域名
            pattern = r'[a-zA-Z0-9.-]+\.' + re.escape(self.domain)
            matches = re.findall(pattern, response.text)
            for match in matches:
                if match.endswith(self.domain):
                    self.subdomains.add(match.lower())

            print(f"  [+] Bing: 发现子域名")
        except Exception as e:
            print(f"  [-] Bing 失败: {e}")

    def _enum_passive(self):
        """被动信息收集"""
        # VirusTotal
        try:
            url = f"https://www.virustotal.com/api/v3/domains/{self.domain}/subdomains"
            response = self.session.get(url, timeout=10)
            if response.status_code == 200:
                data = response.json()
                for item in data.get("data", []):
                    subdomain = item.get("id", "")
                    if subdomain.endswith(self.domain):
                        self.subdomains.add(subdomain.lower())
                print(f"  [+] VirusTotal: 发现子域名")
        except Exception as e:
            print(f"  [-] VirusTotal 失败: {e}")

    def _enum_dns_records(self):
        """DNS 记录查询"""
        record_types = ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SRV", "SOA"]

        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(self.domain, record_type)
                for answer in answers:
                    # 从 CNAME 记录提取子域名
                    if record_type == "CNAME":
                        target = str(answer.target).rstrip(".")
                        if target.endswith(self.domain):
                            self.subdomains.add(target.lower())

                    # 从 MX 记录提取子域名
                    if record_type == "MX":
                        mx = str(answer.exchange).rstrip(".")
                        if mx.endswith(self.domain):
                            self.subdomains.add(mx.lower())

                    # 从 TXT 记录提取子域名
                    if record_type == "TXT":
                        txt = str(answer).strip('"')
                        pattern = r'[a-zA-Z0-9.-]+\.' + re.escape(self.domain)
                        matches = re.findall(pattern, txt)
                        for match in matches:
                            self.subdomains.add(match.lower())

            except Exception:
                pass

        print(f"  [+] DNS记录: 发现子域名")

    def _enum_wordlist(self):
        """子域名爆破"""
        # 扩展字典
        wordlist = [
            "www", "mail", "ftp", "api", "app", "dev", "test", "staging",
            "admin", "manage", "console", "dashboard", "panel",
            "db", "database", "mysql", "redis", "mongo",
            "cdn", "oss", "img", "static", "assets",
            "vpn", "remote", "ssh", "sftp",
            "monitor", "grafana", "zabbix", "nagios",
            "jenkins", "gitlab", "git", "svn",
            "log", "logs", "audit", "backup", "bak",
            "shop", "store", "pay", "payment",
            "blog", "news", "forum", "bbs",
            "help", "support", "ticket",
            "oa", "erp", "crm", "hr", "bi",
            "mobile", "m", "wap", "h5",
            "open", "public", "internal", "private",
            "auth", "login", "sso", "oauth",
            "gateway", "gw", "proxy", "lb",
            "search", "s", "so",
            "video", "live", "tv", "stream",
            "game", "play", "iot", "smart",
            # 数字子域名
            "1", "2", "3", "4", "5", "6", "7", "8", "9", "10",
            # 环境子域名
            "prod", "production", "pre", "uat", "sit", "fat",
            # 版本子域名
            "v1", "v2", "v3", "v4", "v5",
            # 功能子域名
            "user", "users", "account", "accounts",
            "order", "orders", "product", "products",
            "cart", "checkout", "payment", "billing",
            "message", "messages", "notification", "notifications",
            "report", "reports", "analytics", "statistics",
            "config", "settings", "preferences",
            "file", "files", "upload", "uploads",
            "download", "downloads", "export", "imports",
            "data", "datas", "service", "services",
            "task", "tasks", "job", "jobs", "cron",
            "cache", "session", "sessions",
            "health", "status", "ping", "info",
            "version", "build", "release",
            "debug", "trace", "metrics", "monitor",
            "webhook", "webhooks", "callback", "callbacks",
            "event", "events", "hook", "hooks",
            "socket", "websocket", "ws", "wss",
            "rpc", "grpc", "thrift", "rest", "graphql",
            "mq", "queue", "kafka", "rabbitmq",
            "es", "elasticsearch", "solr", "lucene",
            "hadoop", "spark", "hive", "hbase",
            "docker", "k8s", "kubernetes", "mesos",
            "consul", "etcd", "zookeeper", "nacos",
            "redis", "memcached", "mongo", "mysql", "postgres", "oracle",
        ]

        found = []
        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = {executor.submit(self._resolve_subdomain, f"{word}.{self.domain}"): word for word in wordlist}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    found.append(result)

        self.subdomains.update(found)
        print(f"  [+] 爆破: {len(found)} 个子域名")

    def _enum_permutation(self):
        """子域名置换"""
        # 基于已发现的子域名进行置换
        permutations = []
        for subdomain in list(self.subdomains):
            # 提取前缀
            prefix = subdomain.replace(f".{self.domain}", "")

            # 添加数字后缀
            for i in range(1, 10):
                permutations.append(f"{prefix}{i}.{self.domain}")

            # 添加分隔符
            for sep in ["-", "_", "."]:
                permutations.append(f"{prefix}{sep}api.{self.domain}")
                permutations.append(f"{prefix}{sep}app.{self.domain}")
                permutations.append(f"{prefix}{sep}dev.{self.domain}")
                permutations.append(f"{prefix}{sep}test.{self.domain}")

        found = []
        with ThreadPoolExecutor(max_workers=100) as executor:
            futures = {executor.submit(self._resolve_subdomain, perm): perm for perm in permutations[:100]}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    found.append(result)

        self.subdomains.update(found)
        print(f"  [+] 置换: {len(found)} 个子域名")

    def _enum_recursive(self):
        """子域名递归枚举"""
        # 对已发现的子域名进行递归枚举
        recursive_subdomains = set()
        for subdomain in list(self.subdomains):
            # 提取子域名部分
            parts = subdomain.replace(f".{self.domain}", "").split(".")

            # 如果有多级子域名，递归枚举
            if len(parts) > 1:
                # 构造新的域名
                new_domain = ".".join(parts[1:]) + f".{self.domain}"

                # 递归枚举
                try:
                    enumerator = SubdomainEnumerator(new_domain)
                    new_subdomains = enumerator.enumerate_all()
                    recursive_subdomains.update(new_subdomains)
                except:
                    pass

        self.subdomains.update(recursive_subdomains)
        print(f"  [+] 递归: {len(recursive_subdomains)} 个子域名")

    def get_alive_subdomains(self) -> List[Dict]:
        """获取存活的子域名"""
        alive = []

        def check_alive(subdomain):
            try:
                ip = socket.gethostbyname(subdomain)
                return {"subdomain": subdomain, "ip": ip}
            except:
                return None

        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = [executor.submit(check_alive, sub) for sub in self.subdomains]
            for future in as_completed(futures):
                result = future.result()
                if result:
                    alive.append(result)

        return alive


def enumerate_subdomains(domain: str) -> Set[str]:
    """便捷函数：枚举子域名"""
    enumerator = SubdomainEnumerator(domain)
    return enumerator.enumerate_all()


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        domain = sys.argv[1]
        subdomains = enumerate_subdomains(domain)

        print(f"\n[*] 发现的子域名:")
        for sub in sorted(subdomains):
            print(f"  {sub}")

        print(f"\n[*] 总计: {len(subdomains)} 个子域名")
    else:
        print("用法: python subdomain_enhanced.py <domain>")
