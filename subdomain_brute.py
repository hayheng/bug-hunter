# -*- coding: utf-8 -*-
"""
子域名爆破模块
"""

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Set, List
from config import SCAN_CONFIG


# 常见子域名前缀
SUBDOMAIN_WORDLIST = [
    # 常见服务
    "www", "mail", "ftp", "smtp", "pop", "pop3", "imap",
    "dns", "ns", "ns1", "ns2", "ns3", "dns1", "dns2",
    "mx", "mx1", "mx2",

    # Web服务
    "web", "www2", "www3", "dev", "test", "staging", "stage",
    "beta", "demo", "sandbox", "preview", "pre", "uat",
    "sit", "fat", "prod", "production",

    # 开发环境
    "api", "api2", "api3", "v1", "v2", "v3",
    "rest", "graphql", "gateway", "gw",
    "app", "app2", "mobile", "m", "wap",

    # 管理后台
    "admin", "administrator", "manage", "manager",
    "console", "dashboard", "panel", "cpanel",
    "portal", "backoffice", "backend",

    # 办公系统
    "oa", "erp", "crm", "hr", "bi",
    "mail2", "email", "exchange", "outlook",
    "teams", "slack", "zoom", "meeting",

    # 数据库
    "db", "database", "mysql", "mongo", "redis",
    "oracle", "postgres", "sql", "mssql",

    # 中间件
    "jenkins", "gitlab", "github", "git", "svn",
    "ci", "cd", "jira", "confluence", "wiki",
    "nexus", "harbor", "docker", "k8s", "kubernetes",

    # 云服务
    "aws", "azure", "gcp", "aliyun", "oss", "cdn",
    "s3", "cloud", "ecs", "rds", "slb",

    # 其他服务
    "vpn", "remote", "rdp", "ssh", "sftp",
    "monitor", "zabbix", "nagios", "grafana",
    "log", "elk", "kibana", "splunk",
    "backup", "bak", "old", "archive",
    "static", "img", "image", "media", "video",
    "download", "dl", "file", "files",
    "shop", "store", "mall", "pay", "payment",
    "news", "blog", "forum", "bbs", "community",
    "help", "support", "ticket", "issue",
    "hr", "recruit", "job", "career",
    "iot", "smart", "device",
    "game", "play",
    "tv", "live", "stream",
    "search", "s", "so",
    "open", "public",
    "internal", "intranet", "private",
    "secure", "security", "ssl",
    "auth", "login", "sso", "oauth",
    "ws", "websocket", "socket",
    "rpc", "grpc", "thrift",
]

# 高价值子域名前缀
HIGH_VALUE_PREFIXES = [
    "admin", "manage", "console", "dashboard",
    "api", "internal", "intranet", "private",
    "test", "dev", "staging", "debug",
    "jenkins", "gitlab", "git", "svn",
    "vpn", "remote", "rdp",
    "db", "database", "mysql", "redis",
    "backup", "bak",
]


class SubdomainBruteForcer:
    """子域名爆破器"""

    def __init__(self, domain: str, wordlist: List[str] = None):
        self.domain = domain
        self.wordlist = wordlist or SUBDOMAIN_WORDLIST
        self.found_subdomains: Set[str] = set()

    def brute_force(self, max_threads: int = 50) -> Set[str]:
        """执行子域名爆破"""
        print(f"[*] 开始子域名爆破: {self.domain}")
        print(f"[*] 字典大小: {len(self.wordlist)}")

        # 构造子域名列表
        targets = [f"{prefix}.{self.domain}" for prefix in self.wordlist]

        # 多线程爆破
        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            futures = {executor.submit(self._resolve, sub): sub for sub in targets}
            for future in as_completed(futures):
                subdomain = futures[future]
                try:
                    result = future.result()
                    if result:
                        self.found_subdomains.add(result)
                        print(f"  [+] {result}")
                except Exception as e:
                    pass

        print(f"[*] 爆破完成，发现 {len(self.found_subdomains)} 个子域名")
        return self.found_subdomains

    def _resolve(self, subdomain: str) -> str:
        """解析子域名"""
        try:
            ip = socket.gethostbyname(subdomain)
            return subdomain
        except:
            return None

    def get_high_value(self) -> Set[str]:
        """获取高价值子域名"""
        high_value = set()
        for subdomain in self.found_subdomains:
            prefix = subdomain.split(".")[0]
            if prefix in HIGH_VALUE_PREFIXES:
                high_value.add(subdomain)
        return high_value


def brute_force_subdomains(domain: str, wordlist: List[str] = None) -> Set[str]:
    """便捷函数：子域名爆破"""
    bruter = SubdomainBruteForcer(domain, wordlist)
    return bruter.brute_force()


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        domain = sys.argv[1]
        subdomains = brute_force_subdomains(domain)
        print(f"\n发现的子域名:")
        for sub in sorted(subdomains):
            print(f"  {sub}")
    else:
        print("用法: python subdomain_brute.py <domain>")
