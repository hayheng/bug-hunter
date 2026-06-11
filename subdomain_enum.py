# -*- coding: utf-8 -*-
"""
子域名枚举模块
"""

import requests
import json
import re
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Set, List
from config import SCAN_CONFIG, SUBDOMAIN_CONFIG


class SubdomainEnumerator:
    """子域名枚举器"""

    def __init__(self, domain: str):
        self.domain = domain
        self.subdomains: Set[str] = set()
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": SCAN_CONFIG["user_agent"]
        })

    def enumerate_all(self) -> Set[str]:
        """执行所有枚举方法"""
        print(f"[*] 开始枚举子域名: {self.domain}")

        methods = []
        if SUBDOMAIN_CONFIG["use_crt_sh"]:
            methods.append(("crt.sh", self.enum_crt_sh))
        if SUBDOMAIN_CONFIG["use_dns_dumpster"]:
            methods.append(("DNSdumpster", self.enum_dns_dumpster))
        if SUBDOMAIN_CONFIG["use_sublist3r"]:
            methods.append(("Sublist3r", self.enum_sublist3r))

        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = {executor.submit(method): name for name, method in methods}
            for future in as_completed(futures):
                name = futures[future]
                try:
                    result = future.result()
                    print(f"  [+] {name}: 发现 {len(result)} 个子域名")
                    self.subdomains.update(result)
                except Exception as e:
                    print(f"  [-] {name}: 失败 - {e}")

        # 添加主域名
        self.subdomains.add(self.domain)

        print(f"[*] 总计发现 {len(self.subdomains)} 个子域名")
        return self.subdomains

    def enum_crt_sh(self) -> Set[str]:
        """通过 crt.sh 证书透明度查询"""
        result = set()
        try:
            url = f"https://crt.sh/?q=%.{self.domain}&output=json"
            response = self.session.get(url, timeout=SCAN_CONFIG["timeout"])
            if response.status_code == 200:
                data = response.json()
                for entry in data:
                    name = entry.get("name_value", "")
                    for subdomain in name.split("\n"):
                        subdomain = subdomain.strip().lower()
                        if subdomain.endswith(self.domain) and "*" not in subdomain:
                            result.add(subdomain)
        except Exception as e:
            print(f"    crt.sh 错误: {e}")
        return result

    def enum_dns_dumpster(self) -> Set[str]:
        """通过 DNSdumpster 查询"""
        result = set()
        try:
            url = "https://dnsdumpster.com/"
            response = self.session.get(url, timeout=SCAN_CONFIG["timeout"])
            csrf_token = re.search(r"csrfmiddlewaretoken' value='(.*?)'", response.text)
            if csrf_token:
                headers = {
                    "Referer": "https://dnsdumpster.com/",
                    "Cookie": f"csrftoken={csrf_token.group(1)}"
                }
                data = {
                    "csrfmiddlewaretoken": csrf_token.group(1),
                    "targetip": self.domain
                }
                response = self.session.post(url, data=data, headers=headers, timeout=SCAN_CONFIG["timeout"])
                pattern = r"[a-zA-Z0-9\.\-]+\." + re.escape(self.domain)
                matches = re.findall(pattern, response.text)
                result = {m.lower() for m in matches}
        except Exception as e:
            print(f"    DNSdumpster 错误: {e}")
        return result

    def enum_sublist3r(self) -> Set[str]:
        """通过 Sublist3r API 查询"""
        result = set()
        try:
            url = f"https://api.sublist3r.com/search.php?domain={self.domain}"
            response = self.session.get(url, timeout=SCAN_CONFIG["timeout"])
            if response.status_code == 200:
                data = response.json()
                if isinstance(data, list):
                    result = {s.lower() for s in data}
        except Exception as e:
            print(f"    Sublist3r 错误: {e}")
        return result

    def resolve_subdomains(self, subdomains: Set[str]) -> List[dict]:
        """解析子域名的IP地址"""
        print(f"[*] 解析子域名IP地址...")
        resolved = []

        def resolve_one(subdomain):
            try:
                ip = socket.gethostbyname(subdomain)
                return {"subdomain": subdomain, "ip": ip}
            except:
                return None

        with ThreadPoolExecutor(max_workers=SCAN_CONFIG["max_threads"]) as executor:
            futures = [executor.submit(resolve_one, sub) for sub in subdomains]
            for future in as_completed(futures):
                result = future.result()
                if result:
                    resolved.append(result)

        print(f"[*] 成功解析 {len(resolved)} 个子域名")
        return resolved


def enumerate_subdomains(domain: str) -> Set[str]:
    """便捷函数：枚举子域名"""
    enumerator = SubdomainEnumerator(domain)
    return enumerator.enumerate_all()


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        domain = sys.argv[1]
        subdomains = enumerate_subdomains(domain)
        for sub in sorted(subdomains):
            print(sub)
    else:
        print("用法: python subdomain_enum.py <domain>")
