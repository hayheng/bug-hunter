# -*- coding: utf-8 -*-
"""
存活探测模块
"""

import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Set
from config import SCAN_CONFIG


class AliveChecker:
    """存活目标检测器"""

    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": SCAN_CONFIG["user_agent"],
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
        })
        self.session.max_redirects = 5

    def check_alive(self, targets: Set[str]) -> List[Dict]:
        """检测目标是否存活"""
        print(f"[*] 开始存活探测，共 {len(targets)} 个目标...")

        alive_targets = []

        with ThreadPoolExecutor(max_workers=SCAN_CONFIG["max_threads"]) as executor:
            futures = {executor.submit(self._check_single, target): target for target in targets}
            for future in as_completed(futures):
                target = futures[future]
                try:
                    result = future.result()
                    if result:
                        alive_targets.append(result)
                        print(f"  [+] {target} - 存活")
                except Exception as e:
                    pass

        print(f"[*] 发现 {len(alive_targets)} 个存活目标")
        return alive_targets

    def _check_single(self, target: str) -> Dict:
        """检测单个目标"""
        for protocol in ["https", "http"]:
            url = f"{protocol}://{target}"
            try:
                response = self.session.get(
                    url,
                    timeout=SCAN_CONFIG["timeout"],
                    allow_redirects=True,
                    verify=False
                )
                if response.status_code < 500:
                    return {
                        "target": target,
                        "url": url,
                        "status_code": response.status_code,
                        "server": response.headers.get("Server", "Unknown"),
                        "content_type": response.headers.get("Content-Type", ""),
                        "title": self._extract_title(response.text),
                        "redirect_url": response.url if response.url != url else None,
                        "technologies": self._detect_technologies(response),
                    }
            except:
                continue
        return None

    def _extract_title(self, html: str) -> str:
        """提取页面标题"""
        import re
        match = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
        return match.group(1).strip()[:100] if match else ""

    def _detect_technologies(self, response) -> List[str]:
        """检测技术栈"""
        techs = []

        # 检查 Server header
        server = response.headers.get("Server", "").lower()
        if "nginx" in server:
            techs.append("Nginx")
        elif "apache" in server:
            techs.append("Apache")
        elif "iis" in server:
            techs.append("IIS")

        # 检查 X-Powered-By
        powered_by = response.headers.get("X-Powered-By", "").lower()
        if "php" in powered_by:
            techs.append("PHP")
        elif "asp.net" in powered_by:
            techs.append("ASP.NET")
        elif "express" in powered_by:
            techs.append("Node.js/Express")

        # 检查响应内容
        body = response.text.lower()
        if "wp-content" in body or "wp-includes" in body:
            techs.append("WordPress")
        if "drupal" in body:
            techs.append("Drupal")
        if "joomla" in body:
            techs.append("Joomla")
        if "react" in body or "reactdom" in body:
            techs.append("React")
        if "vue" in body or "vue.js" in body:
            techs.append("Vue.js")
        if "angular" in body:
            techs.append("Angular")

        return techs

    def filter_high_value(self, alive_targets: List[Dict]) -> List[Dict]:
        """筛选高价值目标"""
        high_value = []
        for target in alive_targets:
            score = 0

            # 根据状态码评分
            if target["status_code"] == 200:
                score += 10
            elif target["status_code"] in [301, 302]:
                score += 5

            # 根据技术栈评分
            techs = target.get("technologies", [])
            if "WordPress" in techs:
                score += 15
            if "PHP" in techs:
                score += 10
            if "Apache" in techs:
                score += 5

            # 根据标题关键词评分
            title = target.get("title", "").lower()
            if any(kw in title for kw in ["admin", "login", "管理", "后台"]):
                score += 20
            if any(kw in title for kw in ["test", "demo", "dev"]):
                score += 15

            target["score"] = score
            if score >= 10:
                high_value.append(target)

        # 按分数排序
        high_value.sort(key=lambda x: x["score"], reverse=True)
        return high_value


def check_alive_targets(targets: Set[str]) -> List[Dict]:
    """便捷函数：检测存活目标"""
    checker = AliveChecker()
    return checker.check_alive(targets)


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        targets = set(sys.argv[1:])
        alive = check_alive_targets(targets)
        for target in alive:
            print(f"{target['url']} - {target['status_code']} - {target['title']}")
    else:
        print("用法: python alive_checker.py <target1> <target2> ...")
