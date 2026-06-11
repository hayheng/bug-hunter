# -*- coding: utf-8 -*-
"""
目录扫描模块
"""

import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Set
from urllib.parse import urljoin
from config import SCAN_CONFIG


# 常见目录和文件
DIR_WORDLIST = [
    # 配置文件
    ".env", ".env.local", ".env.production", ".env.development",
    ".git/config", ".git/HEAD", ".gitignore",
    ".svn/entries", ".svn/wc.db",
    ".htaccess", ".htpasswd",
    "web.config", "config.php", "config.json", "config.yml", "config.yaml",
    "settings.py", "settings.json", "settings.yml",
    "application.yml", "application.properties",
    "database.yml", "db.php",

    # 敏感文件
    "robots.txt", "sitemap.xml", "crossdomain.xml",
    "favicon.ico", "humans.txt", "security.txt",
    ".well-known/security.txt",
    "LICENSE", "README.md", "CHANGELOG.md",

    # 备份文件
    "backup", "backup.zip", "backup.tar.gz", "backup.sql",
    "db_backup", "database.sql", "dump.sql",
    "www.zip", "www.tar.gz", "web.zip",
    "1.zip", "1.tar.gz",

    # 日志文件
    "log", "logs", "error.log", "access.log",
    "debug.log", "app.log", "server.log",

    # 管理后台
    "admin", "administrator", "manage", "manager",
    "console", "dashboard", "panel", "cpanel",
    "wp-admin", "wp-login.php",
    "phpmyadmin", "pma", "adminer",
    "admin.php", "login.php",

    # API文档
    "api", "api/v1", "api/v2", "api/v3",
    "api-docs", "api/swagger", "swagger-ui.html",
    "swagger-ui/", "swagger/index.html",
    "v2/api-docs", "v3/api-docs",
    "graphql", "graphiql", "playground",
    "openapi.json", "openapi.yaml",

    # 调试接口
    "debug", "test", "dev",
    "phpinfo.php", "info.php", "test.php",
    "server-status", "server-info",
    "actuator", "actuator/env", "actuator/health", "actuator/info",
    "metrics", "health", "status",

    # 常见目录
    "static", "assets", "public", "dist", "build",
    "css", "js", "javascript", "img", "image", "images",
    "upload", "uploads", "file", "files",
    "download", "downloads", "media",
    "temp", "tmp", "cache",

    # 应用目录
    "app", "application", "src", "lib", "vendor",
    "node_modules", "bower_components",
    "includes", "inc", "common",

    # 框架目录
    "wp-content", "wp-includes", "wp-admin",
    "system", "core", "framework",

    # 其他
    "cgi-bin", "bin", "scripts",
    "old", "new", "bak", "backup",
    "test1", "test2", "test3",
    "1", "2", "3",
]

# 正常文件（不算漏洞）
NORMAL_FILES = [
    "robots.txt", "sitemap.xml", "favicon.ico",
    "humans.txt", "crossdomain.xml",
    "LICENSE", "README.md", "CHANGELOG.md",
    "security.txt", ".well-known/security.txt",
]

# 高价值目录
HIGH_VALUE_DIRS = [
    ".env", ".git/config", ".htpasswd",
    "admin", "phpmyadmin", "adminer",
    "api-docs", "swagger-ui.html",
    "debug", "actuator", "actuator/env",
    "backup", "database.sql",
    "phpinfo.php", "info.php",
]


class DirectoryScanner:
    """目录扫描器"""

    def __init__(self, base_url: str, wordlist: List[str] = None):
        self.base_url = base_url.rstrip("/")
        self.wordlist = wordlist or DIR_WORDLIST
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": SCAN_CONFIG["user_agent"],
        })
        self.found_paths: List[Dict] = []

    def scan(self, max_threads: int = 20) -> List[Dict]:
        """执行目录扫描"""
        print(f"[*] 开始目录扫描: {self.base_url}")
        print(f"[*] 字典大小: {len(self.wordlist)}")

        # 构造URL列表
        targets = [f"{self.base_url}/{path}" for path in self.wordlist]

        # 多线程扫描
        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            futures = {executor.submit(self._check_path, url): url for url in targets}
            for future in as_completed(futures):
                url = futures[future]
                try:
                    result = future.result()
                    if result:
                        self.found_paths.append(result)
                        status = result["status_code"]
                        path = result["path"]
                        print(f"  [{status}] {path}")
                except Exception as e:
                    pass

        print(f"[*] 扫描完成，发现 {len(self.found_paths)} 个有效路径")
        return self.found_paths

    def _check_path(self, url: str) -> Dict:
        """检查路径是否存在"""
        try:
            path = url.replace(self.base_url + "/", "")

            # 过滤正常文件
            if path in NORMAL_FILES:
                return None

            response = self.session.get(
                url,
                timeout=5,
                allow_redirects=False,
                verify=False
            )

            # 只记录 200 和 403 状态码
            # 301/302 重定向不算敏感文件泄露
            if response.status_code in [200, 403]:
                # 排除自定义404页面
                if response.status_code == 200 and len(response.text) < 100:
                    if "404" in response.text or "not found" in response.text.lower():
                        return None

                return {
                    "url": url,
                    "path": path,
                    "status_code": response.status_code,
                    "content_type": response.headers.get("Content-Type", ""),
                    "size": len(response.text),
                    "is_high_value": path in HIGH_VALUE_DIRS,
                }
        except:
            pass
        return None

    def get_high_value(self) -> List[Dict]:
        """获取高价值路径"""
        return [p for p in self.found_paths if p["is_high_value"]]


def scan_directories(base_url: str, wordlist: List[str] = None) -> List[Dict]:
    """便捷函数：目录扫描"""
    scanner = DirectoryScanner(base_url, wordlist)
    return scanner.scan()


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        url = sys.argv[1]
        results = scan_directories(url)
        print(f"\n发现的路径:")
        for r in results:
            print(f"  [{r['status_code']}] {r['path']}")
    else:
        print("用法: python dir_scanner.py <url>")
