# -*- coding: utf-8 -*-
"""
漏洞过滤模块
只保留高价值漏洞，过滤低价值漏洞
"""

from typing import List, Dict


class VulnFilter:
    """漏洞过滤器"""

    # 高价值漏洞类型（保留）
    HIGH_VALUE_TYPES = [
        "SQL注入",
        "SQL注入(时间盲注)",
        "SQL注入(报错注入)",
        "SQL注入(WAF绕过)",
        "未授权访问",
        "信息泄露",
        "敏感文件泄露",
        "逻辑漏洞",
        "XSS",
        "反射型XSS",
        "存储型XSS",
        "SSRF",
        "命令注入",
        "命令执行",
        "文件包含",
        "路径遍历",
        "目录遍历",
        "反序列化",
        "XXE",
        "SSTI模板注入",
        "JWT漏洞",
        "GraphQL漏洞",
        "越权访问",
        "水平越权",
        "垂直越权",
        "弱口令",
        "默认凭证",
        "支付逻辑漏洞",
        "密码重置漏洞",
        "验证码绕过",
        "短信轰炸",
        "任意用户注册",
        "任意密码重置",
        "API未授权访问",
        "数据库泄露",
        "源码泄露",
        "配置文件泄露",
        "内网IP泄露",
        "敏感接口泄露",
        "CORS配置错误",
        "HTTP请求走私",
    ]

    # 低价值漏洞类型（过滤）
    LOW_VALUE_TYPES = [
        "Clickjacking",
        "安全头缺失",
        "输出编码漏洞",
        "架构漏洞",
        "加密漏洞",
        "配置错误",
        "PUT方法启用",
        "TRACE方法启用",
        "Host头注入",
        "CRLF注入",
        "开放重定向",
        "弱加密套件",
        "安全配置缺陷",
        "版本信息泄露",
        "服务器信息泄露",
        "技术栈信息泄露",
    ]

    # 高价值路径关键词
    HIGH_VALUE_PATHS = [
        "/admin",
        "/api",
        "/login",
        "/register",
        "/password",
        "/reset",
        "/config",
        "/database",
        "/backup",
        "/env",
        "/.git",
        "/.svn",
        "/debug",
        "/console",
        "/actuator",
        "/swagger",
        "/graphql",
        "/phpmyadmin",
        "/adminer",
    ]

    # 高价值证据关键词
    HIGH_VALUE_EVIDENCE = [
        "password",
        "secret",
        "token",
        "api_key",
        "private_key",
        "database",
        "mysql",
        "redis",
        "mongodb",
        "uid=",
        "root:",
        "admin",
        "sql syntax",
        "ORA-",
        "SQL Server",
        "stack trace",
        "exception",
        "debug",
    ]

    def filter_vulns(self, vulns: List[Dict]) -> List[Dict]:
        """过滤漏洞，只保留高价值漏洞"""
        print(f"[*] 过滤漏洞，原始数量: {len(vulns)}")

        filtered_vulns = []

        for vuln in vulns:
            # 检查是否是高价值漏洞
            if self._is_high_value(vuln):
                filtered_vulns.append(vuln)
            else:
                print(f"  [过滤] {vuln.get('type')} - 低价值漏洞")

        print(f"[*] 过滤完成，保留数量: {len(filtered_vulns)}")
        return filtered_vulns

    def _is_high_value(self, vuln: Dict) -> bool:
        """检查是否是高价值漏洞"""
        vuln_type = vuln.get("type", "")
        url = vuln.get("url", "")
        evidence = vuln.get("evidence", "").lower()
        severity = vuln.get("severity", "")

        # 检查漏洞类型
        for high_type in self.HIGH_VALUE_TYPES:
            if high_type in vuln_type:
                return True

        # 检查低价值漏洞类型
        for low_type in self.LOW_VALUE_TYPES:
            if low_type in vuln_type:
                return False

        # 检查URL路径
        url_lower = url.lower()
        for high_path in self.HIGH_VALUE_PATHS:
            if high_path in url_lower:
                return True

        # 检查证据
        for high_evidence in self.HIGH_VALUE_EVIDENCE:
            if high_evidence in evidence:
                return True

        # 检查严重程度
        if severity in ["Critical", "High"]:
            return True

        return False

    def prioritize_vulns(self, vulns: List[Dict]) -> List[Dict]:
        """漏洞优先级排序"""
        # 优先级分数
        priority_scores = {
            "SQL注入": 100,
            "SQL注入(时间盲注)": 95,
            "命令执行": 90,
            "命令注入": 90,
            "未授权访问": 85,
            "SSRF": 80,
            "文件包含": 80,
            "路径遍历": 75,
            "信息泄露": 70,
            "敏感文件泄露": 70,
            "逻辑漏洞": 65,
            "XSS": 60,
            "反射型XSS": 55,
            "越权访问": 50,
            "弱口令": 45,
        }

        # 计算每个漏洞的优先级分数
        for vuln in vulns:
            vuln_type = vuln.get("type", "")
            score = priority_scores.get(vuln_type, 30)

            # 根据严重程度调整
            severity = vuln.get("severity", "")
            if severity == "Critical":
                score += 20
            elif severity == "High":
                score += 10
            elif severity == "Medium":
                score += 5

            vuln["priority_score"] = score

        # 按优先级分数排序
        return sorted(vulns, key=lambda x: x.get("priority_score", 0), reverse=True)

    def deduplicate_vulns(self, vulns: List[Dict]) -> List[Dict]:
        """去重漏洞"""
        seen = set()
        unique_vulns = []

        for vuln in vulns:
            # 生成唯一标识
            url = vuln.get("url", "")
            vuln_type = vuln.get("type", "")
            evidence = vuln.get("evidence", "")[:50]

            key = f"{url}|{vuln_type}|{evidence}"

            if key not in seen:
                seen.add(key)
                unique_vulns.append(vuln)

        return unique_vulns

    def enhance_vuln(self, vuln: Dict) -> Dict:
        """增强漏洞信息"""
        vuln_type = vuln.get("type", "")
        url = vuln.get("url", "")
        evidence = vuln.get("evidence", "")

        # 添加补天平台类型
        vuln["butian_type"] = self._get_butian_type(vuln_type)

        # 添加漏洞标题
        vuln["title"] = self._generate_title(vuln)

        # 添加复现步骤
        vuln["steps"] = self._generate_steps(vuln)

        # 添加危害说明
        vuln["impact"] = self._generate_impact(vuln)

        # 添加修复建议
        vuln["remediation"] = self._generate_remediation(vuln)

        return vuln

    def _get_butian_type(self, vuln_type: str) -> str:
        """获取补天平台漏洞类型"""
        type_map = {
            "SQL注入": "SQL注入",
            "SQL注入(时间盲注)": "SQL注入",
            "SQL注入(报错注入)": "SQL注入",
            "SQL注入(WAF绕过)": "SQL注入",
            "未授权访问": "未授权访问",
            "信息泄露": "信息泄露",
            "敏感文件泄露": "信息泄露",
            "逻辑漏洞": "逻辑漏洞",
            "XSS": "XSS",
            "反射型XSS": "XSS",
            "存储型XSS": "XSS",
            "SSRF": "SSRF",
            "命令注入": "命令执行",
            "命令执行": "命令执行",
            "文件包含": "文件包含",
            "路径遍历": "目录遍历",
            "目录遍历": "目录遍历",
            "反序列化": "反序列化",
            "XXE": "XXE",
            "SSTI模板注入": "命令执行",
            "JWT漏洞": "逻辑漏洞",
            "GraphQL漏洞": "信息泄露",
            "越权访问": "逻辑漏洞",
            "水平越权": "逻辑漏洞",
            "垂直越权": "逻辑漏洞",
            "弱口令": "弱口令",
            "默认凭证": "弱口令",
            "支付逻辑漏洞": "逻辑漏洞",
            "密码重置漏洞": "逻辑漏洞",
            "验证码绕过": "逻辑漏洞",
            "短信轰炸": "逻辑漏洞",
            "任意用户注册": "逻辑漏洞",
            "任意密码重置": "逻辑漏洞",
            "API未授权访问": "未授权访问",
            "数据库泄露": "信息泄露",
            "源码泄露": "信息泄露",
            "配置文件泄露": "信息泄露",
            "内网IP泄露": "信息泄露",
            "敏感接口泄露": "信息泄露",
            "CORS配置错误": "配置错误",
            "HTTP请求走私": "配置错误",
        }

        # 精确匹配
        if vuln_type in type_map:
            return type_map[vuln_type]

        # 模糊匹配
        for key, value in type_map.items():
            if key in vuln_type:
                return value

        return "其他"

    def _generate_title(self, vuln: Dict) -> str:
        """生成漏洞标题"""
        vuln_type = vuln.get("type", "")
        url = vuln.get("url", "")
        butian_type = vuln.get("butian_type", vuln_type)

        # 提取域名
        from urllib.parse import urlparse
        parsed = urlparse(url)
        domain = parsed.netloc

        return f"{domain}存在{butian_type}漏洞"

    def _generate_steps(self, vuln: Dict) -> str:
        """生成复现步骤"""
        vuln_type = vuln.get("type", "")
        url = vuln.get("url", "")
        evidence = vuln.get("evidence", "")

        # 根据漏洞类型生成步骤
        if "SQL注入" in vuln_type:
            return f"""1. 访问目标URL: {url}
2. 在参数中注入SQL Payload
3. 观察响应，确认存在SQL注入
4. 使用sqlmap验证: sqlmap -u "{url}" --dbs"""

        elif "未授权访问" in vuln_type:
            return f"""1. 直接访问目标URL: {url}
2. 无需登录认证
3. 确认可访问敏感功能或数据"""

        elif "信息泄露" in vuln_type or "敏感文件泄露" in vuln_type:
            return f"""1. 访问目标URL: {url}
2. 查看响应内容
3. 确认泄露敏感信息"""

        elif "XSS" in vuln_type:
            return f"""1. 访问目标URL: {url}
2. 在输入框中注入XSS Payload
3. 触发弹窗或执行JavaScript代码"""

        elif "SSRF" in vuln_type:
            return f"""1. 访问目标URL: {url}
2. 在参数中注入内部地址
3. 确认可访问内部资源"""

        elif "命令注入" in vuln_type or "命令执行" in vuln_type:
            return f"""1. 访问目标URL: {url}
2. 在参数中注入系统命令
3. 确认命令执行成功"""

        elif "逻辑漏洞" in vuln_type:
            return f"""1. 访问目标URL: {url}
2. 执行特定业务操作
3. 确认存在逻辑缺陷"""

        else:
            return f"""1. 访问目标URL: {url}
2. 执行漏洞验证操作
3. 确认漏洞存在"""

    def _generate_impact(self, vuln: Dict) -> str:
        """生成危害说明"""
        vuln_type = vuln.get("type", "")

        impact_map = {
            "SQL注入": "攻击者可通过SQL注入获取数据库敏感信息，包括用户数据、管理员密码等，甚至可能获取服务器权限。",
            "未授权访问": "攻击者无需认证即可访问敏感功能或数据，可能导致数据泄露、权限提升等安全风险。",
            "信息泄露": "泄露敏感信息，包括数据库配置、用户数据、源代码等，可能被攻击者利用进行进一步攻击。",
            "敏感文件泄露": "泄露敏感配置文件，包括数据库连接信息、API密钥等，可能导致系统被完全控制。",
            "XSS": "攻击者可注入恶意脚本，窃取用户Cookie、会话令牌，或进行钓鱼攻击。",
            "SSRF": "攻击者可利用服务器发起任意请求，访问内部网络资源或云服务元数据。",
            "命令注入": "攻击者可执行任意系统命令，完全控制服务器。",
            "逻辑漏洞": "业务逻辑缺陷，可能导致支付绕过、越权访问等安全风险。",
            "越权访问": "攻击者可访问其他用户的数据或功能，导致隐私泄露。",
            "弱口令": "攻击者可轻易猜测密码，获取系统访问权限。",
        }

        # 精确匹配
        if vuln_type in impact_map:
            return impact_map[vuln_type]

        # 模糊匹配
        for key, value in impact_map.items():
            if key in vuln_type:
                return value

        return "该漏洞可能被攻击者利用，对系统安全造成影响。"

    def _generate_remediation(self, vuln: Dict) -> str:
        """生成修复建议"""
        vuln_type = vuln.get("type", "")

        remediation_map = {
            "SQL注入": "1. 使用参数化查询（Prepared Statements）\n2. 使用ORM框架\n3. 输入验证和过滤\n4. 最小权限原则配置数据库用户",
            "未授权访问": "1. 添加身份认证\n2. 实施访问控制\n3. 配置IP白名单\n4. 启用多因素认证",
            "信息泄露": "1. 删除敏感文件\n2. 配置访问控制\n3. 自定义错误页面\n4. 移除调试信息",
            "敏感文件泄露": "1. 删除敏感文件\n2. 配置访问控制\n3. 使用.gitignore排除敏感文件\n4. 配置Web服务器禁止访问",
            "XSS": "1. 对输出进行HTML编码\n2. 使用CSP（内容安全策略）\n3. 设置HttpOnly Cookie\n4. 输入验证和过滤",
            "SSRF": "1. 验证和限制URL白名单\n2. 禁止访问内部网络\n3. 禁用不必要的协议\n4. 使用DNS解析验证",
            "命令注入": "1. 使用白名单验证输入\n2. 避免调用系统命令\n3. 使用参数化API\n4. 实施最小权限原则",
            "逻辑漏洞": "1. 服务端验证业务逻辑\n2. 实施防重放攻击\n3. 添加验证码机制\n4. 记录异常操作日志",
            "越权访问": "1. 实施权限验证\n2. 使用会话管理\n3. 验证资源所有权\n4. 记录访问日志",
            "弱口令": "1. 修改默认密码\n2. 强制密码复杂度\n3. 实施账户锁定策略\n4. 启用多因素认证",
        }

        # 精确匹配
        if vuln_type in remediation_map:
            return remediation_map[vuln_type]

        # 模糊匹配
        for key, value in remediation_map.items():
            if key in vuln_type:
                return value

        return "请联系安全团队获取具体修复方案。"


# 全局实例
_vuln_filter = None


def get_vuln_filter() -> VulnFilter:
    """获取漏洞过滤器实例"""
    global _vuln_filter
    if _vuln_filter is None:
        _vuln_filter = VulnFilter()
    return _vuln_filter


def filter_vulns(vulns: List[Dict]) -> List[Dict]:
    """便捷函数：过滤漏洞"""
    return get_vuln_filter().filter_vulns(vulns)


def prioritize_vulns(vulns: List[Dict]) -> List[Dict]:
    """便捷函数：漏洞优先级排序"""
    return get_vuln_filter().prioritize_vulns(vulns)


def deduplicate_vulns(vulns: List[Dict]) -> List[Dict]:
    """便捷函数：去重漏洞"""
    return get_vuln_filter().deduplicate_vulns(vulns)


def enhance_vulns(vulns: List[Dict]) -> List[Dict]:
    """便捷函数：增强漏洞信息"""
    return [get_vuln_filter().enhance_vuln(vuln) for vuln in vulns]


if __name__ == "__main__":
    # 测试
    test_vulns = [
        {"type": "SQL注入", "severity": "Critical", "url": "https://example.com/api?id=1", "evidence": "sql syntax error"},
        {"type": "Clickjacking", "severity": "Medium", "url": "https://example.com", "evidence": "未设置X-Frame-Options"},
        {"type": "未授权访问", "severity": "High", "url": "https://example.com/admin", "evidence": "返回200"},
        {"type": "安全头缺失", "severity": "Low", "url": "https://example.com", "evidence": "缺少安全头"},
    ]

    print("原始漏洞:")
    for v in test_vulns:
        print(f"  - {v['type']} ({v['severity']})")

    filtered = filter_vulns(test_vulns)
    print(f"\n过滤后漏洞:")
    for v in filtered:
        print(f"  - {v['type']} ({v['severity']})")
