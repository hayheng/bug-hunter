# -*- coding: utf-8 -*-
"""
报告生成模块
"""

import json
from datetime import datetime
from typing import List, Dict
from pathlib import Path
from urllib.parse import urlparse
from config import REPORTS_DIR, REPORT_TEMPLATE
from vuln_details import get_vuln_details
from remediation_templates import get_remediation


class ReportGenerator:
    """报告生成器"""

    # 严重程度中文映射
    SEVERITY_CN = {
        "Critical": "严重",
        "High": "高危",
        "Medium": "中危",
        "Low": "低危",
        "Info": "信息"
    }

    # 域名到单位名称映射（可扩展）
    DOMAIN_ORG_MAP = {
        # 汽车
        "lixiang.com": "理想汽车",
        "www.lixiang.com": "理想汽车",
        "nio.com": "蔚来汽车",
        "xpeng.com": "小鹏汽车",
        "tesla.cn": "特斯拉中国",
        "byd.com": "比亚迪",

        # 金融
        "fenqile.com": "分期乐",
        "www.fenqile.com": "分期乐",
        "ppdai.com": "拍拍贷",
        "lufax.com": "陆金所",
        "jiedaibao.com": "借贷宝",
        "renrendai.com": "人人贷",
        "dianrong.com": "点融",

        # 电商
        "jd.com": "京东",
        "taobao.com": "淘宝",
        "tmall.com": "天猫",
        "pinduoduo.com": "拼多多",
        "suning.com": "苏宁",
        "vip.com": "唯品会",

        # 物流
        "sto.cn": "申通快递",
        "www.sto.cn": "申通快递",
        "sf-express.com": "顺丰速运",
        "yto.net.cn": "圆通速递",
        "zto.com": "中通快递",
        "yundaex.com": "韵达快递",
        "bestex.cc": "百世快递",

        # 科技
        "baidu.com": "百度",
        "alibaba.com": "阿里巴巴",
        "tencent.com": "腾讯",
        "bytedance.com": "字节跳动",
        "meituan.com": "美团",
        "didi.cn": "滴滴出行",

        # 社交
        "weibo.com": "微博",
        "douyin.com": "抖音",
        "kuaishou.com": "快手",
        "xiaohongshu.com": "小红书",
        "zhihu.com": "知乎",
        "bilibili.com": "哔哩哔哩",

        # 游戏
        "163.com": "网易",
        "netease.com": "网易",
        "miHoYo.com": "米哈游",
        "mihoyo.com": "米哈游",

        # 其他
        "ctrip.com": "携程",
        "meituan.com": "美团",
        "dianping.com": "大众点评",
        "58.com": "58同城",
        "ganji.com": "赶集网",
    }

    def __init__(self, target: str):
        self.target = target
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.org_name = self._extract_org_name(target)

    def _extract_org_name(self, domain: str) -> str:
        """从域名提取单位名称"""
        # 先查映射表
        if domain in self.DOMAIN_ORG_MAP:
            return self.DOMAIN_ORG_MAP[domain]

        # 去掉 www 前缀再查
        clean_domain = domain.replace("www.", "")
        if clean_domain in self.DOMAIN_ORG_MAP:
            return self.DOMAIN_ORG_MAP[clean_domain]

        # 从域名提取
        parts = clean_domain.split(".")
        if len(parts) >= 2:
            # 取主域名作为单位名
            main_domain = parts[-2]
            # 首字母大写
            return main_domain.capitalize()

        return domain

    # 漏洞类型到补天平台类型映射
    VULN_TYPE_MAP = {
        # 补天平台类型
        "SQL注入": "SQL注入",
        "XSS": "XSS",
        "命令注入": "命令执行",
        "命令注入(时间盲注)": "命令执行",
        "SSRF": "SSRF",
        "XXE漏洞": "XXE",
        "SSTI模板注入": "命令执行",
        "反序列化": "反序列化",
        "未授权访问": "逻辑漏洞",  # 补天没有未授权访问，映射到逻辑漏洞
        "越权漏洞": "逻辑漏洞",  # 补天没有越权访问，映射到逻辑漏洞
        "默认凭证": "弱口令",
        "路径遍历": "目录遍历",
        "目录遍历": "目录遍历",
        "文件包含": "目录遍历",
        "逻辑漏洞": "逻辑漏洞",
        "敏感文件泄露": "信息泄露",
        "信息泄露": "信息泄露",
        "API端点泄露": "信息泄露",
        "GraphQL漏洞": "配置错误",
        "Clickjacking": "配置错误",
        "CORS配置错误": "配置错误",
        "安全头缺失": "配置错误",
        "PUT方法启用": "配置错误",
        "TRACE方法启用": "配置错误",
        "Host头注入": "配置错误",
        "CRLF注入": "配置错误",
        "HTTP请求走私": "配置错误",
        "弱加密套件": "配置错误",
        "开放重定向": "配置错误",
    }

    def _get_vuln_type_for_platform(self, vuln_type: str) -> str:
        """获取补天平台漏洞类型"""
        # 处理 Nuclei 前缀
        clean_type = vuln_type.replace("Nuclei-", "")

        # 精确匹配
        if clean_type in self.VULN_TYPE_MAP:
            return self.VULN_TYPE_MAP[clean_type]

        # 模糊匹配
        for key, value in self.VULN_TYPE_MAP.items():
            if key in clean_type:
                return value

        return "其他"

    def _get_vuln_title(self, vuln_type: str) -> str:
        """生成漏洞标题：单位名称+漏洞类型"""
        platform_type = self._get_vuln_type_for_platform(vuln_type)
        return f"{self.org_name}存在{platform_type}"

    def generate(self, subdomains: set, alive_targets: List[Dict],
                 vulnerabilities: List[Dict]) -> str:
        """生成完整报告"""
        # 生成 Markdown 报告
        md_report = self._generate_markdown(subdomains, alive_targets, vulnerabilities)

        # 生成 JSON 报告
        json_report = self._generate_json(subdomains, alive_targets, vulnerabilities)

        # 保存报告
        md_path = REPORTS_DIR / f"report_{self.target}_{self.timestamp}.md"
        json_path = REPORTS_DIR / f"report_{self.target}_{self.timestamp}.json"

        md_path.write_text(md_report, encoding="utf-8")
        json_path.write_text(json.dumps(json_report, ensure_ascii=False, indent=2), encoding="utf-8")

        print(f"[*] 报告已保存:")
        print(f"    Markdown: {md_path}")
        print(f"    JSON: {json_path}")

        return str(md_path)

    def _generate_markdown(self, subdomains: set, alive_targets: List[Dict],
                           vulnerabilities: List[Dict]) -> str:
        """生成 Markdown 格式报告"""
        # 按严重程度分类漏洞
        severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
        sorted_vulns = sorted(vulnerabilities, key=lambda x: severity_order.get(x.get("severity", "Info"), 5))

        # 生成漏洞详情
        vuln_details = ""
        if sorted_vulns:
            # 计算优先级
            prioritized_vulns = self._prioritize_vulns(sorted_vulns)

            for i, vuln in enumerate(prioritized_vulns, 1):
                severity_en = vuln.get("severity", "Info")
                severity_cn = self.SEVERITY_CN.get(severity_en, severity_en)
                severity_icon = {
                    "Critical": "🔴",
                    "High": "🟠",
                    "Medium": "🟡",
                    "Low": "🟢",
                    "Info": "🔵"
                }.get(severity_en, "⚪")

                # 获取漏洞详细信息
                vuln_type = vuln.get("type", "")
                details = get_vuln_details(vuln_type)
                url = vuln.get("url", "N/A")
                host = url.replace("https://", "").replace("http://", "").split("/")[0]

                # 生成漏洞标题和补天平台类型
                vuln_title = vuln.get("title", self._get_vuln_title(vuln_type))
                platform_type = vuln.get("butian_type", self._get_vuln_type_for_platform(vuln_type))

                # 计算可利用性评分
                exploit_score = self._calculate_exploit_score(vuln)
                exploit_level = self._get_exploit_level(exploit_score)

                # 计算奖金预估
                bounty_estimate = self._estimate_bounty(severity_en, vuln_type)

                # 计算优先级
                priority = self._get_priority(severity_en, exploit_score)

                # 获取复现步骤
                steps = vuln.get("steps", details['steps'])

                # 获取危害说明
                impact = vuln.get("impact", details['impact'])

                # 获取修复建议
                remediation = vuln.get("remediation", details['remediation'])

                vuln_details += f"""
### {i}. {severity_icon} [{severity_cn}] {vuln_type}

#### 漏洞标题
{vuln_title}

#### 漏洞类型
{platform_type}（补天平台分类）

#### 可利用性评分
{exploit_level} ({exploit_score}/100)

#### 奖金预估
{bounty_estimate}

#### 优先级
{priority}

#### 简要描述
{details['summary']}

#### 影响范围
{impact}

#### 详细细节

**测试/复现过程**:
{steps}

**漏洞URL**: {url}

**证据**:
```
{vuln.get('evidence', 'N/A')[:500]}
```

**PoC / Exploit**:
```html
{details['poc'].format(url=url, host=host, path=urlparse(url).path)}
```

**使用的组件/工具**:
{details['tools']}

#### 修复建议

{remediation}

---
"""
        else:
            vuln_details = "未发现漏洞\n"

        # 生成建议
        recommendations = self._generate_recommendations(sorted_vulns)

        # 统计漏洞数量
        severity_count = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
        for vuln in sorted_vulns:
            severity = vuln.get("severity", "Info")
            severity_count[severity] = severity_count.get(severity, 0) + 1

        # 构建报告
        report = f"""
# 🎯 自动化漏洞扫描报告

**目标**: {self.target}
**扫描时间**: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
**扫描状态**: 完成

---

## 📊 扫描统计

| 项目 | 数量 |
|------|------|
| 子域名发现 | {len(subdomains)} |
| 存活目标 | {len(alive_targets)} |
| 发现漏洞 | {len(sorted_vulns)} |

### 漏洞危险等级分布

| 危险等级 | 数量 |
|----------|------|
| 🔴 严重 | {severity_count.get('Critical', 0)} |
| 🟠 高危 | {severity_count.get('High', 0)} |
| 🟡 中危 | {severity_count.get('Medium', 0)} |
| 🟢 低危 | {severity_count.get('Low', 0)} |
| 🔵 信息 | {severity_count.get('Info', 0)} |

---

## 🌐 子域名列表

```
{chr(10).join(sorted(subdomains)[:50])}
{f"... 共 {len(subdomains)} 个" if len(subdomains) > 50 else ""}
```

---

## 🖥️ 存活目标

| URL | 状态码 | 服务器 | 标题 |
|-----|--------|--------|------|
{chr(10).join([f"| {t.get('url', '')} | {t.get('status_code', '')} | {t.get('server', '')} | {t.get('title', '')[:30]} |" for t in alive_targets[:20]])}
{f"| ... 共 {len(alive_targets)} 个目标 | | | |" if len(alive_targets) > 20 else ""}

---

## 🔍 发现的漏洞

{vuln_details}

---

## 💡 修复建议

{recommendations}

---

## 📚 参考资源

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CWE漏洞分类](https://cwe.mitre.org/)
- [PortSwigger Web安全学院](https://portswigger.net/web-security)

---

*报告由自动化漏洞挖掘系统生成*
"""
        return report

    def _get_remediation_details(self, vuln_type: str) -> str:
        """获取详细的修复方案（精简版）"""
        # 获取补天平台类型
        platform_type = self._get_vuln_type_for_platform(vuln_type)

        # 获取修复模板
        remediation = get_remediation(platform_type, vuln_type)

        # 构建修复方案文本
        result = f"**{remediation['title']}**\n\n"
        result += f"{remediation['description']}\n\n"

        # 添加具体代码示例（只显示第一个）
        if remediation.get('solutions'):
            first_lang = list(remediation['solutions'].keys())[0]
            first_code = remediation['solutions'][first_lang]
            result += f"**{first_lang.upper()} 代码示例**:\n"
            result += f"```{first_lang}\n{first_code}\n```\n\n"

            # 如果有其他语言，只列出
            if len(remediation['solutions']) > 1:
                other_langs = list(remediation['solutions'].keys())[1:]
                result += f"**其他语言**: {', '.join(other_langs)}\n\n"

        return result

    def _calculate_exploit_score(self, vuln: Dict) -> int:
        """计算可利用性评分 (0-100)"""
        score = 50  # 基础分

        # 根据漏洞类型调整
        vuln_type = vuln.get("type", "")
        if "SQL注入" in vuln_type:
            score += 30
        elif "命令注入" in vuln_type or "命令执行" in vuln_type:
            score += 30
        elif "文件包含" in vuln_type or "目录遍历" in vuln_type:
            score += 25
        elif "SSRF" in vuln_type:
            score += 25
        elif "XSS" in vuln_type:
            score += 20
        elif "未授权访问" in vuln_type:
            score += 20
        elif "信息泄露" in vuln_type:
            score += 10
        elif "配置错误" in vuln_type:
            score += 5

        # 根据证据调整
        evidence = vuln.get("evidence", "")
        if "password" in evidence.lower():
            score += 10
        if "token" in evidence.lower():
            score += 10
        if "secret" in evidence.lower():
            score += 10
        if "api_key" in evidence.lower():
            score += 10

        # 限制在 0-100 范围
        return min(max(score, 0), 100)

    def _get_exploit_level(self, score: int) -> str:
        """获取可利用性等级"""
        if score >= 80:
            return "🟢 高"
        elif score >= 60:
            return "🟡 中"
        elif score >= 40:
            return "🟠 低"
        else:
            return "🔴 极低"

    def _estimate_bounty(self, severity: str, vuln_type: str) -> str:
        """估算奖金范围"""
        # 基础奖金
        base_bounty = {
            "Critical": 3000,
            "High": 1000,
            "Medium": 500,
            "Low": 100,
            "Info": 0
        }.get(severity, 0)

        # 漏洞类型调整
        type_multiplier = 1.0
        if "SQL注入" in vuln_type:
            type_multiplier = 1.5
        elif "命令注入" in vuln_type:
            type_multiplier = 1.5
        elif "SSRF" in vuln_type:
            type_multiplier = 1.3
        elif "XSS" in vuln_type:
            type_multiplier = 1.2
        elif "未授权访问" in vuln_type:
            type_multiplier = 1.2
        elif "信息泄露" in vuln_type:
            type_multiplier = 0.8
        elif "配置错误" in vuln_type:
            type_multiplier = 0.6

        # 计算奖金范围
        min_bounty = int(base_bounty * type_multiplier * 0.5)
        max_bounty = int(base_bounty * type_multiplier * 1.5)

        if min_bounty == 0:
            return "无奖金"
        else:
            return f"¥{min_bounty} - ¥{max_bounty}"

    def _prioritize_vulns(self, vulns: List[Dict]) -> List[Dict]:
        """漏洞优先级排序"""
        # 计算每个漏洞的优先级分数
        for vuln in vulns:
            severity = vuln.get("severity", "Info")
            exploit_score = self._calculate_exploit_score(vuln)

            # 优先级分数 = 严重程度分数 + 可利用性分数
            severity_score = {
                "Critical": 100,
                "High": 80,
                "Medium": 60,
                "Low": 40,
                "Info": 20
            }.get(severity, 0)

            vuln["priority_score"] = severity_score + exploit_score

        # 按优先级分数排序
        return sorted(vulns, key=lambda x: x.get("priority_score", 0), reverse=True)

    def _get_priority(self, severity: str, exploit_score: int) -> str:
        """获取优先级"""
        # 计算优先级分数
        severity_score = {
            "Critical": 100,
            "High": 80,
            "Medium": 60,
            "Low": 40,
            "Info": 20
        }.get(severity, 0)

        total_score = severity_score + exploit_score

        # 返回优先级
        if total_score >= 150:
            return "🔴 立即修复"
        elif total_score >= 120:
            return "🟠 尽快修复"
        elif total_score >= 90:
            return "🟡 计划修复"
        elif total_score >= 60:
            return "🟢 低优先级"
        else:
            return "🔵 信息"

    def _generate_json(self, subdomains: set, alive_targets: List[Dict],
                       vulnerabilities: List[Dict]) -> Dict:
        """生成 JSON 格式报告"""
        severity_count = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
        for vuln in vulnerabilities:
            severity = vuln.get("severity", "Info")
            severity_count[severity] = severity_count.get(severity, 0) + 1

        return {
            "target": self.target,
            "scan_time": datetime.now().isoformat(),
            "statistics": {
                "subdomains_count": len(subdomains),
                "alive_targets_count": len(alive_targets),
                "vulnerabilities_count": len(vulnerabilities),
                "severity_distribution": severity_count
            },
            "subdomains": sorted(list(subdomains)),
            "alive_targets": alive_targets,
            "vulnerabilities": vulnerabilities
        }

    def _generate_recommendations(self, vulnerabilities: List[Dict]) -> str:
        """生成修复建议"""
        recommendations = []

        vuln_types = set(vuln.get("type", "") for vuln in vulnerabilities)

        if "SQL注入" in vuln_types:
            recommendations.append("""
**SQL注入防护**
1. 使用参数化查询（Prepared Statements）
2. 使用ORM框架
3. 输入验证和过滤
4. 最小权限原则配置数据库用户
5. 部署WAF（Web应用防火墙）
""")

        if "XSS" in vuln_types:
            recommendations.append("""
**XSS防护**
1. 对输出进行HTML编码
2. 使用CSP（内容安全策略）
3. 设置HttpOnly Cookie
4. 输入验证和过滤
5. 使用现代框架的自动转义功能
""")

        if "信息泄露" in vuln_types:
            recommendations.append("""
**信息泄露防护**
1. 删除页面中的敏感信息
2. 配置错误页面（自定义404、500）
3. 移除不必要的响应头
4. 关闭调试模式
5. 定期审查代码
""")

        if "敏感文件泄露" in vuln_types:
            recommendations.append("""
**敏感文件防护**
1. 删除不必要的文件
2. 配置访问控制
3. 使用.gitignore排除敏感文件
4. 部署时检查文件
5. 定期清理临时文件
""")

        if "CORS配置错误" in vuln_types:
            recommendations.append("""
**CORS配置修复**
1. 限制允许的域名白名单
2. 不要使用通配符 *
3. 谨慎使用 Allow-Credentials
4. 验证 Origin 头
5. 定期审查CORS配置
""")

        if "Clickjacking" in vuln_types:
            recommendations.append("""
**Clickjacking防护**
1. 设置 X-Frame-Options: DENY
2. 使用 CSP frame-ancestors 指令
3. 使用 frame-busting 脚本
4. 验证嵌入来源
""")

        if "开放重定向" in vuln_types:
            recommendations.append("""
**开放重定向防护**
1. 验证重定向目标白名单
2. 使用相对路径
3. 添加重定向确认页面
4. 记录重定向日志
""")

        if not recommendations:
            recommendations.append("""
**通用安全建议**
1. 定期更新依赖库
2. 实施最小权限原则
3. 启用安全响应头
4. 定期进行安全审计
5. 建立安全开发流程
6. 部署WAF和IDS
7. 实施日志监控
""")

        return "\n".join(recommendations)


def generate_report(target: str, subdomains: set, alive_targets: List[Dict],
                    vulnerabilities: List[Dict]) -> str:
    """便捷函数：生成报告"""
    generator = ReportGenerator(target)
    return generator.generate(subdomains, alive_targets, vulnerabilities)
