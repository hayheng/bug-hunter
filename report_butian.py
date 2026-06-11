# -*- coding: utf-8 -*-
"""
补天平台专用报告生成器
"""

import json
from datetime import datetime
from typing import List, Dict
from pathlib import Path
from urllib.parse import urlparse
from butian_rules import (
    BUTIAN_VULN_TYPES,
    get_vuln_template,
    format_vuln_title,
    format_vuln_description,
    check_vuln_quality,
    SEVERITY_STANDARDS,
)


class ButianReportGenerator:
    """补天平台报告生成器"""

    def __init__(self, vendor: str):
        self.vendor = vendor
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    def generate_single_report(self, vuln: Dict) -> str:
        """生成单个漏洞报告（用于提交）"""
        vuln_type = vuln.get("type", "")
        url = vuln.get("url", "")
        evidence = vuln.get("evidence", "")
        severity = vuln.get("severity", "")

        # 获取漏洞模板
        template = get_vuln_template(vuln_type)

        # 格式化标题
        title = format_vuln_title(vuln_type, self.vendor)

        # 格式化描述
        description = format_vuln_description(
            vuln_type,
            vendor=self.vendor,
            url=url,
            parameter=vuln.get("parameter", "未知"),
            injection_type=vuln.get("injection_type", "未知"),
            payload=vuln.get("payload", "未知"),
            database_info=vuln.get("database_info", "未知"),
            type=vuln.get("xss_type", "反射型"),
            browser_info=vuln.get("browser_info", "Chrome 最新版"),
            leak_type=vuln.get("leak_type", "敏感信息"),
            leaked_data=evidence[:500] if evidence else "未知",
            path=urlparse(url).path if url else "/",
            access_content=evidence[:500] if evidence else "未知",
            command_result=vuln.get("command_result", "未知"),
            internal_access=vuln.get("internal_access", "未知"),
            logic_type=vuln.get("logic_type", "业务逻辑"),
            description=vuln.get("description", ""),
            impact=vuln.get("impact", ""),
            config_type=vuln.get("config_type", "安全配置"),
            remediation=vuln.get("remediation", ""),
        )

        # 生成报告
        report = f"""# 漏洞提交报告

## 漏洞标题
{title}

## 漏洞类型
{vuln_type}

## 漏洞等级
{severity}

## 漏洞URL
{url}

{description}

## 证据
```
{evidence[:500]}
```

## 提交时间
{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

---
*由自动化漏洞挖掘系统生成*
"""
        return report

    def generate_batch_report(self, vulns: List[Dict]) -> str:
        """生成批量报告"""
        # 过滤高质量漏洞
        high_quality_vulns = []
        for vuln in vulns:
            is_valid, issues = check_vuln_quality(vuln)
            if is_valid:
                high_quality_vulns.append(vuln)

        # 按严重程度排序
        severity_order = {"严重": 0, "高危": 1, "中危": 2, "低危": 3}
        high_quality_vulns.sort(
            key=lambda x: severity_order.get(x.get("severity", "低危"), 4)
        )

        # 生成报告
        report = f"""# 补天平台漏洞提交报告

## 厂商信息
- **厂商名称**: {self.vendor}
- **扫描时间**: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
- **漏洞总数**: {len(high_quality_vulns)}

## 漏洞列表

"""

        for i, vuln in enumerate(high_quality_vulns, 1):
            vuln_type = vuln.get("type", "")
            severity = vuln.get("severity", "")
            url = vuln.get("url", "")

            report += f"""### {i}. 【{vuln_type}】{severity}

- **URL**: {url}
- **类型**: {vuln_type}
- **等级**: {severity}

---

"""

        # 添加提交建议
        report += """
## 提交建议

### 优先提交
1. 严重漏洞（RCE、SQL注入）
2. 高危漏洞（未授权访问、SSRF）
3. 中危漏洞（信息泄露、逻辑漏洞）

### 注意事项
1. 每个漏洞单独提交
2. 提供详细的复现步骤
3. 附上截图证据
4. 敏感信息需脱敏

### 提交顺序
1. 先提交严重和高危漏洞
2. 再提交中危漏洞
3. 低危漏洞可选提交

---
*由自动化漏洞挖掘系统生成*
"""
        return report

    def generate_submission_guide(self, vulns: List[Dict]) -> str:
        """生成提交指南"""
        guide = f"""# 补天平台提交指南

## 厂商: {self.vendor}

### 漏洞提交步骤

1. **登录补天平台**
   - 访问 https://butian.360.cn
   - 登录账号

2. **选择漏洞类型**
   - 点击"提交漏洞"
   - 选择漏洞类型

3. **填写漏洞信息**
   - 按照报告格式填写
   - 上传截图证据

4. **等待审核**
   - 审核时间：1-3 个工作日
   - 可在"我的漏洞"中查看状态

### 提交模板

"""

        for i, vuln in enumerate(vulns[:5], 1):  # 只显示前5个
            vuln_type = vuln.get("type", "")
            template = get_vuln_template(vuln_type)

            guide += f"""#### 漏洞 {i}: {vuln_type}

**标题**: {format_vuln_title(vuln_type, self.vendor)}

**类型**: {vuln_type}

**等级**: {template.get('severity', '中危')}

**URL**: {vuln.get('url', '')}

**描述**:
{vuln.get('description', '')}

**证据**:
{vuln.get('evidence', '')[:200]}

---

"""

        guide += """
### 常见拒绝原因

1. **漏洞不实际** - 无法证明可利用
2. **重复提交** - 已有人提交
3. **描述不清** - 缺少复现步骤
4. **证据不足** - 缺少截图

### 提高通过率

1. **详细描述** - 复现步骤清晰
2. **截图证据** - 关键步骤有截图
3. **影响范围** - 说明危害程度
4. **首次发现** - 确保非重复

---
*由自动化漏洞挖掘系统生成*
"""
        return guide


def generate_butian_report(vendor: str, vulns: List[Dict], output_dir: str = None) -> Dict[str, str]:
    """生成补天平台报告"""
    generator = ButianReportGenerator(vendor)

    if output_dir is None:
        output_dir = Path(__file__).parent / "reports"
    else:
        output_dir = Path(output_dir)

    output_dir.mkdir(exist_ok=True)

    # 生成批量报告
    batch_report = generator.generate_batch_report(vulns)
    batch_file = output_dir / f"butian_batch_{vendor}_{generator.timestamp}.md"
    batch_file.write_text(batch_report, encoding="utf-8")

    # 生成提交指南
    guide = generator.generate_submission_guide(vulns)
    guide_file = output_dir / f"butian_guide_{vendor}_{generator.timestamp}.md"
    guide_file.write_text(guide, encoding="utf-8")

    # 生成单个漏洞报告
    single_reports = []
    for i, vuln in enumerate(vulns, 1):
        single_report = generator.generate_single_report(vuln)
        single_file = output_dir / f"butian_single_{vendor}_{i}_{generator.timestamp}.md"
        single_file.write_text(single_report, encoding="utf-8")
        single_reports.append(str(single_file))

    return {
        "batch_report": str(batch_file),
        "guide": str(guide_file),
        "single_reports": single_reports,
    }


if __name__ == "__main__":
    # 测试
    test_vulns = [
        {
            "type": "信息泄露",
            "severity": "中危",
            "url": "https://example.com/.env",
            "description": "环境文件泄露",
            "evidence": "DB_PASSWORD=xxx",
        },
        {
            "type": "Clickjacking",
            "severity": "低危",
            "url": "https://example.com",
            "description": "Clickjacking漏洞",
            "evidence": "未设置X-Frame-Options",
        },
    ]

    result = generate_butian_report("示例厂商", test_vulns)
    print(f"批量报告: {result['batch_report']}")
    print(f"提交指南: {result['guide']}")
