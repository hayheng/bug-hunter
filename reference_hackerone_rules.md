---
name: reference-hackerone-rules
description: HackerOne 漏洞提交规则和报告模板
metadata: 
  node_type: memory
  type: reference
  originSessionId: 0ab2350a-34f3-44f9-8e03-41ec7bc24dab
---

# HackerOne 漏洞提交规则

## 官方资源
- **Hacktivity**: https://hackerone.com/hacktivity
- **文档**: https://docs.hackerone.com
- **CVSS计算器**: https://www.first.org/cvss/calculator/3.1

## 报告结构

### 1. 标题 (Title)
- 清晰、简洁、描述性
- 示例: "Stored XSS via Profile Bio Field allows Account Takeover"

### 2. 摘要 (Summary)
- 简要描述漏洞
- 说明影响范围
- 指出受影响的资产

### 3. 严重程度 (Severity)
- 使用 CVSS v3.1 评分
- Critical (9.0-10.0): RCE、认证绕过
- High (7.0-8.9): 存储型XSS、SQL注入、权限提升
- Medium (4.0-6.9): CSRF、反射型XSS、信息泄露
- Low (0.1-3.9): 小问题、版本泄露

### 4. 复现步骤 (Steps to Reproduce)
- 编号、详细步骤
- 包含环境信息（浏览器、OS、版本）
- 任何人可以复现

### 5. 影响 (Impact)
- 说明攻击者能做什么
- 业务影响而非仅技术影响
- 示例: 账户接管、数据泄露

### 6. 概念验证 (PoC)
- 截图
- 视频
- 代码片段
- HTTP请求/响应

### 7. 修复建议 (Remediation)
- 可选但推荐
- 提供具体修复方案

### 8. 参考 (References)
- CVE
- OWASP链接
- 相关研究

## CVSS v3.1 评分要素

| 要素 | 值 |
|------|-----|
| Attack Vector | Network/Adjacent/Local/Physical |
| Attack Complexity | Low/High |
| Privileges Required | None/Low/High |
| User Interaction | None/Required |
| Scope | Changed/Unchanged |
| Confidentiality | None/Low/High |
| Integrity | None/Low/High |
| Availability | None/Low/High |

## 提交注意事项

1. **遵守范围** - 只测试授权目标
2. **不要破坏** - 不要进行破坏性测试
3. **一个报告一个漏洞** - 不要混合多个漏洞
4. **不要公开** - 修复前不要公开披露
5. **检查重复** - 提交前检查是否已有类似报告

## 高质量报告技巧

1. **具体** - 包含确切的URL、参数、payload
2. **可复现** - 任何人可以复现
3. **证明影响** - 展示实际利用，而非理论风险
4. **专业** - 尊重、专业
5. **不要夸大** - 诚实评估严重程度

## 常见漏洞类型

| 类型 | CWE | 严重程度 |
|------|-----|----------|
| SQL注入 | CWE-89 | High-Critical |
| XSS | CWE-79 | Medium-High |
| SSRF | CWE-918 | High |
| IDOR | CWE-639 | High |
| RCE | CWE-94 | Critical |
| 认证绕过 | CWE-287 | Critical |
| 信息泄露 | CWE-200 | Low-Medium |

## 相关文件
- [[project_bug_hunter]] - 自动化漏洞挖掘项目
- [[reference_butian_rules]] - 补天平台规则
