
# 🎯 自动化漏洞扫描报告

**目标**: lixiang.com
**扫描时间**: 2026-05-30 17:06:48
**扫描状态**: 完成

---

## 📊 扫描统计

| 项目 | 数量 |
|------|------|
| 子域名发现 | 1 |
| 存活目标 | 1 |
| 发现漏洞 | 1 |

### 漏洞严重程度分布

| 严重程度 | 数量 |
|----------|------|
| 🔴 Critical | 0 |
| 🟠 High | 0 |
| 🟡 Medium | 1 |
| 🟢 Low | 0 |
| 🔵 Info | 0 |

---

## 🌐 子域名列表

```
lixiang.com

```

---

## 🖥️ 存活目标

| URL | 状态码 | 服务器 | 标题 |
|-----|--------|--------|------|
| https://lixiang.com | 200 | nginx | 理想汽车丨理想，给车和家赋予生命。 |


---

## 🔍 发现的漏洞


### 1. 🟡 [Medium] Clickjacking

- **URL**: https://lixiang.com
- **描述**: 页面缺少 Clickjacking 防护
- **证据**: `未设置 X-Frame-Options 或 CSP frame-ancestors`
- **修复建议**: 添加 X-Frame-Options: DENY 或 CSP frame-ancestors 指令

---


---

## 💡 修复建议


**Clickjacking防护**
1. 设置 X-Frame-Options: DENY
2. 使用 CSP frame-ancestors 指令
3. 使用 frame-busting 脚本
4. 验证嵌入来源


---

## 📚 参考资源

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CWE漏洞分类](https://cwe.mitre.org/)
- [PortSwigger Web安全学院](https://portswigger.net/web-security)

---

*报告由自动化漏洞挖掘系统生成*
