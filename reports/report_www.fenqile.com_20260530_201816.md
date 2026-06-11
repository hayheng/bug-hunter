
# 🎯 自动化漏洞扫描报告

**目标**: www.fenqile.com
**扫描时间**: 2026-05-30 20:18:16
**扫描状态**: 完成

---

## 📊 扫描统计

| 项目 | 数量 |
|------|------|
| 子域名发现 | 1 |
| 存活目标 | 1 |
| 发现漏洞 | 2 |

### 漏洞危险等级分布

| 危险等级 | 数量 |
|----------|------|
| 🔴 严重 | 0 |
| 🟠 高危 | 0 |
| 🟡 中危 | 1 |
| 🟢 低危 | 1 |
| 🔵 信息 | 0 |

---

## 🌐 子域名列表

```
www.fenqile.com

```

---

## 🖥️ 存活目标

| URL | 状态码 | 服务器 | 标题 |
|-----|--------|--------|------|
| https://www.fenqile.com |  |  |  |


---

## 🔍 发现的漏洞


### 1. 🟡 [中危] Clickjacking

#### 漏洞标题
分期乐存在Clickjacking漏洞

#### 漏洞类型
Clickjacking

#### 简要描述
网站缺少 Clickjacking（点击劫持）防护，攻击者可通过 iframe 嵌入目标页面，诱导用户点击隐藏按钮，执行非预期操作。

#### 影响范围
1. 诱导用户执行非预期操作（关注、点赞、授权等）
2. 结合社会工程学进行钓鱼攻击
3. 窃取用户敏感信息
4. 损害品牌形象和用户信任

#### 详细细节

**测试/复现过程**:
1. 创建测试HTML页面，使用iframe嵌入目标网站
2. 设置iframe透明或半透明
3. 在iframe上方放置诱导按钮
4. 用户点击诱导按钮时，实际点击的是目标网站的功能

**漏洞URL**: https://www.fenqile.com

**证据**:
```
未设置 X-Frame-Options 或 CSP frame-ancestors
```

**PoC / Exploit**:
```html
<!DOCTYPE html>
<html>
<head>
    <title>Clickjacking PoC</title>
    <style>
        iframe {
            width: 800px;
            height: 600px;
            opacity: 0.5;  <!-- 半透明显示，测试时可调整为0 -->
            position: absolute;
            top: 0;
            left: 0;
        }
        .decoy {
            position: relative;
            z-index: -1;
            padding: 20px;
            font-size: 24px;
        }
    </style>
</head>
<body>
    <h1>点击下方按钮领取奖励</h1>
    <button class="decoy">🎁 领取优惠券</button>
    <iframe src="https://www.fenqile.com"></iframe>
</body>
</html>
```

**使用的组件/工具**:
- 浏览器 (Chrome/Firefox)
- 文本编辑器
- Burp Suite: https://portswigger.net/burp

#### 修复建议
**修复方案**:

1. **Nginx 配置**
```nginx
# 添加 X-Frame-Options 响应头
add_header X-Frame-Options "DENY" always;

# 添加 CSP frame-ancestors
add_header Content-Security-Policy "frame-ancestors 'self'" always;
```

2. **Apache 配置**
```apache
# 添加响应头
Header always set X-Frame-Options "DENY"
Header always set Content-Security-Policy "frame-ancestors 'self'"
```

3. **PHP 代码**
```php
<?php
header('X-Frame-Options: DENY');
header("Content-Security-Policy: frame-ancestors 'self'");
?>
```

4. **Node.js/Express**
```javascript
app.use((req, res, next) => {
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Content-Security-Policy', "frame-ancestors 'self'");
    next();
});
```

5. **Spring Boot**
```java
@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.headers()
            .frameOptions().deny()
            .contentSecurityPolicy("frame-ancestors 'self'");
    }
}
```

---

### 2. 🟢 [低危] 安全头缺失

#### 漏洞标题
分期乐存在安全配置缺陷

#### 漏洞类型
安全头缺失

#### 简要描述
网站缺少关键的安全响应头，可能导致多种客户端攻击，如XSS、Clickjacking、MIME类型嗅探攻击等。

#### 影响范围
1. 增加XSS攻击风险
2. 增加Clickjacking攻击风险
3. MIME类型嗅探攻击
4. 信息泄露
5. 降低整体安全防护水平

#### 详细细节

**测试/复现过程**:
1. 使用curl或浏览器开发者工具查看响应头
2. 检查是否包含安全响应头
3. 评估缺失的安全头可能带来的风险

**漏洞URL**: https://www.fenqile.com

**证据**:
```
缺失: X-Content-Type-Options, X-Frame-Options, X-XSS-Protection, Strict-Transport-Security, Content-Security-Policy, Referrer-Policy
```

**PoC / Exploit**:
```html
# 使用 curl 检查响应头
curl -I https://www.fenqile.com -v

# 使用 Python 检查
import requests
resp = requests.head("https://www.fenqile.com")
headers = resp.headers

security_headers = [
    "X-Content-Type-Options",
    "X-Frame-Options",
    "X-XSS-Protection",
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "Referrer-Policy"
]

for header in security_headers:
    if header in headers:
        print(f"[存在] {header}: {headers[header]}")
    else:
        print(f"[缺失] {header}")

# 使用浏览器开发者工具
# 1. 按 F12 打开开发者工具
# 2. 切换到 Network 标签
# 3. 刷新页面
# 4. 点击请求，查看响应头
```

**使用的组件/工具**:
- curl: https://curl.se/download.html
- 浏览器开发者工具 (F12)
- Python + requests库
- SecurityHeaders.com: https://securityheaders.com/

#### 修复建议
**修复方案**:

1. **Nginx 完整安全头配置**
```nginx
# 安全响应头
add_header X-Content-Type-Options "nosniff" always;
add_header X-Frame-Options "DENY" always;
add_header X-XSS-Protection "1; mode=block" always;
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'" always;
add_header Referrer-Policy "no-referrer-when-downgrade" always;
add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;
```

2. **Apache 完整安全头配置**
```apache
# 安全响应头
Header always set X-Content-Type-Options "nosniff"
Header always set X-Frame-Options "DENY"
Header always set X-XSS-Protection "1; mode=block"
Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
Header always set Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'"
Header always set Referrer-Policy "no-referrer-when-downgrade"
Header always set Permissions-Policy "camera=(), microphone=(), geolocation=()"
```

3. **PHP 代码**
```php
<?php
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('X-XSS-Protection: 1; mode=block');
header('Strict-Transport-Security: max-age=31536000; includeSubDomains');
header("Content-Security-Policy: default-src 'self'");
header('Referrer-Policy: no-referrer-when-downgrade');
?>
```

4. **Node.js/Express**
```javascript
app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    res.setHeader('Content-Security-Policy', "default-src 'self'");
    res.setHeader('Referrer-Policy', 'no-referrer-when-downgrade');
    next();
});
```

5. **使用 helmet 中间件 (Node.js)**
```javascript
const helmet = require('helmet');
app.use(helmet());
```

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
