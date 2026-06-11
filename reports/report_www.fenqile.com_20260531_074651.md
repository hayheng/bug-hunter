
# 🎯 自动化漏洞扫描报告

**目标**: www.fenqile.com
**扫描时间**: 2026-05-31 07:46:51
**扫描状态**: 完成

---

## 📊 扫描统计

| 项目 | 数量 |
|------|------|
| 子域名发现 | 1 |
| 存活目标 | 1 |
| 发现漏洞 | 4 |

### 漏洞危险等级分布

| 危险等级 | 数量 |
|----------|------|
| 🔴 严重 | 0 |
| 🟠 高危 | 1 |
| 🟡 中危 | 1 |
| 🟢 低危 | 2 |
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


### 1. 🟠 [高危] HTTP请求走私

#### 漏洞标题
分期乐存在配置错误

#### 漏洞类型
配置错误（补天平台分类）

#### 简要描述
发现安全漏洞，可能被攻击者利用进行恶意攻击。

#### 影响范围
1. 可能被攻击者利用
2. 存在安全风险
3. 需要评估具体影响

#### 详细细节

**测试/复现过程**:
1. 访问目标URL
2. 分析响应内容
3. 评估漏洞风险

**漏洞URL**: https://www.fenqile.com

**证据**:
```
服务器接受了Transfer-Encoding头
```

**PoC / Exploit**:
```html
# 请联系安全团队获取详细PoC
```

**使用的组件/工具**:
- Burp Suite: https://portswigger.net/burp
- 浏览器开发者工具

#### 修复建议

**HTTP请求走私漏洞修复**

正确处理Transfer-Encoding和Content-Length头

**NGINX 代码示例**:
```nginx

# Nginx 配置 - 禁用 Transfer-Encoding
# 添加到 http 块

# 禁用 Transfer-Encoding
proxy_http_version 1.1;
proxy_set_header Connection "";

# 或完全禁用 chunked 传输
chunked_transfer_encoding off;

# 使用 HTTP/2 (推荐)
# HTTP/2 不支持 Transfer-Encoding: chunked
listen 443 ssl http2;

```

**APACHE 代码示例**:
```apache

# Apache 配置
# 添加到 httpd.conf

# 禁用 Transfer-Encoding
TraceEnable off

# 使用 HTTP/2
Protocols h2 http/1.1

# 严格解析请求
HttpProtocolOptions Strict

```

**NODEJS 代码示例**:
```nodejs

// Node.js 配置
const http = require('http');

const server = http.createServer((req, res) => {
    // 验证请求头
    if (req.headers['transfer-encoding'] && req.headers['content-length']) {
        res.writeHead(400);
        res.end('Bad Request');
        return;
    }

    // 处理请求
    // ...
});

// 使用框架时的配置
// Express
app.use((req, res, next) => {
    if (req.headers['transfer-encoding'] && req.headers['content-length']) {
        return res.status(400).send('Bad Request');
    }
    next();
});

```



---

### 2. 🟡 [中危] Clickjacking

#### 漏洞标题
分期乐存在配置错误

#### 漏洞类型
配置错误（补天平台分类）

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

**Clickjacking（点击劫持）漏洞修复**

通过设置HTTP响应头防止页面被iframe嵌入

**NGINX 代码示例**:
```nginx

# Nginx 配置 - 添加到 server 或 location 块
add_header X-Frame-Options "DENY" always;
add_header Content-Security-Policy "frame-ancestors 'self'" always;

# 如果需要允许特定域名嵌入
# add_header X-Frame-Options "ALLOW-FROM https://trusted.com" always;
# add_header Content-Security-Policy "frame-ancestors 'self' https://trusted.com" always;

```

**APACHE 代码示例**:
```apache

# Apache 配置 - 添加到 .htaccess 或 httpd.conf
Header always set X-Frame-Options "DENY"
Header always set Content-Security-Policy "frame-ancestors 'self'"

# 如果需要允许特定域名嵌入
# Header always set X-Frame-Options "ALLOW-FROM https://trusted.com"
# Header always set Content-Security-Policy "frame-ancestors 'self' https://trusted.com"

```

**PHP 代码示例**:
```php

<?php
// PHP 代码 - 添加到公共入口文件或框架中间件
header('X-Frame-Options: DENY');
header("Content-Security-Policy: frame-ancestors 'self'");

// Laravel 框架 - 添加到 app/Http/Middleware/
// $response->header('X-Frame-Options', 'DENY');

// ThinkPHP 框架 - 添加到中间件
// header('X-Frame-Options: DENY');
?>

```

**NODEJS 代码示例**:
```nodejs

// Node.js/Express - 添加到中间件
app.use((req, res, next) => {
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Content-Security-Policy', "frame-ancestors 'self'");
    next();
});

// 或使用 helmet 中间件
const helmet = require('helmet');
app.use(helmet.frameguard({ action: 'deny' }));

```

**SPRING 代码示例**:
```spring

// Spring Boot - 添加到 SecurityConfig
@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.headers()
            .frameOptions().deny()
            .contentSecurityPolicy("frame-ancestors 'self'");
    }
}

// 或使用注解
@Configuration
@EnableWebSecurity
public class WebSecurityConfig {
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.headers(headers -> headers
            .frameOptions(HeadersConfigurer.FrameOptionsConfig::deny)
            .contentSecurityPolicy(csp -> csp.policyDirectives("frame-ancestors 'self'"))
        );
        return http.build();
    }
}

```

**DJANGO 代码示例**:
```django

# Django - 添加到 settings.py 或中间件

# 方法1: 中间件 (推荐)
# middleware.py
class SecurityHeadersMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        response['X-Frame-Options'] = 'DENY'
        response['Content-Security-Policy'] = "frame-ancestors 'self'"
        return response

# settings.py
MIDDLEWARE = [
    'path.to.SecurityHeadersMiddleware',
    # ...
]

# 方法2: 使用 django-csp
# pip install django-csp
CSP_FRAME_ANCESTORS = ("'self'",)

```



---

### 3. 🟢 [低危] 安全头缺失

#### 漏洞标题
分期乐存在配置错误

#### 漏洞类型
配置错误（补天平台分类）

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

**安全响应头配置**

添加安全响应头防止常见攻击

**NGINX 代码示例**:
```nginx

# Nginx 完整安全头配置
# 添加到 http, server 或 location 块

# 防止MIME类型嗅探
add_header X-Content-Type-Options "nosniff" always;

# 防止点击劫持
add_header X-Frame-Options "DENY" always;

# XSS防护
add_header X-XSS-Protection "1; mode=block" always;

# HSTS - 强制HTTPS
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;

# 内容安全策略
add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:;" always;

# 引用策略
add_header Referrer-Policy "strict-origin-when-cross-origin" always;

# 权限策略
add_header Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=()" always;

```

**APACHE 代码示例**:
```apache

# Apache 完整安全头配置
# 添加到 .htaccess 或 httpd.conf

Header always set X-Content-Type-Options "nosniff"
Header always set X-Frame-Options "DENY"
Header always set X-XSS-Protection "1; mode=block"
Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
Header always set Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'"
Header always set Referrer-Policy "strict-origin-when-cross-origin"
Header always set Permissions-Policy "camera=(), microphone=(), geolocation=()"

```

**NODEJS 代码示例**:
```nodejs

// Node.js/Express 完整安全头配置
const helmet = require('helmet');

// 使用 helmet (推荐)
app.use(helmet());

// 或手动设置
app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    res.setHeader('Content-Security-Policy', "default-src 'self'");
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
    next();
});

```



---

### 4. 🟢 [低危] 配置错误

#### 漏洞标题
分期乐存在其他

#### 漏洞类型
其他（补天平台分类）

#### 简要描述
发现安全漏洞，可能被攻击者利用进行恶意攻击。

#### 影响范围
1. 可能被攻击者利用
2. 存在安全风险
3. 需要评估具体影响

#### 详细细节

**测试/复现过程**:
1. 访问目标URL
2. 分析响应内容
3. 评估漏洞风险

**漏洞URL**: https://www.fenqile.com

**证据**:
```
缺少: X-Frame-Options, X-Content-Type-Options, X-XSS-Protection, Content-Security-Policy, Strict-Transport-Security
```

**PoC / Exploit**:
```html
# 请联系安全团队获取详细PoC
```

**使用的组件/工具**:
- Burp Suite: https://portswigger.net/burp
- 浏览器开发者工具

#### 修复建议

**其他漏洞修复**

请联系安全团队获取具体修复方案



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
