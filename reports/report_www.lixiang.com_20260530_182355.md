
# 🎯 自动化漏洞扫描报告

**目标**: www.lixiang.com
**扫描时间**: 2026-05-30 18:23:55
**扫描状态**: 完成

---

## 📊 扫描统计

| 项目 | 数量 |
|------|------|
| 子域名发现 | 1 |
| 存活目标 | 1 |
| 发现漏洞 | 8 |

### 漏洞危险等级分布

| 危险等级 | 数量 |
|----------|------|
| 🔴 严重 | 0 |
| 🟠 高危 | 0 |
| 🟡 中危 | 5 |
| 🟢 低危 | 3 |
| 🔵 信息 | 0 |

---

## 🌐 子域名列表

```
www.lixiang.com

```

---

## 🖥️ 存活目标

| URL | 状态码 | 服务器 | 标题 |
|-----|--------|--------|------|
| https://www.lixiang.com |  |  |  |


---

## 🔍 发现的漏洞


### 1. 🟡 [中危] 敏感文件泄露

#### 漏洞标题
理想汽车存在敏感文件泄露

#### 漏洞类型
敏感文件泄露

#### 简要描述
网站存在敏感文件泄露，攻击者可获取网站配置信息、目录结构等敏感数据，为进一步攻击提供信息支持。

#### 影响范围
1. 泄露网站技术架构和配置信息
2. 暴露敏感目录和文件路径
3. 可能包含数据库连接信息、API密钥等
4. 为后续攻击提供信息收集基础

#### 详细细节

**测试/复现过程**:
1. 使用浏览器或curl访问目标URL
2. 确认返回内容为敏感文件内容
3. 分析泄露信息的敏感程度

**漏洞URL**: https://www.lixiang.com/sitemap.xml

**证据**:
```
<?xml version="1.0" encoding="UTF-8"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9" xmlns:news="http://www.google.com/schemas/sitemap-news/0.9" xmlns:xhtml="http://www.w3.org/1999/xhtml"
```

**PoC / Exploit**:
```html
# 使用 curl 验证
curl -v https://www.lixiang.com/sitemap.xml

# 使用 Python 验证
import requests
resp = requests.get("https://www.lixiang.com/sitemap.xml")
print(resp.text)

# 使用浏览器直接访问
# 访问: https://www.lixiang.com/sitemap.xml
```

**使用的组件/工具**:
- curl: https://curl.se/download.html
- Burp Suite: https://portswigger.net/burp
- 浏览器开发者工具 (F12)

#### 修复建议
**修复方案**:

1. **删除敏感文件**
```bash
# 删除不必要的文件
rm -f .env .git/config .htaccess
```

2. **Nginx 配置**
```nginx
# 禁止访问敏感文件
location ~ /\. {
    deny all;
}

location ~* \.(env|git|svn|htaccess|htpasswd)$ {
    deny all;
}

location ~ ^/(robots\.txt|sitemap\.xml)$ {
    allow all;
}
```

3. **Apache 配置**
```apache
# .htaccess 禁止访问敏感文件
<FilesMatch "\.(env|git|svn|htaccess|htpasswd)$">
    Order allow,deny
    Deny from all
</FilesMatch>
```

4. **添加 .gitignore**
```
.env
.git
.htaccess
config.php
```

---

### 2. 🟡 [中危] 敏感文件泄露

#### 漏洞标题
理想汽车存在敏感文件泄露

#### 漏洞类型
敏感文件泄露

#### 简要描述
网站存在敏感文件泄露，攻击者可获取网站配置信息、目录结构等敏感数据，为进一步攻击提供信息支持。

#### 影响范围
1. 泄露网站技术架构和配置信息
2. 暴露敏感目录和文件路径
3. 可能包含数据库连接信息、API密钥等
4. 为后续攻击提供信息收集基础

#### 详细细节

**测试/复现过程**:
1. 使用浏览器或curl访问目标URL
2. 确认返回内容为敏感文件内容
3. 分析泄露信息的敏感程度

**漏洞URL**: https://www.lixiang.com/robots.txt

**证据**:
```
User-agent:*
    Disallow:/?*
    Disallow: /*?*
    Sitemap:http://www.lixiang.com/sitemap.xml
```

**PoC / Exploit**:
```html
# 使用 curl 验证
curl -v https://www.lixiang.com/robots.txt

# 使用 Python 验证
import requests
resp = requests.get("https://www.lixiang.com/robots.txt")
print(resp.text)

# 使用浏览器直接访问
# 访问: https://www.lixiang.com/robots.txt
```

**使用的组件/工具**:
- curl: https://curl.se/download.html
- Burp Suite: https://portswigger.net/burp
- 浏览器开发者工具 (F12)

#### 修复建议
**修复方案**:

1. **删除敏感文件**
```bash
# 删除不必要的文件
rm -f .env .git/config .htaccess
```

2. **Nginx 配置**
```nginx
# 禁止访问敏感文件
location ~ /\. {
    deny all;
}

location ~* \.(env|git|svn|htaccess|htpasswd)$ {
    deny all;
}

location ~ ^/(robots\.txt|sitemap\.xml)$ {
    allow all;
}
```

3. **Apache 配置**
```apache
# .htaccess 禁止访问敏感文件
<FilesMatch "\.(env|git|svn|htaccess|htpasswd)$">
    Order allow,deny
    Deny from all
</FilesMatch>
```

4. **添加 .gitignore**
```
.env
.git
.htaccess
config.php
```

---

### 3. 🟡 [中危] Clickjacking

#### 漏洞标题
理想汽车存在Clickjacking漏洞

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

**漏洞URL**: https://www.lixiang.com

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
    <iframe src="https://www.lixiang.com"></iframe>
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

### 4. 🟡 [中危] PUT方法启用

#### 漏洞标题
理想汽车存在HTTP方法配置不当

#### 漏洞类型
PUT方法启用

#### 简要描述
服务器启用PUT HTTP方法，攻击者可能利用该方法上传恶意文件，获取服务器控制权限。

#### 影响范围
1. 可能上传恶意文件（WebShell）
2. 覆盖现有文件
3. 获取服务器控制权限
4. 数据泄露或篡改

#### 详细细节

**测试/复现过程**:
1. 使用OPTIONS方法确认PUT方法可用
2. 尝试使用PUT方法上传测试文件
3. 验证文件是否成功上传
4. 评估上传文件的执行权限

**漏洞URL**: https://www.lixiang.com

**证据**:
```
PUT返回200
```

**PoC / Exploit**:
```html
# 使用 curl 测试 PUT 方法
curl -X OPTIONS https://www.lixiang.com -v

# 尝试上传文件
curl -X PUT https://www.lixiang.com/test.txt -d "test content" -v

# 使用 Python 测试
import requests

# 测试 OPTIONS
resp = requests.options("https://www.lixiang.com")
print("Allow:", resp.headers.get("Allow"))

# 测试 PUT
resp = requests.put("https://www.lixiang.com/test.txt", data="test content")
print("Status:", resp.status_code)

# 使用 Burp Suite
# 1. 拦截请求
# 2. 修改方法为 PUT
# 3. 添加请求体
# 4. 发送请求
```

**使用的组件/工具**:
- curl: https://curl.se/download.html
- Burp Suite: https://portswigger.net/burp
- Python + requests库
- Postman: https://www.postman.com/downloads/

#### 修复建议
**修复方案**:

1. **Nginx 配置**
```nginx
# 只允许 GET、POST 方法
if ($request_method !~ ^(GET|POST|HEAD)$) {
    return 405;
}
```

2. **Apache 配置**
```apache
# 只允许 GET、POST 方法
<LimitExcept GET POST HEAD>
    Order allow,deny
    Deny from all
</LimitExcept>
```

3. **PHP 配置**
```php
<?php
// 检查请求方法
$allowed_methods = ['GET', 'POST', 'HEAD'];
if (!in_array($_SERVER['REQUEST_METHOD'], $allowed_methods)) {
    http_response_code(405);
    exit('Method Not Allowed');
}
?>
```

4. **Node.js/Express**
```javascript
const allowedMethods = ['GET', 'POST', 'HEAD'];
app.use((req, res, next) => {
    if (!allowedMethods.includes(req.method)) {
        return res.status(405).send('Method Not Allowed');
    }
    next();
});
```

---

### 5. 🟡 [中危] 信息泄露

#### 漏洞标题
理想汽车存在信息泄露

#### 漏洞类型
信息泄露

#### 简要描述
网站页面中泄露敏感信息，如邮箱地址、内部IP地址、HTML注释中的敏感内容等，攻击者可利用这些信息进行社会工程学攻击或进一步渗透。

#### 影响范围
1. 泄露内部人员联系方式，便于社会工程学攻击
2. 暴露内部网络架构
3. HTML注释可能包含开发信息、测试账号等
4. 为攻击者提供目标信息

#### 详细细节

**测试/复现过程**:
1. 访问目标页面
2. 查看页面源代码
3. 搜索邮箱、IP、注释等敏感信息
4. 分析泄露信息的利用价值

**漏洞URL**: https://www.lixiang.com

**证据**:
```
press@lixiang.com, press@lixiang.com, press@lixiang.com, press@lixiang.com
```

**PoC / Exploit**:
```html
# 使用 Python 提取邮箱
import requests
import re

resp = requests.get("https://www.lixiang.com")
emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', resp.text)
print("发现邮箱:", emails)

# 提取内网IP
ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', resp.text)
private_ips = [ip for ip in ips if ip.startswith(('10.', '172.', '192.168.'))]
print("内网IP:", private_ips)

# 提取HTML注释
comments = re.findall(r'<!--(.*?)-->', resp.text, re.DOTALL)
print("HTML注释:", comments)

# 使用浏览器开发者工具
# 1. 按 F12 打开开发者工具
# 2. 使用 Ctrl+F 搜索 @, password, secret 等关键词
```

**使用的组件/工具**:
- 浏览器开发者工具 (F12)
- Burp Suite: https://portswigger.net/burp
- Python + requests库
- grep/正则表达式工具

#### 修复建议
**修复方案**:

1. **删除页面敏感信息**
```html
<!-- 删除HTML注释中的敏感内容 -->
<!-- 错误示例: <!-- TODO: fix password=123456 --> -->
<!-- 正确做法: 部署前删除所有注释 -->
```

2. **Nginx 配置隐藏响应头**
```nginx
# 隐藏服务器版本
server_tokens off;

# 隐藏 X-Powered-By
proxy_hide_header X-Powered-By;
```

3. **Apache 配置**
```apache
# 隐藏服务器版本
ServerTokens Prod
ServerSignature Off

# 隐藏 X-Powered-By
Header always unset X-Powered-By
```

4. **PHP 配置**
```ini
; php.ini
expose_php = Off
display_errors = Off
```

5. **自定义错误页面**
```nginx
# Nginx 自定义错误页
error_page 404 /custom_404.html;
error_page 500 502 503 504 /custom_50x.html;
```

---

### 6. 🟢 [低危] 安全头缺失

#### 漏洞标题
理想汽车存在安全配置缺陷

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

**漏洞URL**: https://www.lixiang.com

**证据**:
```
缺失: X-Frame-Options, Content-Security-Policy, Referrer-Policy
```

**PoC / Exploit**:
```html
# 使用 curl 检查响应头
curl -I https://www.lixiang.com -v

# 使用 Python 检查
import requests
resp = requests.head("https://www.lixiang.com")
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

### 7. 🟢 [低危] Nuclei-weak-cipher-suites

#### 漏洞标题
理想汽车存在weak-cipher-suites

#### 漏洞类型
Nuclei-weak-cipher-suites

#### 简要描述
服务器使用弱加密套件，攻击者可能利用加密弱点破解加密通信，窃取敏感数据。

#### 影响范围
1. 加密通信可能被破解
2. 中间人攻击风险
3. 敏感数据泄露
4. 不符合安全合规要求

#### 详细细节

**测试/复现过程**:
1. 使用SSL/TLS检测工具扫描
2. 检查支持的加密套件
3. 识别弱加密算法
4. 评估风险等级

**漏洞URL**: www.lixiang.com

**证据**:
```
A weak cipher is defined as an encryption/decryption algorithm that uses a key of insufficient length. Using an insufficient length for a key in an encryption/decryption algorithm opens up the possibility (or probability) that the encryption scheme could be broken.
```

**PoC / Exploit**:
```html
# 使用 openssl 检测
openssl s_client -connect www.lixiang.com:443 -cipher 'LOW:EXP'

# 使用 nmap 检测
nmap --script ssl-enum-ciphers -p 443 www.lixiang.com

# 使用 testssl.sh 检测
./testssl.sh www.lixiang.com

# 在线检测
# https://www.ssllabs.com/ssltest/
```

**使用的组件/工具**:
- openssl: https://www.openssl.org/
- nmap: https://nmap.org/download.html
- testssl.sh: https://testssl.sh/
- SSL Labs: https://www.ssllabs.com/ssltest/

#### 修复建议
**修复方案**:

1. **Nginx SSL 配置**
```nginx
# 只允许 TLS 1.2 和 1.3
ssl_protocols TLSv1.2 TLSv1.3;

# 使用强加密套件
ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384';

# 优先使用服务器加密套件
ssl_prefer_server_ciphers on;

# 启用 HSTS
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

# OCSP Stapling
ssl_stapling on;
ssl_stapling_verify on;

# DH 参数
ssl_dhparam /etc/nginx/dhparam.pem;
```

2. **Apache SSL 配置**
```apache
# 只允许 TLS 1.2 和 1.3
SSLProtocol -all +TLSv1.2 +TLSv1.3

# 使用强加密套件
SSLCipherSuite ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384

# 优先使用服务器加密套件
SSLHonorCipherOrder on

# 启用 HSTS
Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
```

3. **生成强 DH 参数**
```bash
openssl dhparam -out /etc/nginx/dhparam.pem 2048
```

4. **在线检测**
- https://www.ssllabs.com/ssltest/
- https://testssl.sh/

5. **参考配置生成器**
- https://ssl-config.mozilla.org/
- https://cipherlist.eu/

---

### 8. 🟢 [低危] Nuclei-weak-cipher-suites

#### 漏洞标题
理想汽车存在weak-cipher-suites

#### 漏洞类型
Nuclei-weak-cipher-suites

#### 简要描述
服务器使用弱加密套件，攻击者可能利用加密弱点破解加密通信，窃取敏感数据。

#### 影响范围
1. 加密通信可能被破解
2. 中间人攻击风险
3. 敏感数据泄露
4. 不符合安全合规要求

#### 详细细节

**测试/复现过程**:
1. 使用SSL/TLS检测工具扫描
2. 检查支持的加密套件
3. 识别弱加密算法
4. 评估风险等级

**漏洞URL**: www.lixiang.com

**证据**:
```
A weak cipher is defined as an encryption/decryption algorithm that uses a key of insufficient length. Using an insufficient length for a key in an encryption/decryption algorithm opens up the possibility (or probability) that the encryption scheme could be broken.
```

**PoC / Exploit**:
```html
# 使用 openssl 检测
openssl s_client -connect www.lixiang.com:443 -cipher 'LOW:EXP'

# 使用 nmap 检测
nmap --script ssl-enum-ciphers -p 443 www.lixiang.com

# 使用 testssl.sh 检测
./testssl.sh www.lixiang.com

# 在线检测
# https://www.ssllabs.com/ssltest/
```

**使用的组件/工具**:
- openssl: https://www.openssl.org/
- nmap: https://nmap.org/download.html
- testssl.sh: https://testssl.sh/
- SSL Labs: https://www.ssllabs.com/ssltest/

#### 修复建议
**修复方案**:

1. **Nginx SSL 配置**
```nginx
# 只允许 TLS 1.2 和 1.3
ssl_protocols TLSv1.2 TLSv1.3;

# 使用强加密套件
ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384';

# 优先使用服务器加密套件
ssl_prefer_server_ciphers on;

# 启用 HSTS
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

# OCSP Stapling
ssl_stapling on;
ssl_stapling_verify on;

# DH 参数
ssl_dhparam /etc/nginx/dhparam.pem;
```

2. **Apache SSL 配置**
```apache
# 只允许 TLS 1.2 和 1.3
SSLProtocol -all +TLSv1.2 +TLSv1.3

# 使用强加密套件
SSLCipherSuite ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384

# 优先使用服务器加密套件
SSLHonorCipherOrder on

# 启用 HSTS
Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
```

3. **生成强 DH 参数**
```bash
openssl dhparam -out /etc/nginx/dhparam.pem 2048
```

4. **在线检测**
- https://www.ssllabs.com/ssltest/
- https://testssl.sh/

5. **参考配置生成器**
- https://ssl-config.mozilla.org/
- https://cipherlist.eu/

---


---

## 💡 修复建议


**信息泄露防护**
1. 删除页面中的敏感信息
2. 配置错误页面（自定义404、500）
3. 移除不必要的响应头
4. 关闭调试模式
5. 定期审查代码


**敏感文件防护**
1. 删除不必要的文件
2. 配置访问控制
3. 使用.gitignore排除敏感文件
4. 部署时检查文件
5. 定期清理临时文件


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
