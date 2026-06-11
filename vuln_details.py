# -*- coding: utf-8 -*-
"""
漏洞详细描述模板库
"""

# 漏洞详细描述模板
VULN_TEMPLATES = {
    "敏感文件泄露": {
        "summary": "网站存在敏感文件泄露，攻击者可获取网站配置信息、目录结构等敏感数据，为进一步攻击提供信息支持。",
        "impact": "1. 泄露网站技术架构和配置信息\n2. 暴露敏感目录和文件路径\n3. 可能包含数据库连接信息、API密钥等\n4. 为后续攻击提供信息收集基础",
        "steps": "1. 使用浏览器或curl访问目标URL\n2. 确认返回内容为敏感文件内容\n3. 分析泄露信息的敏感程度",
        "poc": """# 使用 curl 验证
curl -v {url}

# 使用 Python 验证
import requests
resp = requests.get("{url}")
print(resp.text)

# 使用浏览器直接访问
# 访问: {url}""",
        "tools": "- curl: https://curl.se/download.html\n- Burp Suite: https://portswigger.net/burp\n- 浏览器开发者工具 (F12)",
        "remediation": """**修复方案**:

1. **删除敏感文件**
```bash
# 删除不必要的文件
rm -f .env .git/config .htaccess
```

2. **Nginx 配置**
```nginx
# 禁止访问敏感文件
location ~ /\\. {
    deny all;
}

location ~* \\.(env|git|svn|htaccess|htpasswd)$ {
    deny all;
}

location ~ ^/(robots\\.txt|sitemap\\.xml)$ {
    allow all;
}
```

3. **Apache 配置**
```apache
# .htaccess 禁止访问敏感文件
<FilesMatch "\\.(env|git|svn|htaccess|htpasswd)$">
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
```"""
    },

    "Clickjacking": {
        "summary": "网站缺少 Clickjacking（点击劫持）防护，攻击者可通过 iframe 嵌入目标页面，诱导用户点击隐藏按钮，执行非预期操作。",
        "impact": "1. 诱导用户执行非预期操作（关注、点赞、授权等）\n2. 结合社会工程学进行钓鱼攻击\n3. 窃取用户敏感信息\n4. 损害品牌形象和用户信任",
        "steps": "1. 创建测试HTML页面，使用iframe嵌入目标网站\n2. 设置iframe透明或半透明\n3. 在iframe上方放置诱导按钮\n4. 用户点击诱导按钮时，实际点击的是目标网站的功能",
        "poc": """<!DOCTYPE html>
<html>
<head>
    <title>Clickjacking PoC</title>
    <style>
        iframe {{
            width: 800px;
            height: 600px;
            opacity: 0.5;  <!-- 半透明显示，测试时可调整为0 -->
            position: absolute;
            top: 0;
            left: 0;
        }}
        .decoy {{
            position: relative;
            z-index: -1;
            padding: 20px;
            font-size: 24px;
        }}
    </style>
</head>
<body>
    <h1>点击下方按钮领取奖励</h1>
    <button class="decoy">🎁 领取优惠券</button>
    <iframe src="{url}"></iframe>
</body>
</html>""",
        "tools": "- 浏览器 (Chrome/Firefox)\n- 文本编辑器\n- Burp Suite: https://portswigger.net/burp",
        "remediation": """**修复方案**:

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
```"""
    },

    "信息泄露": {
        "summary": "网站页面中泄露敏感信息，如邮箱地址、内部IP地址、HTML注释中的敏感内容等，攻击者可利用这些信息进行社会工程学攻击或进一步渗透。",
        "impact": "1. 泄露内部人员联系方式，便于社会工程学攻击\n2. 暴露内部网络架构\n3. HTML注释可能包含开发信息、测试账号等\n4. 为攻击者提供目标信息",
        "steps": "1. 访问目标页面\n2. 查看页面源代码\n3. 搜索邮箱、IP、注释等敏感信息\n4. 分析泄露信息的利用价值",
        "poc": """# 使用 Python 提取邮箱
import requests
import re

resp = requests.get("{url}")
emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{{2,}}', resp.text)
print("发现邮箱:", emails)

# 提取内网IP
ips = re.findall(r'\\b(?:\\d{{1,3}}\\.){{3}}\\d{{1,3}}\\b', resp.text)
private_ips = [ip for ip in ips if ip.startswith(('10.', '172.', '192.168.'))]
print("内网IP:", private_ips)

# 提取HTML注释
comments = re.findall(r'<!--(.*?)-->', resp.text, re.DOTALL)
print("HTML注释:", comments)

# 使用浏览器开发者工具
# 1. 按 F12 打开开发者工具
# 2. 使用 Ctrl+F 搜索 @, password, secret 等关键词""",
        "tools": "- 浏览器开发者工具 (F12)\n- Burp Suite: https://portswigger.net/burp\n- Python + requests库\n- grep/正则表达式工具",
        "remediation": """**修复方案**:

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
```"""
    },

    "PUT方法启用": {
        "summary": "服务器启用PUT HTTP方法，攻击者可能利用该方法上传恶意文件，获取服务器控制权限。",
        "impact": "1. 可能上传恶意文件（WebShell）\n2. 覆盖现有文件\n3. 获取服务器控制权限\n4. 数据泄露或篡改",
        "steps": "1. 使用OPTIONS方法确认PUT方法可用\n2. 尝试使用PUT方法上传测试文件\n3. 验证文件是否成功上传\n4. 评估上传文件的执行权限",
        "poc": """# 使用 curl 测试 PUT 方法
curl -X OPTIONS {url} -v

# 尝试上传文件
curl -X PUT {url}/test.txt -d "test content" -v

# 使用 Python 测试
import requests

# 测试 OPTIONS
resp = requests.options("{url}")
print("Allow:", resp.headers.get("Allow"))

# 测试 PUT
resp = requests.put("{url}/test.txt", data="test content")
print("Status:", resp.status_code)

# 使用 Burp Suite
# 1. 拦截请求
# 2. 修改方法为 PUT
# 3. 添加请求体
# 4. 发送请求""",
        "tools": "- curl: https://curl.se/download.html\n- Burp Suite: https://portswigger.net/burp\n- Python + requests库\n- Postman: https://www.postman.com/downloads/",
        "remediation": """**修复方案**:

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
```"""
    },

    "安全头缺失": {
        "summary": "网站缺少关键的安全响应头，可能导致多种客户端攻击，如XSS、Clickjacking、MIME类型嗅探攻击等。",
        "impact": "1. 增加XSS攻击风险\n2. 增加Clickjacking攻击风险\n3. MIME类型嗅探攻击\n4. 信息泄露\n5. 降低整体安全防护水平",
        "steps": "1. 使用curl或浏览器开发者工具查看响应头\n2. 检查是否包含安全响应头\n3. 评估缺失的安全头可能带来的风险",
        "poc": """# 使用 curl 检查响应头
curl -I {url} -v

# 使用 Python 检查
import requests
resp = requests.head("{url}")
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
        print(f"[存在] {{header}}: {{headers[header]}}")
    else:
        print(f"[缺失] {{header}}")

# 使用浏览器开发者工具
# 1. 按 F12 打开开发者工具
# 2. 切换到 Network 标签
# 3. 刷新页面
# 4. 点击请求，查看响应头""",
        "tools": "- curl: https://curl.se/download.html\n- 浏览器开发者工具 (F12)\n- Python + requests库\n- SecurityHeaders.com: https://securityheaders.com/",
        "remediation": """**修复方案**:

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
```"""
    },

    "弱加密套件": {
        "summary": "服务器使用弱加密算法或过时的TLS版本，攻击者可能利用加密弱点进行中间人攻击，窃取加密通信内容。",
        "impact": "1. 加密通信可能被破解\n2. 中间人攻击风险\n3. 敏感数据泄露\n4. 不符合安全合规要求",
        "steps": "1. 使用SSL/TLS检测工具扫描目标\n2. 检查支持的加密套件\n3. 检查TLS版本\n4. 评估加密强度",
        "poc": """# 使用 openssl 检测
openssl s_client -connect {host}:443 -tls1
openssl s_client -connect {host}:443 -tls1_1

# 使用 nmap 检测
nmap --script ssl-enum-ciphers -p 443 {host}

# 使用 Python 检测
import ssl
import socket

def check_ssl(hostname, port=443):
    context = ssl.create_default_context()
    with socket.create_connection((hostname, port)) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
            print("协议版本:", ssock.version())
            print("加密套件:", ssock.cipher())

check_ssl("{host}")

# 在线检测
# https://www.ssllabs.com/ssltest/""",
        "tools": "- openssl: https://www.openssl.org/\n- nmap: https://nmap.org/download.html\n- SSL Labs: https://www.ssllabs.com/ssltest/\n- testssl.sh: https://testssl.sh/",
        "remediation": """**修复方案**:

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

4. **Nginx 使用 DH 参数**
```nginx
ssl_dhparam /etc/nginx/dhparam.pem;
```

5. **在线检测**
- https://www.ssllabs.com/ssltest/
- https://testssl.sh/"""
    },

    "API端点泄露": {
        "summary": "网站暴露了API端点，攻击者可利用这些端点进行未授权访问、数据泄露或业务逻辑攻击。",
        "impact": "1. API可能缺少认证\n2. 可能泄露敏感数据\n3. 可能存在业务逻辑漏洞\n4. 为攻击者提供攻击面",
        "steps": "1. 访问常见API路径\n2. 检查返回内容类型\n3. 尝试未授权访问\n4. 分析API文档和参数",
        "poc": """# 使用 curl 测试常见API路径
curl {url}/api
curl {url}/api/v1
curl {url}/api/v2
curl {url}/api/docs
curl {url}/swagger-ui.html
curl {url}/api-docs

# 使用 Python 扫描
import requests

api_paths = [
    "/api", "/api/v1", "/api/v2",
    "/api/docs", "/swagger-ui.html",
    "/api/users", "/api/admin"
]

for path in api_paths:
    url = f"{url}{path}"
    try:
        resp = requests.get(url, timeout=5)
        if resp.status_code == 200:
            print(f"[发现] {{url}} - {{resp.status_code}}")
    except:
        pass""",
        "tools": "- curl: https://curl.se/download.html\n- Burp Suite: https://portswigger.net/burp\n- Postman: https://www.postman.com/\n- ffuf: https://github.com/ffuf/ffuf",
        "remediation": """**修复方案**:

1. **Nginx 限制API访问**
```nginx
# 限制API访问
location /api {
    # 只允许内网访问
    allow 10.0.0.0/8;
    allow 172.16.0.0/12;
    allow 192.168.0.0/16;
    deny all;

    # 或要求认证
    auth_basic "API Access";
    auth_basic_user_file /etc/nginx/.htpasswd;
}
```

2. **添加认证中间件 (Node.js)**
```javascript
const jwt = require('jsonwebtoken');

const authMiddleware = (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
        return res.status(401).json({ error: 'Unauthorized' });
    }
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded;
        next();
    } catch (err) {
        res.status(401).json({ error: 'Invalid token' });
    }
};

app.use('/api', authMiddleware);
```

3. **配置CORS**
```javascript
const cors = require('cors');
app.use(cors({
    origin: ['https://yourdomain.com'],
    methods: ['GET', 'POST'],
    credentials: true
}));
```

4. **API网关配置 (Kong/Nginx)**
```nginx
# 限流配置
location /api {
    limit_req zone=api burst=20 nodelay;
    proxy_pass http://backend;
}
```"""
    },

    "GraphQL漏洞": {
        "summary": "GraphQL端点可访问，可能泄露完整Schema，攻击者可利用introspection获取所有可查询的数据类型和字段。",
        "impact": "1. 泄露完整数据模型\n2. 暴露所有可查询字段\n3. 可能存在越权查询\n4. 数据泄露风险",
        "steps": "1. 检测GraphQL端点\n2. 测试introspection查询\n3. 分析返回的Schema\n4. 尝试构造恶意查询",
        "poc": """# 测试 GraphQL 端点
curl -X POST {url}/graphql \\
  -H "Content-Type: application/json" \\
  -d '{{"query": "{{__schema{{types{{name}}}}}}"}}'

# 测试 introspection
curl -X POST {url}/graphql \\
  -H "Content-Type: application/json" \\
  -d '{{
    "query": "query IntrospectionQuery {{ __schema {{ queryType {{ name }} mutationType {{ name }} types {{ name kind fields {{ name type {{ name }} }} }} }} }}"
  }}'

# 使用 Python 测试
import requests

query = {{"query": "{{__schema{{types{{name}}}}}}"}}
resp = requests.post("{url}/graphql", json=query)
print(resp.text)

# 使用 GraphQL Playground
# 访问: {url}/graphql 或 {url}/playground""",
        "tools": "- curl: https://curl.se/download.html\n- GraphQL Playground\n- Burp Suite: https://portswigger.net/burp\n- InQL (Burp插件): https://github.com/doyensec/inql",
        "remediation": """**修复方案**:

1. **禁用 Introspection (Node.js/Express-graphql)**
```javascript
const { graphqlHTTP } = require('express-graphql');
const { NoSchemaIntrospectionCustomRule } = require('graphql');

app.use('/graphql', graphqlHTTP({
    schema: MyGraphQLSchema,
    validationRules: [NoSchemaIntrospectionCustomRule]
}));
```

2. **配置查询深度限制**
```javascript
const depthLimit = require('graphql-depth-limit');

app.use('/graphql', graphqlHTTP({
    schema: MyGraphQLSchema,
    validationRules: [depthLimit(10)]
}));
```

3. **配置查询复杂度限制**
```javascript
const { createComplexityLimitRule } = require('graphql-validation-complexity');

app.use('/graphql', graphqlHTTP({
    schema: MyGraphQLSchema,
    validationRules: [createComplexityLimitRule(1000)]
}));
```

4. **添加认证中间件**
```javascript
const graphqlAuth = (req, res, next) => {
    if (!req.user) {
        return res.status(401).json({ error: 'Unauthorized' });
    }
    next();
};

app.use('/graphql', graphqlAuth, graphqlHTTP({
    schema: MyGraphQLSchema
}));
```

5. **Nginx 限制 GraphQL 访问**
```nginx
location /graphql {
    # 限制请求大小
    client_max_body_size 10k;

    # 限流
    limit_req zone=graphql burst=10 nodelay;

    proxy_pass http://backend;
}
```"""
    },

    "SSRF": {
        "summary": "服务器端请求伪造（SSRF）漏洞，攻击者可利用服务器发起任意请求，访问内部网络资源或云服务元数据。",
        "impact": "1. 访问内部网络资源\n2. 获取云服务元数据（AWS/GCP/Azure）\n3. 端口扫描内部网络\n4. 读取本地文件\n5. 远程代码执行（某些情况）",
        "steps": "1. 识别可能的SSRF参数（url, link, src等）\n2. 构造指向内部地址的payload\n3. 观察响应内容\n4. 尝试访问云服务元数据",
        "poc": """# 测试 SSRF Payloads
# 访问本地服务
?url=http://127.0.0.1
?url=http://localhost
?url=http://[::1]

# 访问云服务元数据
?url=http://169.254.169.254/latest/meta-data/  # AWS
?url=http://metadata.google.internal/  # GCP
?url=http://169.254.169.254/metadata/v1/  # DigitalOcean

# 读取本地文件
?url=file:///etc/passwd
?url=file:///c:/windows/system32/drivers/etc/hosts

# 使用 Python 测试
import requests

payloads = [
    "http://127.0.0.1",
    "http://localhost",
    "http://169.254.169.254/latest/meta-data/",
    "file:///etc/passwd"
]

for payload in payloads:
    resp = requests.get("{url}", params={{"url": payload}})
    print(f"{{payload}}: {{resp.status_code}}")""",
        "tools": "- curl: https://curl.se/download.html\n- Burp Suite: https://portswigger.net/burp\n- SSRFmap: https://github.com/swisskyrepo/SSRFmap\n- Gopherus: https://github.com/tarunkant/Gopherus",
        "remediation": """**修复方案**:

1. **URL 白名单验证 (Python)**
```python
import urllib.parse
import ipaddress

def is_valid_url(url):
    parsed = urllib.parse.urlparse(url)

    # 只允许 http/https
    if parsed.scheme not in ['http', 'https']:
        return False

    # 解析IP
    try:
        ip = ipaddress.ip_address(parsed.hostname)
        # 禁止内网IP
        if ip.is_private or ip.is_loopback:
            return False
        # 禁止云服务元数据
        if str(ip).startswith('169.254.'):
            return False
    except ValueError:
        # 域名验证
        allowed_domains = ['example.com', 'api.example.com']
        if not any(parsed.hostname.endswith(d) for d in allowed_domains):
            return False

    return True
```

2. **Node.js URL 验证**
```javascript
const { URL } = require('url');
const ipaddr = require('ipaddr.js');

function isValidUrl(urlString) {
    try {
        const url = new URL(urlString);

        // 只允许 http/https
        if (!['http:', 'https:'].includes(url.protocol)) {
            return false;
        }

        // 检查IP
        const ip = ipaddr.parse(url.hostname);
        if (ip.range() !== 'unicast') {
            return false;
        }

        return true;
    } catch (err) {
        return false;
    }
}
```

3. **Nginx 限制内部访问**
```nginx
# 禁止访问内部网络
location /proxy {
    # 只允许访问外部网络
    proxy_pass $arg_url;

    # 禁止访问内网
    set $block 0;
    if ($arg_url ~* "10\\."){
        set $block 1;
    }
    if ($arg_url ~* "172\\.16\\."){
        set $block 1;
    }
    if ($arg_url ~* "192\\.168\\."){
        set $block 1;
    }
    if ($block = 1){
        return 403;
    }
}
```"""
    },

    "命令注入": {
        "summary": "操作系统命令注入漏洞，攻击者可通过构造恶意输入执行任意系统命令，完全控制服务器。",
        "impact": "1. 执行任意系统命令\n2. 获取服务器控制权限\n3. 读取敏感文件\n4. 植入后门\n5. 内网渗透",
        "steps": "1. 识别可能的命令注入参数\n2. 构造命令注入payload\n3. 观察响应内容\n4. 验证命令执行结果",
        "poc": """# 常见命令注入 Payload
;id
|id
`id`
$(id)
;whoami
|whoami
;cat /etc/passwd
|cat /etc/passwd

# 时间盲注
;sleep 5
|sleep 5
;ping -c 5 127.0.0.1

# 使用 Python 测试
import requests
import time

# 报错注入
payloads = [";id", "|id", "`id`"]
for payload in payloads:
    resp = requests.get("{url}", params={{"cmd": f"test{{payload}}"}})
    if "uid=" in resp.text:
        print(f"[存在] 命令注入: {{payload}}")

# 时间盲注
start = time.time()
requests.get("{url}", params={{"cmd": "test;sleep 5"}})
if time.time() - start > 4:
    print("[存在] 时间盲注")

# 使用 Burp Suite
# 1. 拦截请求
# 2. 修改参数为 payload
# 3. 发送请求并分析响应""",
        "tools": "- curl: https://curl.se/download.html\n- Burp Suite: https://portswigger.net/burp\n- commix: https://github.com/commixproject/commix\n- http://www.commixproject.com/",
        "remediation": """**修复方案**:

1. **使用白名单验证输入 (Python)**
```python
import re

def validate_input(input_str):
    # 只允许字母、数字、下划线
    if not re.match(r'^[a-zA-Z0-9_]+$', input_str):
        raise ValueError("Invalid input")
    return input_str
```

2. **避免调用系统命令 (Python)**
```python
# 错误示例
import os
os.system(f"ping {user_input}")

# 正确示例：使用 subprocess 并验证输入
import subprocess
import shlex

def safe_ping(host):
    # 验证主机名
    if not re.match(r'^[a-zA-Z0-9.-]+$', host):
        raise ValueError("Invalid hostname")

    # 使用列表形式，避免shell注入
    result = subprocess.run(
        ['ping', '-c', '1', host],
        capture_output=True,
        text=True,
        timeout=5
    )
    return result.stdout
```

3. **Node.js 安全命令执行**
```javascript
const { execFile } = require('child_process');

function safeExec(command, args) {
    return new Promise((resolve, reject) => {
        // 使用 execFile 而不是 exec
        execFile(command, args, (error, stdout, stderr) => {
            if (error) {
                reject(error);
                return;
            }
            resolve(stdout);
        });
    });
}

// 使用示例
safeExec('ping', ['-c', '1', userInput]);
```

4. **PHP 安全命令执行**
```php
<?php
// 错误示例
system("ping $input");

// 正确示例
function safeExec($command, $args) {
    // 验证参数
    foreach ($args as $arg) {
        if (!preg_match('/^[a-zA-Z0-9.-]+$/', $arg)) {
            throw new Exception("Invalid argument");
        }
    }
    // 使用 escapeshellarg
    $cmd = escapeshellcmd($command) . ' ' . implode(' ', array_map('escapeshellarg', $args));
    return shell_exec($cmd);
}
?>
```"""
    },

    "未授权访问": {
        "summary": "敏感路径可未授权访问，攻击者无需登录即可访问管理后台、调试接口、敏感数据等。",
        "impact": "1. 访问管理后台\n2. 获取敏感数据\n3. 执行管理操作\n4. 信息泄露\n5. 系统被控制",
        "steps": "1. 访问常见敏感路径\n2. 检查是否需要认证\n3. 尝试执行操作\n4. 评估泄露信息的敏感程度",
        "poc": """# 使用 curl 测试常见敏感路径
curl {url}/admin
curl {url}/admin/login
curl {url}/dashboard
curl {url}/console
curl {url}/debug
curl {url}/actuator
curl {url}/actuator/env
curl {url}/swagger-ui.html
curl {url}/api-docs

# 使用 Python 扫描
import requests

paths = [
    "/admin", "/dashboard", "/console",
    "/debug", "/actuator", "/actuator/env",
    "/swagger-ui.html", "/api-docs"
]

for path in paths:
    url = f"{url}{path}"
    try:
        resp = requests.get(url, timeout=5, allow_redirects=False)
        if resp.status_code == 200:
            print(f"[发现] {{url}} - {{resp.status_code}}")
    except:
        pass

# 使用 ffuf 扫描
ffuf -u {url}/FUZZ -w wordlist.txt""",
        "tools": "- curl: https://curl.se/download.html\n- ffuf: https://github.com/ffuf/ffuf\n- dirsearch: https://github.com/maurosoria/dirsearch\n- Burp Suite: https://portswigger.net/burp",
        "remediation": """**修复方案**:

1. **Nginx 访问控制**
```nginx
# 限制管理后台访问
location /admin {
    # IP白名单
    allow 10.0.0.0/8;
    allow 192.168.1.100;
    deny all;

    # 或要求认证
    auth_basic "Admin Area";
    auth_basic_user_file /etc/nginx/.htpasswd;
}

# 限制敏感路径
location ~ ^/(debug|console|actuator) {
    deny all;
}
```

2. **Apache 访问控制**
```apache
# .htaccess 限制管理后台
<Directory "/var/www/html/admin">
    AuthType Basic
    AuthName "Admin Area"
    AuthUserFile /etc/apache2/.htpasswd
    Require valid-user
</Directory>

# 限制敏感路径
<Directory "/var/www/html/debug">
    Require all denied
</Directory>
```

3. **Node.js 访问控制中间件**
```javascript
const basicAuth = require('express-basic-auth');

// 管理后台认证
app.use('/admin', basicAuth({
    users: { 'admin': 'password' },
    challenge: true
}));

// IP白名单
const ipWhitelist = (req, res, next) => {
    const allowedIps = ['10.0.0.1', '192.168.1.100'];
    if (!allowedIps.includes(req.ip)) {
        return res.status(403).send('Forbidden');
    }
    next();
};

app.use('/admin', ipWhitelist);
```

4. **Spring Boot 安全配置**
```java
@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
            .antMatchers("/admin/**").hasRole("ADMIN")
            .antMatchers("/debug/**").denyAll()
            .anyRequest().permitAll()
            .and()
            .httpBasic();
    }
}
```"""
    },

    "默认凭证": {
        "summary": "系统使用默认用户名和密码，攻击者可利用默认凭证直接登录系统，获取完全控制权限。",
        "impact": "1. 直接登录系统\n2. 获取管理权限\n3. 数据泄露\n4. 系统被控制\n5. 横向渗透",
        "steps": "1. 识别登录页面\n2. 尝试常见默认凭证\n3. 验证登录是否成功\n4. 评估登录后的权限",
        "poc": """# 常见默认凭证
admin/admin
admin/123456
admin/password
root/root
root/toor
test/test
guest/guest

# 使用 Python 测试
import requests

login_url = "{url}/login"
credentials = [
    ("admin", "admin"),
    ("admin", "123456"),
    ("admin", "password"),
    ("root", "root"),
    ("test", "test")
]

for username, password in credentials:
    data = {{"username": username, "password": password}}
    resp = requests.post(login_url, data=data, allow_redirects=False)
    if resp.status_code in [301, 302]:
        print(f"[成功] {{username}}/{{password}}")

# 使用 Burp Suite Intruder
# 1. 拦截登录请求
# 2. 发送到 Intruder
# 3. 设置 payload 为默认凭证列表
# 4. 开始攻击""",
        "tools": "- Burp Suite: https://portswigger.net/burp\n- Hydra: https://github.com/vanhauser-thc/thc-hydra\n- Medusa: https://github.com/jmk-foofus/medusa\n- 常见默认凭证列表",
        "remediation": """**修复方案**:

1. **强制修改默认密码**
```bash
# MySQL
mysql -u root -p
ALTER USER 'root'@'localhost' IDENTIFIED BY 'NewStrongPassword!';

# PostgreSQL
psql -U postgres
ALTER USER postgres PASSWORD 'NewStrongPassword!';

# Redis
# 修改 redis.conf
requirepass NewStrongPassword
```

2. **密码复杂度验证 (Node.js)**
```javascript
function validatePassword(password) {
    const minLength = 12;
    const hasUpperCase = /[A-Z]/.test(password);
    const hasLowerCase = /[a-z]/.test(password);
    const hasNumbers = /\\d/.test(password);
    const hasSpecialChar = /[!@#$%^&*(),.?":{}|<>]/.test(password);

    return password.length >= minLength &&
           hasUpperCase &&
           hasLowerCase &&
           hasNumbers &&
           hasSpecialChar;
}
```

3. **账户锁定策略 (Node.js)**
```javascript
const loginAttempts = new Map();

function checkAccountLock(username) {
    const attempts = loginAttempts.get(username) || { count: 0, lastAttempt: 0 };

    // 5次失败后锁定30分钟
    if (attempts.count >= 5 && Date.now() - attempts.lastAttempt < 30 * 60 * 1000) {
        return true; // 账户锁定
    }

    return false;
}

function recordLoginAttempt(username, success) {
    const attempts = loginAttempts.get(username) || { count: 0, lastAttempt: 0 };

    if (success) {
        loginAttempts.delete(username);
    } else {
        attempts.count++;
        attempts.lastAttempt = Date.now();
        loginAttempts.set(username, attempts);
    }
}
```

4. **多因素认证 (Node.js)**
```javascript
const speakeasy = require('speakeasy');
const qrcode = require('qrcode');

// 生成密钥
const secret = speakeasy.generateSecret({
    name: 'YourApp:user@example.com'
});

// 验证令牌
function verifyToken(secret, token) {
    return speakeasy.totp.verify({
        secret: secret,
        encoding: 'base32',
        token: token
    });
}
```"""
    },

    "Host头注入": {
        "summary": "服务器反射Host头，攻击者可利用此漏洞进行缓存投毒、密码重置劫持等攻击。",
        "impact": "1. 缓存投毒\n2. 密码重置劫持\n3. SSRF绕过\n4. Web缓存欺骗",
        "steps": "1. 修改请求的Host头\n2. 观察响应内容\n3. 检查是否反射恶意Host\n4. 评估可利用场景",
        "poc": """# 使用 curl 测试 Host 头注入
curl -H "Host: evil.com" {url}

# 使用 Python 测试
import requests

headers = {{"Host": "evil.com"}}
resp = requests.get("{url}", headers=headers)

if "evil.com" in resp.text:
    print("[存在] Host头注入")

# 使用 Burp Suite
# 1. 拦截请求
# 2. 修改 Host 头为 evil.com
# 3. 发送请求
# 4. 检查响应中是否包含 evil.com""",
        "tools": "- curl: https://curl.se/download.html\n- Burp Suite: https://portswigger.net/burp\n- Python + requests库",
        "remediation": """**修复方案**:

1. **Nginx Host头验证**
```nginx
# 定义允许的Host
map $http_host $valid_host {
    default 0;
    "example.com" 1;
    "www.example.com" 1;
}

server {
    # 拒绝非法Host
    if ($valid_host = 0) {
        return 444;
    }
}
```

2. **Apache Host头验证**
```apache
# 只允许特定Host
<VirtualHost *:80>
    ServerName example.com
    ServerAlias www.example.com

    # 拒绝其他Host
    <If "%{HTTP_HOST} != 'example.com' && %{HTTP_HOST} != 'www.example.com'">
        Require all denied
    </If>
</VirtualHost>
```

3. **Node.js Host头验证**
```javascript
const allowedHosts = ['example.com', 'www.example.com'];

app.use((req, res, next) => {
    const host = req.headers.host?.split(':')[0]; // 去掉端口
    if (!allowedHosts.includes(host)) {
        return res.status(400).send('Invalid Host');
    }
    next();
});
```

4. **使用绝对URL**
```javascript
// 错误示例：使用相对URL
const resetLink = `http://${req.headers.host}/reset-password?token=${token}`;

// 正确示例：使用绝对URL
const resetLink = `https://example.com/reset-password?token=${token}`;
```"""
    },

    "CRLF注入": {
        "summary": "HTTP响应头注入漏洞，攻击者可注入恶意响应头，进行XSS、缓存投毒、会话固定等攻击。",
        "impact": "1. 注入恶意响应头\n2. XSS攻击\n3. 缓存投毒\n4. 会话固定\n5. 重定向劫持",
        "steps": "1. 构造包含CRLF字符的payload\n2. 观察响应头\n3. 检查是否注入成功\n4. 评估可利用场景",
        "poc": """# CRLF Payloads
%0d%0aInjected-Header:evil
%0aInjected-Header:evil
\\r\\nInjected-Header:evil

# 使用 curl 测试
curl "{url}/%0d%0aInjected-Header:evil" -v

# 使用 Python 测试
import requests

payloads = [
    "%0d%0aInjected-Header:evil",
    "%0aInjected-Header:evil"
]

for payload in payloads:
    url = f"{url}/{payload}"
    resp = requests.get(url, allow_redirects=False)
    if "Injected-Header" in str(resp.headers):
        print(f"[存在] CRLF注入: {{payload}}")

# 使用 Burp Suite
# 1. 拦截请求
# 2. 修改URL添加CRLF payload
# 3. 发送请求
# 4. 检查响应头""",
        "tools": "- curl: https://curl.se/download.html\n- Burp Suite: https://portswigger.net/burp\n- CRLF Injection Scanner: https://github.com/Nefcore/CRLFsuite",
        "remediation": """**修复方案**:

1. **过滤特殊字符 (Python)**
```python
import re

def sanitize_input(input_str):
    # 过滤 CRLF 字符
    return re.sub(r'[\\r\\n]', '', input_str)
```

2. **Node.js 输入过滤**
```javascript
function sanitizeInput(input) {
    // 过滤 CRLF 字符
    return input.replace(/[\\r\\n]/g, '');
}

// 使用中间件
app.use((req, res, next) => {
    // 过滤URL中的CRLF
    req.url = sanitizeInput(req.url);
    next();
});
```

3. **Nginx 配置**
```nginx
# 过滤URL中的特殊字符
if ($request_uri ~* "[\\r\\n]") {
    return 400;
}
```

4. **Apache 配置**
```apache
# 过滤URL中的特殊字符
RewriteEngine On
RewriteCond %{REQUEST_URI} [\\r\\n]
RewriteRule .* - [F]
```

5. **使用框架安全API**
```javascript
// 错误示例：直接拼接header
res.setHeader('Location', userInput);

// 正确示例：使用框架的URL编码
const url = new URL(userInput, 'https://example.com');
res.setHeader('Location', url.toString());
```"""
    },

    "TRACE方法启用": {
        "summary": "服务器启用TRACE方法，攻击者可利用此方法进行跨站追踪（XST）攻击，窃取用户Cookie。",
        "impact": "1. 窃取用户Cookie\n2. 绕过HttpOnly保护\n3. 会话劫持\n4. 跨站追踪攻击",
        "steps": "1. 使用TRACE方法发送请求\n2. 检查响应内容\n3. 验证是否反射请求头\n4. 评估XST攻击可行性",
        "poc": """# 使用 curl 测试 TRACE 方法
curl -X TRACE {url} -v

# 使用 Python 测试
import requests

resp = requests.request("TRACE", "{url}")
print("Status:", resp.status_code)
print("Body:", resp.text[:500])

# 使用 Burp Suite
# 1. 拦截请求
# 2. 修改方法为 TRACE
# 3. 发送请求
# 4. 检查响应""",
        "tools": "- curl: https://curl.se/download.html\n- Burp Suite: https://portswigger.net/burp\n- Python + requests库",
        "remediation": """**修复方案**:

1. **Nginx 禁用 TRACE 方法**
```nginx
# 只允许 GET、POST、HEAD 方法
if ($request_method !~ ^(GET|POST|HEAD)$) {
    return 405;
}
```

2. **Apache 禁用 TRACE 方法**
```apache
# 禁用 TRACE 方法
TraceEnable Off

# 或使用 LimitExcept
<LimitExcept GET POST HEAD>
    Order allow,deny
    Deny from all
</LimitExcept>
```

3. **Tomcat 禁用 TRACE 方法**
```xml
<!-- web.xml -->
<security-constraint>
    <web-resource-collection>
        <url-pattern>/*</url-pattern>
        <http-method>TRACE</http-method>
    </web-resource-collection>
    <auth-constraint />
</security-constraint>
```

4. **Node.js 禁用 TRACE 方法**
```javascript
app.use((req, res, next) => {
    if (req.method === 'TRACE') {
        return res.status(405).send('Method Not Allowed');
    }
    next();
});
```

5. **IIS 禁用 TRACE 方法**
```xml
<!-- web.config -->
<configuration>
    <system.webServer>
        <security>
            <requestFiltering>
                <verbs>
                    <add verb="TRACE" allowed="false" />
                </verbs>
            </requestFiltering>
        </security>
    </system.webServer>
</configuration>
```"""
    },

    "Nuclei-weak-cipher-suites": {
        "summary": "服务器使用弱加密套件，攻击者可能利用加密弱点破解加密通信，窃取敏感数据。",
        "impact": "1. 加密通信可能被破解\n2. 中间人攻击风险\n3. 敏感数据泄露\n4. 不符合安全合规要求",
        "steps": "1. 使用SSL/TLS检测工具扫描\n2. 检查支持的加密套件\n3. 识别弱加密算法\n4. 评估风险等级",
        "poc": """# 使用 openssl 检测
openssl s_client -connect {host}:443 -cipher 'LOW:EXP'

# 使用 nmap 检测
nmap --script ssl-enum-ciphers -p 443 {host}

# 使用 testssl.sh 检测
./testssl.sh {host}

# 在线检测
# https://www.ssllabs.com/ssltest/""",
        "tools": "- openssl: https://www.openssl.org/\n- nmap: https://nmap.org/download.html\n- testssl.sh: https://testssl.sh/\n- SSL Labs: https://www.ssllabs.com/ssltest/",
        "remediation": """**修复方案**:

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
- https://cipherlist.eu/"""
    }
}


def get_vuln_details(vuln_type: str) -> dict:
    """获取漏洞详细信息"""
    # 模糊匹配
    for key in VULN_TEMPLATES:
        if key in vuln_type or vuln_type in key:
            return VULN_TEMPLATES[key]

    # 默认模板
    return {
        "summary": "发现安全漏洞，可能被攻击者利用进行恶意攻击。",
        "impact": "1. 可能被攻击者利用\n2. 存在安全风险\n3. 需要评估具体影响",
        "steps": "1. 访问目标URL\n2. 分析响应内容\n3. 评估漏洞风险",
        "poc": "# 请联系安全团队获取详细PoC",
        "tools": "- Burp Suite: https://portswigger.net/burp\n- 浏览器开发者工具",
        "remediation": "1. 及时修复漏洞\n2. 部署安全防护\n3. 定期安全审计"
    }
