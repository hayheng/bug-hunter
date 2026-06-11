# -*- coding: utf-8 -*-
"""
漏洞修复模板库 - 提供具体可执行的修复代码
"""

REMEDIATION_TEMPLATES = {
    "配置错误": {
        "Clickjacking": {
            "title": "Clickjacking（点击劫持）漏洞修复",
            "description": "通过设置HTTP响应头防止页面被iframe嵌入",
            "solutions": {
                "nginx": """
# Nginx 配置 - 添加到 server 或 location 块
add_header X-Frame-Options "DENY" always;
add_header Content-Security-Policy "frame-ancestors 'self'" always;

# 如果需要允许特定域名嵌入
# add_header X-Frame-Options "ALLOW-FROM https://trusted.com" always;
# add_header Content-Security-Policy "frame-ancestors 'self' https://trusted.com" always;
""",
                "apache": """
# Apache 配置 - 添加到 .htaccess 或 httpd.conf
Header always set X-Frame-Options "DENY"
Header always set Content-Security-Policy "frame-ancestors 'self'"

# 如果需要允许特定域名嵌入
# Header always set X-Frame-Options "ALLOW-FROM https://trusted.com"
# Header always set Content-Security-Policy "frame-ancestors 'self' https://trusted.com"
""",
                "php": """
<?php
// PHP 代码 - 添加到公共入口文件或框架中间件
header('X-Frame-Options: DENY');
header("Content-Security-Policy: frame-ancestors 'self'");

// Laravel 框架 - 添加到 app/Http/Middleware/
// $response->header('X-Frame-Options', 'DENY');

// ThinkPHP 框架 - 添加到中间件
// header('X-Frame-Options: DENY');
?>
""",
                "nodejs": """
// Node.js/Express - 添加到中间件
app.use((req, res, next) => {
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Content-Security-Policy', "frame-ancestors 'self'");
    next();
});

// 或使用 helmet 中间件
const helmet = require('helmet');
app.use(helmet.frameguard({ action: 'deny' }));
""",
                "spring": """
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
""",
                "django": """
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
""",
            }
        },
        "CORS配置错误": {
            "title": "CORS（跨域资源共享）配置错误修复",
            "description": "限制允许访问的域名，避免使用通配符",
            "solutions": {
                "nginx": """
# Nginx CORS 配置
# 只允许特定域名访问
if ($http_origin ~* "^https://(www\\.example\\.com|api\\.example\\.com)$") {
    add_header Access-Control-Allow-Origin $http_origin always;
    add_header Access-Control-Allow-Methods "GET, POST, OPTIONS" always;
    add_header Access-Control-Allow-Headers "Authorization, Content-Type" always;
    add_header Access-Control-Allow-Credentials "true" always;
    add_header Access-Control-Max-Age 3600 always;
}

# 禁止其他域名的CORS请求
# 不要使用: add_header Access-Control-Allow-Origin *;
""",
                "nodejs": """
// Node.js/Express CORS 配置
const cors = require('cors');

// 方法1: 使用cors中间件 (推荐)
const corsOptions = {
    origin: function (origin, callback) {
        const allowedOrigins = [
            'https://www.example.com',
            'https://api.example.com'
        ];
        if (!origin || allowedOrigins.indexOf(origin) !== -1) {
            callback(null, true);
        } else {
            callback(new Error('Not allowed by CORS'));
        }
    },
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    credentials: true,
    optionsSuccessStatus: 204
};
app.use(cors(corsOptions));

// 方法2: 手动设置
app.use((req, res, next) => {
    const allowedOrigins = ['https://www.example.com'];
    const origin = req.headers.origin;
    if (allowedOrigins.includes(origin)) {
        res.setHeader('Access-Control-Allow-Origin', origin);
    }
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    next();
});
""",
                "spring": """
// Spring Boot CORS 配置
@Configuration
public class CorsConfig implements WebMvcConfigurer {
    @Override
    public void addCorsMappings(CorsRegistry registry) {
        registry.addMapping("/api/**")
            .allowedOrigins("https://www.example.com", "https://api.example.com")
            .allowedMethods("GET", "POST", "PUT", "DELETE")
            .allowedHeaders("*")
            .allowCredentials(true)
            .maxAge(3600);
    }
}

// 或使用注解
@CrossOrigin(origins = "https://www.example.com", allowCredentials = "true")
@GetMapping("/api/data")
public ResponseEntity<?> getData() {
    // ...
}
""",
            }
        },
        "安全头缺失": {
            "title": "安全响应头配置",
            "description": "添加安全响应头防止常见攻击",
            "solutions": {
                "nginx": """
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
""",
                "apache": """
# Apache 完整安全头配置
# 添加到 .htaccess 或 httpd.conf

Header always set X-Content-Type-Options "nosniff"
Header always set X-Frame-Options "DENY"
Header always set X-XSS-Protection "1; mode=block"
Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
Header always set Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'"
Header always set Referrer-Policy "strict-origin-when-cross-origin"
Header always set Permissions-Policy "camera=(), microphone=(), geolocation=()"
""",
                "nodejs": """
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
""",
            }
        },
        "HTTP请求走私": {
            "title": "HTTP请求走私漏洞修复",
            "description": "正确处理Transfer-Encoding和Content-Length头",
            "solutions": {
                "nginx": """
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
""",
                "apache": """
# Apache 配置
# 添加到 httpd.conf

# 禁用 Transfer-Encoding
TraceEnable off

# 使用 HTTP/2
Protocols h2 http/1.1

# 严格解析请求
HttpProtocolOptions Strict
""",
                "nodejs": """
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
""",
            }
        },
        "PUT方法启用": {
            "title": "HTTP方法限制",
            "description": "只允许必要的HTTP方法",
            "solutions": {
                "nginx": """
# Nginx - 只允许 GET, POST, HEAD
if ($request_method !~ ^(GET|POST|HEAD)$) {
    return 405;
}
""",
                "apache": """
# Apache - 只允许 GET, POST, HEAD
<LimitExcept GET POST HEAD>
    Order allow,deny
    Deny from all
</LimitExcept>
""",
                "nodejs": """
// Node.js/Express - 方法限制中间件
const allowedMethods = ['GET', 'POST', 'HEAD', 'OPTIONS'];

app.use((req, res, next) => {
    if (!allowedMethods.includes(req.method)) {
        return res.status(405).json({ error: 'Method Not Allowed' });
    }
    next();
});
""",
            }
        },
    },
    "SQL注入": {
        "default": {
            "title": "SQL注入漏洞修复",
            "description": "使用参数化查询防止SQL注入",
            "solutions": {
                "php": """
<?php
// PDO 参数化查询 (推荐)
$pdo = new PDO('mysql:host=localhost;dbname=test', 'user', 'pass');

// 方法1: prepare + execute
$stmt = $pdo->prepare('SELECT * FROM users WHERE id = :id AND name = :name');
$stmt->execute(['id' => $id, 'name' => $name]);
$results = $stmt->fetchAll();

// 方法2: 位置参数
$stmt = $pdo->prepare('SELECT * FROM users WHERE id = ? AND name = ?');
$stmt->execute([$id, $name]);

// MySQLi 参数化查询
$mysqli = new mysqli('localhost', 'user', 'pass', 'test');
$stmt = $mysqli->prepare('SELECT * FROM users WHERE id = ? AND name = ?');
$stmt->bind_param('is', $id, $name);
$stmt->execute();
$result = $stmt->get_result();

// 错误示例 - 存在SQL注入
// $sql = "SELECT * FROM users WHERE id = $id";  // 危险!
// $sql = "SELECT * FROM users WHERE name = '$name'";  // 危险!
?>
""",
                "python": """
# Python - 使用参数化查询

# SQLAlchemy (推荐)
from sqlalchemy import create_engine, text

engine = create_engine('mysql+pymysql://user:pass@localhost/test')

# 方法1: text + bindparams
with engine.connect() as conn:
    result = conn.execute(
        text("SELECT * FROM users WHERE id = :id AND name = :name"),
        {"id": user_id, "name": user_name}
    )

# 方法2: ORM
from sqlalchemy.orm import Session
with Session(engine) as session:
    user = session.query(User).filter(User.id == user_id).first()

# PyMySQL 参数化查询
import pymysql
conn = pymysql.connect(host='localhost', user='user', password='pass', db='test')
cursor = conn.cursor()
cursor.execute("SELECT * FROM users WHERE id = %s AND name = %s", (user_id, user_name))

# 错误示例 - 存在SQL注入
# sql = f"SELECT * FROM users WHERE id = {user_id}"  # 危险!
# sql = "SELECT * FROM users WHERE name = '" + user_name + "'"  # 危险!
""",
                "java": """
// Java - 使用 PreparedStatement

// JDBC PreparedStatement
String sql = "SELECT * FROM users WHERE id = ? AND name = ?";
PreparedStatement pstmt = connection.prepareStatement(sql);
pstmt.setInt(1, userId);
pstmt.setString(2, userName);
ResultSet rs = pstmt.executeQuery();

// MyBatis - 使用 #{}
// UserMapper.xml
// <select id="getUser" resultType="User">
//     SELECT * FROM users WHERE id = #{id} AND name = #{name}
// </select>

// 错误示例 - 存在SQL注入
// String sql = "SELECT * FROM users WHERE id = " + userId;  // 危险!
// String sql = "SELECT * FROM users WHERE name = '" + userName + "'";  // 危险!
""",
                "nodejs": """
// Node.js - 使用参数化查询

// MySQL2
const mysql = require('mysql2/promise');
const pool = mysql.createPool({
    host: 'localhost',
    user: 'user',
    password: 'pass',
    database: 'test'
});

// 方法1: 占位符 ?
const [rows] = await pool.execute(
    'SELECT * FROM users WHERE id = ? AND name = ?',
    [userId, userName]
);

// 方法2: 命名占位符
const [rows] = await pool.execute(
    'SELECT * FROM users WHERE id = :id AND name = :name',
    { id: userId, name: userName }
);

// Sequelize ORM
const user = await User.findOne({
    where: { id: userId, name: userName }
});

// 错误示例 - 存在SQL注入
// const sql = `SELECT * FROM users WHERE id = ${userId}`;  // 危险!
// const sql = "SELECT * FROM users WHERE name = '" + userName + "'";  // 危险!
""",
            }
        }
    },
    "XSS": {
        "default": {
            "title": "XSS（跨站脚本）漏洞修复",
            "description": "对输出进行HTML编码，使用CSP策略",
            "solutions": {
                "php": """
<?php
// HTML编码输出
function escapeHtml($str) {
    return htmlspecialchars($str, ENT_QUOTES, 'UTF-8');
}

// 使用
echo escapeHtml($userInput);

// 在HTML属性中使用
echo '<div data-name="' . escapeHtml($userInput) . '">';

// 在JavaScript中使用
echo '<script>var name = ' . json_encode($userInput, JSON_HEX_TAG) . ';</script>';
?>
""",
                "python": """
# Python - HTML编码

# 使用 markupsafe (推荐)
from markupsafe import escape
safe_html = escape(user_input)

# 使用 html 模块
import html
safe_html = html.escape(user_input)

# Django 模板自动转义
# {{ user_input }}  # 自动转义
# {{ user_input|safe }}  # 标记为安全（谨慎使用）

# Jinja2 模板自动转义
# {{ user_input }}  # 自动转义
""",
                "javascript": """
// JavaScript - HTML编码

// 方法1: 创建文本节点
function escapeHtml(str) {
    const div = document.createElement('div');
    div.appendChild(document.createTextNode(str));
    return div.innerHTML;
}

// 方法2: 替换特殊字符
function escapeHtml(str) {
    return str
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

// 使用
element.textContent = userInput;  // 安全
// element.innerHTML = userInput;  // 危险!

// React - 自动转义
// <div>{userInput}</div>  // 安全
// <div dangerouslySetInnerHTML={{__html: userInput}} />  // 危险!
""",
                "csp": """
# Content-Security-Policy 配置

# Nginx
add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'nonce-random123'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:;";

# Apache
Header always set Content-Security-Policy "default-src 'self'; script-src 'self' 'nonce-random123'; style-src 'self' 'unsafe-inline';"

# Node.js
res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self' 'nonce-random123';");
"""
            }
        }
    },
    "SSRF": {
        "default": {
            "title": "SSRF（服务端请求伪造）漏洞修复",
            "description": "验证和限制URL白名单，禁止访问内网",
            "solutions": {
                "python": """
# Python - SSRF防护
import ipaddress
from urllib.parse import urlparse
import socket

def is_safe_url(url, allowed_domains=None):
    \"\"\"
    验证URL是否安全，防止SSRF
    \"\"\"
    try:
        parsed = urlparse(url)

        # 只允许http/https
        if parsed.scheme not in ['http', 'https']:
            return False

        # 解析域名
        hostname = parsed.hostname
        if not hostname:
            return False

        # 检查是否是IP地址
        try:
            ip = ipaddress.ip_address(hostname)
            # 禁止内网IP
            if ip.is_private or ip.is_loopback or ip.is_link_local:
                return False
            # 禁止云服务元数据
            if str(ip).startswith('169.254.'):
                return False
        except ValueError:
            # 是域名，检查白名单
            if allowed_domains:
                if not any(hostname.endswith(d) for d in allowed_domains):
                    return False

        # DNS解析检查
        resolved_ip = socket.gethostbyname(hostname)
        ip = ipaddress.ip_address(resolved_ip)
        if ip.is_private or ip.is_loopback:
            return False

        return True
    except Exception:
        return False

# 使用示例
allowed_domains = ['example.com', 'api.example.com']
if is_safe_url(user_url, allowed_domains):
    # 安全，可以请求
    response = requests.get(user_url, timeout=5)
else:
    # 不安全，拒绝请求
    raise ValueError("URL not allowed")
""",
                "nodejs": """
// Node.js - SSRF防护
const { URL } = require('url');
const dns = require('dns').promises;
const ipaddr = require('ipaddr.js');

async function isSafeUrl(urlString, allowedDomains = []) {
    try {
        const url = new URL(urlString);

        // 只允许http/https
        if (!['http:', 'https:'].includes(url.protocol)) {
            return false;
        }

        // DNS解析
        const { address } = await dns.lookup(url.hostname);

        // 检查IP
        const ip = ipaddr.parse(address);
        const range = ip.range();

        // 禁止内网IP
        if (['private', 'loopback', 'linkLocal', 'uniqueLocal'].includes(range)) {
            return false;
        }

        // 检查域名白名单
        if (allowedDomains.length > 0) {
            const isAllowed = allowedDomains.some(d => url.hostname.endsWith(d));
            if (!isAllowed) return false;
        }

        return true;
    } catch (err) {
        return false;
    }
}

// 使用示例
const allowedDomains = ['example.com', 'api.example.com'];
if (await isSafeUrl(userUrl, allowedDomains)) {
    // 安全
    const response = await fetch(userUrl);
} else {
    throw new Error('URL not allowed');
}
""",
                "java": """
// Java - SSRF防护
import java.net.*;
import java.util.List;

public class SsrfProtection {
    public static boolean isSafeUrl(String urlStr, List<String> allowedDomains) throws Exception {
        URL url = new URL(urlStr);

        // 只允许http/https
        if (!url.getProtocol().equals("http") && !url.getProtocol().equals("https")) {
            return false;
        }

        // DNS解析
        InetAddress address = InetAddress.getByName(url.getHost());

        // 检查是否是内网IP
        if (address.isLoopbackAddress() || address.isSiteLocalAddress() || address.isLinkLocalAddress()) {
            return false;
        }

        // 检查域名白名单
        if (allowedDomains != null && !allowedDomains.isEmpty()) {
            boolean isAllowed = allowedDomains.stream()
                .anyMatch(d -> url.getHost().endsWith(d));
            if (!isAllowed) return false;
        }

        return true;
    }
}
"""
            }
        }
    },
    "命令执行": {
        "default": {
            "title": "命令注入漏洞修复",
            "description": "使用白名单验证输入，避免调用系统命令",
            "solutions": {
                "python": """
# Python - 安全执行命令
import subprocess
import shlex
import re

def safe_execute(command, args):
    \"\"\"
    安全执行命令，防止命令注入
    \"\"\"
    # 验证命令白名单
    allowed_commands = ['ping', 'nslookup', 'traceroute']
    if command not in allowed_commands:
        raise ValueError(f"Command not allowed: {command}")

    # 验证参数
    for arg in args:
        if not re.match(r'^[a-zA-Z0-9._-]+$', arg):
            raise ValueError(f"Invalid argument: {arg}")

    # 使用列表形式执行，避免shell注入
    result = subprocess.run(
        [command] + args,
        capture_output=True,
        text=True,
        timeout=10
    )
    return result.stdout

# 使用示例
# 错误: os.system(f"ping {user_input}")  # 危险!
# 正确:
output = safe_execute('ping', ['-c', '1', user_input])
""",
                "nodejs": """
// Node.js - 安全执行命令
const { execFile } = require('child_process');
const util = require('util');
const execFilePromise = util.promisify(execFile);

async function safeExecute(command, args) {
    // 验证命令白名单
    const allowedCommands = ['ping', 'nslookup', 'traceroute'];
    if (!allowedCommands.includes(command)) {
        throw new Error('Command not allowed');
    }

    // 验证参数
    const safeArgRegex = /^[a-zA-Z0-9._-]+$/;
    for (const arg of args) {
        if (!safeArgRegex.test(arg)) {
            throw new Error('Invalid argument');
        }
    }

    // 使用execFile而不是exec
    const { stdout } = await execFilePromise(command, args, { timeout: 10000 });
    return stdout;
}

// 使用示例
// 错误: exec(`ping ${userInput}`)  # 危险!
// 正确:
const output = await safeExecute('ping', ['-c', '1', userInput]);
""",
                "php": """
<?php
// PHP - 安全执行命令

function safeExecute($command, $args) {
    // 验证命令白名单
    $allowedCommands = ['ping', 'nslookup', 'traceroute'];
    if (!in_array($command, $allowedCommands)) {
        throw new Exception('Command not allowed');
    }

    // 验证参数
    foreach ($args as $arg) {
        if (!preg_match('/^[a-zA-Z0-9._-]+$/', $arg)) {
            throw new Exception('Invalid argument');
        }
    }

    // 使用escapeshellarg转义参数
    $escapedArgs = array_map('escapeshellarg', $args);
    $cmd = escapeshellcmd($command) . ' ' . implode(' ', $escapedArgs);

    return shell_exec($cmd);
}

// 使用示例
// 错误: system("ping $userInput");  # 危险!
// 正确:
$output = safeExecute('ping', ['-c', '1', $userInput]);
?>
"""
            }
        }
    },
    "信息泄露": {
        "default": {
            "title": "信息泄露漏洞修复",
            "description": "移除敏感信息，配置错误页面",
            "solutions": {
                "nginx": """
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
location ~ /\\. {
    deny all;
}

location ~* \\.(env|git|svn|htpasswd|bak|sql)$ {
    deny all;
}
""",
                "apache": """
# Apache - 隐藏敏感信息

# 隐藏服务器版本
ServerTokens Prod
ServerSignature Off

# 隐藏 X-Powered-By
Header always unset X-Powered-By

# 禁止访问敏感文件
<FilesMatch "\\.(env|git|svn|htpasswd|bak|sql)$">
    Order allow,deny
    Deny from all
</FilesMatch>

# 自定义错误页面
ErrorDocument 404 /custom_404.html
ErrorDocument 500 /custom_500.html
""",
                "php": """
<?php
// PHP - 隐藏敏感信息

// php.ini 配置
// expose_php = Off
// display_errors = Off
// error_reporting = E_ALL & ~E_NOTICE & ~E_DEPRECATED

// 代码中设置
ini_set('display_errors', 'Off');
error_reporting(E_ALL & ~E_NOTICE & ~E_DEPRECATED);

// 生产环境日志记录
ini_set('log_errors', 'On');
ini_set('error_log', '/var/log/php_errors.log');
?>
""",
            }
        }
    },
    "越权访问": {
        "default": {
            "title": "越权访问漏洞修复",
            "description": "实施权限验证，使用会话管理",
            "solutions": {
                "python": """
# Python - 权限验证

from functools import wraps
from flask import session, abort

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            abort(401)
        return f(*args, **kwargs)
    return decorated_function

def permission_required(permission):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            user = get_user(session['user_id'])
            if not user.has_permission(permission):
                abort(403)
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# 水平越权防护 - 检查资源所有权
def check_resource_ownership(resource_id, user_id):
    resource = get_resource(resource_id)
    if resource.user_id != user_id:
        abort(403)

# 使用示例
@app.route('/api/user/<int:user_id>')
@login_required
def get_user_profile(user_id):
    # 水平越权检查
    if user_id != session['user_id'] and not is_admin():
        abort(403)
    return get_user_data(user_id)
""",
                "nodejs": """
// Node.js - 权限验证中间件

// 登录验证
const requireAuth = (req, res, next) => {
    if (!req.session.userId) {
        return res.status(401).json({ error: 'Unauthorized' });
    }
    next();
};

// 角色验证
const requireRole = (role) => {
    return (req, res, next) => {
        if (req.user.role !== role) {
            return res.status(403).json({ error: 'Forbidden' });
        }
        next();
    };
};

// 水平越权防护
const checkOwnership = (resourceType) => {
    return async (req, res, next) => {
        const resource = await getResource(resourceType, req.params.id);
        if (resource.userId !== req.session.userId && !req.user.isAdmin) {
            return res.status(403).json({ error: 'Forbidden' });
        }
        req.resource = resource;
        next();
    };
};

// 使用示例
app.get('/api/user/:id', requireAuth, checkOwnership('user'), (req, res) => {
    res.json(req.resource);
});
"""
            }
        }
    },
    "弱口令": {
        "default": {
            "title": "弱口令漏洞修复",
            "description": "强制密码复杂度，实施账户锁定",
            "solutions": {
                "python": """
# Python - 密码策略

import re
import hashlib
import secrets

def validate_password(password):
    \"\"\"
    验证密码强度
    \"\"\"
    if len(password) < 12:
        return False, "密码长度至少12位"
    if not re.search(r'[A-Z]', password):
        return False, "密码必须包含大写字母"
    if not re.search(r'[a-z]', password):
        return False, "密码必须包含小写字母"
    if not re.search(r'[0-9]', password):
        return False, "密码必须包含数字"
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False, "密码必须包含特殊字符"
    return True, "密码符合要求"

def hash_password(password):
    \"\"\"
    安全哈希密码
    \"\"\"
    salt = secrets.token_hex(16)
    key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
    return f"{salt}:{key.hex()}"

# 账户锁定
login_attempts = {}

def check_account_lock(username):
    if username in login_attempts:
        attempts, last_attempt = login_attempts[username]
        if attempts >= 5 and time.time() - last_attempt < 1800:  # 30分钟
            return True
    return False

def record_login_attempt(username, success):
    if success:
        login_attempts.pop(username, None)
    else:
        attempts, _ = login_attempts.get(username, (0, 0))
        login_attempts[username] = (attempts + 1, time.time())
""",
                "nodejs": """
// Node.js - 密码策略

const bcrypt = require('bcrypt');
const crypto = require('crypto');

// 密码强度验证
function validatePassword(password) {
    const errors = [];
    if (password.length < 12) errors.push('密码长度至少12位');
    if (!/[A-Z]/.test(password)) errors.push('密码必须包含大写字母');
    if (!/[a-z]/.test(password)) errors.push('密码必须包含小写字母');
    if (!/[0-9]/.test(password)) errors.push('密码必须包含数字');
    if (!/[!@#$%^&*(),.?":{}|<>]/.test(password)) errors.push('密码必须包含特殊字符');
    return { valid: errors.length === 0, errors };
}

// 安全哈希密码
async function hashPassword(password) {
    const salt = await bcrypt.genSalt(12);
    return bcrypt.hash(password, salt);
}

// 账户锁定
const loginAttempts = new Map();

function checkAccountLock(username) {
    const attempts = loginAttempts.get(username);
    if (attempts && attempts.count >= 5 && Date.now() - attempts.lastAttempt < 1800000) {
        return true; // 锁定30分钟
    }
    return false;
}
"""
            }
        }
    },
    "目录遍历": {
        "default": {
            "title": "目录遍历漏洞修复",
            "description": "过滤路径遍历字符，使用白名单",
            "solutions": {
                "python": """
# Python - 防止目录遍历
import os
from pathlib import Path

def safe_path(base_dir, user_path):
    \"\"\"
    安全路径拼接，防止目录遍历
    \"\"\"
    # 规范化路径
    base = Path(base_dir).resolve()
    target = (base / user_path).resolve()

    # 检查是否在基础目录内
    if not str(target).startswith(str(base)):
        raise ValueError("Path traversal detected")

    return target

# 使用示例
try:
    file_path = safe_path('/var/www/uploads', user_input)
    with open(file_path, 'r') as f:
        content = f.read()
except ValueError:
    abort(403)
""",
                "nodejs": """
// Node.js - 防止目录遍历
const path = require('path');
const fs = require('fs');

function safePath(baseDir, userPath) {
    // 规范化路径
    const target = path.resolve(baseDir, userPath);

    // 检查是否在基础目录内
    if (!target.startsWith(path.resolve(baseDir))) {
        throw new Error('Path traversal detected');
    }

    return target;
}

// 使用示例
try {
    const filePath = safePath('/var/www/uploads', userInput);
    const content = fs.readFileSync(filePath, 'utf8');
} catch (err) {
    res.status(403).send('Forbidden');
}
"""
            }
        }
    }
}


def get_remediation(vuln_type: str, sub_type: str = "default") -> dict:
    """
    获取漏洞修复方案

    Args:
        vuln_type: 漏洞类型 (如 SQL注入, XSS, SSRF)
        sub_type: 子类型 (如 Clickjacking, CORS配置错误)

    Returns:
        修复方案字典
    """
    # 首先尝试精确匹配
    if vuln_type in REMEDIATION_TEMPLATES:
        template = REMEDIATION_TEMPLATES[vuln_type]
        if sub_type in template:
            return template[sub_type]
        if "default" in template:
            return template["default"]

    # 模糊匹配
    for key, value in REMEDIATION_TEMPLATES.items():
        if key in vuln_type or vuln_type in key:
            if sub_type in value:
                return value[sub_type]
            if "default" in value:
                return value["default"]

    # 默认返回
    return {
        "title": f"{vuln_type}漏洞修复",
        "description": "请联系安全团队获取具体修复方案",
        "solutions": {}
    }
