
# 🎯 自动化漏洞扫描报告

**目标**: www.bt.cn
**扫描时间**: 2026-05-31 06:42:48
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
| 🟡 中危 | 3 |
| 🟢 低危 | 0 |
| 🔵 信息 | 0 |

---

## 🌐 子域名列表

```
www.bt.cn

```

---

## 🖥️ 存活目标

| URL | 状态码 | 服务器 | 标题 |
|-----|--------|--------|------|
| https://www.bt.cn |  |  |  |


---

## 🔍 发现的漏洞


### 1. 🟠 [高危] HTTP请求走私

#### 漏洞标题
Bt存在HTTP请求走私

#### 漏洞类型
HTTP请求走私

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

**漏洞URL**: https://www.bt.cn

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
1. 及时修复漏洞
2. 部署安全防护
3. 定期安全审计

---

### 2. 🟡 [中危] 敏感文件泄露

#### 漏洞标题
Bt存在敏感文件泄露

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

**漏洞URL**: https://www.bt.cn/database.sql

**证据**:
```
状态码: 403
```

**PoC / Exploit**:
```html
# 使用 curl 验证
curl -v https://www.bt.cn/database.sql

# 使用 Python 验证
import requests
resp = requests.get("https://www.bt.cn/database.sql")
print(resp.text)

# 使用浏览器直接访问
# 访问: https://www.bt.cn/database.sql
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

### 3. 🟡 [中危] 敏感文件泄露

#### 漏洞标题
Bt存在敏感文件泄露

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

**漏洞URL**: https://www.bt.cn/admin

**证据**:
```
状态码: 200
```

**PoC / Exploit**:
```html
# 使用 curl 验证
curl -v https://www.bt.cn/admin

# 使用 Python 验证
import requests
resp = requests.get("https://www.bt.cn/admin")
print(resp.text)

# 使用浏览器直接访问
# 访问: https://www.bt.cn/admin
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

### 4. 🟡 [中危] 信息泄露

#### 漏洞标题
Bt存在信息泄露

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

**漏洞URL**: https://www.bt.cn

**证据**:
```
ä¸é®éç½®ï¼lamp/lnmpãç½ç«ãæ°æ®åºãftpãsslï¼éè¿webç«¯è½»æ¾ç®¡çæå¡å¨ã"><me
```

**PoC / Exploit**:
```html
# 使用 Python 提取邮箱
import requests
import re

resp = requests.get("https://www.bt.cn")
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


---

## 📚 参考资源

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CWE漏洞分类](https://cwe.mitre.org/)
- [PortSwigger Web安全学院](https://portswigger.net/web-security)

---

*报告由自动化漏洞挖掘系统生成*
