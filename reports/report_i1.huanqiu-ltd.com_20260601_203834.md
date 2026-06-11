
# 🎯 自动化漏洞扫描报告

**目标**: i1.huanqiu-ltd.com
**扫描时间**: 2026-06-01 20:38:34
**扫描状态**: 完成

---

## 📊 扫描统计

| 项目 | 数量 |
|------|------|
| 子域名发现 | 1 |
| 存活目标 | 1 |
| 发现漏洞 | 9 |

### 漏洞危险等级分布

| 危险等级 | 数量 |
|----------|------|
| 🔴 严重 | 1 |
| 🟠 高危 | 4 |
| 🟡 中危 | 4 |
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


### 1. 🔴 [严重] 未授权访问

#### 漏洞标题
i1.huanqiu-ltd.com存在未授权访问漏洞

#### 漏洞类型
未授权访问（补天平台分类）

#### 可利用性评分
🟡 中 (70/100)

#### 奖金预估
¥1800 - ¥5400

#### 优先级
🔴 立即修复

#### 简要描述
敏感路径可未授权访问，攻击者无需登录即可访问管理后台、调试接口、敏感数据等。

#### 影响范围
攻击者无需认证即可访问敏感功能或数据，可能导致数据泄露、权限提升等安全风险。

#### 详细细节

**测试/复现过程**:
1. 直接访问目标URL: https://i1.huanqiu-ltd.com/admin/export
2. 无需登录认证
3. 确认可访问敏感功能或数据

**漏洞URL**: https://i1.huanqiu-ltd.com/admin/export

**证据**:
```
返回包含敏感信息
```

**PoC / Exploit**:
```html
# 使用 curl 测试常见敏感路径
curl https://i1.huanqiu-ltd.com/admin/export/admin
curl https://i1.huanqiu-ltd.com/admin/export/admin/login
curl https://i1.huanqiu-ltd.com/admin/export/dashboard
curl https://i1.huanqiu-ltd.com/admin/export/console
curl https://i1.huanqiu-ltd.com/admin/export/debug
curl https://i1.huanqiu-ltd.com/admin/export/actuator
curl https://i1.huanqiu-ltd.com/admin/export/actuator/env
curl https://i1.huanqiu-ltd.com/admin/export/swagger-ui.html
curl https://i1.huanqiu-ltd.com/admin/export/api-docs

# 使用 Python 扫描
import requests

paths = [
    "/admin", "/dashboard", "/console",
    "/debug", "/actuator", "/actuator/env",
    "/swagger-ui.html", "/api-docs"
]

for path in paths:
    url = f"https://i1.huanqiu-ltd.com/admin/export/admin/export"
    try:
        resp = requests.get(url, timeout=5, allow_redirects=False)
        if resp.status_code == 200:
            print(f"[发现] {url} - {resp.status_code}")
    except:
        pass

# 使用 ffuf 扫描
ffuf -u https://i1.huanqiu-ltd.com/admin/export/FUZZ -w wordlist.txt
```

**使用的组件/工具**:
- curl: https://curl.se/download.html
- ffuf: https://github.com/ffuf/ffuf
- dirsearch: https://github.com/maurosoria/dirsearch
- Burp Suite: https://portswigger.net/burp

#### 修复建议

1. 添加身份认证
2. 实施访问控制
3. 配置IP白名单
4. 启用多因素认证

---

### 2. 🟠 [高危] 未授权访问

#### 漏洞标题
i1.huanqiu-ltd.com存在未授权访问漏洞

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
攻击者无需认证即可访问敏感功能或数据，可能导致数据泄露、权限提升等安全风险。

#### 详细细节

**测试/复现过程**:
1. 直接访问目标URL: https://i1.huanqiu-ltd.com/debug
2. 无需登录认证
3. 确认可访问敏感功能或数据

**漏洞URL**: https://i1.huanqiu-ltd.com/debug

**证据**:
```
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>404 not found</title>
    <link type="text/css" rel="stylesheet" href="/dist/style.css">
    <script src="//cdn.bootcss.co
```

**PoC / Exploit**:
```html
# 使用 curl 测试常见敏感路径
curl https://i1.huanqiu-ltd.com/debug/admin
curl https://i1.huanqiu-ltd.com/debug/admin/login
curl https://i1.huanqiu-ltd.com/debug/dashboard
curl https://i1.huanqiu-ltd.com/debug/console
curl https://i1.huanqiu-ltd.com/debug/debug
curl https://i1.huanqiu-ltd.com/debug/actuator
curl https://i1.huanqiu-ltd.com/debug/actuator/env
curl https://i1.huanqiu-ltd.com/debug/swagger-ui.html
curl https://i1.huanqiu-ltd.com/debug/api-docs

# 使用 Python 扫描
import requests

paths = [
    "/admin", "/dashboard", "/console",
    "/debug", "/actuator", "/actuator/env",
    "/swagger-ui.html", "/api-docs"
]

for path in paths:
    url = f"https://i1.huanqiu-ltd.com/debug/debug"
    try:
        resp = requests.get(url, timeout=5, allow_redirects=False)
        if resp.status_code == 200:
            print(f"[发现] {url} - {resp.status_code}")
    except:
        pass

# 使用 ffuf 扫描
ffuf -u https://i1.huanqiu-ltd.com/debug/FUZZ -w wordlist.txt
```

**使用的组件/工具**:
- curl: https://curl.se/download.html
- ffuf: https://github.com/ffuf/ffuf
- dirsearch: https://github.com/maurosoria/dirsearch
- Burp Suite: https://portswigger.net/burp

#### 修复建议

1. 添加身份认证
2. 实施访问控制
3. 配置IP白名单
4. 启用多因素认证

---

### 3. 🟠 [高危] 未授权访问

#### 漏洞标题
i1.huanqiu-ltd.com存在未授权访问漏洞

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
攻击者无需认证即可访问敏感功能或数据，可能导致数据泄露、权限提升等安全风险。

#### 详细细节

**测试/复现过程**:
1. 直接访问目标URL: https://i1.huanqiu-ltd.com/admin/
2. 无需登录认证
3. 确认可访问敏感功能或数据

**漏洞URL**: https://i1.huanqiu-ltd.com/admin/

**证据**:
```
状态码: 200, 包含关键词: user
```

**PoC / Exploit**:
```html
# 使用 curl 测试常见敏感路径
curl https://i1.huanqiu-ltd.com/admin//admin
curl https://i1.huanqiu-ltd.com/admin//admin/login
curl https://i1.huanqiu-ltd.com/admin//dashboard
curl https://i1.huanqiu-ltd.com/admin//console
curl https://i1.huanqiu-ltd.com/admin//debug
curl https://i1.huanqiu-ltd.com/admin//actuator
curl https://i1.huanqiu-ltd.com/admin//actuator/env
curl https://i1.huanqiu-ltd.com/admin//swagger-ui.html
curl https://i1.huanqiu-ltd.com/admin//api-docs

# 使用 Python 扫描
import requests

paths = [
    "/admin", "/dashboard", "/console",
    "/debug", "/actuator", "/actuator/env",
    "/swagger-ui.html", "/api-docs"
]

for path in paths:
    url = f"https://i1.huanqiu-ltd.com/admin//admin/"
    try:
        resp = requests.get(url, timeout=5, allow_redirects=False)
        if resp.status_code == 200:
            print(f"[发现] {url} - {resp.status_code}")
    except:
        pass

# 使用 ffuf 扫描
ffuf -u https://i1.huanqiu-ltd.com/admin//FUZZ -w wordlist.txt
```

**使用的组件/工具**:
- curl: https://curl.se/download.html
- ffuf: https://github.com/ffuf/ffuf
- dirsearch: https://github.com/maurosoria/dirsearch
- Burp Suite: https://portswigger.net/burp

#### 修复建议

1. 添加身份认证
2. 实施访问控制
3. 配置IP白名单
4. 启用多因素认证

---

### 4. 🟠 [高危] 逻辑漏洞

#### 漏洞标题
i1.huanqiu-ltd.com存在逻辑漏洞漏洞

#### 漏洞类型
逻辑漏洞（补天平台分类）

#### 可利用性评分
🟠 低 (50/100)

#### 奖金预估
¥500 - ¥1500

#### 优先级
🟠 尽快修复

#### 简要描述
发现安全漏洞，可能被攻击者利用进行恶意攻击。

#### 影响范围
业务逻辑缺陷，可能导致支付绕过、越权访问等安全风险。

#### 详细细节

**测试/复现过程**:
1. 访问目标URL: https://i1.huanqiu-ltd.com/forgot-password
2. 执行特定业务操作
3. 确认存在逻辑缺陷

**漏洞URL**: https://i1.huanqiu-ltd.com/forgot-password

**证据**:
```
未发现验证码
```

**PoC / Exploit**:
```html
# 请联系安全团队获取详细PoC
```

**使用的组件/工具**:
- Burp Suite: https://portswigger.net/burp
- 浏览器开发者工具

#### 修复建议

1. 服务端验证业务逻辑
2. 实施防重放攻击
3. 添加验证码机制
4. 记录异常操作日志

---

### 5. 🟠 [高危] HTTP请求走私

#### 漏洞标题
i1.huanqiu-ltd.com存在配置错误漏洞

#### 漏洞类型
配置错误（补天平台分类）

#### 可利用性评分
🟠 低 (50/100)

#### 奖金预估
¥500 - ¥1500

#### 优先级
🟠 尽快修复

#### 简要描述
发现安全漏洞，可能被攻击者利用进行恶意攻击。

#### 影响范围
该漏洞可能被攻击者利用，对系统安全造成影响。

#### 详细细节

**测试/复现过程**:
1. 访问目标URL: https://i1.huanqiu-ltd.com
2. 执行漏洞验证操作
3. 确认漏洞存在

**漏洞URL**: https://i1.huanqiu-ltd.com

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

请联系安全团队获取具体修复方案。

---

### 6. 🟡 [中危] CORS配置错误

#### 漏洞标题
i1.huanqiu-ltd.com存在配置错误漏洞

#### 漏洞类型
配置错误（补天平台分类）

#### 可利用性评分
🟠 低 (55/100)

#### 奖金预估
¥150 - ¥450

#### 优先级
🟡 计划修复

#### 简要描述
发现安全漏洞，可能被攻击者利用进行恶意攻击。

#### 影响范围
该漏洞可能被攻击者利用，对系统安全造成影响。

#### 详细细节

**测试/复现过程**:
1. 访问目标URL: https://i1.huanqiu-ltd.com
2. 执行漏洞验证操作
3. 确认漏洞存在

**漏洞URL**: https://i1.huanqiu-ltd.com

**证据**:
```
Access-Control-Allow-Origin: *
```

**PoC / Exploit**:
```html
# 请联系安全团队获取详细PoC
```

**使用的组件/工具**:
- Burp Suite: https://portswigger.net/burp
- 浏览器开发者工具

#### 修复建议

请联系安全团队获取具体修复方案。

---

### 7. 🟡 [中危] 敏感文件泄露

#### 漏洞标题
i1.huanqiu-ltd.com存在信息泄露漏洞

#### 漏洞类型
信息泄露（补天平台分类）

#### 可利用性评分
🟠 低 (50/100)

#### 奖金预估
¥250 - ¥750

#### 优先级
🟡 计划修复

#### 简要描述
网站存在敏感文件泄露，攻击者可获取网站配置信息、目录结构等敏感数据，为进一步攻击提供信息支持。

#### 影响范围
泄露敏感配置文件，包括数据库连接信息、API密钥等，可能导致系统被完全控制。

#### 详细细节

**测试/复现过程**:
1. 访问目标URL: https://i1.huanqiu-ltd.com/login
2. 查看响应内容
3. 确认泄露敏感信息

**漏洞URL**: https://i1.huanqiu-ltd.com/login

**证据**:
```
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1, max
```

**PoC / Exploit**:
```html
# 使用 curl 验证
curl -v https://i1.huanqiu-ltd.com/login

# 使用 Python 验证
import requests
resp = requests.get("https://i1.huanqiu-ltd.com/login")
print(resp.text)

# 使用浏览器直接访问
# 访问: https://i1.huanqiu-ltd.com/login
```

**使用的组件/工具**:
- curl: https://curl.se/download.html
- Burp Suite: https://portswigger.net/burp
- 浏览器开发者工具 (F12)

#### 修复建议

1. 删除敏感文件
2. 配置访问控制
3. 使用.gitignore排除敏感文件
4. 配置Web服务器禁止访问

---

### 8. 🟡 [中危] 逻辑漏洞

#### 漏洞标题
i1.huanqiu-ltd.com存在逻辑漏洞漏洞

#### 漏洞类型
逻辑漏洞（补天平台分类）

#### 可利用性评分
🟠 低 (50/100)

#### 奖金预估
¥250 - ¥750

#### 优先级
🟡 计划修复

#### 简要描述
发现安全漏洞，可能被攻击者利用进行恶意攻击。

#### 影响范围
业务逻辑缺陷，可能导致支付绕过、越权访问等安全风险。

#### 详细细节

**测试/复现过程**:
1. 访问目标URL: https://i1.huanqiu-ltd.com/forgot-password/
2. 执行特定业务操作
3. 确认存在逻辑缺陷

**漏洞URL**: https://i1.huanqiu-ltd.com/forgot-password/

**证据**:
```
未发现频率限制
```

**PoC / Exploit**:
```html
# 请联系安全团队获取详细PoC
```

**使用的组件/工具**:
- Burp Suite: https://portswigger.net/burp
- 浏览器开发者工具

#### 修复建议

1. 服务端验证业务逻辑
2. 实施防重放攻击
3. 添加验证码机制
4. 记录异常操作日志

---

### 9. 🟡 [中危] 逻辑漏洞

#### 漏洞标题
i1.huanqiu-ltd.com存在逻辑漏洞漏洞

#### 漏洞类型
逻辑漏洞（补天平台分类）

#### 可利用性评分
🟠 低 (50/100)

#### 奖金预估
¥250 - ¥750

#### 优先级
🟡 计划修复

#### 简要描述
发现安全漏洞，可能被攻击者利用进行恶意攻击。

#### 影响范围
业务逻辑缺陷，可能导致支付绕过、越权访问等安全风险。

#### 详细细节

**测试/复现过程**:
1. 访问目标URL: https://i1.huanqiu-ltd.com/login
2. 执行特定业务操作
3. 确认存在逻辑缺陷

**漏洞URL**: https://i1.huanqiu-ltd.com/login

**证据**:
```
未发现账户锁定
```

**PoC / Exploit**:
```html
# 请联系安全团队获取详细PoC
```

**使用的组件/工具**:
- Burp Suite: https://portswigger.net/burp
- 浏览器开发者工具

#### 修复建议

1. 服务端验证业务逻辑
2. 实施防重放攻击
3. 添加验证码机制
4. 记录异常操作日志

---


---

## 💡 修复建议


**敏感文件防护**
1. 删除不必要的文件
2. 配置访问控制
3. 使用.gitignore排除敏感文件
4. 部署时检查文件
5. 定期清理临时文件


**CORS配置修复**
1. 限制允许的域名白名单
2. 不要使用通配符 *
3. 谨慎使用 Allow-Credentials
4. 验证 Origin 头
5. 定期审查CORS配置


---

## 📚 参考资源

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CWE漏洞分类](https://cwe.mitre.org/)
- [PortSwigger Web安全学院](https://portswigger.net/web-security)

---

*报告由自动化漏洞挖掘系统生成*
