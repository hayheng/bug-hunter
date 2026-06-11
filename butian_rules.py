# -*- coding: utf-8 -*-
"""
补天平台漏洞提交规则
"""

# 补天平台漏洞类型
BUTIAN_VULN_TYPES = {
    "SQL注入": {
        "title_format": "【SQL注入】{vendor}存在SQL注入漏洞",
        "required_fields": ["url", "parameter", "injection_type", "payload", "database_info"],
        "description_template": """
## 漏洞描述
{vendor}网站存在SQL注入漏洞，攻击者可通过构造恶意SQL语句获取数据库敏感信息。

## 漏洞URL
{url}

## 注入参数
{parameter}

## 注入类型
{injection_type}

## Payload
```
{payload}
```

## 数据库信息
{database_info}

## 复现步骤
1. 访问漏洞URL
2. 在参数中注入Payload
3. 观察响应结果

## 修复建议
1. 使用参数化查询（Prepared Statements）
2. 使用ORM框架
3. 输入验证和过滤
4. 最小权限原则配置数据库用户
""",
        "severity": "高危",
        "prize_range": "500-5000",
    },
    "XSS": {
        "title_format": "【XSS】{vendor}存在{type}XSS漏洞",
        "required_fields": ["url", "type", "payload", "browser_info"],
        "description_template": """
## 漏洞描述
{vendor}网站存在{type}XSS漏洞，攻击者可注入恶意脚本窃取用户Cookie或进行钓鱼攻击。

## 漏洞URL
{url}

## XSS类型
{type}

## Payload
```
{payload}
```

## 浏览器信息
{browser_info}

## 复现步骤
1. 访问漏洞URL
2. 注入XSS Payload
3. 观察弹窗或执行结果

## 修复建议
1. 对输出进行HTML编码
2. 使用CSP（内容安全策略）
3. 设置HttpOnly Cookie
4. 输入验证和过滤
""",
        "severity": "中危",
        "prize_range": "200-2000",
    },
    "信息泄露": {
        "title_format": "【信息泄露】{vendor}存在{leak_type}泄露",
        "required_fields": ["url", "leak_type", "leaked_data"],
        "description_template": """
## 漏洞描述
{vendor}网站存在信息泄露漏洞，可泄露{leak_type}等敏感信息。

## 漏洞URL
{url}

## 泄露类型
{leak_type}

## 泄露数据（已脱敏）
```
{leaked_data}
```

## 复现步骤
1. 访问漏洞URL
2. 查看响应内容
3. 确认敏感信息泄露

## 修复建议
1. 删除敏感文件
2. 配置访问控制
3. 自定义错误页面
4. 移除调试信息
""",
        "severity": "中危",
        "prize_range": "100-1000",
    },
    "未授权访问": {
        "title_format": "【未授权访问】{vendor}存在{path}未授权访问漏洞",
        "required_fields": ["url", "path", "access_content"],
        "description_template": """
## 漏洞描述
{vendor}网站存在未授权访问漏洞，攻击者无需登录即可访问{path}，获取敏感数据或执行管理操作。

## 漏洞URL
{url}

## 访问路径
{path}

## 访问内容
{access_content}

## 复现步骤
1. 直接访问漏洞URL
2. 无需登录认证
3. 可查看/操作敏感数据

## 修复建议
1. 添加身份认证
2. 实施访问控制
3. 配置IP白名单
4. 启用多因素认证
""",
        "severity": "高危",
        "prize_range": "500-3000",
    },
    "命令执行": {
        "title_format": "【命令执行】{vendor}存在远程命令执行漏洞",
        "required_fields": ["url", "parameter", "payload", "command_result"],
        "description_template": """
## 漏洞描述
{vendor}网站存在远程命令执行漏洞，攻击者可执行任意系统命令，完全控制服务器。

## 漏洞URL
{url}

## 注入参数
{parameter}

## Payload
```
{payload}
```

## 命令执行结果
```
{command_result}
```

## 复现步骤
1. 访问漏洞URL
2. 在参数中注入命令
3. 查看命令执行结果

## 修复建议
1. 使用白名单验证输入
2. 避免调用系统命令
3. 使用参数化API
4. 实施最小权限原则
""",
        "severity": "严重",
        "prize_range": "1000-10000",
    },
    "SSRF": {
        "title_format": "【SSRF】{vendor}存在服务端请求伪造漏洞",
        "required_fields": ["url", "parameter", "payload", "internal_access"],
        "description_template": """
## 漏洞描述
{vendor}网站存在SSRF漏洞，攻击者可利用服务器发起任意请求，访问内部网络资源或云服务元数据。

## 漏洞URL
{url}

## 注入参数
{parameter}

## Payload
```
{payload}
```

## 内部访问结果
```
{internal_access}
```

## 复现步骤
1. 访问漏洞URL
2. 在参数中注入内部地址
3. 查看响应结果

## 修复建议
1. 验证和限制URL白名单
2. 禁止访问内部网络
3. 禁用不必要的协议
4. 使用DNS解析验证
""",
        "severity": "高危",
        "prize_range": "500-3000",
    },
    "逻辑漏洞": {
        "title_format": "【逻辑漏洞】{vendor}存在{logic_type}逻辑漏洞",
        "required_fields": ["url", "logic_type", "description", "impact"],
        "description_template": """
## 漏洞描述
{vendor}网站存在{logic_type}逻辑漏洞，{description}

## 漏洞URL
{url}

## 漏洞类型
{logic_type}

## 详细描述
{description}

## 影响范围
{impact}

## 复现步骤
1. 访问漏洞URL
2. 执行特定操作
3. 观察异常行为

## 修复建议
1. 服务端验证业务逻辑
2. 实施防重放攻击
3. 添加验证码机制
4. 记录异常操作日志
""",
        "severity": "中危",
        "prize_range": "200-2000",
    },
    "配置错误": {
        "title_format": "【配置错误】{vendor}存在{config_type}配置错误",
        "required_fields": ["url", "config_type", "evidence"],
        "description_template": """
## 漏洞描述
{vendor}网站存在{config_type}配置错误，可能导致安全风险。

## 漏洞URL
{url}

## 配置问题
{config_type}

## 证据
```
{evidence}
```

## 复现步骤
1. 访问漏洞URL
2. 检查响应头/配置信息
3. 确认配置问题

## 修复建议
{remediation}
""",
        "severity": "低危",
        "prize_range": "50-300",
    },
}

# 补天平台审核标准
AUDIT_CRITERIA = {
    "accepted": [
        "漏洞可实际利用",
        "有明确的复现步骤",
        "提供截图/视频证据",
        "影响范围明确",
        "首次发现（非重复）",
    ],
    "rejected": [
        "纯理论漏洞，无实际利用场景",
        "已被公开或已修复的漏洞",
        "自动化扫描工具批量提交",
        "Self-XSS（自己才能触发）",
        "仅影响极旧浏览器",
        "社工钓鱼类问题",
        "功能设计如此（By Design）",
        "无法证明实际危害",
    ],
}

# 补天平台漏洞等级标准
SEVERITY_STANDARDS = {
    "严重": {
        "description": "可直接获取服务器权限、大量数据泄露",
        "examples": ["RCE", "SQL注入（可获取数据）", "反序列化", "任意文件上传"],
        "prize": "1000-10000",
    },
    "高危": {
        "description": "可获取敏感数据、影响业务安全",
        "examples": ["XSS（存储型）", "SSRF", "未授权访问", "逻辑漏洞（支付）"],
        "prize": "500-5000",
    },
    "中危": {
        "description": "存在一定安全风险，需要特定条件",
        "examples": ["XSS（反射型）", "信息泄露", "配置错误", "逻辑漏洞"],
        "prize": "200-1000",
    },
    "低危": {
        "description": "安全风险较低，影响有限",
        "examples": ["安全头缺失", "版本信息泄露", "Clickjacking"],
        "prize": "50-300",
    },
}


def get_vuln_template(vuln_type: str) -> dict:
    """获取漏洞模板"""
    return BUTIAN_VULN_TYPES.get(vuln_type, BUTIAN_VULN_TYPES.get("配置错误"))


def format_vuln_title(vuln_type: str, vendor: str, **kwargs) -> str:
    """格式化漏洞标题"""
    template = get_vuln_template(vuln_type)
    title_format = template.get("title_format", f"【{vuln_type}】{vendor}存在漏洞")

    # 提供默认值
    defaults = {
        "leak_type": "敏感信息",
        "type": "反射型",
        "path": "/",
        "logic_type": "业务逻辑",
        "config_type": "安全配置",
    }

    # 合并参数
    format_args = {"vendor": vendor}
    format_args.update(defaults)
    format_args.update(kwargs)

    try:
        return title_format.format(**format_args)
    except KeyError:
        # 如果格式化失败，返回默认标题
        return f"【{vuln_type}】{vendor}存在漏洞"


def format_vuln_description(vuln_type: str, **kwargs) -> str:
    """格式化漏洞描述"""
    template = get_vuln_template(vuln_type)
    description_template = template.get("description_template", "")

    # 提供默认值
    defaults = {
        "vendor": "未知",
        "url": "未知",
        "parameter": "未知",
        "injection_type": "未知",
        "payload": "未知",
        "database_info": "未知",
        "type": "反射型",
        "browser_info": "Chrome 最新版",
        "leak_type": "敏感信息",
        "leaked_data": "未知",
        "path": "/",
        "access_content": "未知",
        "command_result": "未知",
        "internal_access": "未知",
        "logic_type": "业务逻辑",
        "description": "未知",
        "impact": "未知",
        "config_type": "安全配置",
        "remediation": "请联系安全团队获取修复方案",
        "evidence": "未知",
    }

    # 合并参数
    format_args = defaults.copy()
    format_args.update(kwargs)

    try:
        return description_template.format(**format_args)
    except KeyError as e:
        # 如果格式化失败，返回简化描述
        return f"## 漏洞描述\n{format_args.get('vendor', '未知')}存在{vuln_type}漏洞\n\n## 漏洞URL\n{format_args.get('url', '未知')}\n\n## 证据\n{format_args.get('evidence', '未知')}"


def check_vuln_quality(vuln: dict) -> tuple:
    """检查漏洞质量"""
    issues = []

    # 检查必要字段
    vuln_type = vuln.get("type", "")
    template = get_vuln_template(vuln_type)
    required_fields = template.get("required_fields", [])

    for field in required_fields:
        if not vuln.get(field):
            issues.append(f"缺少必要字段: {field}")

    # 检查证据
    evidence = vuln.get("evidence", "")
    if len(evidence) < 10:
        issues.append("证据不足，需要更详细的截图或描述")

    # 检查URL
    url = vuln.get("url", "")
    if not url.startswith("http"):
        issues.append("URL格式不正确")

    # 检查严重程度
    severity = vuln.get("severity", "")
    if severity not in ["严重", "高危", "中危", "低危"]:
        issues.append("严重程度不正确")

    return len(issues) == 0, issues


if __name__ == "__main__":
    # 测试
    print("补天平台漏洞类型:")
    for vuln_type, info in BUTIAN_VULN_TYPES.items():
        print(f"  - {vuln_type}: {info['severity']} ({info['prize_range']})")
