# 🎯 自动化漏洞挖掘系统

## 快速开始

### 1. 安装依赖

```bash
cd bug-hunter
pip install requests urllib3
```

### 2. 单目标扫描

```bash
# 完整扫描（子域名 + 存活探测 + 漏洞扫描）
python main.py example.com

# 只枚举子域名
python main.py example.com -m subdomain

# 只检测存活
python main.py example.com -m alive

# 只扫描漏洞（跳过子域名和存活探测）
python main.py example.com -m scan
```

### 3. 批量扫描

```bash
# 创建目标列表文件 targets.txt
echo "example.com" > targets.txt
echo "test.com" >> targets.txt

# 批量扫描
python main.py -l targets.txt
```

## 扫描模式说明

| 模式 | 说明 | 适用场景 |
|------|------|----------|
| `full` | 完整扫描 | 全面评估目标 |
| `subdomain` | 只枚举子域名 | 资产发现 |
| `alive` | 只检测存活 | 快速确认目标 |
| `scan` | 只扫描漏洞 | 已知目标快速扫描 |

## 检测的漏洞类型

### 🔴 Critical
- SQL注入（报错型、时间盲注）
- CORS配置错误（允许凭证）

### 🟠 High
- XSS（反射型）
- 敏感文件泄露（.env, .git/config）
- CORS配置错误（反射Origin）

### 🟡 Medium
- 信息泄露
- CORS配置错误（通配符）
- Clickjacking
- 开放重定向

### 🟢 Low
- 响应头信息泄露
- 服务器版本泄露

## 报告位置

扫描完成后，报告保存在 `reports/` 目录：

- `reports/report_<domain>_<timestamp>.md` - Markdown 格式
- `reports/report_<domain>_<timestamp>.json` - JSON 格式

## 配置文件

编辑 `config.py` 可以自定义：

- 扫描线程数
- 超时时间
- 检测的漏洞类型
- 敏感文件路径
- SQL/XSS Payload

## 注意事项

⚠️ **法律提醒**：
1. 只扫描你有权限的目标
2. 遵守各平台的赏金规则
3. 不要进行破坏性测试
4. 发现漏洞及时报告

## 进阶用法

### 自定义扫描

```python
from vuln_scanner import VulnScanner

scanner = VulnScanner()
target = {"url": "https://example.com"}
vulns = scanner.scan_target(target)

for vuln in vulns:
    print(f"[{vuln.severity}] {vuln.vuln_type}: {vuln.url}")
```

### 添加新的检测模块

在 `vuln_scanner.py` 中添加新的检测方法：

```python
def _check_new_vuln(self, url: str) -> List[Vulnerability]:
    vulns = []
    # 你的检测逻辑
    return vulns
```

然后在 `scan_target` 方法中调用。

## 常见问题

**Q: 扫描速度太慢？**
A: 调整 `config.py` 中的 `max_threads`，但不要设置太高以免被封。

**Q: 误报太多？**
A: 减少 Payload 数量，或在 `config.py` 中禁用某些检测。

**Q: 如何添加新的 Payload？**
A: 在 `config.py` 中的相应列表添加。

## 工具链推荐

配合以下工具使用效果更佳：

- **Burp Suite** - 手动测试
- **nuclei** - 模板化扫描
- **ffuf** - 目录爆破
- **sqlmap** - SQL注入测试

## 免责声明

本工具仅供安全研究和授权测试使用。使用者需自行承担使用风险，开发者不对任何滥用行为负责。
