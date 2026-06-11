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

## 🚀 部署建议

### 环境要求

| 项目 | 要求 |
|------|------|
| Python | 3.8+ |
| 操作系统 | Windows / Linux / macOS |
| 内存 | 建议 4GB+ |
| 网络 | 需要稳定的网络连接 |

### 快速部署

#### Windows

```bash
# 1. 克隆仓库
git clone https://github.com/hayheng/bug-hunter.git
cd bug-hunter

# 2. 安装依赖
pip install requests urllib3 pyyaml

# 3. 运行扫描
python main.py example.com
```

#### Linux / macOS

```bash
# 1. 克隆仓库
git clone https://github.com/hayheng/bug-hunter.git
cd bug-hunter

# 2. 创建虚拟环境（推荐）
python3 -m venv venv
source venv/bin/activate

# 3. 安装依赖
pip install requests urllib3 pyyaml

# 4. 运行扫描
python main.py example.com
```

### 使用 Docker（推荐）

```dockerfile
FROM python:3.10-slim

WORKDIR /app

COPY . .

RUN pip install --no-cache-dir requests urllib3 pyyaml

CMD ["python", "main.py", "--help"]
```

```bash
# 构建镜像
docker build -t bug-hunter .

# 运行扫描
docker run -v $(pwd)/reports:/app/reports bug-hunter python main.py example.com
```

### 高级部署

#### 1. 定时扫描（Cron）

```bash
# 每天凌晨3点执行扫描
0 3 * * * cd /path/to/bug-hunter && python main.py -l targets.txt >> /var/log/bug-hunter.log 2>&1
```

#### 2. 后台运行（Linux）

```bash
# 使用 screen
screen -S bug-hunter
python main.py -l targets.txt
# Ctrl+A+D 分离会话

# 使用 nohup
nohup python main.py -l targets.txt > scan.log 2>&1 &
```

#### 3. Windows 计划任务

```powershell
# 使用任务计划程序
schtasks /create /tn "BugHunter" /tr "python D:\bug-hunter\main.py -l D:\bug-hunter\targets.txt" /sc daily /st 03:00
```

### 配置优化

编辑 `config.yaml` 调整扫描参数：

```yaml
scan:
  threads: 50        # 线程数（根据网络调整）
  timeout: 10        # 超时时间
  delay: 0.1         # 请求间隔（避免被封）
```

### 代理配置

如果需要使用代理：

```yaml
proxy:
  enabled: true
  http: "http://127.0.0.1:7890"
  https: "http://127.0.0.1:7890"
```

### 注意事项

⚠️ **法律提醒**：
1. 只扫描你有权限的目标
2. 遵守各平台的赏金规则
3. 不要进行破坏性测试
4. 发现漏洞及时报告

⚠️ **性能建议**：
1. 线程数不要超过 100，避免被封 IP
2. 批量扫描时增加请求间隔
3. 使用代理可以避免 IP 被封

⚠️ **安全建议**：
1. 不要将扫描结果公开上传
2. 定期更新 Nuclei 模板
3. 使用虚拟环境隔离依赖

## 📦 依赖说明

核心依赖：
- `requests` — HTTP 请求
- `urllib3` — HTTP 客户端
- `pyyaml` — 配置文件解析

可选依赖：
- `nuclei` — 模板化漏洞扫描（需要单独安装）

## 🔧 常见部署问题

### Q: 提示找不到模块？
A: 确保在项目目录下运行，且依赖已安装。

### Q: 扫描速度太慢？
A: 调整 `config.yaml` 中的 `threads` 和 `delay`。

### Q: 被目标网站封禁？
A: 降低线程数，增加延迟，或使用代理。

### Q: Nuclei 扫描不工作？
A: 需要单独安装 Nuclei，参考 https://github.com/projectdiscovery/nuclei

## 免责声明

本工具仅供安全研究和授权测试使用。使用者需自行承担使用风险，开发者不对任何滥用行为负责。
