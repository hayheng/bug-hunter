# 软件漏洞扫描指南

## 支持的软件类型

| 类型 | 文件格式 | 扫描内容 | 工具 |
|------|----------|----------|------|
| Android APK | .apk | 敏感信息、配置错误、WebView漏洞 | apktool, jadx |
| Windows EXE | .exe | 字符串分析、敏感信息 | strings, Python |
| .NET 程序 | .exe, .dll | 反编译分析、敏感信息 | dnSpy, ILSpy |
| Electron应用 | 目录或.asar | 源码分析、配置检查 | asar |
| 微信小程序 | .wxapkg或目录 | 源码分析、配置检查 | wxappUnpacker |
| 支付宝小程序 | 目录 | 源码分析、配置检查 | - |

---

## 安装依赖

### 基础依赖
```bash
pip install frida-tools
```

### Android APK 扫描
```bash
# 方式1: 使用 scoop 安装
scoop install apktool

# 方式2: 手动下载
# 下载地址: https://ibotpeaches.github.io/Apktool/
# 将 apktool.jar 放到 tools 目录
```

### .NET 程序扫描
```bash
# 下载 dnSpy
# https://github.com/dnSpy/dnSpy/releases

# 或下载 ILSpy
# https://github.com/icsharpcode/ILSpy/releases

# 解压到 tools 目录
```

### Electron 应用扫描
```bash
npm install -g asar
```

### 微信小程序扫描
```bash
# 克隆 wxappUnpacker
git clone https://github.com/nicebug/wxappUnpacker.git D:\bug-hunter\tools\wxappUnpacker
cd D:\bug-hunter\tools\wxappUnpacker
npm install
```

---

## 使用方法

### 命令行使用

```bash
# 基础扫描
python software_scanner.py <软件路径>

# 深度扫描（反编译分析）
python software_scanner.py <软件路径> --deep
```

### 示例

```bash
# 扫描 Android APK
python software_scanner.py app.apk
python software_scanner.py app.apk --deep

# 扫描 Windows EXE
python software_scanner.py app.exe

# 扫描 .NET 程序
python software_scanner.py app.exe
python software_scanner.py app.dll

# 扫描 Electron 应用
python software_scanner.py ./electron-app/
python software_scanner.py app.asar

# 扫描微信小程序
python software_scanner.py app.wxapkg
python software_scanner.py ./miniapp/
```

---

## 扫描内容

### Android APK
- [x] 敏感信息泄露
- [x] 不安全配置 (debuggable, allowBackup)
- [x] 硬编码凭证
- [x] 不安全网络通信
- [x] 组件暴露
- [x] WebView漏洞
- [x] 权限分析
- [x] 反编译分析 (深度扫描)

### Windows EXE
- [x] 字符串分析 (ASCII, Unicode, 中文)
- [x] URL/IP泄露
- [x] API Key泄露
- [x] 私钥泄露
- [x] 加密信息分析
- [x] 代码特征分析

### .NET 程序
- [x] 反编译分析
- [x] 连接字符串泄露
- [x] 配置文件分析
- [x] SQL 注入风险
- [x] 命令注入风险
- [x] 弱加密算法

### Electron 应用
- [x] 源码敏感信息
- [x] 配置文件检查
- [x] nodeIntegration检查
- [x] webSecurity检查
- [x] .env文件检查

### 微信小程序
- [x] 源码敏感信息
- [x] AppID泄露
- [x] AppSecret泄露
- [x] 云函数敏感信息
- [x] 调试模式检查

---

## Frida 动态分析

### 安装
```bash
pip install frida-tools
```

### 使用
```bash
# 生成 Hook 脚本
python frida_scanner.py <target> [platform]

# 示例
python frida_scanner.py com.example.app android
python frida_scanner.py app.exe windows
```

### 生成的 Hook 脚本
- `scripts/android_hooks.js` - Android Hook
- `scripts/ios_hooks.js` - iOS Hook
- `scripts/windows_hooks.js` - Windows Hook

### 执行 Hook
```bash
# Android
frida -U -f com.example.app -l scripts/android_hooks.js --no-pause

# iOS
frida -U com.example.app -l scripts/ios_hooks.js

# Windows
frida app.exe -l scripts/windows_hooks.js
```

---

## 输出示例

```
[*] 检测到软件类型: android
[*] 开始扫描APK: com.example.app
[*] 反编译APK...
[*] 扫描敏感信息...
[*] 扫描不安全配置...
[*] 扫描硬编码凭证...
[*] 扫描不安全网络通信...
[*] 扫描组件暴露...
[*] 扫描WebView漏洞...
[*] 扫描完成，发现 5 个漏洞

[High] 信息泄露: 发现API Key硬编码
[High] 配置错误: 应用开启了debug模式
[Medium] 配置错误: 应用允许备份
[Medium] 配置错误: WebView存在JavaScript启用漏洞
[High] 信息泄露: 发现密码硬编码
```

---

## 注意事项

1. **仅用于授权测试** - 请确保你有权扫描目标软件
2. **保护隐私** - 不要泄露扫描结果中的敏感信息
3. **及时报告** - 发现漏洞后及时报告给厂商
4. **遵守法律** - 遵守当地法律法规

---

## 常见问题

### Q: apktool 未安装怎么办？
A: 下载 apktool.jar 并放到 tools 目录，或使用 scoop 安装：`scoop install apktool`

### Q: asar 未安装怎么办？
A: 运行 `npm install -g asar` 安装

### Q: wxappUnpacker 未安装怎么办？
A: 克隆仓库到 `D:\bug-hunter\tools\wxappUnpacker` 并运行 `npm install`

### Q: Frida 未安装怎么办？
A: 运行 `pip install frida-tools` 安装

### Q: 扫描结果太多误报怎么办？
A: 可以调整扫描规则，或手动验证每个漏洞
