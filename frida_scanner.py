# -*- coding: utf-8 -*-
"""
Frida 动态分析模块
支持: Android, iOS, Windows, macOS, Linux
"""

import os
import re
import json
import time
import tempfile
from typing import List, Dict, Optional


class FridaScanner:
    """Frida 动态分析扫描器"""

    def __init__(self, target: str, platform: str = "auto"):
        self.target = target
        self.platform = platform
        self.vulnerabilities = []
        self.frida = None

    def scan(self) -> List[Dict]:
        """执行扫描"""
        print(f"[*] Frida 动态分析: {self.target}")

        # 检查 Frida 是否安装
        if not self._check_frida():
            print("[!] Frida 未安装")
            print("[*] 安装命令: pip install frida-tools")
            return []

        # 检测平台
        if self.platform == "auto":
            self.platform = self._detect_platform()

        # 执行扫描
        if self.platform == "android":
            self._scan_android()
        elif self.platform == "ios":
            self._scan_ios()
        elif self.platform == "windows":
            self._scan_windows()
        else:
            print(f"[!] 不支持的平台: {self.platform}")

        print(f"[*] 扫描完成，发现 {len(self.vulnerabilities)} 个漏洞")
        return self.vulnerabilities

    def _check_frida(self) -> bool:
        """检查 Frida 是否安装"""
        try:
            import frida
            self.frida = frida
            return True
        except ImportError:
            return False

    def _detect_platform(self) -> str:
        """检测平台"""
        if self.target.endswith('.apk') or 'android' in self.target.lower():
            return "android"
        elif self.target.endswith('.ipa') or 'ios' in self.target.lower():
            return "ios"
        elif self.target.endswith('.exe'):
            return "windows"
        return "android"

    def _scan_android(self):
        """扫描 Android 应用"""
        print("[*] 扫描 Android 应用...")

        # Hook 脚本
        hook_scripts = {
            "ssl_pinning": """
Java.perform(function() {
    // Hook SSL Pinning
    var TrustManager = Java.registerClass({
        name: 'com.frida.TrustManager',
        implements: [Java.use('javax.net.ssl.X509TrustManager')],
        methods: {
            checkClientTrusted: function(chain, authType) {},
            checkServerTrusted: function(chain, authType) {},
            getAcceptedIssuers: function() { return []; }
        }
    });

    var SSLContext = Java.use('javax.net.ssl.SSLContext');
    SSLContext.init.overload(
        '[Ljavax.net.ssl.KeyManager;',
        '[Ljavax.net.ssl.TrustManager;',
        'java.security.SecureRandom'
    ).implementation = function(keyManagers, trustManagers, secureRandom) {
        this.init(keyManagers, [TrustManager.$new()], secureRandom);
        send({type: 'ssl_pinning', status: 'bypassed'});
    };

    send({type: 'ssl_pinning', status: 'hooked'});
});
""",
            "root_detection": """
Java.perform(function() {
    // Hook Root Detection
    var RootDetection = [
        'com.scottyab.rootbeer.RootBeer',
        'com.thirdparty.superuser.SuperUser',
    ];

    RootDetection.forEach(function(className) {
        try {
            var cls = Java.use(className);
            cls.isRooted.implementation = function() {
                send({type: 'root_detection', class: className, status: 'bypassed'});
                return false;
            };
        } catch(e) {}
    });

    send({type: 'root_detection', status: 'hooked'});
});
""",
            "debug_detection": """
Java.perform(function() {
    // Hook Debug Detection
    var Debug = Java.use('android.os.Debug');
    Debug.isDebuggerConnected.implementation = function() {
        send({type: 'debug_detection', status: 'bypassed'});
        return false;
    };

    send({type: 'debug_detection', status: 'hooked'});
});
""",
            "crypto": """
Java.perform(function() {
    // Hook Crypto Operations
    var Cipher = Java.use('javax.crypto.Cipher');
    Cipher.doFinal.overload('[B').implementation = function(input) {
        send({
            type: 'crypto',
            algorithm: this.getAlgorithm(),
            input: input.length + ' bytes'
        });
        return this.doFinal(input);
    };

    send({type: 'crypto', status: 'hooked'});
});
""",
            "network": """
Java.perform(function() {
    // Hook Network Operations
    var URL = Java.use('java.net.URL');
    URL.$init.overload('java.lang.String').implementation = function(url) {
        send({type: 'network', url: url});
        return this.$init(url);
    };

    send({type: 'network', status: 'hooked'});
});
""",
        }

        print("[*] 提示: 请确保设备已连接并运行 frida-server")
        print("[*] 使用方法:")
        print(f"    frida -U -f {self.target} -l hook_script.js --no-pause")

        # 生成 Hook 脚本
        script_path = os.path.join(os.path.dirname(__file__), "scripts", "android_hooks.js")
        os.makedirs(os.path.dirname(script_path), exist_ok=True)

        with open(script_path, 'w', encoding='utf-8') as f:
            f.write("// Frida Android Hook Script\n")
            f.write("// Generated by Bug Hunter\n\n")
            for name, script in hook_scripts.items():
                f.write(f"// {name}\n")
                f.write(script)
                f.write("\n")

        print(f"[+] Hook 脚本已生成: {script_path}")

        self.vulnerabilities.append({
            "type": "动态分析",
            "severity": "Info",
            "url": self.target,
            "description": "Frida Hook 脚本已生成",
            "evidence": script_path,
            "remediation": "使用 frida 命令执行 Hook"
        })

    def _scan_ios(self):
        """扫描 iOS 应用"""
        print("[*] 扫描 iOS 应用...")

        hook_scripts = {
            "ssl_pinning": """
Interceptor.attach(ObjC.classes.AFSecurityPolicy['- evaluateTrust:'].implementation, {
    onEnter: function(args) {
        send({type: 'ssl_pinning', status: 'hooked'});
    },
    onLeave: function(retval) {
        retval.replace(0x01);
        send({type: 'ssl_pinning', status: 'bypassed'});
    }
});
""",
            "jailbreak_detection": """
Interceptor.attach(ObjC.classes.JailbreakDetection['- isJailbroken'].implementation, {
    onLeave: function(retval) {
        retval.replace(0x00);
        send({type: 'jailbreak_detection', status: 'bypassed'});
    }
});
""",
            "keychain": """
Interceptor.attach(ObjC.classes.UIDevice['- identifierForVendor'].implementation, {
    onLeave: function(retval) {
        send({type: 'keychain', value: ObjC.Object(retval).toString()});
    }
});
""",
        }

        print("[*] 提示: 请确保设备已越狱并运行 frida-server")
        print("[*] 使用方法:")
        print(f"    frida -U {self.target} -l hook_script.js")

        # 生成 Hook 脚本
        script_path = os.path.join(os.path.dirname(__file__), "scripts", "ios_hooks.js")
        os.makedirs(os.path.dirname(script_path), exist_ok=True)

        with open(script_path, 'w', encoding='utf-8') as f:
            f.write("// Frida iOS Hook Script\n")
            f.write("// Generated by Bug Hunter\n\n")
            for name, script in hook_scripts.items():
                f.write(f"// {name}\n")
                f.write(script)
                f.write("\n")

        print(f"[+] Hook 脚本已生成: {script_path}")

        self.vulnerabilities.append({
            "type": "动态分析",
            "severity": "Info",
            "url": self.target,
            "description": "Frida Hook 脚本已生成",
            "evidence": script_path,
            "remediation": "使用 frida 命令执行 Hook"
        })

    def _scan_windows(self):
        """扫描 Windows 程序"""
        print("[*] 扫描 Windows 程序...")

        hook_scripts = {
            "crypto": """
Interceptor.attach(Module.findExportByName('advapi32.dll', 'CryptEncrypt'), {
    onEnter: function(args) {
        send({type: 'crypto', function: 'CryptEncrypt'});
    }
});

Interceptor.attach(Module.findExportByName('advapi32.dll', 'CryptDecrypt'), {
    onEnter: function(args) {
        send({type: 'crypto', function: 'CryptDecrypt'});
    }
});
""",
            "network": """
Interceptor.attach(Module.findExportByName('ws2_32.dll', 'connect'), {
    onEnter: function(args) {
        var sockaddr = args[1];
        var port = (sockaddr.add(2).readU8() << 8) | sockaddr.add(3).readU8();
        var ip = sockaddr.add(4).readU8() + '.' +
                 sockaddr.add(5).readU8() + '.' +
                 sockaddr.add(6).readU8() + '.' +
                 sockaddr.add(7).readU8();
        send({type: 'network', ip: ip, port: port});
    }
});
""",
            "file": """
Interceptor.attach(Module.findExportByName('kernel32.dll', 'CreateFileW'), {
    onEnter: function(args) {
        var path = args[0].readUtf16String();
        send({type: 'file', path: path});
    }
});
""",
            "registry": """
Interceptor.attach(Module.findExportByName('advapi32.dll', 'RegOpenKeyExW'), {
    onEnter: function(args) {
        var key = args[1].readUtf16String();
        send({type: 'registry', key: key});
    }
});
""",
        }

        print("[*] 使用方法:")
        print(f"    frida {self.target} -l hook_script.js")

        # 生成 Hook 脚本
        script_path = os.path.join(os.path.dirname(__file__), "scripts", "windows_hooks.js")
        os.makedirs(os.path.dirname(script_path), exist_ok=True)

        with open(script_path, 'w', encoding='utf-8') as f:
            f.write("// Frida Windows Hook Script\n")
            f.write("// Generated by Bug Hunter\n\n")
            for name, script in hook_scripts.items():
                f.write(f"// {name}\n")
                f.write(script)
                f.write("\n")

        print(f"[+] Hook 脚本已生成: {script_path}")

        self.vulnerabilities.append({
            "type": "动态分析",
            "severity": "Info",
            "url": self.target,
            "description": "Frida Hook 脚本已生成",
            "evidence": script_path,
            "remediation": "使用 frida 命令执行 Hook"
        })


def scan_with_frida(target: str, platform: str = "auto") -> List[Dict]:
    """便捷函数：使用 Frida 扫描"""
    scanner = FridaScanner(target, platform)
    return scanner.scan()


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        target = sys.argv[1]
        platform = sys.argv[2] if len(sys.argv) > 2 else "auto"

        vulns = scan_with_frida(target, platform)
        for vuln in vulns:
            print(f"[{vuln['severity']}] {vuln['type']}: {vuln['description']}")
    else:
        print("用法: python frida_scanner.py <target> [platform]")
        print("平台: android, ios, windows")
