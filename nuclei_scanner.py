# -*- coding: utf-8 -*-
"""
Nuclei 扫描器集成模块
"""

import subprocess
import json
import os
from typing import List, Dict
from pathlib import Path


class NucleiScanner:
    """Nuclei 扫描器"""

    def __init__(self):
        self.nuclei_path = Path(__file__).parent / "tools" / "nuclei.exe"
        self.templates_path = Path(__file__).parent / "templates" / "nuclei-templates"

    def scan(self, target: str, severity: str = "low,medium,high,critical") -> List[Dict]:
        """使用 nuclei 扫描目标"""
        print(f"[*] Nuclei 扫描: {target}")

        vulns = []

        try:
            # 构建命令
            cmd = [
                str(self.nuclei_path),
                "-u", target,
                "-t", str(self.templates_path),
                "-silent",
                "-severity", severity,
                "-jsonl",
                "-no-color"
            ]

            # 执行扫描
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,
                encoding='utf-8'
            )

            # 解析结果
            for line in result.stdout.strip().split("\n"):
                if line:
                    try:
                        data = json.loads(line)
                        vuln = self._parse_finding(data)
                        if vuln:
                            vulns.append(vuln)
                    except json.JSONDecodeError:
                        continue

        except subprocess.TimeoutExpired:
            print("  [!] Nuclei 扫描超时")
        except Exception as e:
            print(f"  [!] Nuclei 扫描失败: {e}")

        print(f"  [+] Nuclei 发现 {len(vulns)} 个漏洞")
        return vulns

    def _parse_finding(self, data: Dict) -> Dict:
        """解析 nuclei 发现"""
        try:
            template_id = data.get("template-id", "")
            info = data.get("info", {})
            severity = info.get("severity", "info").capitalize()
            name = info.get("name", template_id)
            description = info.get("description", "")
            reference = info.get("reference", [])
            matcher = data.get("matcher-name", "")
            matched = data.get("matched", "")
            host = data.get("host", "")
            curl_command = data.get("curl-command", "")

            # 严重程度映射
            severity_map = {
                "Critical": "Critical",
                "High": "High",
                "Medium": "Medium",
                "Low": "Low",
                "Info": "Info"
            }

            return {
                "type": f"Nuclei-{template_id}",
                "severity": severity_map.get(severity, "Info"),
                "url": matched or host,
                "description": f"[{template_id}] {name}",
                "evidence": description[:500] if description else "",
                "remediation": self._get_remediation(template_id),
                "poc": curl_command if curl_command else "",
                "cve": self._extract_cve(template_id, info),
                "reference": reference if isinstance(reference, list) else [reference],
                "matcher": matcher
            }
        except Exception as e:
            return None

    def _extract_cve(self, template_id: str, info: Dict) -> str:
        """提取CVE编号"""
        import re
        # 从模板ID提取
        cve_match = re.search(r'CVE-\d{4}-\d+', template_id, re.IGNORECASE)
        if cve_match:
            return cve_match.group(0).upper()

        # 从分类提取
        classification = info.get("classification", {})
        return classification.get("cve-id", "")

    def _get_remediation(self, template_id: str) -> str:
        """获取修复建议"""
        remediation_map = {
            "cves": "更新软件到最新版本",
            "vulnerabilities": "修复已知漏洞",
            "misconfiguration": "修正配置错误",
            "default-login": "修改默认凭证",
            "exposures": "限制敏感信息暴露",
            "weak-cipher": "升级加密算法",
            "ssl": "更新SSL/TLS配置",
        }

        for key, remediation in remediation_map.items():
            if key in template_id.lower():
                return remediation

        return "参考 nuclei 官方文档进行修复"

    def scan_list(self, targets: List[str], severity: str = "low,medium,high,critical") -> List[Dict]:
        """批量扫描目标"""
        all_vulns = []

        for target in targets:
            vulns = self.scan(target, severity)
            all_vulns.extend(vulns)

        return all_vulns


def scan_with_nuclei(target: str, severity: str = "low,medium,high,critical") -> List[Dict]:
    """便捷函数：使用 nuclei 扫描"""
    scanner = NucleiScanner()
    return scanner.scan(target, severity)


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        vulns = scan_with_nuclei(sys.argv[1])
        for vuln in vulns:
            print(f"[{vuln['severity']}] {vuln['type']}: {vuln['url']}")
            print(f"  描述: {vuln['description']}")
            print()
    else:
        print("用法: python nuclei_scanner.py <url>")
