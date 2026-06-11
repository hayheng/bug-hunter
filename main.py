# -*- coding: utf-8 -*-
"""
自动化漏洞挖掘系统 - 主程序
"""

import sys
import argparse
import time
from datetime import datetime
from pathlib import Path

# 修复 Windows 控制台编码
import io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8')

# 禁用 SSL 警告
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from subdomain_enum import enumerate_subdomains
from subdomain_enhanced import enumerate_subdomains as enumerate_subdomains_enhanced
from alive_checker import check_alive_targets
from dir_scanner import scan_directories
from vuln_scanner import scan_single_target
from advanced_scanner import scan_advanced
from critical_scanner import scan_critical
from vuln_boost import scan_boost
from vuln_extra import scan_extra
from vuln_advanced import scan_advanced_vulns
from vuln_expert import scan_expert_vulns
from vuln_pro import scan_pro
from vuln_ml import scan_ml
from butian_scanner import scan_butian
from nuclei_scanner import scan_with_nuclei
from vuln_verifier import verify_vulnerabilities
from vuln_exploit import verify_exploits
from vuln_filter import filter_vulns, prioritize_vulns, deduplicate_vulns, enhance_vulns
from report_generator import generate_report
from continuous_learning import record_scan, get_stats, get_suggestions
from batch_scanner import BatchScanner, ScanScheduler


class BugHunter:
    """自动化漏洞挖掘器"""

    def __init__(self, target: str, mode: str = "full"):
        self.target = target
        self.mode = mode
        self.subdomains = set()
        self.alive_targets = []
        self.vulnerabilities = []

    def run(self):
        """执行完整扫描流程"""
        print("""
╔════════════════════════════════════════════════════════════╗
║           🎯 自动化漏洞挖掘系统 v2.0                       ║
║           Author: AI Assistant                             ║
╚════════════════════════════════════════════════════════════╝
        """)

        start_time = time.time()

        # Step 1: 子域名枚举
        if self.mode in ["full", "subdomain"]:
            print("\n" + "="*60)
            print("Step 1: 子域名枚举")
            print("="*60)
            # 在线API枚举
            api_subdomains = enumerate_subdomains(self.target)
            self.subdomains.update(api_subdomains)

            # 子域名爆破
            print("\n[*] 开始子域名爆破...")
            brute_subdomains = brute_force_subdomains(self.target)
            self.subdomains.update(brute_subdomains)
        else:
            self.subdomains = {self.target}

        # Step 2: 存活探测
        if self.mode in ["full", "alive"]:
            print("\n" + "="*60)
            print("Step 2: 存活探测")
            print("="*60)
            self.alive_targets = check_alive_targets(self.subdomains)
        else:
            self.alive_targets = [{"url": f"https://{self.target}", "target": self.target}]

        # Step 3: 目录扫描
        print("\n" + "="*60)
        print("Step 3: 目录扫描")
        print("="*60)

        for i, target in enumerate(self.alive_targets, 1):
            print(f"\n[{i}/{len(self.alive_targets)}] 目录扫描中...")
            try:
                url = target.get("url", f"https://{target}")
                dir_results = scan_directories(url)
                # 将高价值目录添加到漏洞列表
                for dir_info in dir_results:
                    if dir_info.get("is_high_value"):
                        self.vulnerabilities.append({
                            "type": "敏感文件泄露",
                            "severity": "Medium",
                            "url": dir_info["url"],
                            "description": f"发现敏感路径: {dir_info['path']}",
                            "evidence": f"状态码: {dir_info['status_code']}",
                            "remediation": "删除或限制访问敏感文件"
                        })
            except Exception as e:
                print(f"  扫描失败: {e}")

        # Step 4: 基础漏洞扫描
        print("\n" + "="*60)
        print("Step 4: 基础漏洞扫描")
        print("="*60)

        total = len(self.alive_targets)
        for i, target in enumerate(self.alive_targets, 1):
            print(f"\n[{i}/{total}] 扫描中...")
            try:
                vulns = scan_single_target(target)
                self.vulnerabilities.extend([v.to_dict() for v in vulns])
                if vulns:
                    print(f"  发现 {len(vulns)} 个漏洞!")
            except Exception as e:
                print(f"  扫描失败: {e}")

        # Step 5: 高级漏洞扫描
        print("\n" + "="*60)
        print("Step 5: 高级漏洞扫描")
        print("="*60)

        for i, target in enumerate(self.alive_targets, 1):
            print(f"\n[{i}/{total}] 深度扫描中...")
            try:
                url = target.get("url", f"https://{target}")
                vulns = scan_advanced(url)
                self.vulnerabilities.extend([v.to_dict() for v in vulns])
                if vulns:
                    print(f"  发现 {len(vulns)} 个高级漏洞!")
            except Exception as e:
                print(f"  扫描失败: {e}")

        # Step 6: 中高危漏洞深度扫描
        print("\n" + "="*60)
        print("Step 6: 中高危漏洞深度扫描")
        print("="*60)

        for i, target in enumerate(self.alive_targets, 1):
            print(f"\n[{i}/{total}] 中高危漏洞扫描中...")
            try:
                url = target.get("url", f"https://{target}")
                vulns = scan_critical(url)
                self.vulnerabilities.extend(vulns)
                if vulns:
                    print(f"  发现 {len(vulns)} 个中高危漏洞!")
            except Exception as e:
                print(f"  扫描失败: {e}")

        # Step 7: 增强漏洞扫描
        print("\n" + "="*60)
        print("Step 7: 增强漏洞扫描")
        print("="*60)

        for i, target in enumerate(self.alive_targets, 1):
            print(f"\n[{i}/{total}] 增强扫描中...")
            try:
                url = target.get("url", f"https://{target}")
                vulns = scan_boost(url)
                self.vulnerabilities.extend(vulns)
                if vulns:
                    print(f"  发现 {len(vulns)} 个漏洞!")
            except Exception as e:
                print(f"  扫描失败: {e}")

        # Step 8: 额外漏洞扫描
        print("\n" + "="*60)
        print("Step 8: 额外漏洞扫描")
        print("="*60)

        for i, target in enumerate(self.alive_targets, 1):
            print(f"\n[{i}/{total}] 额外扫描中...")
            try:
                url = target.get("url", f"https://{target}")
                vulns = scan_extra(url)
                self.vulnerabilities.extend(vulns)
                if vulns:
                    print(f"  发现 {len(vulns)} 个漏洞!")
            except Exception as e:
                print(f"  扫描失败: {e}")

        # Step 9: 高级漏洞扫描
        print("\n" + "="*60)
        print("Step 9: 高级漏洞扫描")
        print("="*60)

        for i, target in enumerate(self.alive_targets, 1):
            print(f"\n[{i}/{total}] 高级扫描中...")
            try:
                url = target.get("url", f"https://{target}")
                vulns = scan_advanced_vulns(url)
                self.vulnerabilities.extend(vulns)
                if vulns:
                    print(f"  发现 {len(vulns)} 个漏洞!")
            except Exception as e:
                print(f"  扫描失败: {e}")

        # Step 10: 专家级漏洞扫描
        print("\n" + "="*60)
        print("Step 10: 专家级漏洞扫描")
        print("="*60)

        for i, target in enumerate(self.alive_targets, 1):
            print(f"\n[{i}/{total}] 专家级扫描中...")
            try:
                url = target.get("url", f"https://{target}")
                vulns = scan_expert_vulns(url)
                self.vulnerabilities.extend(vulns)
                if vulns:
                    print(f"  发现 {len(vulns)} 个漏洞!")
            except Exception as e:
                print(f"  扫描失败: {e}")

        # Step 11: Nuclei 漏洞扫描
        print("\n" + "="*60)
        print("Step 11: Nuclei 漏洞扫描")
        print("="*60)

        for i, target in enumerate(self.alive_targets, 1):
            print(f"\n[{i}/{total}] Nuclei 扫描中...")
            try:
                url = target.get("url", f"https://{target}")
                vulns = scan_with_nuclei(url)
                self.vulnerabilities.extend(vulns)
                if vulns:
                    print(f"  发现 {len(vulns)} 个漏洞!")
            except Exception as e:
                print(f"  扫描失败: {e}")

        # Step 12: 专业级漏洞扫描
        print("\n" + "="*60)
        print("Step 12: 专业级漏洞扫描")
        print("="*60)

        for i, target in enumerate(self.alive_targets, 1):
            print(f"\n[{i}/{total}] 专业级扫描中...")
            try:
                url = target.get("url", f"https://{target}")
                vulns = scan_pro(url)
                self.vulnerabilities.extend(vulns)
                if vulns:
                    print(f"  发现 {len(vulns)} 个漏洞!")
            except Exception as e:
                print(f"  扫描失败: {e}")

        # Step 13: 补天平台专用扫描
        print("\n" + "="*60)
        print("Step 13: 补天平台专用扫描")
        print("="*60)

        for i, target in enumerate(self.alive_targets, 1):
            print(f"\n[{i}/{total}] 补天专用扫描中...")
            try:
                url = target.get("url", f"https://{target}")
                vulns = scan_butian(url)
                self.vulnerabilities.extend(vulns)
                if vulns:
                    print(f"  发现 {len(vulns)} 个漏洞!")
            except Exception as e:
                print(f"  扫描失败: {e}")

        # Step 14: 漏洞验证
        print("\n" + "="*60)
        print("Step 14: 漏洞验证")
        print("="*60)

        self.vulnerabilities = verify_vulnerabilities(self.vulnerabilities)

        # Step 15: 漏洞过滤
        print("\n" + "="*60)
        print("Step 15: 漏洞过滤")
        print("="*60)

        # 过滤低价值漏洞
        self.vulnerabilities = filter_vulns(self.vulnerabilities)

        # 去重
        self.vulnerabilities = deduplicate_vulns(self.vulnerabilities)

        # 优先级排序
        self.vulnerabilities = prioritize_vulns(self.vulnerabilities)

        # 增强漏洞信息
        self.vulnerabilities = enhance_vulns(self.vulnerabilities)

        # Step 16: 生成报告
        print("\n" + "="*60)
        print("Step 16: 生成报告")
        print("="*60)

        report_path = generate_report(
            self.target,
            self.subdomains,
            self.alive_targets,
            self.vulnerabilities
        )

        # Step 17: 持续学习
        print("\n" + "="*60)
        print("Step 17: 持续学习")
        print("="*60)

        elapsed = time.time() - start_time
        record_scan(self.target, self.vulnerabilities, elapsed)

        # 获取学习统计
        stats = get_stats()
        print(f"[*] 学习统计:")
        print(f"  总扫描次数: {stats.get('total_scans', 0)}")
        print(f"  总验证次数: {stats.get('total_verified', 0)}")
        print(f"  总误报次数: {stats.get('total_false_positive', 0)}")

        # 获取改进建议
        suggestions = get_suggestions()
        if suggestions:
            print(f"[*] 改进建议:")
            for suggestion in suggestions:
                print(f"  - {suggestion}")

        # 打印统计
        self._print_summary(elapsed)

        return report_path

    def _print_summary(self, elapsed: float):
        """打印扫描摘要"""
        print("\n" + "="*60)
        print("📊 扫描完成统计")
        print("="*60)

        # 统计漏洞严重程度
        severity_count = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
        for vuln in self.vulnerabilities:
            severity = vuln.get("severity", "Info")
            severity_count[severity] = severity_count.get(severity, 0) + 1

        print(f"""
🎯 目标: {self.target}
⏱️  耗时: {elapsed:.2f} 秒
🔍 子域名: {len(self.subdomains)} 个
🖥️  存活目标: {len(self.alive_targets)} 个
🐛 发现漏洞: {len(self.vulnerabilities)} 个

漏洞分布:
  🔴 严重: {severity_count['Critical']}
  🟠 高危: {severity_count['High']}
  🟡 中危: {severity_count['Medium']}
  🟢 低危: {severity_count['Low']}
  🔵 信息: {severity_count['Info']}
        """)


def main():
    parser = argparse.ArgumentParser(
        description="自动化漏洞挖掘系统",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  python main.py example.com              # 完整扫描
  python main.py example.com -m subdomain # 只枚举子域名
  python main.py example.com -m alive     # 只检测存活
  python main.py example.com -m scan      # 只扫描漏洞
  python main.py -l targets.txt           # 批量扫描
        """
    )

    parser.add_argument("target", nargs="?", help="目标域名")
    parser.add_argument("-m", "--mode", choices=["full", "subdomain", "alive", "scan"],
                        default="full", help="扫描模式 (默认: full)")
    parser.add_argument("-l", "--list", help="目标列表文件")
    parser.add_argument("-t", "--threads", type=int, default=50, help="线程数 (默认: 50)")
    parser.add_argument("--batch", action="store_true", help="批量扫描模式")
    parser.add_argument("--schedule", help="定时扫描时间 (格式: HH:MM)")
    parser.add_argument("--stats", action="store_true", help="显示学习统计")
    parser.add_argument("--suggestions", action="store_true", help="显示改进建议")

    args = parser.parse_args()

    # 显示学习统计
    if args.stats:
        stats = get_stats()
        print("\n[*] 学习统计:")
        print(f"  总扫描次数: {stats.get('total_scans', 0)}")
        print(f"  总验证次数: {stats.get('total_verified', 0)}")
        print(f"  总误报次数: {stats.get('total_false_positive', 0)}")
        print(f"  漏洞类型分布: {stats.get('vuln_type_distribution', {})}")
        if stats.get('latest_model_performance'):
            perf = stats['latest_model_performance']
            print(f"  最新模型性能:")
            print(f"    准确率: {perf.get('accuracy', 0):.4f}")
            print(f"    精确率: {perf.get('precision', 0):.4f}")
            print(f"    召回率: {perf.get('recall', 0):.4f}")
            print(f"    F1分数: {perf.get('f1', 0):.4f}")
        return

    # 显示改进建议
    if args.suggestions:
        suggestions = get_suggestions()
        print("\n[*] 改进建议:")
        for suggestion in suggestions:
            print(f"  - {suggestion}")
        return

    if not args.target and not args.list:
        parser.print_help()
        sys.exit(1)

    # 更新线程数
    from config import SCAN_CONFIG
    SCAN_CONFIG["max_threads"] = args.threads

    targets = []
    if args.list:
        # 从文件读取目标列表
        try:
            with open(args.list, "r", encoding="utf-8") as f:
                targets = [line.strip() for line in f if line.strip() and not line.startswith("#")]
        except Exception as e:
            print(f"[-] 读取目标列表失败: {e}")
            sys.exit(1)
    else:
        targets = [args.target]

    # 批量扫描模式
    if args.batch and len(targets) > 1:
        print(f"[*] 批量扫描模式，共 {len(targets)} 个目标")
        scanner = BatchScanner()
        results = scanner.batch_scan(targets, args.mode)
        scanner.export_results()
        return

    # 定时扫描模式
    if args.schedule:
        print(f"[*] 定时扫描模式，时间: {args.schedule}")
        scanner = BatchScanner()
        scanner.schedule_scan(targets, args.schedule, args.mode)
        scanner.start_scheduler_in_background()
        print("[*] 定时扫描已启动，按 Ctrl+C 退出")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n[!] 用户中断")
        return

    # 执行扫描
    for target in targets:
        try:
            hunter = BugHunter(target, args.mode)
            hunter.run()
        except KeyboardInterrupt:
            print("\n[!] 用户中断扫描")
            sys.exit(0)
        except Exception as e:
            print(f"\n[-] 扫描 {target} 失败: {e}")
            continue


if __name__ == "__main__":
    main()
