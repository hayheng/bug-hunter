# -*- coding: utf-8 -*-
"""
批量扫描模块
支持批量扫描、定时扫描、自动化报告
"""

import os
import json
import time
import schedule
import threading
from typing import List, Dict, Optional
from pathlib import Path
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed


class BatchScanner:
    """批量扫描器"""

    def __init__(self, max_workers: int = 5):
        self.max_workers = max_workers
        self.scan_results = []
        self.is_running = False
        self.scheduled_tasks = []

    def batch_scan(self, targets: List[str], mode: str = "scan") -> List[Dict]:
        """批量扫描多个目标"""
        print(f"[*] 开始批量扫描，共 {len(targets)} 个目标")

        self.is_running = True
        results = []

        # 并发扫描
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {}
            for target in targets:
                future = executor.submit(self._scan_single, target, mode)
                futures[future] = target

            # 收集结果
            for future in as_completed(futures):
                target = futures[future]
                try:
                    result = future.result()
                    results.append(result)
                    print(f"  [✓] {target} - 完成")
                except Exception as e:
                    print(f"  [✗] {target} - 失败: {e}")
                    results.append({
                        "target": target,
                        "status": "failed",
                        "error": str(e),
                    })

        self.is_running = False
        self.scan_results.extend(results)

        print(f"[*] 批量扫描完成，共 {len(results)} 个目标")
        return results

    def _scan_single(self, target: str, mode: str) -> Dict:
        """扫描单个目标"""
        import subprocess

        # 构建命令
        cmd = ["python", "main.py", target, "-m", mode]

        try:
            # 执行扫描
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=600,
                cwd=os.path.dirname(__file__)
            )

            return {
                "target": target,
                "status": "success",
                "output": result.stdout,
                "errors": result.stderr,
                "returncode": result.returncode,
                "timestamp": datetime.now().isoformat(),
            }

        except subprocess.TimeoutExpired:
            return {
                "target": target,
                "status": "timeout",
                "error": "扫描超时",
                "timestamp": datetime.now().isoformat(),
            }
        except Exception as e:
            return {
                "target": target,
                "status": "failed",
                "error": str(e),
                "timestamp": datetime.now().isoformat(),
            }

    def schedule_scan(self, targets: List[str], time_str: str, mode: str = "scan"):
        """定时扫描"""
        print(f"[*] 设置定时扫描: {time_str}")

        # 添加定时任务
        task = {
            "targets": targets,
            "time": time_str,
            "mode": mode,
            "created": datetime.now().isoformat(),
        }

        self.scheduled_tasks.append(task)

        # 设置定时执行
        schedule.every().day.at(time_str).do(
            self.batch_scan,
            targets=targets,
            mode=mode
        )

        print(f"[*] 定时扫描已设置: {time_str}")

    def run_scheduler(self):
        """运行定时任务调度器"""
        print("[*] 启动定时任务调度器...")

        while True:
            schedule.run_pending()
            time.sleep(60)

    def start_scheduler_in_background(self):
        """在后台启动调度器"""
        thread = threading.Thread(target=self.run_scheduler, daemon=True)
        thread.start()
        print("[*] 定时任务调度器已在后台启动")

    def get_results_summary(self) -> Dict:
        """获取结果摘要"""
        summary = {
            "total_scans": len(self.scan_results),
            "success_count": sum(1 for r in self.scan_results if r.get("status") == "success"),
            "failed_count": sum(1 for r in self.scan_results if r.get("status") == "failed"),
            "timeout_count": sum(1 for r in self.scan_results if r.get("status") == "timeout"),
        }

        # 统计漏洞数量
        total_vulns = 0
        for result in self.scan_results:
            if result.get("status") == "success":
                # 从输出中提取漏洞数量
                output = result.get("output", "")
                if "发现漏洞:" in output:
                    try:
                        vuln_line = [line for line in output.split("\n") if "发现漏洞:" in line][0]
                        vuln_count = int(vuln_line.split("发现漏洞:")[1].strip().split("个")[0])
                        total_vulns += vuln_count
                    except:
                        pass

        summary["total_vulns"] = total_vulns

        return summary

    def export_results(self, output_file: str = None):
        """导出结果"""
        if output_file is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = os.path.join(os.path.dirname(__file__), "reports", f"batch_scan_{timestamp}.json")

        os.makedirs(os.path.dirname(output_file), exist_ok=True)

        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(self.scan_results, f, ensure_ascii=False, indent=2)

        print(f"[*] 结果已导出: {output_file}")
        return output_file


class ScanScheduler:
    """扫描调度器"""

    def __init__(self):
        self.tasks = []
        self.is_running = False

    def add_task(self, name: str, targets: List[str], time_str: str, mode: str = "scan"):
        """添加定时任务"""
        task = {
            "name": name,
            "targets": targets,
            "time": time_str,
            "mode": mode,
            "created": datetime.now().isoformat(),
            "last_run": None,
            "next_run": None,
        }

        self.tasks.append(task)

        # 设置定时执行
        schedule.every().day.at(time_str).do(
            self._execute_task,
            task=task
        )

        print(f"[*] 定时任务已添加: {name} ({time_str})")

    def _execute_task(self, task: Dict):
        """执行任务"""
        print(f"[*] 执行定时任务: {task['name']}")

        # 更新任务状态
        task["last_run"] = datetime.now().isoformat()

        # 执行扫描
        scanner = BatchScanner()
        results = scanner.batch_scan(task["targets"], task["mode"])

        # 导出结果
        scanner.export_results()

        print(f"[*] 定时任务完成: {task['name']}")

    def start(self):
        """启动调度器"""
        self.is_running = True
        print("[*] 调度器已启动")

        while self.is_running:
            schedule.run_pending()
            time.sleep(60)

    def stop(self):
        """停止调度器"""
        self.is_running = False
        print("[*] 调度器已停止")

    def get_tasks(self) -> List[Dict]:
        """获取任务列表"""
        return self.tasks


def batch_scan(targets: List[str], mode: str = "scan") -> List[Dict]:
    """便捷函数：批量扫描"""
    scanner = BatchScanner()
    return scanner.batch_scan(targets, mode)


def schedule_scan(targets: List[str], time_str: str, mode: str = "scan"):
    """便捷函数：定时扫描"""
    scanner = BatchScanner()
    scanner.schedule_scan(targets, time_str, mode)
    scanner.start_scheduler_in_background()


if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1:
        # 从文件读取目标
        target_file = sys.argv[1]
        with open(target_file, 'r', encoding='utf-8') as f:
            targets = [line.strip() for line in f if line.strip() and not line.startswith("#")]

        # 批量扫描
        results = batch_scan(targets)

        # 输出摘要
        scanner = BatchScanner()
        scanner.scan_results = results
        summary = scanner.get_results_summary()
        print(f"\n[*] 扫描摘要:")
        print(f"  总目标: {summary['total_scans']}")
        print(f"  成功: {summary['success_count']}")
        print(f"  失败: {summary['failed_count']}")
        print(f"  超时: {summary['timeout_count']}")
        print(f"  总漏洞: {summary['total_vulns']}")
    else:
        print("用法: python batch_scanner.py <targets.txt>")
        print("目标文件格式: 每行一个目标域名")
