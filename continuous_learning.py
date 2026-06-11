# -*- coding: utf-8 -*-
"""
持续学习模块
从实战中学习，持续提升发现率
"""

import os
import json
import time
import pickle
import hashlib
from typing import List, Dict, Optional
from pathlib import Path
from datetime import datetime


class ContinuousLearner:
    """持续学习器"""

    def __init__(self, data_dir: str = None):
        self.data_dir = data_dir or os.path.join(os.path.dirname(__file__), "learning_data")
        os.makedirs(self.data_dir, exist_ok=True)

        # 数据文件
        self.scan_results_file = os.path.join(self.data_dir, "scan_results.json")
        self.vuln_verified_file = os.path.join(self.data_dir, "vuln_verified.json")
        self.false_positive_file = os.path.join(self.data_dir, "false_positive.json")
        self.model_performance_file = os.path.join(self.data_dir, "model_performance.json")

        # 加载数据
        self.scan_results = self._load_data(self.scan_results_file, [])
        self.vuln_verified = self._load_data(self.vuln_verified_file, [])
        self.false_positive = self._load_data(self.false_positive_file, [])
        self.model_performance = self._load_data(self.model_performance_file, [])

    def _load_data(self, file_path: str, default: any) -> any:
        """加载数据"""
        if os.path.exists(file_path):
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except:
                pass
        return default

    def _save_data(self, file_path: str, data: any):
        """保存数据"""
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)

    def record_scan_result(self, url: str, vulns: List[Dict], scan_time: float):
        """记录扫描结果"""
        result = {
            "url": url,
            "vulns_count": len(vulns),
            "vulns_types": [v.get("type") for v in vulns],
            "scan_time": scan_time,
            "timestamp": datetime.now().isoformat(),
        }

        self.scan_results.append(result)

        # 只保留最近 1000 条记录
        if len(self.scan_results) > 1000:
            self.scan_results = self.scan_results[-1000:]

        self._save_data(self.scan_results_file, self.scan_results)

    def record_vuln_verified(self, vuln: Dict, verified: bool, user_feedback: str = ""):
        """记录漏洞验证结果"""
        record = {
            "vuln_type": vuln.get("type"),
            "url": vuln.get("url"),
            "severity": vuln.get("severity"),
            "evidence": vuln.get("evidence", "")[:100],
            "verified": verified,
            "user_feedback": user_feedback,
            "timestamp": datetime.now().isoformat(),
        }

        self.vuln_verified.append(record)

        # 只保留最近 1000 条记录
        if len(self.vuln_verified) > 1000:
            self.vuln_verified = self.vuln_verified[-1000:]

        self._save_data(self.vuln_verified_file, self.vuln_verified)

    def record_false_positive(self, vuln: Dict, reason: str):
        """记录误报"""
        record = {
            "vuln_type": vuln.get("type"),
            "url": vuln.get("url"),
            "evidence": vuln.get("evidence", "")[:100],
            "reason": reason,
            "timestamp": datetime.now().isoformat(),
        }

        self.false_positive.append(record)

        # 只保留最近 1000 条记录
        if len(self.false_positive) > 1000:
            self.false_positive = self.false_positive[-1000:]

        self._save_data(self.false_positive_file, self.false_positive)

    def record_model_performance(self, accuracy: float, precision: float, recall: float, f1: float):
        """记录模型性能"""
        record = {
            "accuracy": accuracy,
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "timestamp": datetime.now().isoformat(),
        }

        self.model_performance.append(record)

        # 只保留最近 100 条记录
        if len(self.model_performance) > 100:
            self.model_performance = self.model_performance[-100:]

        self._save_data(self.model_performance_file, self.model_performance)

    def get_learning_stats(self) -> Dict:
        """获取学习统计"""
        stats = {
            "total_scans": len(self.scan_results),
            "total_verified": len(self.vuln_verified),
            "total_false_positive": len(self.false_positive),
            "total_model_performance": len(self.model_performance),
        }

        # 计算漏洞类型分布
        vuln_types = {}
        for result in self.scan_results:
            for vuln_type in result.get("vulns_types", []):
                vuln_types[vuln_type] = vuln_types.get(vuln_type, 0) + 1

        stats["vuln_type_distribution"] = vuln_types

        # 计算验证率
        if self.vuln_verified:
            verified_count = sum(1 for v in self.vuln_verified if v.get("verified"))
            stats["verification_rate"] = verified_count / len(self.vuln_verified)

        # 计算误报率
        if self.false_positive:
            stats["false_positive_rate"] = len(self.false_positive) / max(stats["total_scans"], 1)

        # 最新模型性能
        if self.model_performance:
            latest = self.model_performance[-1]
            stats["latest_model_performance"] = latest

        return stats

    def generate_training_data(self) -> List[Dict]:
        """生成训练数据"""
        training_data = []

        # 从验证结果生成正样本
        for record in self.vuln_verified:
            if record.get("verified"):
                training_data.append({
                    "url": record.get("url"),
                    "vuln_type": record.get("vuln_type"),
                    "label": 1,
                    "source": "verified",
                })

        # 从误报生成负样本
        for record in self.false_positive:
            training_data.append({
                "url": record.get("url"),
                "vuln_type": record.get("vuln_type"),
                "label": 0,
                "source": "false_positive",
            })

        return training_data

    def get_improvement_suggestions(self) -> List[str]:
        """获取改进建议"""
        suggestions = []

        stats = self.get_learning_stats()

        # 检查验证率
        if stats.get("verification_rate", 0) < 0.5:
            suggestions.append("验证率较低，建议优化漏洞验证逻辑")

        # 检查误报率
        if stats.get("false_positive_rate", 0) > 0.2:
            suggestions.append("误报率较高，建议优化误报过滤")

        # 检查漏洞类型分布
        vuln_types = stats.get("vuln_type_distribution", {})
        if vuln_types:
            most_common = max(vuln_types.items(), key=lambda x: x[1])
            suggestions.append(f"最常见漏洞类型: {most_common[0]} ({most_common[1]}次)")

        # 检查模型性能
        latest_perf = stats.get("latest_model_performance", {})
        if latest_perf:
            if latest_perf.get("accuracy", 0) < 0.8:
                suggestions.append("模型准确率较低，建议重新训练")
            if latest_perf.get("recall", 0) < 0.7:
                suggestions.append("模型召回率较低，建议增加训练数据")

        return suggestions


# 全局实例
_learner = None


def get_learner() -> ContinuousLearner:
    """获取持续学习器实例"""
    global _learner
    if _learner is None:
        _learner = ContinuousLearner()
    return _learner


def record_scan(url: str, vulns: List[Dict], scan_time: float):
    """记录扫描结果"""
    learner = get_learner()
    learner.record_scan_result(url, vulns, scan_time)


def record_verification(vuln: Dict, verified: bool, user_feedback: str = ""):
    """记录验证结果"""
    learner = get_learner()
    learner.record_vuln_verified(vuln, verified, user_feedback)


def record_false_positive(vuln: Dict, reason: str):
    """记录误报"""
    learner = get_learner()
    learner.record_false_positive(vuln, reason)


def get_stats() -> Dict:
    """获取统计信息"""
    learner = get_learner()
    return learner.get_learning_stats()


def get_suggestions() -> List[str]:
    """获取改进建议"""
    learner = get_learner()
    return learner.get_improvement_suggestions()


if __name__ == "__main__":
    # 测试
    learner = ContinuousLearner()

    # 记录扫描结果
    learner.record_scan_result(
        "https://example.com",
        [{"type": "SQL注入", "severity": "High"}],
        10.5
    )

    # 获取统计
    stats = learner.get_learning_stats()
    print(f"统计: {stats}")

    # 获取建议
    suggestions = learner.get_improvement_suggestions()
    print(f"建议: {suggestions}")
