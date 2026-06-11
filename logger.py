# -*- coding: utf-8 -*-
"""
日志系统模块
"""

import logging
import sys
from pathlib import Path
from datetime import datetime


class Logger:
    """日志管理器"""

    def __init__(self, log_file: str = None, level: str = "INFO", console: bool = True):
        """
        初始化日志系统

        Args:
            log_file: 日志文件路径
            level: 日志级别 (DEBUG/INFO/WARNING/ERROR)
            console: 是否输出到控制台
        """
        self.logger = logging.getLogger("BugHunter")
        self.logger.setLevel(getattr(logging, level.upper()))

        # 清除现有处理器
        self.logger.handlers.clear()

        # 日志格式
        formatter = logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )

        # 控制台处理器
        if console:
            console_handler = logging.StreamHandler(sys.stdout)
            console_handler.setFormatter(formatter)
            self.logger.addHandler(console_handler)

        # 文件处理器
        if log_file:
            log_path = Path(log_file)
            log_path.parent.mkdir(parents=True, exist_ok=True)
            file_handler = logging.FileHandler(log_file, encoding='utf-8')
            file_handler.setFormatter(formatter)
            self.logger.addHandler(file_handler)

    def debug(self, message: str):
        """调试信息"""
        self.logger.debug(message)

    def info(self, message: str):
        """普通信息"""
        self.logger.info(message)

    def warning(self, message: str):
        """警告信息"""
        self.logger.warning(message)

    def error(self, message: str):
        """错误信息"""
        self.logger.error(message)

    def success(self, message: str):
        """成功信息"""
        self.logger.info(f"[✓] {message}")

    def fail(self, message: str):
        """失败信息"""
        self.logger.error(f"[✗] {message}")

    def vuln_found(self, vuln_type: str, severity: str, url: str):
        """发现漏洞"""
        self.logger.info(f"[漏洞] [{severity}] {vuln_type}: {url}")

    def scan_start(self, target: str):
        """扫描开始"""
        self.logger.info(f"{'='*60}")
        self.logger.info(f"开始扫描: {target}")
        self.logger.info(f"{'='*60}")

    def scan_end(self, target: str, vuln_count: int, elapsed: float):
        """扫描结束"""
        self.logger.info(f"{'='*60}")
        self.logger.info(f"扫描完成: {target}")
        self.logger.info(f"发现漏洞: {vuln_count} 个")
        self.logger.info(f"耗时: {elapsed:.2f} 秒")
        self.logger.info(f"{'='*60}")

    def step_start(self, step_name: str):
        """步骤开始"""
        self.logger.info(f"\n{'='*60}")
        self.logger.info(f"Step: {step_name}")
        self.logger.info(f"{'='*60}")

    def step_end(self, step_name: str, result: str = ""):
        """步骤结束"""
        if result:
            self.logger.info(f"Step完成: {step_name} - {result}")
        else:
            self.logger.info(f"Step完成: {step_name}")


# 全局日志实例
_logger = None


def get_logger(log_file: str = None, level: str = "INFO", console: bool = True) -> Logger:
    """获取日志实例"""
    global _logger
    if _logger is None:
        _logger = Logger(log_file, level, console)
    return _logger


def setup_logging(log_file: str = None, level: str = "INFO", console: bool = True):
    """设置日志系统"""
    global _logger
    _logger = Logger(log_file, level, console)
    return _logger


# 便捷函数
def log_info(message: str):
    """记录普通信息"""
    get_logger().info(message)


def log_error(message: str):
    """记录错误信息"""
    get_logger().error(message)


def log_warning(message: str):
    """记录警告信息"""
    get_logger().warning(message)


def log_success(message: str):
    """记录成功信息"""
    get_logger().success(message)


def log_fail(message: str):
    """记录失败信息"""
    get_logger().fail(message)


def log_vuln(vuln_type: str, severity: str, url: str):
    """记录漏洞信息"""
    get_logger().vuln_found(vuln_type, severity, url)
