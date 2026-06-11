# -*- coding: utf-8 -*-
"""
机器学习漏洞检测模块
"""

import requests
import re
import json
from typing import List, Dict
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from config import SCAN_CONFIG
from ml_engine import get_ml_engine, predict_vulnerability


class MLVulnScanner:
    """机器学习漏洞扫描器"""

    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": SCAN_CONFIG["user_agent"],
        })
        self.ml_engine = get_ml_engine()
        self.vulnerabilities = []

        # 确保模型已加载
        if self.ml_engine.model is None:
            self.ml_engine.load_model()

    def scan(self, url: str) -> List[Dict]:
        """执行机器学习扫描"""
        print(f"[*] 机器学习漏洞扫描: {url}")

        vulns = []

        # 1. 基于机器学习的漏洞检测
        vulns.extend(self._ml_detection(url))

        # 2. 基于特征的漏洞检测
        vulns.extend(self._feature_detection(url))

        # 3. 基于模式的漏洞检测
        vulns.extend(self._pattern_detection(url))

        # 4. 智能漏洞检测
        vulns.extend(self._smart_detection(url))

        self.vulnerabilities.extend(vulns)
        return vulns

    def _ml_detection(self, url: str) -> List[Dict]:
        """基于机器学习的漏洞检测"""
        vulns = []

        try:
            response = self.session.get(url, timeout=5, verify=False)

            # 准备特征
            response_headers = dict(response.headers)
            response_headers['status_code'] = response.status_code

            # 预测漏洞概率
            probability, details = predict_vulnerability(
                url,
                response.text,
                response_headers
            )

            # 如果概率大于阈值，认为存在漏洞
            if probability > 0.7:
                # 获取重要特征
                top_features = details.get('top_features', [])
                feature_desc = ", ".join([f"{f[0]}: {f[1]:.3f}" for f in top_features[:3]])

                vulns.append({
                    "type": "AI检测",
                    "severity": "High" if probability > 0.9 else "Medium",
                    "url": url,
                    "description": f"AI检测到潜在漏洞 (概率: {probability:.2%})",
                    "evidence": f"重要特征: {feature_desc}",
                    "remediation": "人工验证漏洞",
                    "exploitable": probability > 0.8,
                    "confidence": probability,
                    "ml_details": details,
                })

        except Exception as e:
            pass

        return vulns

    def _feature_detection(self, url: str) -> List[Dict]:
        """基于特征的漏洞检测"""
        vulns = []

        try:
            response = self.session.get(url, timeout=5, verify=False)
            content = response.text
            headers = response.headers

            # 特征检测
            features = {
                "敏感信息": self._check_sensitive_info(content),
                "配置错误": self._check_misconfig(headers),
                "安全头缺失": self._check_missing_headers(headers),
                "调试信息": self._check_debug_info(content),
                "版本信息": self._check_version_info(headers),
            }

            # 根据特征判断漏洞
            for vuln_type, score in features.items():
                if score > 0.5:
                    vulns.append({
                        "type": vuln_type,
                        "severity": "High" if score > 0.8 else "Medium",
                        "url": url,
                        "description": f"检测到{vuln_type} (置信度: {score:.2%})",
                        "evidence": f"特征分数: {score:.2f}",
                        "remediation": self._get_remediation(vuln_type),
                        "exploitable": score > 0.7,
                        "confidence": score,
                    })

        except Exception as e:
            pass

        return vulns

    def _check_sensitive_info(self, content: str) -> float:
        """检查敏感信息"""
        score = 0.0
        content_lower = content.lower()

        # 敏感关键词
        sensitive_keywords = [
            ("password", 0.3),
            ("secret", 0.3),
            ("token", 0.2),
            ("api_key", 0.3),
            ("private_key", 0.4),
            ("database", 0.2),
            ("mysql", 0.2),
            ("redis", 0.2),
            ("mongodb", 0.2),
            ("aws_access", 0.4),
            ("aws_secret", 0.4),
        ]

        for keyword, weight in sensitive_keywords:
            if keyword in content_lower:
                score += weight

        return min(score, 1.0)

    def _check_misconfig(self, headers: Dict) -> float:
        """检查配置错误"""
        score = 0.0

        # 检查服务器信息泄露
        if 'server' in headers:
            score += 0.2

        if 'x-powered-by' in headers:
            score += 0.2

        # 检查安全头缺失
        security_headers = [
            'x-frame-options',
            'x-content-type-options',
            'x-xss-protection',
            'content-security-policy',
            'strict-transport-security',
        ]

        missing_count = 0
        for header in security_headers:
            if header not in headers:
                missing_count += 1

        score += missing_count * 0.1

        return min(score, 1.0)

    def _check_missing_headers(self, headers: Dict) -> float:
        """检查安全头缺失"""
        score = 0.0

        security_headers = [
            'x-frame-options',
            'x-content-type-options',
            'x-xss-protection',
            'content-security-policy',
            'strict-transport-security',
        ]

        missing_count = 0
        for header in security_headers:
            if header not in headers:
                missing_count += 1

        score = missing_count / len(security_headers)

        return score

    def _check_debug_info(self, content: str) -> float:
        """检查调试信息"""
        score = 0.0
        content_lower = content.lower()

        debug_patterns = [
            ("stack trace", 0.4),
            ("traceback", 0.4),
            ("debug", 0.2),
            ("exception", 0.3),
            ("error in", 0.2),
            ("line number", 0.2),
            ("file path", 0.2),
        ]

        for pattern, weight in debug_patterns:
            if pattern in content_lower:
                score += weight

        return min(score, 1.0)

    def _check_version_info(self, headers: Dict) -> float:
        """检查版本信息"""
        score = 0.0

        # 检查服务器版本
        server = headers.get('server', '')
        if server and re.search(r'\d+\.\d+', server):
            score += 0.3

        # 检查 X-Powered-By
        powered_by = headers.get('x-powered-by', '')
        if powered_by and re.search(r'\d+\.\d+', powered_by):
            score += 0.3

        return min(score, 1.0)

    def _get_remediation(self, vuln_type: str) -> str:
        """获取修复建议"""
        remediation_map = {
            "敏感信息": "移除敏感信息，使用环境变量存储",
            "配置错误": "修正配置，添加安全响应头",
            "安全头缺失": "添加安全响应头",
            "调试信息": "关闭调试模式，移除调试信息",
            "版本信息": "隐藏版本信息",
        }

        return remediation_map.get(vuln_type, "请参考安全最佳实践")

    def _pattern_detection(self, url: str) -> List[Dict]:
        """基于模式的漏洞检测"""
        vulns = []
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        if not params:
            return vulns

        # 模式检测
        patterns = {
            "SQL注入": [
                (r"' OR '1'='1", "SQL注入"),
                (r"' OR 1=1", "SQL注入"),
                (r"UNION SELECT", "SQL注入"),
                (r"SLEEP\(\d+\)", "SQL注入"),
            ],
            "XSS": [
                (r"<script>alert\(", "XSS"),
                (r"onerror=alert", "XSS"),
                (r"onload=alert", "XSS"),
            ],
            "命令注入": [
                (r";\s*id\b", "命令注入"),
                (r"\|\s*id\b", "命令注入"),
                (r"`id`", "命令注入"),
            ],
            "路径遍历": [
                (r"\.\./\.\./\.\.", "路径遍历"),
                (r"etc/passwd", "路径遍历"),
            ],
        }

        # 检测每个参数
        for param_name, param_values in params.items():
            for param_value in param_values:
                for vuln_type, pattern_list in patterns.items():
                    for pattern, _ in pattern_list:
                        if re.search(pattern, param_value, re.IGNORECASE):
                            vulns.append({
                                "type": vuln_type,
                                "severity": "High",
                                "url": url,
                                "description": f"参数 {param_name} 存在{vuln_type}模式",
                                "evidence": f"模式: {pattern}",
                                "remediation": "验证和过滤输入",
                                "exploitable": True,
                                "confidence": 0.8,
                            })
                            break

        return vulns

    def _smart_detection(self, url: str) -> List[Dict]:
        """智能漏洞检测"""
        vulns = []

        # 智能检测逻辑
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        # 智能路径猜测
        smart_paths = [
            ("/api/v1/users", "API接口"),
            ("/api/v1/admin", "管理接口"),
            ("/api/v1/config", "配置接口"),
            ("/api/v1/debug", "调试接口"),
            ("/swagger-ui.html", "API文档"),
            ("/graphql", "GraphQL"),
            ("/actuator", "监控接口"),
            ("/metrics", "指标接口"),
        ]

        for path, desc in smart_paths:
            full_url = urljoin(base, path)
            try:
                response = self.session.get(full_url, timeout=3, verify=False)

                if response.status_code == 200:
                    # 使用ML预测
                    response_headers = dict(response.headers)
                    response_headers['status_code'] = response.status_code

                    probability, details = predict_vulnerability(
                        full_url,
                        response.text,
                        response_headers
                    )

                    if probability > 0.6:
                        vulns.append({
                            "type": "智能检测",
                            "severity": "High" if probability > 0.8 else "Medium",
                            "url": full_url,
                            "description": f"发现{desc} (概率: {probability:.2%})",
                            "evidence": f"AI预测概率: {probability:.2%}",
                            "remediation": "限制访问权限",
                            "exploitable": probability > 0.7,
                            "confidence": probability,
                        })

            except:
                pass

        return vulns


def scan_ml(url: str) -> List[Dict]:
    """便捷函数：机器学习扫描"""
    scanner = MLVulnScanner()
    return scanner.scan(url)


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        # 先训练模型
        engine = get_ml_engine()
        if engine.model is None:
            engine.auto_train()

        # 扫描
        vulns = scan_ml(sys.argv[1])
        for vuln in vulns:
            print(f"[{vuln.get('severity')}] {vuln.get('type')}: {vuln.get('description')}")
    else:
        print("用法: python vuln_ml.py <url>")
