# -*- coding: utf-8 -*-
"""
机器学习引擎
用于自动识别漏洞
"""

import os
import re
import json
import pickle
import hashlib
import numpy as np
from typing import List, Dict, Tuple, Optional
from pathlib import Path
from urllib.parse import urlparse, parse_qs


class MLEngine:
    """机器学习引擎"""

    def __init__(self, model_dir: str = None):
        self.model_dir = model_dir or os.path.join(os.path.dirname(__file__), "models")
        os.makedirs(self.model_dir, exist_ok=True)

        self.model = None
        self.vectorizer = None
        self.label_encoder = None

        # 特征缓存
        self.feature_cache = {}

    def extract_features(self, url: str, response_text: str, response_headers: Dict) -> Dict:
        """提取特征"""
        # 缓存键
        cache_key = hashlib.md5(f"{url}|{response_text[:100]}".encode()).hexdigest()

        if cache_key in self.feature_cache:
            return self.feature_cache[cache_key]

        features = {}

        # URL 特征
        parsed = urlparse(url)
        features['url_length'] = len(url)
        features['path_depth'] = len(parsed.path.split('/'))
        features['has_query'] = 1 if parsed.query else 0
        features['query_params_count'] = len(parse_qs(parsed.query))
        features['has_fragment'] = 1 if parsed.fragment else 0

        # 域名特征
        features['domain_length'] = len(parsed.netloc)
        features['subdomain_count'] = len(parsed.netloc.split('.')) - 2
        features['is_ip'] = 1 if re.match(r'\d+\.\d+\.\d+\.\d+', parsed.netloc) else 0

        # 路径特征
        path = parsed.path.lower()
        features['has_admin'] = 1 if 'admin' in path else 0
        features['has_api'] = 1 if 'api' in path else 0
        features['has_login'] = 1 if 'login' in path else 0
        features['has_config'] = 1 if 'config' in path else 0
        features['has_backup'] = 1 if 'backup' in path else 0
        features['has_env'] = 1 if '.env' in path else 0
        features['has_git'] = 1 if '.git' in path else 0
        features['has_svn'] = 1 if '.svn' in path else 0
        features['has_debug'] = 1 if 'debug' in path else 0
        features['has_test'] = 1 if 'test' in path else 0

        # 响应特征
        features['response_length'] = len(response_text)
        features['status_code'] = response_headers.get('status_code', 0)

        # 内容特征
        content_lower = response_text.lower()
        features['has_password'] = 1 if 'password' in content_lower else 0
        features['has_secret'] = 1 if 'secret' in content_lower else 0
        features['has_token'] = 1 if 'token' in content_lower else 0
        features['has_api_key'] = 1 if 'api_key' in content_lower or 'apikey' in content_lower else 0
        features['has_database'] = 1 if 'database' in content_lower or 'mysql' in content_lower else 0
        features['has_error'] = 1 if 'error' in content_lower or 'exception' in content_lower else 0
        features['has_stack_trace'] = 1 if 'stack trace' in content_lower or 'traceback' in content_lower else 0
        features['has_sql'] = 1 if 'sql' in content_lower or 'select' in content_lower else 0
        features['has_xss'] = 1 if '<script>' in content_lower or 'alert(' in content_lower else 0
        features['has_command'] = 1 if 'exec' in content_lower or 'system(' in content_lower else 0

        # 响应头特征
        features['has_server'] = 1 if 'server' in response_headers else 0
        features['has_x_powered_by'] = 1 if 'x-powered-by' in response_headers else 0
        features['has_x_frame_options'] = 1 if 'x-frame-options' in response_headers else 0
        features['has_csp'] = 1 if 'content-security-policy' in response_headers else 0
        features['has_hsts'] = 1 if 'strict-transport-security' in response_headers else 0

        # 缓存特征
        self.feature_cache[cache_key] = features

        return features

    def features_to_vector(self, features: Dict) -> np.ndarray:
        """特征转换为向量"""
        # 特征顺序
        feature_keys = [
            'url_length', 'path_depth', 'has_query', 'query_params_count', 'has_fragment',
            'domain_length', 'subdomain_count', 'is_ip',
            'has_admin', 'has_api', 'has_login', 'has_config', 'has_backup',
            'has_env', 'has_git', 'has_svn', 'has_debug', 'has_test',
            'response_length', 'status_code',
            'has_password', 'has_secret', 'has_token', 'has_api_key', 'has_database',
            'has_error', 'has_stack_trace', 'has_sql', 'has_xss', 'has_command',
            'has_server', 'has_x_powered_by', 'has_x_frame_options', 'has_csp', 'has_hsts'
        ]

        vector = []
        for key in feature_keys:
            vector.append(features.get(key, 0))

        return np.array(vector).reshape(1, -1)

    def train(self, training_data: List[Dict]) -> float:
        """训练模型"""
        from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
        from sklearn.model_selection import train_test_split
        from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
        from sklearn.preprocessing import StandardScaler

        print("[*] 开始训练模型...")

        # 准备数据
        X = []
        y = []

        for data in training_data:
            features = self.extract_features(
                data['url'],
                data.get('response_text', ''),
                data.get('response_headers', {})
            )
            vector = self.features_to_vector(features)
            X.append(vector.flatten())
            y.append(data.get('label', 0))

        X = np.array(X)
        y = np.array(y)

        # 数据标准化
        self.scaler = StandardScaler()
        X_scaled = self.scaler.fit_transform(X)

        # 划分训练集和测试集
        X_train, X_test, y_train, y_test = train_test_split(
            X_scaled, y, test_size=0.2, random_state=42
        )

        # 训练模型
        self.model = GradientBoostingClassifier(
            n_estimators=100,
            max_depth=5,
            learning_rate=0.1,
            random_state=42
        )

        self.model.fit(X_train, y_train)

        # 评估模型
        y_pred = self.model.predict(X_test)
        accuracy = accuracy_score(y_test, y_pred)
        precision = precision_score(y_test, y_pred, zero_division=0)
        recall = recall_score(y_test, y_pred, zero_division=0)
        f1 = f1_score(y_test, y_pred, zero_division=0)

        print(f"[*] 模型训练完成:")
        print(f"  准确率: {accuracy:.4f}")
        print(f"  精确率: {precision:.4f}")
        print(f"  召回率: {recall:.4f}")
        print(f"  F1分数: {f1:.4f}")

        # 保存模型
        self.save_model()

        return accuracy

    def predict(self, url: str, response_text: str, response_headers: Dict) -> Tuple[float, Dict]:
        """预测漏洞概率"""
        if self.model is None:
            self.load_model()

        if self.model is None:
            return 0.0, {}

        # 提取特征
        features = self.extract_features(url, response_text, response_headers)
        vector = self.features_to_vector(features)

        # 标准化
        vector_scaled = self.scaler.transform(vector)

        # 预测
        probability = self.model.predict_proba(vector_scaled)[0][1]

        # 特征重要性
        feature_importance = {}
        feature_keys = [
            'url_length', 'path_depth', 'has_query', 'query_params_count', 'has_fragment',
            'domain_length', 'subdomain_count', 'is_ip',
            'has_admin', 'has_api', 'has_login', 'has_config', 'has_backup',
            'has_env', 'has_git', 'has_svn', 'has_debug', 'has_test',
            'response_length', 'status_code',
            'has_password', 'has_secret', 'has_token', 'has_api_key', 'has_database',
            'has_error', 'has_stack_trace', 'has_sql', 'has_xss', 'has_command',
            'has_server', 'has_x_powered_by', 'has_x_frame_options', 'has_csp', 'has_hsts'
        ]

        for i, key in enumerate(feature_keys):
            feature_importance[key] = self.model.feature_importances_[i]

        # 排序特征重要性
        sorted_features = sorted(feature_importance.items(), key=lambda x: x[1], reverse=True)

        return probability, {
            "top_features": sorted_features[:5],
            "all_features": feature_importance
        }

    def save_model(self):
        """保存模型"""
        model_path = os.path.join(self.model_dir, "vuln_model.pkl")
        scaler_path = os.path.join(self.model_dir, "scaler.pkl")

        with open(model_path, 'wb') as f:
            pickle.dump(self.model, f)

        with open(scaler_path, 'wb') as f:
            pickle.dump(self.scaler, f)

        print(f"[*] 模型已保存: {model_path}")

    def load_model(self):
        """加载模型"""
        model_path = os.path.join(self.model_dir, "vuln_model.pkl")
        scaler_path = os.path.join(self.model_dir, "scaler.pkl")

        if os.path.exists(model_path) and os.path.exists(scaler_path):
            with open(model_path, 'rb') as f:
                self.model = pickle.load(f)

            with open(scaler_path, 'rb') as f:
                self.scaler = pickle.load(f)

            print(f"[*] 模型已加载: {model_path}")
            return True

        return False

    def generate_training_data(self) -> List[Dict]:
        """生成训练数据"""
        # 已知漏洞特征
        vuln_patterns = {
            "SQL注入": {
                "url_patterns": ["id=", "user=", "page=", "search=", "query="],
                "response_patterns": ["sql syntax", "mysql", "ora-", "sql server"],
                "path_patterns": ["login", "admin", "api", "search"],
            },
            "XSS": {
                "url_patterns": ["q=", "search=", "input=", "name="],
                "response_patterns": ["<script>", "alert(", "onerror="],
                "path_patterns": ["search", "comment", "feedback"],
            },
            "信息泄露": {
                "url_patterns": [],
                "response_patterns": ["password", "secret", "token", "api_key"],
                "path_patterns": [".env", ".git", "config", "backup", "debug"],
            },
            "配置错误": {
                "url_patterns": [],
                "response_patterns": ["server:", "x-powered-by:", "debug"],
                "path_patterns": ["admin", "console", "dashboard", "actuator"],
            },
        }

        training_data = []

        # 生成正样本
        for vuln_type, patterns in vuln_patterns.items():
            for i in range(100):
                url = f"https://example.com/{patterns['path_patterns'][i % len(patterns['path_patterns'])]}?id={i}"

                response_text = ""
                if patterns['response_patterns']:
                    response_text = f"Error: {patterns['response_patterns'][i % len(patterns['response_patterns'])]}"

                response_headers = {
                    "status_code": 200,
                    "server": "nginx",
                }

                training_data.append({
                    "url": url,
                    "response_text": response_text,
                    "response_headers": response_headers,
                    "label": 1,
                    "vuln_type": vuln_type,
                })

        # 生成负样本
        for i in range(400):
            url = f"https://example.com/page{i}"

            response_text = f"<html><body>Page {i} content</body></html>"

            response_headers = {
                "status_code": 200,
                "server": "nginx",
                "x-frame-options": "DENY",
                "content-security-policy": "default-src 'self'",
            }

            training_data.append({
                "url": url,
                "response_text": response_text,
                "response_headers": response_headers,
                "label": 0,
                "vuln_type": "none",
            })

        return training_data

    def auto_train(self):
        """自动训练"""
        print("[*] 开始自动训练...")

        # 生成训练数据
        training_data = self.generate_training_data()

        # 训练模型
        accuracy = self.train(training_data)

        return accuracy


# 全局实例
_ml_engine = None


def get_ml_engine() -> MLEngine:
    """获取机器学习引擎实例"""
    global _ml_engine
    if _ml_engine is None:
        _ml_engine = MLEngine()
    return _ml_engine


def predict_vulnerability(url: str, response_text: str, response_headers: Dict) -> Tuple[float, Dict]:
    """预测漏洞概率"""
    engine = get_ml_engine()
    return engine.predict(url, response_text, response_headers)


if __name__ == "__main__":
    # 测试
    engine = MLEngine()

    # 自动训练
    engine.auto_train()

    # 测试预测
    test_url = "https://example.com/admin?id=1"
    test_response = "Error: sql syntax near '1'"
    test_headers = {"status_code": 200, "server": "nginx"}

    probability, details = engine.predict(test_url, test_response, test_headers)
    print(f"\n[*] 测试预测:")
    print(f"  URL: {test_url}")
    print(f"  漏洞概率: {probability:.4f}")
    print(f"  重要特征: {details.get('top_features', [])}")
