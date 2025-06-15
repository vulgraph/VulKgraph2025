#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
代码克隆检测核心算法实现
实现论文中Algorithm 1: 综合软件复用检测

主要功能：
1. TPL特征构建 - 构建第三方库特征库
2. LSH距离计算 - 基于局部敏感哈希的相似度计算
3. 时间感知复用检测 - 基于BirthTime的方向性复用检测
4. 自适应阈值机制 - 针对生态系统异构性的动态阈值调整
5. SBOM解析 - 显式依赖关系提取

作者：VulnGraph项目组
日期：2024年
"""

import os
import json
import re
import hashlib
import time
from datetime import datetime
from typing import Dict, List, Tuple, Set, Optional
from collections import defaultdict
import subprocess
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

# 设置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class FunctionSignature:
    """
    函数签名类，用于存储和处理函数特征
    包含函数内容、哈希值、诞生时间等信息
    """
    
    def __init__(self, content: str, file_path: str, line_number: int, 
                 repo_name: str, author: str, birth_time: Optional[datetime] = None):
        self.content = content
        self.file_path = file_path
        self.line_number = line_number
        self.repo_name = repo_name
        self.author = author
        self.birth_time = birth_time
        
        # 预处理函数内容
        self.processed_content = self._preprocess_content(content)
        
        # 计算SimHash
        self.simhash = self._compute_simhash(self.processed_content)
        
        # 计算MD5哈希作为唯一标识
        self.md5_hash = hashlib.md5(self.processed_content.encode('utf-8')).hexdigest()
    
    def _preprocess_content(self, content: str) -> str:
        """
        预处理函数内容，移除注释、空白字符和其他非语义元素
        
        Args:
            content: 原始函数内容
            
        Returns:
            处理后的函数内容
        """
        # 移除单行注释
        content = re.sub(r'//.*', '', content)
        
        # 移除多行注释
        content = re.sub(r'/\*.*?\*/', '', content, flags=re.DOTALL)
        
        # 移除多余的空白字符
        content = re.sub(r'\s+', ' ', content)
        
        # 移除字符串字面量
        content = re.sub(r'"[^"]*"', '""', content)
        content = re.sub(r"'[^']*'", "''", content)
        
        # 标准化大括号和分号
        content = content.replace('{', ' { ').replace('}', ' } ')
        content = content.replace(';', ' ; ')
        
        return content.strip()
    
    def _compute_simhash(self, content: str) -> int:
        """
        计算SimHash值，用于快速相似度比较
        
        Args:
            content: 预处理后的函数内容
            
        Returns:
            64位SimHash值
        """
        # 提取特征（关键词）
        features = self._extract_features(content)
        
        # 初始化权重向量
        weights = [0] * 64
        
        for feature in features:
            # 计算特征的哈希值
            feature_hash = hashlib.md5(feature.encode('utf-8')).hexdigest()
            
            # 将哈希值转换为64位二进制
            hash_int = int(feature_hash, 16) & ((1 << 64) - 1)
            
            # 更新权重向量
            for i in range(64):
                if (hash_int >> i) & 1:
                    weights[i] += 1
                else:
                    weights[i] -= 1
        
        # 生成SimHash
        simhash = 0
        for i in range(64):
            if weights[i] > 0:
                simhash |= (1 << i)
        
        return simhash
    
    def _extract_features(self, content: str) -> List[str]:
        """
        从函数内容中提取特征词
        
        Args:
            content: 函数内容
            
        Returns:
            特征词列表
        """
        # C/C++关键词
        keywords = {
            'int', 'float', 'double', 'char', 'void', 'if', 'else', 'for', 
            'while', 'do', 'switch', 'case', 'return', 'break', 'continue',
            'struct', 'union', 'enum', 'typedef', 'const', 'static', 'extern',
            'malloc', 'free', 'sizeof', 'printf', 'scanf', 'NULL'
        }
        
        # 提取标识符和操作符
        tokens = re.findall(r'\w+|[+\-*/=<>!&|]', content)
        
        # 构建特征集合
        features = []
        
        # 添加关键词特征
        for token in tokens:
            if token.lower() in keywords:
                features.append(f"keyword_{token.lower()}")
        
        # 添加标识符特征
        identifiers = [token for token in tokens if token.isalpha() and token.lower() not in keywords]
        for identifier in identifiers:
            features.append(f"identifier_{identifier}")
        
        # 添加操作符特征
        operators = [token for token in tokens if not token.isalnum()]
        for operator in operators:
            features.append(f"operator_{operator}")
        
        # 添加bigram特征
        for i in range(len(tokens) - 1):
            features.append(f"bigram_{tokens[i]}_{tokens[i+1]}")
        
        return features
    
    def hamming_distance(self, other: 'FunctionSignature') -> int:
        """
        计算与另一个函数签名的汉明距离
        
        Args:
            other: 另一个函数签名对象
            
        Returns:
            汉明距离
        """
        xor_result = self.simhash ^ other.simhash
        return bin(xor_result).count('1')


class TPLFeatureLibrary:
    """
    第三方库特征库类
    用于存储和管理所有软件项目的函数特征
    """
    
    def __init__(self):
        # 存储所有函数签名的字典：repo_name -> version -> [FunctionSignature]
        self.library: Dict[str, Dict[str, List[FunctionSignature]]] = defaultdict(lambda: defaultdict(list))
        
        # 存储函数的全局索引，用于快速查找
        self.function_index: Dict[str, List[FunctionSignature]] = defaultdict(list)
        
        # 存储每个仓库的复用统计信息
        self.reuse_stats: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
    
    def add_function(self, function: FunctionSignature, version: str):
        """
        添加函数到特征库
        
        Args:
            function: 函数签名对象
            version: 软件版本
        """
        repo_key = f"{function.author}%{function.repo_name}"
        
        # 添加到主库
        self.library[repo_key][version].append(function)
        
        # 添加到索引
        self.function_index[function.md5_hash].append(function)
        
        logger.debug(f"Added function from {repo_key}@{version}: {function.md5_hash[:8]}")
    
    def get_functions_by_repo(self, repo_name: str, author: str, version: str = None) -> List[FunctionSignature]:
        """
        获取指定仓库的所有函数
        
        Args:
            repo_name: 仓库名称
            author: 作者名称
            version: 版本号（可选）
            
        Returns:
            函数签名列表
        """
        repo_key = f"{author}%{repo_name}"
        
        if version:
            return self.library.get(repo_key, {}).get(version, [])
        else:
            # 返回所有版本的函数
            all_functions = []
            for ver_functions in self.library.get(repo_key, {}).values():
                all_functions.extend(ver_functions)
            return all_functions
    
    def update_reuse_stats(self, repo_name: str, author: str, reused_functions: int):
        """
        更新仓库的复用统计信息
        
        Args:
            repo_name: 仓库名称
            author: 作者名称
            reused_functions: 被复用的函数数量
        """
        repo_key = f"{author}%{repo_name}"
        self.reuse_stats[repo_key]['reused_count'] += reused_functions
        self.reuse_stats[repo_key]['total_functions'] = len(self.get_functions_by_repo(repo_name, author))


class CodeCloneDetector:
    """
    代码克隆检测器核心类
    实现论文中的Algorithm 1: 综合软件复用检测
    """
    
    def __init__(self, config: Dict):
        """
        初始化代码克隆检测器
        
        Args:
            config: 配置字典，包含阈值、路径等配置信息
        """
        self.config = config
        
        # 初始化特征库
        self.tpl_library = TPLFeatureLibrary()
        
        # 设置阈值参数
        self.base_threshold = config.get('base_threshold', 0.1)  # 基础阈值θ0
        self.hamming_threshold = config.get('hamming_threshold', 8)  # 汉明距离阈值（64位中的8位）
        
        # 设置路径
        self.oss_path = config.get('oss_path', '/home/deeplearning/nas-files/tracer/data/data/MyProj/')
        self.ccscanner_path = config.get('ccscanner_path', '/home/deeplearning/nas-files/tplite/document/CCScanner_dataset/')
        
        # 线程池配置
        self.max_workers = config.get('max_workers', 4)
        
        logger.info(f"初始化代码克隆检测器 - 基础阈值: {self.base_threshold}, 汉明距离阈值: {self.hamming_threshold}")
    
    def extract_functions_from_file(self, file_path: str, repo_name: str, author: str) -> List[FunctionSignature]:
        """
        从C/C++文件中提取函数
        
        Args:
            file_path: 文件路径
            repo_name: 仓库名称
            author: 作者名称
            
        Returns:
            函数签名列表
        """
        functions = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # 使用正则表达式提取函数定义
            # 这是一个简化的函数提取器，实际应用中可能需要更复杂的解析器
            function_pattern = r'(?:^|\n)([a-zA-Z_][a-zA-Z0-9_]*\s+[a-zA-Z_][a-zA-Z0-9_]*\s*\([^)]*\)\s*\{[^}]*\})'
            
            matches = re.finditer(function_pattern, content, re.MULTILINE | re.DOTALL)
            
            for match in matches:
                func_content = match.group(1).strip()
                line_number = content[:match.start()].count('\n') + 1
                
                # 过滤掉太短的函数（可能是宏或声明）
                if len(func_content) < 50:
                    continue
                
                # 获取函数的诞生时间（通过git blame）
                birth_time = self._get_function_birth_time(file_path, line_number, repo_name, author)
                
                function = FunctionSignature(
                    content=func_content,
                    file_path=file_path,
                    line_number=line_number,
                    repo_name=repo_name,
                    author=author,
                    birth_time=birth_time
                )
                
                functions.append(function)
        
        except Exception as e:
            logger.warning(f"解析文件 {file_path} 时出错: {e}")
        
        return functions
    
    def _get_function_birth_time(self, file_path: str, line_number: int, repo_name: str, author: str) -> Optional[datetime]:
        """
        获取函数的诞生时间（首次提交时间）
        
        Args:
            file_path: 文件路径
            line_number: 函数起始行号
            repo_name: 仓库名称
            author: 作者名称
            
        Returns:
            函数诞生时间
        """
        try:
            repo_path = os.path.join(self.oss_path, f"{author}%{repo_name}")
            
            # 尝试找到实际的git仓库路径
            if os.path.exists(os.path.join(repo_path, repo_name)):
                repo_path = os.path.join(repo_path, repo_name)
            
            if not os.path.exists(repo_path):
                return None
            
            # 获取相对路径
            rel_path = os.path.relpath(file_path, repo_path)
            
            # 使用git log获取文件的首次提交时间
            cmd = ['git', '-C', repo_path, 'log', '--follow', '--format=%ai', '--', rel_path]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0 and result.stdout.strip():
                # 获取最后一行（最早的提交）
                dates = result.stdout.strip().split('\n')
                if dates:
                    earliest_date = dates[-1]
                    return datetime.strptime(earliest_date[:19], '%Y-%m-%d %H:%M:%S')
        
        except Exception as e:
            logger.debug(f"获取函数诞生时间失败 {file_path}:{line_number} - {e}")
        
        return None
    
    def build_tpl_feature_library(self, repo_list: List[str] = None):
        """
        构建TPL特征库
        
        Args:
            repo_list: 要处理的仓库列表，如果为None则处理所有仓库
        """
        logger.info("开始构建TPL特征库...")
        
        if repo_list is None:
            # 扫描OSS目录下的所有仓库
            repo_list = [d for d in os.listdir(self.oss_path) 
                        if os.path.isdir(os.path.join(self.oss_path, d)) and '%' in d]
        
        # 使用线程池并行处理
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = []
            
            for repo in repo_list:
                future = executor.submit(self._process_repository, repo)
                futures.append(future)
            
            # 等待所有任务完成
            for future in as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        repo_name, author, functions_count = result
                        logger.info(f"处理完成 {author}%{repo_name}: {functions_count} 个函数")
                except Exception as e:
                    logger.error(f"处理仓库时出错: {e}")
        
        total_repos = len(self.tpl_library.library)
        total_functions = sum(len(funcs) for repo in self.tpl_library.library.values() 
                            for funcs in repo.values())
        
        logger.info(f"TPL特征库构建完成 - 共处理 {total_repos} 个仓库，{total_functions} 个函数")
    
    def _process_repository(self, repo_dir: str) -> Optional[Tuple[str, str, int]]:
        """
        处理单个仓库，提取其中的函数特征
        
        Args:
            repo_dir: 仓库目录名（格式：author%repo_name）
            
        Returns:
            (repo_name, author, functions_count) 或 None
        """
        try:
            author, repo_name = repo_dir.split('%', 1)
            repo_path = os.path.join(self.oss_path, repo_dir)
            
            # 检查是否有嵌套目录
            if os.path.exists(os.path.join(repo_path, repo_name)):
                repo_path = os.path.join(repo_path, repo_name)
            
            if not os.path.exists(repo_path):
                logger.warning(f"仓库路径不存在: {repo_path}")
                return None
            
            # 获取版本信息
            versions = self._get_repository_versions(repo_path)
            if not versions:
                versions = ['main']  # 默认版本
            
            total_functions = 0
            
            # 遍历C/C++文件
            for root, dirs, files in os.walk(repo_path):
                # 跳过隐藏目录和常见的非源码目录
                dirs[:] = [d for d in dirs if not d.startswith('.') and d not in ['build', 'test', 'tests', 'doc', 'docs']]
                
                for file in files:
                    if file.endswith(('.c', '.cpp', '.cc', '.cxx', '.h', '.hpp')):
                        file_path = os.path.join(root, file)
                        
                        # 提取函数
                        functions = self.extract_functions_from_file(file_path, repo_name, author)
                        
                        # 添加到特征库（使用最新版本）
                        current_version = versions[0] if versions else 'main'
                        for function in functions:
                            self.tpl_library.add_function(function, current_version)
                        
                        total_functions += len(functions)
            
            return repo_name, author, total_functions
        
        except Exception as e:
            logger.error(f"处理仓库 {repo_dir} 时出错: {e}")
            return None
    
    def _get_repository_versions(self, repo_path: str) -> List[str]:
        """
        获取仓库的版本列表
        
        Args:
            repo_path: 仓库路径
            
        Returns:
            版本列表（按时间倒序）
        """
        try:
            cmd = ['git', '-C', repo_path, 'tag', '--sort=-version:refname']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                tags = result.stdout.strip().split('\n')
                return [tag for tag in tags if tag]
        
        except Exception as e:
            logger.debug(f"获取版本信息失败 {repo_path}: {e}")
        
        return []
    
    def detect_all_reuse(self, project_path: str, project_name: str, project_author: str) -> Dict[str, any]:
        """
        实现Algorithm 1: 综合软件复用检测
        
        Args:
            project_path: 项目路径
            project_name: 项目名称
            project_author: 项目作者
            
        Returns:
            检测结果字典
        """
        logger.info(f"开始检测项目 {project_author}%{project_name} 的复用关系...")
        
        reuse_results = {
            'software_reuses': [],      # (Project_A, reuses, Project_B)
            'version_reuses': [],       # (Project_A, reuses_version, lib@version)
            'statistics': {}
        }
        
        # Part 1: 代码克隆检测
        logger.info("执行代码克隆检测...")
        code_clone_results = self._detect_code_clones(project_path, project_name, project_author)
        reuse_results['software_reuses'] = code_clone_results
        
        # Part 2: SBOM分析
        logger.info("执行SBOM分析...")
        sbom_results = self._analyze_sbom(project_path, project_name, project_author)
        reuse_results['version_reuses'] = sbom_results
        
        # 统计信息
        reuse_results['statistics'] = {
            'total_code_clones': len(code_clone_results),
            'total_sbom_dependencies': len(sbom_results),
            'analysis_time': time.time()
        }
        
        logger.info(f"复用检测完成 - 代码克隆: {len(code_clone_results)}, SBOM依赖: {len(sbom_results)}")
        
        return reuse_results
    
    def _detect_code_clones(self, project_path: str, project_name: str, project_author: str) -> List[Dict]:
        """
        检测代码克隆复用关系
        
        Args:
            project_path: 项目路径
            project_name: 项目名称
            project_author: 项目作者
            
        Returns:
            复用关系列表
        """
        reuse_relationships = []
        
        # 提取项目A的函数
        project_functions = []
        for root, dirs, files in os.walk(project_path):
            for file in files:
                if file.endswith(('.c', '.cpp', '.cc', '.cxx', '.h', '.hpp')):
                    file_path = os.path.join(root, file)
                    functions = self.extract_functions_from_file(file_path, project_name, project_author)
                    project_functions.extend(functions)
        
        logger.info(f"项目 {project_name} 共提取 {len(project_functions)} 个函数")
        
        # 与特征库中的每个项目进行比较
        for repo_key, versions in self.tpl_library.library.items():
            if repo_key == f"{project_author}%{project_name}":
                continue  # 跳过自己
            
            target_author, target_repo = repo_key.split('%', 1)
            
            # 获取目标项目的所有函数
            target_functions = []
            for version_functions in versions.values():
                target_functions.extend(version_functions)
            
            if not target_functions:
                continue
            
            # 检测共同函数
            common_functions = self._find_common_functions(project_functions, target_functions)
            
            if not common_functions:
                continue
            
            # 计算复用率
            reuse_rate = len(common_functions) / len(project_functions)
            
            # 计算自适应阈值
            adaptive_threshold = self._calculate_adaptive_threshold(target_repo, target_author, target_functions)
            
            # 判断是否构成复用关系
            if reuse_rate >= max(self.base_threshold, adaptive_threshold):
                reuse_relationships.append({
                    'source_project': f"{project_author}%{project_name}",
                    'target_project': repo_key,
                    'reuse_rate': reuse_rate,
                    'common_functions': len(common_functions),
                    'total_functions': len(project_functions),
                    'adaptive_threshold': adaptive_threshold,
                    'relationship_type': 'reuses'
                })
                
                logger.info(f"发现复用关系: {project_name} -> {target_repo} (复用率: {reuse_rate:.3f})")
        
        return reuse_relationships
    
    def _find_common_functions(self, functions_a: List[FunctionSignature], 
                              functions_b: List[FunctionSignature]) -> List[Tuple[FunctionSignature, FunctionSignature]]:
        """
        找到两个函数集合之间的共同函数（基于时间约束）
        
        Args:
            functions_a: 项目A的函数列表
            functions_b: 项目B的函数列表
            
        Returns:
            共同函数对列表
        """
        common_functions = []
        
        for func_a in functions_a:
            for func_b in functions_b:
                # 计算汉明距离
                hamming_dist = func_a.hamming_distance(func_b)
                
                # 检查相似度阈值
                if hamming_dist <= self.hamming_threshold:
                    # 检查时间约束：func_b应该早于func_a
                    if (func_a.birth_time and func_b.birth_time and 
                        func_b.birth_time < func_a.birth_time):
                        common_functions.append((func_a, func_b))
                        break  # 找到匹配就跳出内层循环
                    elif not func_a.birth_time or not func_b.birth_time:
                        # 如果没有时间信息，基于相似度判断
                        common_functions.append((func_a, func_b))
                        break
        
        return common_functions
    
    def _calculate_adaptive_threshold(self, target_repo: str, target_author: str, 
                                    target_functions: List[FunctionSignature]) -> float:
        """
        计算自适应阈值
        
        Args:
            target_repo: 目标仓库名
            target_author: 目标作者
            target_functions: 目标函数列表
            
        Returns:
            自适应阈值
        """
        repo_key = f"{target_author}%{target_repo}"
        
        # 获取该仓库的复用统计信息
        reuse_stats = self.tpl_library.reuse_stats.get(repo_key, {})
        total_functions = len(target_functions)
        reused_count = reuse_stats.get('reused_count', 0)
        
        if total_functions == 0:
            return self.base_threshold
        
        # 计算复用活跃度
        reuse_activity = reused_count / total_functions
        
        # 自适应阈值公式：θ_adapted = 1 / (Reused_num_B / |s_B|)
        if reuse_activity > 0:
            adaptive_threshold = 1.0 / reuse_activity
            # 限制阈值范围
            adaptive_threshold = min(adaptive_threshold, 1.0)
            adaptive_threshold = max(adaptive_threshold, 0.01)
        else:
            adaptive_threshold = self.base_threshold
        
        return adaptive_threshold
    
    def _analyze_sbom(self, project_path: str, project_name: str, project_author: str) -> List[Dict]:
        """
        分析SBOM文件，提取显式依赖关系
        
        Args:
            project_path: 项目路径
            project_name: 项目名称
            project_author: 项目作者
            
        Returns:
            版本复用关系列表
        """
        version_reuses = []
        
        # 查找项目对应的CCScanner结果
        ccscanner_file = os.path.join(self.ccscanner_path, f"{project_author}@@{project_name}.json")
        
        if not os.path.exists(ccscanner_file):
            logger.warning(f"未找到CCScanner结果文件: {ccscanner_file}")
            return version_reuses
        
        try:
            with open(ccscanner_file, 'r', encoding='utf-8') as f:
                ccscanner_data = json.load(f)
            
            # 解析CCScanner结果
            for repo_key, components in ccscanner_data.items():
                if not components:
                    continue
                
                for comp_name, comp_list in components.items():
                    for comp in comp_list:
                        dep_name = comp.get('depname', '')
                        version = comp.get('version', '')
                        version_op = comp.get('version_op', '')
                        
                        if dep_name and version:
                            version_reuses.append({
                                'source_project': f"{project_author}%{project_name}",
                                'target_library': dep_name,
                                'version': version,
                                'version_operator': version_op,
                                'relationship_type': 'reuses_version'
                            })
            
            logger.info(f"从SBOM中提取到 {len(version_reuses)} 个版本依赖")
        
        except Exception as e:
            logger.error(f"解析CCScanner结果时出错: {e}")
        
        return version_reuses
    
    def save_results(self, results: Dict, output_path: str):
        """
        保存检测结果到文件
        
        Args:
            results: 检测结果
            output_path: 输出文件路径
        """
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(results, f, indent=2, ensure_ascii=False, default=str)
            
            logger.info(f"结果已保存到: {output_path}")
        
        except Exception as e:
            logger.error(f"保存结果时出错: {e}")


def main():
    """
    主函数，演示代码克隆检测器的使用
    """
    # 配置参数
    config = {
        'base_threshold': 0.1,
        'hamming_threshold': 8,
        'oss_path': '/home/deeplearning/nas-files/tracer/data/data/MyProj/',
        'ccscanner_path': '/home/deeplearning/nas-files/tplite/document/CCScanner_dataset/',
        'max_workers': 4
    }
    
    # 初始化检测器
    detector = CodeCloneDetector(config)
    
    # 构建TPL特征库（可以指定特定的仓库列表）
    # sample_repos = ["torvalds%linux", "openssl%openssl"]  # 示例仓库
    # detector.build_tpl_feature_library(sample_repos)
    
    # 构建完整的TPL特征库
    detector.build_tpl_feature_library()
    
    # 检测特定项目的复用关系
    project_path = "/home/deeplearning/nas-files/tracer/data/data/MyProj/curl%curl/curl"
    project_name = "curl"
    project_author = "curl"
    
    results = detector.detect_all_reuse(project_path, project_name, project_author)
    
    # 保存结果
    output_path = f"/home/deeplearning/nas-files/github_push_dir/Vulgraph-Gao/document/results_{project_name}_reuse_analysis.json"
    detector.save_results(results, output_path)
    
    # 打印统计信息
    print(f"\n=== 复用检测结果统计 ===")
    print(f"代码克隆复用关系: {results['statistics']['total_code_clones']}")
    print(f"SBOM版本依赖: {results['statistics']['total_sbom_dependencies']}")
    print(f"总计发现复用关系: {results['statistics']['total_code_clones'] + results['statistics']['total_sbom_dependencies']}")


if __name__ == "__main__":
    main() 