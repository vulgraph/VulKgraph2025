from py2neo import Graph, Node, Relationship,Subgraph,NodeMatcher
import re
import os
import json
import time
from urllib.parse import quote
import threading
import subprocess
from Node import CVE,Software,LibVersion


from py2neo import NodeMatcher



def process_CCScanner(CCScanner_json_path):
    with open(CCScanner_json_path, 'r') as file:
        data = json.load(file)
    
    nodes = []
    relationships = []

    # 创建节点和关系
    for repo_name, components in data.items():
        # 使用 Software 类创建库节点
        tx = graph.begin()
        name = repo_name.split("@@")[1]
        author = repo_name.split("@@")[0]
        # repo_node = Software(name = name,author =author,path = None,entity_type = "Library").create_node()
        # nodes.append(repo_node)
        # tx.merge(repo_node)
        repo_node = graph.match(name = name,author = author)

        # 遍历组件
        if components:
            for comp_name, comp_list in components.items():
                for comp in comp_list:
                    # 使用 Component 类创建组件节点

                    # comp_node = Software(name = comp['depname'],author = None,path=None,entity_type = "Component").create_node()
                    # nodes.append(comp_node)
                    # tx.merge(comp_node)

                    comp_node = graph.match(name = comp['depname'])
                    version = comp.get('version')
                    version_op = comp.get('version_op')

                    matched_version_nodes = match_lib_version(version, version_op)

                    # 创建从库到组件的关系
                    rel = Relationship(repo_node, "REUSES", comp_node,
                                           version=comp.get('version'),
                                           version_op=comp.get('version_op'))

                    


                    # relationships.append(rel)
                    # tx.create(rel)
                    # 检查并写入 version 和 version_op
                    '''if comp.get('version') or comp.get('version_op'):
                        fp.write(f"{comp['depname']}: version={comp.get('version')}, version_op={comp.get('version_op')}\n")   '''  
        graph.commit(tx)


from py2neo import Graph, NodeMatcher, Relationship

# 初始化Neo4j连接
graph=Graph("http://localhost:7474", auth=("neo4j", "neo4j"),name="neo4j")


def extract_version(version_str):
    """
    提取出大版本号和次要版本号，返回格式化的版本号。
    """
    parts = version_str.split('.')
    major = parts[0]
    minor = parts[1] if len(parts) > 1 else '0'
    return f"{major}.{minor}"

def parse_version_dependency(version_str):
    """
    解析 version 字段并根据标志返回版本的大版本号和次要版本号。
    """
    caret_pattern = r'^\^(\d+\.\d+(\.\d+)?)$'
    tilde_pattern = r'^~(\d+\.\d+(\.\d+)?)$'

    if re.match(caret_pattern, version_str):
        version_number = re.match(caret_pattern, version_str).group(1)
        major = version_number.split('.')[0]  # 提取大版本号
        return ('^', major, version_number)  # 返回标志，大版本号，和完整版本号
    elif re.match(tilde_pattern, version_str):
        version_number = re.match(tilde_pattern, version_str).group(1)
        major, minor = version_number.split('.')[:2]  # 提取大版本号和次要版本号
        return ('~', f"{major}.{minor}", version_number)  # 返回标志，大版本号和次要版本号，和完整版本号
    else:
        return (None, version_str)  # 指定版本或无操作符

def parse_version_condition(version, version_op):
    version = "^4.2.1"
    version_op =None
    if version_op is None:
        if version.startswith('^'):
            major_version = extract_version(version[1:])  # 提取大版本号
            return f"STARTS WITH '{major_version}.0'"
        elif version.startswith('~'):
            major_minor_version = extract_version(version[1:])  # 提取大版本号和次要版本号
            return f"STARTS WITH '{major_minor_version}.0'"
        else:
            return f"= '{version}'"  # 精确匹配
    else:
        return f"{version_op} '{version}'"  # 使用操作符

def process_reuse_relationships():
    # graph = driver.session()
    
    # 获取所有软件复用关系
    query = "MATCH (s1:Software)-[r:REUSE]->(s2:Software) RETURN s1, s2, r"
    relationships = graph.run(query)
    
    for s1, s2, r in relationships:
        version = r['version']
        version_op = r['version_op']
        condition = parse_version_condition(version, version_op)
        
        # 根据条件查询符合版本的LibVersion节点
        lib_versions_query = f"MATCH (s2)-[:HAS_VERSION]->(lv:LibVersion) WHERE lv.version {condition} RETURN lv"
        lib_versions = graph.run(lib_versions_query)
        
        for lv in lib_versions:
            # 创建新的版本复用关系
            reuse_rel = Relationship(s1, "VERSION_REUSE", lv, version=version, version_op=version_op)
            graph.create(reuse_rel)
            print(f"Created VERSION_REUSE relationship from {s1['name']} to LibVersion {lv['version']}")

# 运行函数
process_reuse_relationships()

# 调用函数处理所有软件复用关系
# process_reuse_relationships()
'''test = [v8-tools: version=1.0.0, version_op=None
local-web-server: version=^4.2.1, version_op=None]'''
print(parse_version_condition("^4.2.1",None))