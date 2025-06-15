from py2neo.ogm import Model, Property, RelatedTo, RelatedFrom, Label
from neo4j import GraphDatabase
import os
import json
import sys
from urllib.parse import quote
from py2neo import Graph, Node, Subgraph
import re

# 连接数据库
graph=Graph("http://localhost:7475", auth=("neo4j", "neo4j"),name="neo4j")

current_path=os.getcwd()
sys.path.append(current_path)

#json_path=current_path+"/test_examples/"

json_path="/home/deeplearning/nas-files/tplite/document/test_examples/"



# 定义 CVE 类
class CVE:
    def __init__(self, cve_id, description, published_date, last_modified_date, affected_cpes, cwe,
                 cvss_v2=None, severity=None, exploitability_score=None, impact_score=None):
        self.cve_id = cve_id
        self.description = description
        self.published_date = published_date
        self.last_modified_date = last_modified_date
        self.affected_cpes = affected_cpes  # 这将是一个列表，包含字典
        self.cwe = cwe
        self.cvss_v2 = cvss_v2
        self.severity = severity
        self.exploitability_score = exploitability_score
        self.impact_score = impact_score

    def to_node(self):
        cvss_v2_str = json.dumps(self.cvss_v2)  # 将 cvss_v2 字典转换为 JSON 字符串
        affected_cpes_str = json.dumps(self.affected_cpes)  # 将扩展的 CPE 信息转换为 JSON 字符串
        node = Node("CVE",
                    cve_id=self.cve_id,
                    description=self.description,
                    published_date=self.published_date,
                    last_modified_date=self.last_modified_date,
                    affected_cpes=affected_cpes_str,  # 保存为 JSON 字符串
                    cwe=self.cwe,
                    cvss_v2=cvss_v2_str,
                    severity=self.severity,
                    exploitability_score=self.exploitability_score,
                    impact_score=self.impact_score)
        node.__primarylabel__ = "CVE"
        node.__primarykey__ = "cve_id"
        return node



class Software:
    def __init__(self, name, author, path, entity_type):
        self.name = name
        self.author = author
        self.path = path
        self.entity_type = entity_type  # "Library" 或 "Component"
        self.unique_id = f"{self.author}%{self.name}"

    def create_node(self):  
        node = Node("Software",
                    name = self.name,
                    author = self.author,
                    path = self.path,
                    entity_type = self.entity_type,
                    unique_id=self.unique_id)
        node.__primarylabel__ = "Software"
        node.__primarykey__ = "unique_id"
        return node

    



class LibVersion:   
    def __init__(self, tag, commit_date, repo_name, author):
        self.tag = tag #github tag
        self.version = extract_version(self.tag) #formatted tag  #FIXME 目前定义是按照git tag的每一个tag创建版本节点 实际上最好按照发布版本创建版本节点 不同的Tag（git tag）会对应同一个发布节点
        self.commit_date = commit_date
        self.repo_name = repo_name
        self.author = author
        self.unique_id=f"{self.author}%{self.repo_name}%{self.tag}"

    def create_node(self):
        # 创建并返回节点
        node = Node("LibVersion",
                    tag=self.tag,
                    commit_date=self.commit_date,
                    repo_name=self.repo_name,
                    author=self.author,
                    unique_id=self.unique_id,
                    version = self.version)  # 添加 unique_id 作为属性
        node.__primarylabel__ = "LibVersion"
        node.__primarykey__ = "unique_id"
        return node

'''class LibVersion:
    def __init__(self, version, commit_date, repo_name, author):
        # self.tag = tag
        self.version = version
        self.commit_date = commit_date
        self.repo_name = repo_name
        self.author = author
        self.unique_id=f"{self.author}%{self.repo_name}%{self.version}"

    def create_node(self):
        # 创建并返回节点
        node = Node("LibVersion",
                    # tag=self.tag,
                    version = self.version,
                    commit_date=self.commit_date,
                    repo_name=self.repo_name,
                    author=self.author,
                    unique_id=self.unique_id)  # 添加 unique_id 作为属性
        node.__primarylabel__ = "LibVersion"
        node.__primarykey__ = "unique_id"
        return node
'''
class Patch:
    def __init__(self, cve_id,commit_id,repo_name, repo_owner, commit_date,commit_version):
        self.cve_id=cve_id
        self.commit_id = commit_id
        self.repo_owner = repo_owner
        self.repo_name = repo_name
        self.commit_date = commit_date
        self.commit_version = commit_version
        self.commit_format_version = extract_version(commit_version)
    def create_node(self):
        node = Node("Patch",
                    cve_id=self.cve_id,
                    commit_id=self.commit_id,
                    repo_name =self.repo_name,
                    repo_owner=self.repo_owner,
                    commit_date=self.commit_date,
                    commit_version=self.commit_version,
                    commit_format_version= self.commit_format_version)  # 保存为 JSON 字符串
        node.__primarylabel__ = "Patch"
        node.__primarykey__ = "commit_id"
        return node


# 解析获得 CPE 信息
def parse_cpe_from_json(configurations):
    cpes = []
    for node in configurations.get("nodes", []):
        if "cpe_match" in node:
            for cpe in node["cpe_match"]:
                if cpe.get("vulnerable", False):
                    cpe_info = {
                        "cpe23Uri": cpe.get("cpe23Uri", ""),
                        "versionStartIncluding": cpe.get("versionStartIncluding", ""),
                        "versionEndExcluding": cpe.get("versionEndExcluding", "")
                    }
                    cpes.append(cpe_info)

        if "children" in node:  # 如果有子节点，则递归解析
            cpes.extend(parse_cpe_from_json({"nodes": node["children"]}))
    return cpes


def extract_version(tag):
    # 正则表达式解析复杂版本字符串
    # 该表达式首先尝试找到连续的三个数字或不足三个数字，每个数字的长度不超过四位数，可能包含点或下划线分隔的数字
    pattern = r'(?:[a-zA-Z_-]*[vV]?[a-zA-Z_]*[\-_])?(\d{1,4}(?:[._-]\d{1,4}){0,2})(?:[._][a-zA-Z0-9]*[\-_][a-zA-Z0-9]*)?'
    match = re.search(pattern, tag)
    if match:
        # 提取连续的数字作为版本号
        version = match.group(1)
        # 将数字间的分隔符统一成点
        version = re.sub(r'[._-]', '.', version)
        # 检查小版本号长度，如果大于等于四，舍去小版本号
        version_parts = version.split('.')
        if len(version_parts) >= 3 and len(version_parts[2]) >= 4:
            version = '.'.join(version_parts[:2])
        return version
    return None



def main():
    tx = graph.begin()  
    n  = 0
    #for jsonfile in os.listdir(json_path):
    #    with open(os.path.join(json_path, jsonfile), 'r', encoding = "UTF-8") as fp:
    test_file="/home/deeplearning/nas-files/tplite/document/test_examples/CVE-2013-0001.json"

    with open(test_file, 'r', encoding = "UTF-8") as fp:
        
        json_data = json.load(fp)

        cve_id = json_data["cve"]["CVE_data_meta"]["ID"]
        description = json_data["cve"]["description"]["description_data"][0]["value"]
        published_date = json_data["publishedDate"]
        last_modified_date = json_data["lastModifiedDate"]
        affected_cpes = parse_cpe_from_json(json_data["configurations"])
        cwe = json_data["cve"]["problemtype"]["problemtype_data"][0]["description"][0]["value"]

        # 创建 CVE 实例
        cve = CVE(cve_id, description, published_date, last_modified_date, affected_cpes, cwe)
        tx.create(cve.to_node()) 
        n+=1
    
    graph.commit(tx)
    print(n)