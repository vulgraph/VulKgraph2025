from py2neo import Graph, Node, Relationship,Subgraph,NodeMatcher
import re
import os
import json
import time
from urllib.parse import quote
import threading
import subprocess
from Node import CVE,Software,LibVersion
from packaging import version
from Node import extract_version

current_path = "/home/deeplearning/nas-files/tplite/document/"
OSS_Path = "/home/deeplearning/nas-files/tracer/data/data/MyProj/"
git2cpe_path = current_path +"V1SCAN/git2cpe.json"
git2cpe_ver_path = current_path+"V1SCAN/Git2CPE_ver/"

# 连接到Neo4j
graph=Graph("http://localhost:7475", auth=("neo4j", "neo4j"),name="neo4j")




def load_name_mappings(filename):
    with open(filename, 'r') as file:
        mappings = json.load(file)
    # 反转映射，以便我们可以使用CPE信息查找GitHub信息

    # git2cpe文件 
    reverse_mappings = {v: k for k, v in mappings.items()}
    return reverse_mappings

def load_version_mappings(directory):
    version_mappings = {}
    for filename in os.listdir(directory):
        path = os.path.join(directory, filename)
        with open(path, 'r') as file:
            mappings = {}
            for line in file:
                git_version, cpe_version = line.strip().split('@#@')
                if cpe_version not in mappings:
                    mappings[cpe_version] = []
                #多个gitversion可能对应同一个cpe_version
                mappings[cpe_version].append(git_version)
            version_mappings[filename.replace('.txt', '')] = mappings
    return version_mappings


def extract_major_minor(version):
    """
    Extracts the major and minor parts from a version string.
    
    Args:
    version (str): The version string in the format of 'major.minor.patch'.
    
    Returns:
    str: The 'major.minor' part of the version, or an empty string if not found.
    """
    pattern = r"^(\d+\.\d+)"
    match = re.match(pattern, version)
    if match:
        return match.group(1)
    return ""



def parse_cpe(cpe_str):
    pattern = r'cpe:2\.3:(?P<part>[aho]):(?P<vendor>[^:]*):(?P<product>[^:]*):(?P<version>[^:]*):.*'
    match = re.match(pattern, cpe_str)
    if match:
        return match.groupdict()
    else:
        return None


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
                        "versionStartExcluding":cpe.get("versionStartExcluding", ""),
                        "versionEndIncluding":cpe.get("versionEndIncluding", ""),
                        "versionEndExcluding": cpe.get("versionEndExcluding", "")
                    }
                    cpes.append(cpe_info)

        if "children" in node:  # 如果有子节点，则递归解析
            cpes.extend(parse_cpe_from_json({"nodes": node["children"]}))
    return cpes


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
        repo_node = Software(name = name,author =author,path = None,entity_type = "Library").create_node()
        # nodes.append(repo_node)
        tx.merge(repo_node)
        # 遍历组件
        if components:
            for comp_name, comp_list in components.items():
                for comp in comp_list:
                    # 使用 Component 类创建组件节点

                    comp_node = Software(name = comp['depname'],author = None,path=None,entity_type = "Component").create_node()
                    # nodes.append(comp_node)
                    tx.merge(comp_node)
                    # 创建从库到组件的关系
                    rel = Relationship(repo_node, "REUSES", comp_node,
                                           version=comp.get('version'),
                                           version_op=comp.get('version_op'))

                    # relationships.append(rel)
                    tx.create(rel)
                    # 检查并写入 version 和 version_op
                    '''if comp.get('version') or comp.get('version_op'):
                        fp.write(f"{comp['depname']}: version={comp.get('version')}, version_op={comp.get('version_op')}\n")   '''  
        graph.commit(tx)


def parse_repository_name(repo_name):
    """解析库名格式"""
    parts = repo_name.split('%')
    if len(parts) == 2:
        return parts[0], parts[1]
    return None, None

def get_tag_details(repo_path):
    """使用单次 git 命令调用来获取所有标签及其对应的第一次提交日期，
    对没有日期的标签，使用其最近的提交日期作为标签日期。"""
    # 获取所有标签及其首次提交日期
    command = [
        "git", "-C", repo_path, "for-each-ref", "--sort=creatordate",
        "--format=%(creatordate:short) %(refname:short)", "refs/tags"
    ]
    result = subprocess.run(command, stdout=subprocess.PIPE, text=True)
    raw_tags_data = result.stdout.strip().split('\n')

    tag_details = {}
    for line in raw_tags_data:
        if line:
            parts = line.split()
            if len(parts) < 2:
                # print(f"警告: 无法解析行 '{line}'，因为它不包含足够的信息。尝试获取最近的提交日期。")
                # 尝试获取这个标签的最近提交日期
                tag = ' '.join(parts)  # 标签可能是整行，如果它不包含日期
                git_log_command = ["git", "-C", repo_path, "log", "-1", "--format=%ai", tag]
                log_result = subprocess.run(git_log_command, stdout=subprocess.PIPE, text=True)
                date = log_result.stdout.strip()
                tag_details[tag] = date 
            else:
                date = parts[0]
                tag = ' '.join(parts[1:])  # 如果标签名中包含空格，将剩余部分再组合回去
                tag_details[tag] = date

    return tag_details

def process_libraries(OSS_Path):
    """处理所有库及其版本"""
    repositories = [d for d in os.listdir(OSS_Path) if os.path.isdir(os.path.join(OSS_Path, d))]
    # repositories = ["torvalds%linux"]
    # repositories = ["wazuh%wazuh"]
    # cnt = 0
    for repo in repositories:
        tx = graph.begin()  # 开始一个新的事务
        try:
            fp = open(current_path+"completed_lib2.txt","a+")
            # cnt = cnt+1
            fp.seek(0)
            lines = [line.rstrip('\n') for line in fp.readlines()]
            # print(lines)
            if repo in lines:
                continue
            
            #print(repo)
            author, repo_name = repo.split('%')
            #print(f"processing {repo}")
            if not author or not repo_name:
                raise ValueError("Repository name format error, expected 'author%repo_name'.")

            repo_path = os.path.join(OSS_Path,repo)
            #print(repo_path)
            if os.path.isdir(os.path.join(repo_path,repo_name)):
                repo_path = os.path.join(repo_path,repo_name)
            #print(1)
            tag_details = get_tag_details(repo_path)
            #print(2)
    
            software = Software(name=repo_name, author=author, path=repo_path, entity_type=None)
            software_node = software.create_node()
            tx.merge(software_node)

            versions=[]
            
            sorted_tags = sorted(tag_details.items(), key=lambda item: item[1])  # 根据日期排序
            previous_version_node = None
            # print(sorted_tags)
            # for tag, date in tag_details.items():

            #print(3)
            for tag, date in sorted_tags:
                version = extract_version(tag)
                #print(tag)
                #print(version)
                if version in versions:
                    continue
                versions.append(version)
                version_node = LibVersion(version=version, commit_date=date, repo_name=repo_name, author=author).create_node()
                tx.merge(version_node)

                if previous_version_node:
                    rel_precedes = Relationship(previous_version_node, "PRECEDES", version_node)
                    rel_follows = Relationship(version_node, "FOLLOWS", previous_version_node)
                    #tx.create(rel_precedes)
                    #tx.create(rel_follows)
                    tx.merge(rel_precedes)
                    tx.merge(rel_follows)

                previous_version_node = version_node  # 更新上一个版本节点


                relationship = Relationship(software_node, "HAS_VERSION", version_node)
                tx.merge(relationship, "HAS_VERSION")  # Merge relationship
                
                
            print(f"Processed {repo_name} by {author}")
            fp.write(f"{author}%{repo_name}\n")
            fp.close()
        except ValueError as e:
            print(f"Error processing {repo}: {str(e)}")
        graph.commit(tx)  # 提交事务
    

if __name__ == '__main__':

    #1.处理所有库生成库节点和版本节点
    test_path = "/home/deeplearning/nas-files/tplite/document/dataset/"
    # process_libraries(test_path)
    process_libraries(OSS_Path)

    #2.处理CCScanner提供的复用关系
    # CCScanner_json_path = current_path + "test.json"
    # CCScanner_json_path = current_path + "CCScanner_dataset/repo2dep.json"
    # process_CCScanner(CCScanner_json_path)

    #2.5处理代码克隆检测的复用关系