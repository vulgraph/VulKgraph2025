from py2neo import Graph, Node, Relationship,Subgraph,NodeMatcher
import re
import os
import json
import time
from urllib.parse import quote
import threading
import subprocess
from Node import CVE,Software,LibVersion,Patch
# from Node import extract_version

CVE_json_path = "/home/deeplearning/nas-files/tracer/data/data/CVE/DataSet-NVD/NVDItems/"
test_path = "/home/deeplearning/nas-files/tplite/document/dataset/torvalds%linux"
OSS_Path = "/home/deeplearning/nas-files/tracer/data/data/MyProj/"
graph=Graph("http://localhost:7474", auth=("neo4j", "neo4j"),name="neo4j")


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

def extract_git_commits(json_data):
    git_commits = []
    reference_data = json_data.get("references", {}).get("reference_data", [])
    for reference in reference_data:
        url = reference.get('url', '')
        if 'commit' in url:
            git_commits.append(url)
    return git_commits

# 假设 json_data 是已加载的CVE数据
# patches = extract_git_commits(json_data)
# for commit_url in patches:
#     print(commit_url)
def extract_patch_node_from_json(json_path):
    with open(json_path,"r") as fp:
        json_data = json.load(fp)


import subprocess

def get_commit_tags(commit_id):
    # 使用git tag命令获取commit所在的tag列表
    try:
        output = subprocess.check_output(['git', 'tag', '--contains', commit_id]).decode('utf-8').strip()
        tags = output.split('\n')
        return tags
    except subprocess.CalledProcessError as e:
        print(f"Error retrieving tags for commit {commit_id}:", e)
        return []



def get_commit_version(commit_id, path):
    try:
        # 使用 git describe --abbrev=0 命令获取最接近的标签
        output = subprocess.check_output(['git', 'describe', '--abbrev=0', commit_id], cwd=path).decode('utf-8').strip()
        return output
    except subprocess.CalledProcessError as e:
        print(f"Error retrieving commit position for commit {commit_id}: {e} at {path}")
        return "Unknown"

def get_commit_time(commit_id, repo_path):
    os.chdir(repo_path)
    try:
        output = subprocess.check_output(['git', 'show', '--format=%ci', '-s', commit_id]).decode('utf-8').strip()
        return output
    except subprocess.CalledProcessError as e:
        print(f"Error retrieving commit time for commit {commit_id}:", e)
        return "Unknown"



                        


def extract_patch_node_from_diff():
    # file_path = "/home/deeplearning/nas-files/tplite/document/patch_examples/test/"
    file_path = "/home/deeplearning/nas-files/tracer/data/data/CVE/Filter_CVE"
    for root, dirs, files in os.walk(file_path):
        for file in files:
            if file.endswith("_patch_info.txt") and not file.endswith("changed_patch_info.txt"):
                tx = graph.begin()
                cve = file.split('_')[0]
                newfilename = f"{cve}_changed_patch_info.txt"
                #results = open(os.path.join(root, newfilename), 'a')
                completed_commits = []
                print(f"Processing {cve}")
                
                with open(os.path.join(root, file), 'r') as f:
                    for line in f.readlines():
                        parts = line.strip().split(' ')
                        cve_id = parts[0]
                        repo_owner, repo_name = parts[1].split('%')
                        commit_id = parts[2]
                        repo_path = os.path.join(OSS_Path, repo_owner + '%' + repo_name)
                        
                        if not os.path.isdir(repo_path):
                            print(f"Repository {repo_owner}%{repo_name} not found at {repo_path}")
                            continue
                        if commit_id in completed_commits:
                            continue

                        print(f"Switching to repository {repo_owner}%{repo_name}")
                        if os.path.isdir(os.path.join(repo_path,repo_name)):
                            repo_path = os.path.join(repo_path,repo_name)

                        version = get_commit_version(commit_id, repo_path)
                        
                        if version == "Unknown":
                            print(f"Commit {commit_id} not found in repository {repo_owner}%{repo_name}")

                        commit_time = get_commit_time(commit_id, repo_path)
                        format_version = extract_version(version)
                        
                        # print(f"{cve_id} affects {repo_owner}%{repo_name} patch fix {format_version} at {commit_time}")
                        print(f"{cve_id} affects {repo_owner}%{repo_name} patch fix {version} {format_version} at {commit_id} in {commit_time}")
                        # results.write(f"{cve_id} {repo_owner}%{repo_name} {commit_id} {version} {format_version}\n")
                        node = Patch(cve_id=cve_id,commit_id= commit_id,repo_name = repo_name,repo_owner = repo_owner,commit_version = version,commit_date=commit_time)
                        patch_node = node.create_node()
                        completed_commits.append(commit_id)
                        tx.merge(patch_node)
                        # 匹配漏洞节点并创建关系
                        cve_query = f"MATCH (c:CVE {{cve_id: '{cve_id}'}}) RETURN c"
                        cve_node = tx.run(cve_query).evaluate()
                        if cve_node:
                            cve_relationship = Relationship(patch_node, "FIXES_CVE", cve_node)
                            tx.merge(cve_relationship)

                        # 匹配软件节点并创建关系
                        software_query = f"MATCH (s:Software {{name: '{repo_name}', author: '{repo_owner}'}}) RETURN s"
                        software_node = tx.run(software_query).evaluate()
                        if software_node:
                            software_relationship = Relationship(patch_node, "FIX", software_node)
                            tx.merge(software_relationship)

                        # 匹配版本节点并创建关系
                        version_query = f"MATCH (v:LibVersion {{repo_name: '{repo_name}', tag: '{version}'}}) RETURN v"
                        version_node = tx.run(version_query).evaluate()
                        if version_node:
                            version_relationship = Relationship(patch_node, "FIXES_VERSION", version_node)
                            tx.merge(version_relationship)
                        
                        #
                        '''format_version = extract_version(verison)
                        version_query = f"MATCH (v:LibVersion {{repo_name: '{repo_name}', tag: '{version}'}}) RETURN v"
                        version_node = tx.run(version_query).evaluate()
                        if version_node:
                            version_relationship = Relationship(patch_node, "FIXES_VERSION", version_node)
                            tx.merge(version_relationship)'''



                graph.commit(tx)
                # results.close()

# 使用示例
'''commit_id = "77d8aa79ecfb209308e0644c02f655122b31def7"

version = get_commit_version(commit_id,test_path)
print(extract_version(version))
# print(f"Commit {commit_id} is at version: {version}")'''
#4.处理补丁节点和修补关系
extract_patch_node_from_diff()