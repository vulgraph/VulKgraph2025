from py2neo import Graph, Node, Relationship,Subgraph,NodeMatcher
import re
import os
import json
import time
from urllib.parse import quote
import threading
import subprocess
from Node import CVE,Software,LibVersion
from Node import extract_version
from packaging import version

current_path = "/home/deeplearning/nas-files/tplite/document/"
OSS_Path = "/home/deeplearning/nas-files/tracer/data/data/MyProj/"
git2cpe_path = current_path +"V1SCAN/git2cpe.json"
git2cpe_ver_path = current_path+"V1SCAN/Git2CPE_ver/"
CVE_path = "/home/deeplearning/nas-files/tracer/data/data/CVE/DataSet-NVD/NVDItems/2008/"

# 连接到Neo4j
graph=Graph("http://localhost:7474", auth=("neo4j", "neo4j"),name="neo4j")

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
                #多个gitverison可能对应同一个cpe_version
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


def compare_versions(version1, version2):
    """
    比较两个版本号的大小。

    参数:
    - version1: 字符串，表示第一个版本号
    - version2: 字符串，表示第二个版本号

    返回值:
    - 如果 version1 大于 version2，则返回 1
    - 如果 version1 等于 version2，则返回 0
    - 如果 version1 小于 version2，则返回 -1
    """
    parts1 = version1.split('.')
    parts2 = version2.split('.')

    # 比较大版本号
    if int(parts1[0]) > int(parts2[0]):
        return 1
    elif int(parts1[0]) < int(parts2[0]):
        return -1

    # 如果大版本号相同，且版本号包含次要版本号，则比较次要版本号
    if len(parts1) > 1 and len(parts2) > 1:
        if int(parts1[1]) > int(parts2[1]):
            return 1
        elif int(parts1[1]) < int(parts2[1]):
            return -1
    elif len(parts1) > 1:
        # 如果 version2 没有次要版本号，则 version1 大于 version2
        return 1
    elif len(parts2) > 1:
        # 如果 version1 没有次要版本号，则 version1 小于 version2
        return -1

    # 如果大版本号和次要版本号相同，且版本号包含小版本号，则比较小版本号
    if len(parts1) > 2 and len(parts2) > 2:
        if int(parts1[2]) > int(parts2[2]):
            return 1
        elif int(parts1[2]) < int(parts2[2]):
            return -1
    elif len(parts1) > 2:
        # 如果 version2 没有小版本号，则 version1 大于 version2
        return 1
    elif len(parts2) > 2:
        # 如果 version1 没有小版本号，则 version1 小于 version2
        return -1

    # 如果三个版本号都相同，则返回 0
    return 1




def find_versions_by_tag(tx, author, repo_name, start_including, start_excluding, end_including, end_excluding):
    # 根据 start_including 和 end_including 确定是否包含边界版本
    include_start = True if start_including else False
    include_end = True if end_including else False
    print(f"GIT: start_including:{start_including} start_excluding:{start_excluding} end_including:{end_including} end_excluding:{end_excluding}")
    # 确定起始和终止版本
    start_version = start_including if start_including else start_excluding
    end_version = end_including if end_including else end_excluding
    print(f"GIT: start_version:{start_version} end_version:{end_version}")

    if start_version == None and end_version: #如果只有一个Endversion
        end_node_query =  "MATCH (n:LibVersion {author: $author, repo_name: $repo_name, tag: $tag}) RETURN n"
        end_node = tx.run(end_node_query, author=author, repo_name=repo_name, tag=end_version).evaluate()
        versions = []
        current_node = end_node
        while current_node:
            if current_node == end_node and end_including:
                versions.append(current_node)
            # 使用 Cypher 查询查找下一个版本节点
            next_node_query = """
            MATCH (current:LibVersion)-[:FOLLOWS]->(next:LibVersion)
            WHERE id(current) = $current_id
            RETURN next LIMIT 1
            """
            next_node = tx.run(next_node_query, current_id=current_node.identity).evaluate()

            if not next_node:
                break  # 如果没有后续节点，则结束循环

            current_node = next_node
            if current_node != end_node:
                versions.append(current_node)

    else:
            # 使用 Cypher 查询找到起始和终止节点
        start_node_query = "MATCH (n:LibVersion {author: $author, repo_name: $repo_name, tag: $tag}) RETURN n"
        start_node = tx.run(start_node_query, author=author, repo_name=repo_name, tag=start_version).evaluate()
        end_node = tx.run(start_node_query, author=author, repo_name=repo_name, tag=end_version).evaluate()

        if not start_node:
            return []  # 如果起始节点不存在，则返回空列表

        versions = []
        current_node = start_node

        # 进行节点遍历
        while current_node:
            # 检查是否到达终止节点
            if current_node == end_node:
                if include_end:
                    versions.append(current_node)
                break

            # 如果是起始节点，根据 include_start 判断是否添加
            if current_node == start_node and include_start:
                versions.append(current_node)

            # 使用 Cypher 查询查找下一个版本节点
            next_node_query = """
            MATCH (current:LibVersion)-[:PRECEDES]->(next:LibVersion)
            WHERE id(current) = $current_id
            RETURN next LIMIT 1
            """
            next_node = tx.run(next_node_query, current_id=current_node.identity).evaluate()

            if not next_node:
                break  # 如果没有后续节点，则结束循环

            current_node = next_node
            if current_node != start_node:
                versions.append(current_node)

    return versions



def find_versions_by_format_version(tx, author, repo_name, start_including, start_excluding, end_including, end_excluding): #FIXME
     # 根据 start_including 和 end_including 确定是否包含边界版本
    include_start = True if start_including else False
    include_end = True if end_including else False
    print(f"GIT: start_including:{start_including} start_excluding:{start_excluding} end_including:{end_including} end_excluding:{end_excluding}")
    # 确定起始和终止版本
    start_version = start_including if start_including else start_excluding
    end_version = end_including if end_including else end_excluding
    print(f"GIT: start_version:{start_version} end_version:{end_version}")

    if start_version == None and end_version: #如果只有一个Endversion
        end_node_query =  "MATCH (n:LibVersion {author: $author, repo_name: $repo_name, version: $version}) RETURN n"
        end_node = tx.run(end_node_query, author=author, repo_name=repo_name, tag=end_version).evaluate()
        versions = []
        current_node = end_node
        while current_node:
            if current_node == end_node and end_including:
                versions.append(current_node)
            # 使用 Cypher 查询查找下一个版本节点
            next_node_query = """
            MATCH (current:LibVersion)-[:FOLLOWS]->(next:LibVersion)
            WHERE id(current) = $current_id
            RETURN next LIMIT 1
            """
            next_node = tx.run(next_node_query, current_id=current_node.identity).evaluate()

            if not next_node:
                break  # 如果没有后续节点，则结束循环

            current_node = next_node
            if current_node != end_node:
                versions.append(current_node)

    else:
            # 使用 Cypher 查询找到起始和终止节点
        start_node_query = "MATCH (n:LibVersion {author: $author, repo_name: $repo_name, tag: $tag}) RETURN n"
        start_node = tx.run(start_node_query, author=author, repo_name=repo_name, tag=start_version).evaluate()
        end_node = tx.run(start_node_query, author=author, repo_name=repo_name, tag=end_version).evaluate()

        if not start_node:
            return []  # 如果起始节点不存在，则返回空列表

        versions = []
        current_node = start_node

        # 进行节点遍历
        while current_node:
            # 检查是否到达终止节点
            if current_node == end_node:
                if include_end:
                    versions.append(current_node)
                break

            # 如果是起始节点，根据 include_start 判断是否添加
            if current_node == start_node and include_start:
                versions.append(current_node)

            # 使用 Cypher 查询查找下一个版本节点
            next_node_query = """
            MATCH (current:LibVersion)-[:PRECEDES]->(next:LibVersion)
            WHERE id(current) = $current_id
            RETURN next LIMIT 1
            """
            next_node = tx.run(next_node_query, current_id=current_node.identity).evaluate()

            if not next_node:
                break  # 如果没有后续节点，则结束循环

            current_node = next_node
            if current_node != start_node:
                versions.append(current_node)

    return versions

def is_valid_version(version_str):
    """
    判断字符串是否符合版本号格式。

    参数:
    - version_str: 字符串，待检查的版本号

    返回值:
    - 如果 version_str 符合版本号格式，则返回 True
    - 如果 version_str 不符合版本号格式，则返回 False
    """
    # 定义版本号的正则表达式模式
    version_pattern = r'^\d+(\.\d+){0,2}$'

    # 使用正则表达式检查字符串是否匹配版本号格式
    if re.match(version_pattern, version_str):
        return True
    else:
        return False


def process_CVE():

    
    cve_num  = 0
    # for jsonfile in os.listdir(json_path):
    #    with open(os.path.join(json_path, jsonfile), 'r', encoding = "UTF-8") as fp:
    test_file="/home/deeplearning/nas-files/tplite/document/test_examples/CVE-2017-12762.json"

    # 加载映射
    name_mappings = load_name_mappings(git2cpe_path)
    version_mappings = load_version_mappings(current_path+"V1SCAN/Git2CPE_ver/")

    for root, directories, files in os.walk(CVE_path):
        for file_name in files:
            if not file_name.endswith(".json"):
                continue
            tx = graph.begin()  
            fp = open(os.path.join(root,file_name), 'r', encoding = "UTF-8")
    #tx = graph.begin()
    #with open(test_file, 'r', encoding = "UTF-8") as fp:
    #    if True:
            json_data = json.load(fp)
            cve_id = json_data.get("cve", {}).get("CVE_data_meta", {}).get("ID")
            description_data = json_data.get("cve", {}).get("description", {}).get("description_data", [])
            if description_data:
                description = description_data[0].get("value")
            else:
                description = None

            published_date = json_data.get("publishedDate")
            last_modified_date = json_data.get("lastModifiedDate")

            problemtype_data = json_data.get("cve", {}).get("problemtype", {}).get("problemtype_data", [])
            if problemtype_data:
                cwe_description = problemtype_data[0].get("description", [])
                if cwe_description:
                    cwe = cwe_description[0].get("value")
                else:
                    cwe = None
            else:
                cwe = None
            affected_cpes = parse_cpe_from_json(json_data["configurations"])
            impact = json_data.get("impact", {}).get("baseMetricV2", {})
            cvss_v2 = impact.get("cvssV2", {})
            severity = impact.get("severity")
            exploitability_score = impact.get("exploitabilityScore")
            impact_score = impact.get("impactScore")

            print(f"processing CVE {cve_id}")
        
            cve = CVE(cve_id, description, published_date, last_modified_date, affected_cpes, cwe,
                      cvss_v2, severity, exploitability_score, impact_score)
            cve_node = cve.to_node()
            tx.merge(cve_node)
            cve_num += 1

            for cpe in affected_cpes:
                parsed_cpe = parse_cpe(cpe["cpe23Uri"])
                if parsed_cpe:
                    vendor = parsed_cpe.get("vendor")
                    product = parsed_cpe.get("product")
                    version = parsed_cpe.get("version")
                    cpe_key = f"{vendor}@@{product}"
                
                    # print(f"{version}")
                    if cpe_key in name_mappings:#对应的库具有名称映射
                        github_key = name_mappings[cpe_key]  # 获取github对应的作者和库名
                    
                        github_author, github_repo = github_key.split('@@')
                    
                        # 查找对应的Software节点
                        software_node = tx.evaluate(f"MATCH (s:Software {{name: '{github_repo}', author: '{github_author}'}}) RETURN s")
                    
                        if software_node:
                            cve = CVE(cve_id, description, published_date, last_modified_date, affected_cpes, cwe,
                                        cvss_v2, severity, exploitability_score, impact_score)
                            cve_node = cve.to_node()
                            tx.merge(cve_node)
                            cve_num += 1

                            relationship = Relationship(cve_node, "AFFECTS", software_node)
                            tx.merge(relationship)
                        
                            # 查找和建立与LibVersion节点的关系
                            if cpe_key in version_mappings: #对应的版本具有版本映射
                            
                                # print(f"cpe_key:{cpe_key},查找LibVersion")
                            
                                mappings = version_mappings.get(cpe_key)
                                # print(mappings)
                                start_including = cpe.get('versionStartIncluding')
                                start_excluding = cpe.get('versionStartExcluding')
                                end_including = cpe.get('versionEndIncluding')
                                end_excluding = cpe.get('versionEndExcluding')
                                # print(f"start_including:{start_including} start_excluding:{start_excluding} end_including:{end_including} end_excluding:{end_excluding}")

                                if mappings:
                       
                                    # 如果cpe条目只表示一个版本
                               
                                    if is_valid_version(version) and not start_including  and not start_excluding  and not end_including and not end_excluding:
                                        
                                        git_versions =  mappings.get(version,{})
                                        if git_versions:
                                            for git_version in git_versions:
                                                version_node = tx.evaluate(f"MATCH (v:LibVersion {{tag: '{git_version}', repo_name: '{github_repo}'}}) RETURN v")
                                                if version_node:
                                                    version_relationship = Relationship(cve_node, "AFFECTS_VERSION", version_node)
                                                    tx.merge(version_relationship)  
                                        else:
                                            version_nodes_data = tx.run(f"MATCH (v:LibVersion {{repo_name: '{github_repo}'}}) RETURN v").data()
                                            for version_node_data in version_nodes_data:
                                            # 创建 LibVersion 实例
                                                version = LibVersion(tag=version_node_data['v']['tag'],
                                                    commit_date=version_node_data['v']['commit_date'],
                                                    repo_name=version_node_data['v']['repo_name'],
                                                    author=version_node_data['v']['author'])
        
                                                # 提取版本并检查是否与目标版本匹配
                                                if version.version == version:
                                                    # 创建关系
                                                    version_node = version.create_node()
                                                    version_relationship = Relationship(cve_node, "AFFECTS_VERSION", version_node)
                                                    tx.merge(version_relationship)

                                           
                                
                                    # 如果是一个版本范围
                                    else:
                     
                                        start_include_version = None
                                        start_exclude_version = None
                                        end_include_version = None
                                        end_exclude_version = None
                                        start_include_versions = []
                                        start_exclude_versions = []
                                        end_include_versions = []
                                        end_exclude_versions = []

                                            # 映射cpe_version ->git_version
                                        if start_including:
                                            start_include_versions = mappings.get(start_including)
                                            if not start_include_versions:
                                                start_include_versions = mappings.get(extract_major_minor(start_including))
                                            if start_include_versions:
                                                start_include_version = start_include_versions[0]
                                
                                        elif start_excluding:
                                            start_exclude_versions = mappings.get(start_excluding)
                                            if not start_exclude_versions:
                                                start_exclude_versions = mappings.get(extract_major_minor(start_excluding))
                                            if start_exclude_versions:
                                                start_exclude_version = start_exclude_versions[0]


                                        if end_including:
                                            end_include_versions = mappings.get(end_including)
                                            if not end_include_versions:
                                                end_include_versions = mappings.get(extract_major_minor(end_including))
                                            if end_include_versions:
                                                end_include_version = end_include_versions[0]

                                        elif end_excluding:
                                            end_exclude_versions = mappings.get(end_excluding)
                                            if not end_exclude_versions:
                                                end_exclude_versions = mappings.get(extract_major_minor(end_excluding))
                                            if end_exclude_versions:
                                                end_exclude_version = end_exclude_versions[0]
                                   
                                        affected_versions = find_versions_by_tag(
                                        tx,
                                        github_author,
                                        github_repo,
                                        start_include_version,
                                        start_exclude_version,
                                        end_include_version,
                                        end_exclude_version
                                        )
  
                                        for version_node in affected_versions:
                                            if version_node:
                                        
                                                version_relationship = Relationship(cve_node, "AFFECTS_VERSION", version_node)
                                                tx.merge(version_relationship)      
                                else: # 对应的版本不具有版本映射（库具有名称映射的情况）#FIXME 手动将github tag和NVD的版本号对应
                                     # 如果cpe条目只表示一个版本
                                    '''if version!='-' and version!='*' and start_including == None and start_excluding == None and end_including == None and end_excluding == None:
                                        version_nodes = tx.evaluate(f"MATCH (v:LibVersion {{tag: '{}', repo_name: '{github_repo}'}}) RETURN v")
                                        for version_node in version_nodes:
                                            version_relationship = Relationship(cve_node, "AFFECTS_VERSION", version_node)
                                            tx.merge(version_relationship)    
                                
                                    else:
                                   
                                        affected_versions = find_versions_by_format_version(
                                        tx,
                                        github_author,
                                        github_repo,
                                        start_including,
                                        start_excluding,
                                        end_including,
                                        end_excluding
                                        )
                         
                                        for version_node in affected_versions:
                                            if version_node:
                                                
                                                version_relationship = Relationship(cve_node, "AFFECTS_VERSION", version_node)
                                                tx.merge(version_relationship) '''
                    
                    else: #没有名称映射没有版本映射 #FIXME 手动对应GitHub和NVDCPE的库名称、Github gittag 和NVD CPE的版本名称
                        print(1)


            graph.commit(tx)                  
            fp.close()
        # 创建 CVE 实例
    
    print(cve_num)


if __name__ == '__main__':
    #3.处理CVE 生成CVE节点和影响关系
    process_CVE() 

# 示例
    '''version1 = "2.5.6"
    version2 = "2.1"
    result = compare_versions(version1, version2)
    if result == 1:
        print(f"{version1} 大于 {version2}")
    elif result == -1:
        print(f"{version1} 小于 {version2}")
    else:
        dtprint(f"{version1} 等于 {version2}")'''