import os
import json
import requests
import time
from urllib.parse import quote
import threading
import subprocess
import shutil
import glob

current_path = "/home/deeplearning/nas-files/tplite/document/"
OSS_Path = "/home/deeplearning/nas-files/tracer/data/data/MyProj"

def Repo_name():  
    '''获得服务器原有库库名列表 作者%库名'''
    f = open(current_path+"Repo2.txt",'a') 
    '''for path, dirs, files in os.walk(OSS_Path):
        for file in files :
            filePath = os.path.join(path, file)
            if file.endswith("_repo_branches.txt"):
                with open(filePath,'r',encoding="UTF-8") as fp:
                    lines = fp.readlines()
                    for line in lines:
                        repoName = line.split()[1]
                        print(repoName)
                        f.write(repoName+'\n')'''
    entries = os.listdir(OSS_Path)
    # 过滤出目录
    directories = [entry for entry in entries if os.path.isdir(os.path.join(OSS_Path, entry))]
    # 打印目录名
    for directory in directories:
        repo = directory.replace('%','/')
        f.write(repo+'\n')
    f.close()


def find_files(directory, patterns):
    """查找匹配特定模式的文件"""
    for pattern in patterns:
        # 使用glob.glob递归查找所有匹配的文件
        for file_path in glob.glob(os.path.join(directory, '**', pattern), recursive=True):
            yield file_path

def is_cpp_project(directory,repo,threshold=0.4):
    """判断一个项目是否是C/C++项目"""
    cpp_patterns = ['*.c', '*.cpp', '*.cxx', '*.cc', '*.h', '*.hpp', '*.hxx']
    all_files = list(glob.glob(os.path.join(directory, '**', '*.*'), recursive=True))
    cpp_files = list(find_files(directory, cpp_patterns))

    # 计算C/C++文件的比例
    if len(all_files) == 0:
        return False  # 防止除以零的错误
    cpp_ratio = len(cpp_files) / len(all_files)

    print(f"Found {len(cpp_files)} C/C++ files out of {len(all_files)} total files in {repo}.")
    print(f"C/C++ files ratio: {cpp_ratio:.2f}")

    return cpp_ratio >= threshold

def IsCproject():
    all_projects = []
    for repo in os.listdir(OSS_Path):
        if os.path.isdir(os.path.join(OSS_Path,repo)):
            repo_path = os.path.join(OSS_Path,repo)
            dic={}
            dic[repo] = is_cpp_project(repo_path,repo)
            all_projects.append(dic)
    os.chdir(current_path)
    with open("isCorC++project.json","w") as f:
        json.dump(all_projects,f)

    

def read_txt_file(txt_file_path):
    with open(txt_file_path, 'r') as file:
        data = file.read().splitlines()
        return {item.replace('%','/') for item in data}
        # return data


def clone_repositories(repos_to_clone, clone_directory,base_url="https://github.com/"):
    for repo in repos_to_clone:
        author, repo_name = repo.split('/')
        full_repo_path = os.path.join(clone_directory, f"{author}%{repo_name}")
        time.sleep(5)
        # 检查目录是否已存在且克隆完整
        if os.path.exists(full_repo_path):
            # print(3)
            file_counts = len(os.listdir(full_repo_path))
            if file_counts > 1:  # 假设存在多个文件则认为之前克隆成功
                print(f"Repository already exists and is complete: {full_repo_path}")
                continue  # 跳过当前循环，不执行克隆
        
        # 如果之前没有克隆完整，则尝试重新克隆
        print(f"Cloning {repo} into {clone_directory}")

        #os.chdir(clone_directory)
        if not os.path.exists(full_repo_path):
            os.mkdir(full_repo_path)
        os.chdir(full_repo_path)
        subprocess.run(['git', 'clone', base_url + repo, '.']) 

        #subprocess.run(['git', 'clone', base_url + repo, full_repo_path])
        print("克隆完成，等待文件系统更新...")
        time.sleep(1)  # 等待文件系统更新
            

        # 克隆后的目录检查
        if os.path.exists(full_repo_path):
            # 检查是否有足够的文件
            if len(os.listdir(full_repo_path)) <= 1:
                print(f"Failed to properly clone {repo}, cleaning up.")
                shutil.rmtree(full_repo_path)  # 删除不完全的克隆
            else:
                print(f"Clone and rename successful for {repo}")



def cloning_threads(repos, chunk_size=200):
    """ 每200个仓库启动一个线程进行克隆 """
    threads = []
    repos_list = list(repos)
    clone_directory = current_path+"dataset/"
    #clone_directory = "/home/deeplearning/nas-files/tracer/data/data/MyProj/"
    # 分块处理
    # print(1)
    for i in range(0, len(repos_list), chunk_size):
        chunk = repos_list[i:i + chunk_size]
        # 为每个块创建一个线程
        thread = threading.Thread(target=clone_repositories, args=(chunk, clone_directory))
        threads.append(thread)
        thread.start()

    # 等待所有线程完成
    for thread in threads:
        thread.join()

    print("All repositories have been cloned.")






def fetch_github_repositories(language ,max_stars,min_stars=1000,token="***REMOVED***",):
    headers = {
        'Authorization': f'token {token}',
        'Accept': 'application/vnd.github.v3+json'  # 使用正确的媒体类型
    }
    repos = []
    page = 1
    proxies = {
        "http": "socks5://127.0.0.1:20170",
        "https": "socks5://127.0.0.1:20170"
    }
    
    #在GitHub搜索API中，包含特殊字符（如+在C++中）可能需要进行适当的编码，因为+在URL中表示空格。。
    if language == "C++":
        print(1)
        encoded_language = quote(language)
        print(encoded_language)
    else:
        encoded_language = "C"
    output_filename = current_path+'github_repos2.txt'  # 确保文件路径正确
    with open(output_filename, encoding="utf-8", mode="a") as fp:
        repo_cnt = 0 
        while True:
            time.sleep(10)
            #query = f"language:{encoded_language} stars:{lower_limit}..{star}"
            query = f"language:{encoded_language} stars:1000..1500" #范围随时改
            # query = f"language:{encoded_language} stars:>=5000"
            url = f"https://api.github.com/search/repositories?q={query}&sort=stars&order=desc&per_page=100&page={page}"
            response = requests.get(url, headers=headers, verify=False, proxies=proxies)
            requests.packages.urllib3.disable_warnings()
            # print("Requesting:", url)  # 打印URL检查
            
            
            if response.status_code != 200:
                print(f"Failed with status code: {response.status_code}")
                print(response.text)  
                break

            result = response.json()
            repositories = result.get("items", [])
            print("Fetched Repositories:", len(repositories))  # 打印获取的库数量
            if not repositories:
                break

            for repo in repositories:
                repos.append(repo)
                repo_cnt = repo_cnt + 1
                fp.write(repo["full_name"] + "\n")  

            page += 1
    print(f"collect {repo_cnt} {language} repos")

    return repos

def save_to_file(filename, repos):
    with open(filename, 'w') as f:
        for repo in repos:
            f.write(repo + '\n')

def merge_sort_deduplicate(c_repos, cpp_repos):
    # Dictionary to hold repositories by full name to deduplicate
    repo_dict = {}
    for repo in c_repos + cpp_repos:
        repo_dict[repo['full_name']] = repo

    # Extract values and sort them by stargazers_count
    unique_repos = list(repo_dict.values())
    sorted_repos = sorted(unique_repos, key=lambda x: x['stargazers_count'], reverse=True)
    return sorted_repos

if __name__ == '__main__':

    #0.预处理 包括获取服务器存在的所有库、爬虫获取github所有C/C++ star超过xxx的库 爬虫过程需要手动调整star范围 1000-1500 1500-2000 2000-3000 ...
    #获取所有需要克隆的库 多线程克隆等

    # Repo_name() 获取服务器所有库（库格式 有的有外层文件夹有的没有）
    '''# 获取C和C++库列表
    max_stars = 183000 # linux 169k stars tensorflow 182k

    cpp_repos = fetch_github_repositories("C++",max_stars) 
    
    max_stars = 170000 
    
    c_repos = fetch_github_repositories("C",max_stars)

    total_repos = merge_sort_deduplicate(c_repos,cpp_repos)
    f = open(current_path+"SortedGitRepo.txt",'a') # 按star排序的所有库
    for repo in total_repos:
        f.write(f"{repo['full_name']}\n")
    f.close()
    print(f"Saved {len(total_repos)} repositories")'''


        # 去除TXT文件中的重复项
    # remove_duplicates_from_txt(...) #去重

    '''CurrentRepoPath = current_path+"Repo2.txt"
    GitRepoPath = current_path+"gitclonelist.txt" #去重后的需要克隆的所有github库
    current_repos = read_txt_file(CurrentRepoPath)
    git_repos = read_txt_file(GitRepoPath)
    needtoclone = git_repos - current_repos #需要克隆的所有库-现在拥有的库 = need to clone
    with open(current_path+"needtoclone2.txt", 'w') as file:
        for item in needtoclone:
            file.write(f"{item}\n")'''

    
    '''#GitRepoPath = current_path+"test_repo.txt"
    GitRepoPath = current_path+"needtoclone2.txt" 克隆库
    data = read_txt_file(GitRepoPath)
    cloning_threads(data)'''

