# coding=utf-8
'''
by：Segador
Improved by：7ech_N3rd
'''
import subprocess
import sys
import json
import requests
import re
import os
import logging
import argparse 
from openai import OpenAI


# 在文件顶部创建全局 logger 对象
logger = logging.getLogger(__name__)
config=json.load(open('config.json','r',encoding='utf-8'))
api_url = config['api_url'] 
api_key=config['api_key']  
clean_php_code=False

client = OpenAI(
    api_key=api_key,
    base_url=api_url,
)

print("api_url: {}".format(api_url))
print("api_key: {}".format(api_key))



def run_phpid(directory):
    """运行 phpid.py，并返回输出"""
    command = ['python', 'phpid.py', '-d', directory]
    # logger.debug(f"执行命令: {' '.join(command)}")
    try:
        process = subprocess.run(command, capture_output=True, text=True, check=True)
        logger.debug(f"phpid.py 执行成功，输出长度: {len(process.stdout)}")
        return process.stdout
    except subprocess.CalledProcessError as e:
        logger.error(f"Error running phpid.py: {e.stderr}")
        sys.exit(1)

def get_file_content(file_path):
    """读取文件内容"""
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
            return file.read()
    except Exception as e:
        logger.error(f"Error reading file {file_path}: {str(e)}")
        return None
def remove_redundancies(php_code):
    """
    移除PHP代码中的注释和多余的空白，以减少token数量。

    Args:
        php_code (str): 原始PHP代码字符串。

    Returns:
        str: 精简后的PHP代码字符串。
    """
    php_code = re.sub(r'//.*|#.*', '', php_code)
    php_code = re.sub(r'/\*[\s\S]*?\*/', '', php_code)
    php_code = re.sub(r'\s+', ' ', php_code)
    php_code = re.sub(r'\s*([\{\};(),=<>]+)\s*', r'\1', php_code)
    return php_code.strip()



def ask_gpt(content, api_key, api_url):
    logger.debug("开始询问 GPT")

    # 设置请求头，包含 API 密钥和 JSON 内容类型

    try:
        # 发送 POST 请求到 API
        # 检查响应状态码
        completion=client.chat.completions.create(
            model=f"{config['model']}",
            messages=[
                {
                    "role": "user",
                    "content": "{}".format(content)

                }
            ],
            temperature=0.3,
        )
        return completion.choices[0].message.content
    except Exception as e:
        # 捕获异常并记录错误日志
        logger.error(f"请求 GPT 时发生异常: {str(e)}")
        return f"[-]Exception: {str(e)}"

def extract_route(file_content):
    """从文件内容中提取路由信息"""
    route_patterns = [
        r'@Route\(["\'](.+?)["\']\)',  # Symfony 风格
        r'\$router->add\(["\'](.+?)["\']',  # 一些 PHP 框架
        r'->route\(["\'](.+?)["\']',  # Laravel 风格
        r'app->get\(["\'](.+?)["\']',  # Express.js 风格 (如果有 PHP 等效)
    ]
    
    for pattern in route_patterns:
        match = re.search(pattern, file_content)
        if match:
            return match.group(1)
    
    # 如果没有找到路由，返回文件名作为默认路由
    return None

def analyze_file(file_path, file_content,matches,plugins=None):
    route = extract_route(file_content) or os.path.basename(file_path)
    plugin_content=""
    if plugins!=None:
        for plugin in plugins:
            if get_file_content("./plugin/{}.txt".format(plugin),encoding='utf-8')==None:
                print("[-]Error:Failed to load plugins:"+str(plugin)+"\nplz check ./plugins folder")
                sys.exit(1)
            plugin_content+=get_file_content("./plugin/{}.txt".format(plugin),encoding='utf-8')
    matches_content=""
    for match in matches:
        matches_content+=f"潜在的{match['vul_type']}漏洞,具体位置:{match['content']}"

    if clean_php_code:
        file_content = remove_redundancies(file_content)


    prompt = f"""
{plugin_content}
作为一个安全专家，请分析以下PHP代码是否存在安全隐患：
文件路径：{file_path}
路由信息：{route}

--------------文件内容开始-------------------
{file_content}
--------------文件内容结束-------------------
{matches_content}
如果存在安全隐患，请提供以下信息：
1. 漏洞类型
2. 漏洞描述
3.攻击者可能的利用方式
4. 修复建议


如果不存在安全隐患，请回复"该文件不存在安全隐患"。
请使用如下 JSON 格式输出你的回复：
例如：
{{
    "is_vulnerable": 1,
    "reason": "明确存在漏洞，原因。以及攻击者可以通过发送...来进行攻击",
    "FixSuggestion":"..."

}}

{{
    "is_vulnerable": 0.7,
    "reason": "很可能存在漏洞，原因:...。",
    "FixSuggestion":"..."

}}

{{
    "is_vulnerable": 0.4,
    "reason": "无法明确存在漏洞，原因:...。",
    "FixSuggestion":"..."

}}

{{
    "is_vulnerable": 0.1,
    "reason": "不存在漏洞，原因:...。",
    "FixSuggestion":"..."

}}

注意：
- 请确保你的回复符合 JSON 格式。
- is_vulnerable 为0-1的整数类型，表示是否存在漏洞的可能性。
- reason FixSuggestion 为字符串类型
"""
    return ask_gpt(prompt,api_key,api_url)



def main(directory,report_path,plugins):
    logging.basicConfig(level=logging.INFO)

    logger.debug(f"开始分析目录: {directory}")

    phpid_output = run_phpid(directory)
    phpid_output = json.loads(phpid_output)
    print('Successfully parsed phpid output')
    files = []
    seen_files = set()  # 用来存储已处理的文件名
    for file_info in phpid_output:
        file_name = file_info['file']
        if file_name not in seen_files:
            files.append(dict(file=file_info['file'], vulnerability=file_info['vulnerability'], matches=file_info['matches']))
            seen_files.add(file_name)
    print(files[1])

    vulnerability_count = 0
    vulnerability_types = {}
    results = []

    for file in files:
        file_content = get_file_content(file['file'])
        if file_content:
            route = extract_route(file_content) or os.path.basename(file['file'])
            analysis_result = analyze_file(file['file'], file_content,file['matches'])
            if analysis_result[:9]=='[-]Error:':
                print(f"Invoke Gpt Error: {analysis_result},exiting...")
                sys.exit(1)
            print(f"文件: {file['file']}")
            print(f"路由: {route}")
            print("分析结果:")
            print(analysis_result)
            with open(report_path, 'a', encoding='utf-8') as f:
                f.write(
                    f"{{{file['file']},{route},{analysis_result}}}\n\n\n\n"
                )
            
            
            print("-" * 50)
        else:
            logger.error(f"无法读取文件内容: {file['file']}")

    print("\n漏洞分析统计:")
    print(f"总共发现 {vulnerability_count} 个漏洞")
    print("漏洞类型统计:")
    for vuln_type, count in vulnerability_types.items():
        print(f"- {vuln_type}: {count} 个")

    # 生成 HTML 报告
    # html_report = generate_html_report(results, vulnerability_count, vulnerability_types)
    
    # 保存 HTML 报告
    # with open('vulnerability_report.html', 'w', encoding='utf-8') as f:
    #     f.write(html_report)
    
    print("\n漏洞分析完成，报告已保存到 vulnerability_report.html")

if __name__ == '__main__':
    # 使用 argparse 解析命令行参数
    parser = argparse.ArgumentParser(description="Process a directory and generate a report using a specific plugin.")
    
    # 添加参数
    parser.add_argument(
        '-d','--directory', 
        type=str, 
        required=True, 
        help='The directory to be processed'
    )
    
    parser.add_argument(
        '-r', '--report', 
        type=str, 
        default='report.txt', 
        help='The output report file (default: report.txt)'
    )
    
    parser.add_argument(
        '-p', '--plugins', 
        type=str, 
        nargs='+',  # 接受一个或多个插件
        help='The plugins to be used for processing (one or more)'
    )

    parser.add_argument(
        '-cc', '--clean-code', 
        type=bool, 
        default=False,
        help='Clean php code before analyzing to short used token.',
        required=False
    )
    # 解析参数
    args = parser.parse_args()
    clean_php_code=args.clean_code
    # 调用主函数并传入参数
    main(args.directory, args.report, args.plugins)