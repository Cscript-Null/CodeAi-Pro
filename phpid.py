# coding=utf-8
'''
by：Segador
Improved by: 7ech_N3rd
'''
import re
import os
import optparse
import sys
import chardet
import json
from lxml.html import etree

class phpid(object):
    def __init__(self, dir):
        self._function = ''
        self._fpanttern = ''
        self._line = ''
        self._dir = dir
        self._filename = ''
        self._vultype = ''
        self.choice = '1'
        self.results = []  # 用于存储匹配结果

    def _run(self):
        try:
            self.handlePath(self._dir)
            # print("danger information Finished!")
            # 输出结果为 JSON 格式
            print(json.dumps(self.results, indent=4, ensure_ascii=True))
        except Exception as e:
            print(f"Error: {e}")
            raise

    def report_id(self, vul,matches):
        message = {
            "vulnerability": vul,
            "function": self._function,
            "file": self._filename,
            "matches": matches
        }
        self.results.append(message)

    def report_line(self, line_content):
        # 将匹配的行号和内容添加到最后一个 result 中
        if self.results:
            self.results[-1]["matches"].append({
                "line": self._line,
                "content": line_content.strip()
            })

    def handlePath(self, path):
        dirs = os.listdir(path)
        for d in dirs:
            subpath = os.path.join(path, d)
            if os.path.isfile(subpath):
                if os.path.splitext(subpath)[1] in ['.php','.phtml']:
                    self._filename = subpath
                    file = "regexp"
                    self.handleFile(subpath, file)
            else:
                self.handlePath(subpath)

    def handleFile(self, fileName, file):
        with open(fileName, 'rb') as f:  # 以二进制模式打开
            raw_data = f.read()
            result = chardet.detect(raw_data)  # 检测编码
            encoding = result['encoding']

        # 使用检测到的编码读取文件
        with open(fileName, 'r', encoding=encoding, errors='ignore') as f:
            self._line = 0
            content = f.read()
            content = self.remove_comment(content)
            self.check_regexp(content, file)

    def function_search_line(self):
        with open(self._filename, 'r', encoding='utf-8', errors='ignore') as fl:
            self._line = 0
            while True:
                line = fl.readline()
                if not line:
                    break
                self._line += 1
                # 调试输出：查看每一行是否包含函数名
                # print(f"Checking line {self._line}: {line.strip()}")
                if self._function in line:
                    # print(f'find danger information on line: {line.strip()}')
                    self.report_line(line.strip())

    def regexp_search(self, rule_dom, content):
        regmatch_doms = list(rule_dom[0].xpath("regmatch"))
        exp_patterns_list = []
        
        # 构建所有的正则表达式列表
        for regmatch_dom in regmatch_doms:
            regexp_doms = regmatch_dom.xpath("regexp")
            exp_patterns = [re.compile(regexp_dom.text) for regexp_dom in regexp_doms]
            exp_patterns_list.append(exp_patterns)

        matches = []  # 用于存储匹配的行内容

        # 逐行检查文件内容
        lines = content.splitlines()
        for line_num, line in enumerate(lines, 1):  # 枚举每一行，line_num 从 1 开始
            match_results = [all(exp_pattern.search(line) for exp_pattern in exp_patterns) for exp_patterns in exp_patterns_list]
            
            # 如果当前行匹配所有正则表达式
            if all(match_results):
                matches.append({
                    "content": line.strip(),
                    "vul_type": self._vultype,
                })


        # 如果有匹配的行，报告漏洞
        if matches:
            # print(f"find danger information on line: {matches}")
            self.report_id(self._vultype, matches)
            self.function_search_line()  # 调用其他相关处理逻辑

        return True


    def check_regexp(self, content, file):
        if not content:
            return
        xml_file = "regexp.xml"
        self._xmlstr_dom = etree.parse(xml_file)
        phpid_doms = self._xmlstr_dom.xpath("phpid")
        for phpid_dom in phpid_doms:
            self._vultype = phpid_dom.get("vultype")
            function_doms = phpid_dom.xpath("function")
            for function_dom in function_doms:
                self._function = function_dom.xpath("rule")[0].get("name")
                self.regexp_search(function_dom, content)
        return True

    def remove_comment(self, content):
        # TODO: remove comments from content
        return content

if __name__ == '__main__':
    parser = optparse.OptionParser('usage: python %prog [options](eg: python %prog -d /user/php/demo)')
    parser.add_option('-d', '--dir', dest='dir', type='string', help='source code file dir')

    (options, args) = parser.parse_args()

    if options.dir is None or options.dir == "":
        parser.print_help()
        sys.exit()
    dir = options.dir
    phpididentify = phpid(dir)
    phpididentify._run()
