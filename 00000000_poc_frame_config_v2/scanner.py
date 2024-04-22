#!/usr/bin/python3
# -*- coding: utf-8 -*-
# author : Lem
import urllib.request
import re
import requests
import io
import sys
import json
import argparse
import yaml
import os
from Lem_base import ScanBase
import concurrent.futures
requests.packages.urllib3.disable_warnings()

class Scanner:
    def __init__(self):
        self.scan_base = ScanBase()
        self.output_file_1 = None
        self.output_file_2 = None

    def readfiles(self):
        result = []
        try:
            with open(r"urls.txt", 'r') as f:
                for line in f:
                    result.append(line.strip().split(',')[0])
        except Exception as e:
            print(f"读取文件时发生错误：{e}")
            #result = []
        return result

    def scan_urls_method(self):
        result = self.readfiles()

        # 创建一个 ThreadPoolExecutor 实例，这里假设我们最多使用 10 个线程
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            # 提交每个 URL 的扫描任务到线程池
            future_to_url = {executor.submit(self.scan_single_url, url): url for url in result}

            for future in concurrent.futures.as_completed(future_to_url):
                url = future_to_url[future]
                try:
                    # 获取线程执行的结果
                    data = future.result()
                    # 如果线程返回了数据，可以继续处理
                    if data:
                        print(f'multithreading success： {url}')
                except Exception as exc:
                    print(f'生成 {url} 的结果时出错: {exc}')

    def scan_single_url(self, url):
        timeout_s,proxies,requests_methods = self.scan_base.basic_setting()
        #timeout_s,_ ,requests_methods= basic_setting()  #禁用proxies
        scan_url = f"{url}{self.scan_base.poc_url_path}"
        print(scan_url)
        try:
            if self.scan_base.method in requests_methods:
                re_data = requests_methods[self.scan_base.method] (scan_url,
                                                                   data=self.scan_base.poc_post_data,
                                                                   json=self.scan_base.poc_json_data,
                                                                   files=self.scan_base.poc_files,
                                                                   timeout=timeout_s,
                                                                   headers=self.scan_base.header,
                                                                   verify=False,
                                                                   proxies='')
            else:
                raise ValueError('Invalid method. Only "get", "post", "put" and "delete" are supported.')
            print(f"status_code：{re_data.status_code}")
            print(re_data.text)
            if re_data.status_code == self.scan_base.status_code:
                #if re_data.status_code == 200:
                with open(self.output_file_1, mode='a') as file_handle:
                    self.process_verification(url,scan_url,file_handle,re_data)
            else:
                print("不存在")
                #print(re_data.text)
        except requests.exceptions.RequestException as e:
            print(f"请检查目标列表 \n {str(e)}")
            #print(re_data.status_code)
            #print(str(e))

    def process_verification(self,url,scan_url,file_handle,re_data):
        if self.scan_base.verification == 'status_code':
            print(f"status_code:{re_data.status_code}")
            file_handle.write(f"{scan_url}\n")
            if self.scan_base.Secondary_verification == 'true':
                print(self.scan_other_url(url))  # 对二次验证链接内容进行请求

        elif self.scan_base.verification == 'response' and self.scan_base.re_data_keyword in re_data.text :
            print('Successfully_queried')
            file_handle.write(f"{scan_url}\n{re_data.text}\n")
            if self.scan_base.Secondary_verification == 'true':
                print(self.scan_other_url(url))  # 对二次验证链接内容进行请求

        elif self.scan_base.verification == 'regex':
            find_list = re.findall(self.scan_base.regex_match, re_data.text)
            #print(find_list)
            if find_list:
                print(f'Successfully_queried:{find_list}')
                file_handle.write(f"{scan_url}-{find_list}\n")
                if self.scan_base.Secondary_verification == 'true':
                    print(self.scan_regex_match_url(url,find_list))  #对匹配的链接内容进行请求
                #else:
                    #print('异常')
        elif self.scan_base.verification == 'json':
            find_data = json.loads(re_data.text)
            if self.scan_base.re_data_keyword in find_data:
                print(f'Successfully_queried:{find_data[self.scan_base.re_data_keyword]}')
                file_handle.write(f"{scan_url}-{find_data[self.scan_base.re_data_keyword]}\n")
        else:
            print('未定义验证方式或验证失败')

    def scan_regex_match_url(self,url,find_list,Secondary_verification_path,header):
        timeout_s,proxies,requests_methods = self.scan_base.basic_setting()
        scan_path=f"{url}{Secondary_verification_path}{find_list[0]}" #根据实际情况组合地址路径
        if requests.get(scan_path,timeout=timeout_s,headers=header,verify=False).status_code == 200:
            print(f'Secondary_verification success:{scan_path}')
            with open(self.output_file_2, mode='a') as file_handle:
                file_handle.write(f"{scan_path}\n")
        else:
            print(f'wrong_{requests.get(scan_path,timeout=timeout_s,headers=header,verify=False).status_code}:{scan_path}')

    def scan_other_url(self,url):
        timeout_s,proxies,requests_methods = self.scan_base.basic_setting()
        scan_path=f"{url}{self.scan_base.Secondary_verification_path}" #根据实际情况组合地址路径
        if requests.get(scan_path,timeout=timeout_s,headers=self.scan_base.header,verify=False).status_code == 200:
            print(f'Secondary_verification success:{scan_path}')
            with open(self.output_file_2, mode='a') as file_handle:
                file_handle.write(f"{scan_path}\n")
        else:
            print(f'wrong_{requests.get(scan_path,timeout=timeout_s,headers=self.scan_base.header,verify=False).status_code}:{scan_path}')
    def scan_ouput(self):
        output_dir = 'Lem_output'
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)  # 如果目录不存在，则创建它
        # 构造输出文件的完整路径
        self.output_file_1 = os.path.join(output_dir, f'scan_out_{os.path.basename(self.scan_base.config_path)}.txt')
        self.output_file_2 = os.path.join(output_dir, 'Secondary_verification_success.txt')

    def scan_start(self):
        try:
            parser = argparse.ArgumentParser(description="Process some integers.")
            parser.add_argument('-c', '--config', type=str, help="Config file path")
            args = parser.parse_args()
            if args.config:
                self.scan_base.load_poc(args.config)
                self.scan_ouput()
                self.scan_urls_method()
            else:
                config_dir = 'Lem_config'
                print(f"error,try to {config_dir} load config")
                for filename in os.listdir(config_dir):
                    #print(filename)
                    if filename.endswith(".yml") or filename.endswith(".yaml"):  # 确保只处理YAML文件
                        file_path = os.path.join(config_dir, filename)
                        self.scan_base.load_poc(file_path)
                        self.scan_ouput()
                        self.scan_urls_method()
        except Exception as e:
            print(f"error,{e}")


if __name__ == '__main__':
    test_scan = Scanner()
    test_scan.scan_start()
