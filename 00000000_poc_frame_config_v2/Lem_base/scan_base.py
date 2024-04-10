#!/usr/bin/python3
# -*- coding: utf-8 -*-
# author : Lem

import requests
import io
import sys
import json
import argparse
import yaml
requests.packages.urllib3.disable_warnings()



class ScanBase:
    def __init__(self):
        # 初始化类时，这些属性还未设置
        self.config_path = None
        self.Author = None
        self.Condition = None
        self.Name = None
        self.Vulnerability_details = None
        self.Solutions = None
        self.method = None
        self.poc_url_path = None
        self.header = None
        self.poc_files = None
        self.poc_post_data = None
        self.poc_json_data = None
        self.verification = None
        self.re_data_keyword = None
        self.regex_match = None
        self.status_code = None
        self.Secondary_verification = None
        self.Secondary_verification_path = None

    def load_poc(self, config_path):
        #print(f"config路径：{config_path}")
        with open(config_path, 'r', encoding='utf-8') as file:
            config = yaml.safe_load(file)
            # 将配置中的值赋给类的属性
        self.config_path = config_path
        self.Author = config['Poc']['Author']
        self.Condition = config['Poc']['Condition']
        self.Name = config['Poc']['Name']
        self.Vulnerability_details = config['Poc']['Vulnerability details']
        self.Solutions = config['Poc']['Solutions']
        self.method = config['Poc']['method']
        self.poc_url_path = config['Poc']['poc_url_path']
        self.header = config['Poc']['header']
        self.poc_files = config['Poc']['poc_files']
        self.poc_post_data = config['Poc']['poc_post_data']
        self.poc_json_data = config['Poc']['poc_json_data']
        self.verification = config['Poc']['verification']
        self.re_data_keyword = config['Poc']['re_data_keyword']
        self.regex_match = config['Poc']['regex_match']
        self.status_code = config['Poc']['status_code']
        self.Secondary_verification = config['Poc']['Secondary_verification']
        self.Secondary_verification_path = config['Poc']['Secondary_verification_path']
        print(f'loading：{config_path}')
        self.title()

    def title(self):
        print(f"""
        Author: {self.Author}
        Condition:{self.Condition}
        Name:{self.Name}
        Vulnerability details: {self.Vulnerability_details}
        Solutions:{self.Solutions}
        """)

    def basic_setting(self):
        timeout_s=3
        proxies = {
        'http': 'http://127.0.0.1:8080',  #proxies=proxies
        'https': 'http://127.0.0.1:8080',
        }
        requests_methods = {'get': requests.get, 'post': requests.post, 'put': requests.put, 'delete': requests.delete}
        return timeout_s,proxies,requests_methods

    # def readfiles(self): #批量读取文件，文本格式为https://127.0.0.1:8080
    #     result = []
    #     with open(r'urls.txt' ,'r') as f:
    #         for line in f:
    #          result.append(line.strip().split(',')[0])
    #         return result

    # def load_poc(self,config_path):  #自定义加载poc内容
    #     with open(config_path, 'r', encoding='utf-8') as file:
    #         config = yaml.safe_load(file)
    #     config_path = config_path
    #     Author = config['Poc']['Author']
    #     Condition = config['Poc']['Condition']
    #     Name = config['Poc']['Name']
    #     Vulnerability_details = config['Poc']['Vulnerability details']
    #     Solutions = config['Poc']['Solutions']
    #
    #     method = config['Poc']['method']
    #     poc_url_path = config['Poc']['poc_url_path']
    #     header = config['Poc']['header']
    #     poc_files = config['Poc']['poc_files']
    #     poc_post_data = config['Poc']['poc_post_data']
    #     poc_json_data = config['Poc']['poc_json_data']
    #     verification = config['Poc']['verification']
    #     re_data_keyword = config['Poc']['re_data_keyword']
    #     regex_match = config['Poc']['regex_match']
    #     status_code  = config['Poc']['status_code']
    #     Secondary_verification  = config['Poc']['Secondary_verification']
    #     Secondary_verification_path = config['Poc']['Secondary_verification_path']
    #     print(f'loading：{config_path}')
    #     self.title(Author,Condition,Name,Vulnerability_details,Solutions)

        #scan_urls_method(poc_url_path, poc_post_data,header,poc_files,method,verification,re_data_keyword,regex_match,poc_json_data,config_path,status_code,Secondary_verification,Secondary_verification_path)
