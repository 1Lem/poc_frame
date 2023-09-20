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
requests.packages.urllib3.disable_warnings()  



def title(Author,Condition,Name,Vulnerability_details,Solutions):
    print(f"""
    Author: {Author}
    Condition:{Condition}
    Name:{Name}
    Vulnerability details: {Vulnerability_details}
    Solutions:{Solutions}
    """)

def basic_setting():
    timeout_s=3 
    proxies = {  
    'http': 'http://127.0.0.1:8080',  #proxies=proxies
    'https': 'http://127.0.0.1:8080',  
    }
    requests_methods = {'get': requests.get, 'post': requests.post, 'put': requests.put, 'delete': requests.delete}   
    return timeout_s,proxies,requests_methods

def readfiles(): #批量读取文件，文本格式为https://127.0.0.1:8080
    result = [] 
    with open(r'urls.txt' ,'r') as f:
        for line in f:
         result.append(line.strip().split(',')[0])  
        return result

def load_poc(config_path):  #自定义加载poc内容  
    with open(config_path, 'r', encoding='utf-8') as file:  
        config = yaml.safe_load(file)
    config_path = config_path  
    Author = config['Poc']['Author'] 
    Condition = config['Poc']['Condition'] 
    Name = config['Poc']['Name'] 
    Vulnerability_details = config['Poc']['Vulnerability details'] 
    Solutions = config['Poc']['Solutions']  
    method = config['Poc']['method']  
    poc_url_path = config['Poc']['poc_url_path']  
    header = config['Poc']['header']  
    poc_files = config['Poc']['poc_files']  
    poc_post_data = config['Poc']['poc_post_data']  
    poc_json_data = config['Poc']['poc_json_data']  
    verification = config['Poc']['verification']  
    re_data_keyword = config['Poc']['re_data_keyword']  
    regex_match = config['Poc']['regex_match']
    status_code  = config['Poc']['status_code']
    print(f'loading：{config_path}')
    title(Author,Condition,Name,Vulnerability_details,Solutions)
    scan_urls_method(poc_url_path, poc_post_data,header,poc_files,method,verification,re_data_keyword,regex_match,poc_json_data,config_path,status_code)

def scan_urls_method(poc_url_path, poc_post_data,header,poc_files,method,verification,re_data_keyword,regex_match,poc_json_data,config_path,status_code):
    result = readfiles()   
    timeout_s,proxies,requests_methods = basic_setting()
    #timeout_s,regex_match,_ ,requests_methods= basic_setting()  #禁用proxies   
    for url in result:  
        scan_url = f"{url}{poc_url_path}"   
        print(scan_url)  
        try:
            if method in requests_methods:
                re_data = requests_methods[method] (scan_url,data=poc_post_data,json=poc_json_data,files=poc_files,timeout=timeout_s,headers=header,verify=False,proxies='') 
            else:
                raise ValueError('Invalid method. Only "get", "post", "pu t" and "delete" are supported.') 
            print(re_data.status_code) 
            #print(re_data.text) 
            if re_data.status_code == status_code:
            #if re_data.status_code == 200:
                with open(f'scan_out_{config_path}.txt', mode='a') as file_handle:
                    process_verification(scan_url, re_data, verification,re_data_keyword,regex_match, file_handle)    
            else:  
                print("不存在")  
                #print(re_data.text)  
        except requests.exceptions.RequestException as e:  
            print("请检查目标列表")  
            #print(re_data.status_code)  
            print(str(e)) 

def process_verification(scan_url, re_data, verification, re_data_keyword,regex_match, file_handle):  
    if verification == 'status_code':  
        print(f"status_code:{re_data.status_code}")  
        file_handle.write(f"{scan_url}\n")  
    elif verification == 'response' and re_data_keyword in re_data.text :  
        print('Successfully_queried')  
        file_handle.write(f"{scan_url}\n{re_data.text}\n")  
    elif verification == 'regex':  
        find_list = re.findall(regex_match, re_data.text)  
        #print(find_list)  
        if find_list:
            print(f'Successfully_queried:{find_list}')  
            file_handle.write(f"{scan_url}-{find_list}\n")  
            #scan_regex_match_url(scan_url,url,find_list)  对匹配的链接内容进行请求  
    elif verification == 'json':
        find_data = json.loads(re_data.text) 
        if re_data_keyword in find_data:
            print(f'Successfully_queried:{find_data[re_data_keyword]}')
            file_handle.write(f"{scan_url}-{find_data[re_data_keyword]}\n") 
    else:  
        print('未定义验证方式或验证失败')

def scan_regex_match_url(scan_url,url,find_list):
    scan_path=f"{url}{find_list[0]}" #根据实际情况组合地址路径
    if requests.get(scan_path,timeout=timeout_s,headers=header,verify=False).status_code == 200:
        print('success') 
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Process some integers.")  
    parser.add_argument('-c', '--config', type=str, help="Config file path")  
    args = parser.parse_args()
    load_poc(args.config)   