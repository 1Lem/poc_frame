# poc_frame

用于快速收录、测试常见安全漏洞，支持proxies代理调试；

支持常见HTTP验证请求，GET、POST、PUT、DELETE等；

支持四种验证方式，正则、响应包、状态码、JSON参数；

## 录入方法：

确定漏洞POC结构，如GET请求获取地址获取正则匹配内容；

### 示例POC：

xx漏洞POC：http://127.0.0.1/rce.php 

回显关键内容：'id':administrator;

### 录入：

method= '<mark>get</mark>'

poc_url_path = "/<mark>rce.php</mark>"

verification = '<mark>regex</mark>'

regex_match=r"<mark>'id':(.+?);</mark>"



```
def poc():  #自定义poc内容
    method= 'get'  # {get,post,put,delete}
    poc_url_path = "/rce.php"   
    header = {'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
          #'Accept-Encoding': 'gzip, deflate',
          #'Accept-Language': 'zh-CN,zh;q=0.9',
          #'Cache-Control': 'max-age=0',
          #'Connection': 'keep-alive',
          #'Cookie': 'cookie',
          #'Host': 'www.baidu.com',
          'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/64.0.3282.186 Safari/537.36'
          }
    poc_files = ''     #{"file":("test.txt","hello")}  #Content-Disposition: form-data; name="file"; filename="test.txt"
    poc_post_data = ''
    poc_json_data = ''
    verification = 'regex'  # {'正则':'regex','响应包':'response','状态码':'status_code','json':'json'}
    re_data_keyword = '' # 响应包关键词
    regex_match=r"'id':(.+?)" #自定义正则匹配规则 r'r(.+?)l'
    return poc_url_path, poc_post_data,header,poc_files,method,verification,re_data_keyword,regex_match,poc_json_data
```

待检测url.txt加入批量地址信息自动检测；

#### 使用

py -3 poc_frame.py

20230919持续优化中

#### 20230919更新为加载yml实现漏洞验证
py -3 poc_frame_config_yml.py -c config.yml

py -3 poc_frame_config_yml.py -c xxxxx.yml

#### 20231011
适应了一段时间nuclei，还是nuclei好用，就不重复造轮子了，nuclei解决不了问题时再启用这个版本
#### 20240412
优化了一下框架逻辑，调整了代码分布；更好适应需要二次请求验证的poc；默认加载所以yaml文件验证扫描
#### 20240422
增加了多线程扫描能力
