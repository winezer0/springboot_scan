import requests, sys, os, argparse
from binascii import b2a_hex
from datetime import datetime
import logging
import time,random
from concurrent.futures import ThreadPoolExecutor # , as_completed
requests.packages.urllib3.disable_warnings()
from collections import defaultdict

method_list = ["head", "get", "post"]
retry_times = len(method_list) *3  #每种方法最多重试3次
headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:74.0) Gecko/20100101 Firefox/74.0'}

def get_logger(logger_name,log_file,level=logging.INFO):
    logger = logging.getLogger(logger_name)
    formatter = logging.Formatter('%(message)s')
    fileHandler = logging.FileHandler(log_file, mode='a')
    fileHandler.setFormatter(formatter)
    logger.setLevel(level)
    logger.addHandler(fileHandler)
    return logger

# 简单的读文件到列表
def read_file(file):
    result_list = []
    with open(file) as fileopen:
        for line in fileopen.readlines():
            if line.strip() != '':
                result_list.append(line.strip())
        return result_list

#输出结果处理
def requests_print(logger_handle , logger_source , target_url , resp_status,  resp_content_length,  resp_text_size, resp_bytes_head , retry ):
    size_and_length_sum = resp_content_length+resp_text_size
    logger_string = '{},"{}",{},{},{},{},{},{}'.format( logger_source , target_url  , resp_status ,  resp_content_length,  resp_text_size,size_and_length_sum, resp_bytes_head ,  retry_times - retry)
    print(logger_handle , logger_string)
    if logger_handle == "log_result" : log_result.info(logger_string)
    elif logger_handle == "log_waive" : log_waive.info(logger_string)
    elif logger_handle == "log_manual" : log_manual.info(logger_string)
    elif logger_handle == "log_retry" : log_retry.info(logger_string)
    elif logger_handle == "log_filter" : log_filter.info(logger_string)
    else: print("please input logger_handle")
    
#请求测试路径
def requests_common(method="get" , scope = None , target_url=None, cookie=None, stream=True, timeout=10 , retry= retry_times  , proxies=None , sleep=0):
    resp_status=0
    resp_bytes_head = "NULL"
    resp_content_length = 0
    resp_text_size = 0
    resp = None

    try:
        time.sleep(sleep)
        resp = requests.request(method=method, url=target_url, cookies=cookie, timeout=timeout , stream=stream, proxies=proxies, headers=headers, verify=False)
        try: resp_status = resp.status_code
        except Exception as tmp: pass
        # 获取三个关键匹配项目
        try: resp_bytes_head = b2a_hex(resp.raw.read(10)).decode() if  b2a_hex(resp.raw.read(10)).decode().strip() !=""  else "NULL"
        except Exception as tmp: pass
        if resp_bytes_head .strip() =="": resp_bytes_head = "NULL"
        try: resp_content_length = int(str(resp.headers.get('Content-Length')))
        except Exception as tmp: pass
        try: resp_text_size = resp_content_length if resp_content_length >1024000 * 5 else  len(resp.text)
        except Exception as tmp: pass
        
        return [target_url , resp_status, resp_content_length, resp_text_size ,resp_bytes_head ]
    except KeyboardInterrupt:
        sys.exit()
    except Exception as e:
        try: resp_status = resp.status_code
        except Exception as tmp: pass
        # 获取三个关键匹配项目
        try: resp_bytes_head = b2a_hex(resp.raw.read(10)).decode() if  b2a_hex(resp.raw.read(10)).decode().strip() !=""  else "NULL"
        except Exception as tmp: pass
        if resp_bytes_head .strip() =="": resp_bytes_head = "NULL"
        try: resp_content_length = int(str(resp.headers.get('Content-Length')))
        except Exception as tmp: pass
        try: resp_text_size = resp_content_length if resp_content_length >1024000 * 5 else  len(resp.text)
        except Exception as tmp: pass
        return [target_url , resp_status, resp_content_length, resp_text_size ,resp_bytes_head ]


#请求文件测试
def requests_stream(method="get" , scope = None , target_url=None, cookie=None, stream=True, timeout=10 , retry= retry_times  , proxies=None , sleep=0):
    #print("Requests {}".format(target_url))
    resp_status=0
    resp_bytes_head = "NULL"
    resp_content_length = 0
    resp_text_size = 0
    resp = None
    if retry < 0 : 
        requests_print("log_manual", "Retry-{}-Times".format(retry_times),  target_url , resp_status,  resp_content_length,  resp_text_size, resp_bytes_head , retry)
        return 
    if '/shutdown' in target_url: method = 'post'
    try:
        time.sleep(sleep)
        resp = requests.request(method=method, url=target_url, cookies=cookie, timeout=timeout , stream=stream, proxies=proxies, headers=headers, verify=False)
        
        try: resp_status = resp.status_code
        except Exception as tmp: pass
        # 获取三个关键匹配项目
        try: resp_bytes_head = b2a_hex(resp.raw.read(10)).decode() if  b2a_hex(resp.raw.read(10)).decode().strip() !=""  else "NULL"
        except Exception as tmp: pass
        if resp_bytes_head .strip() =="": resp_bytes_head = "NULL"
        try: resp_content_length = int(str(resp.headers.get('Content-Length')))
        except Exception as tmp: pass
        if resp_content_length >= 1024000 * 5  : resp_text_size = resp_content_length
        else: resp_text_size = len(resp.text)

        #对响应进行处理和判断
        if str(resp_status).startswith("404") or str(resp_status).startswith("403")  or str(resp_status).startswith("500") :
            #404\403\500响应直接弃用处理
            requests_print("log_waive", "Normal-NotExistUrl",  target_url , resp_status,  resp_content_length,  resp_text_size, resp_bytes_head , retry)
        elif str(resp_status).startswith("503") :
            #503响应需要重新测试
            requests_print("log_retry", "Normal-ServerBad",  target_url , resp_status,  resp_content_length,  resp_text_size, resp_bytes_head , retry)
            for index in range(0,len(method_list)):
                if retry % len(method_list) == index : requests_stream(method=method_list[index] , scope = scope, target_url= target_url, cookie = cookie, stream=True , timeout=15, retry= retry-1, proxies=proxies , sleep=random.random())
        else: 
            #响应状态码为20X时,暂未考虑到30X
            #200响应时,如果没有判断数据就需要重试
            if (resp_content_length == 0) and (resp_text_size == 0) and ( resp_bytes_head == "NULL" ):
                requests_print("log_retry", "Normal-ALLKeyZero",  target_url , resp_status,  resp_content_length,  resp_text_size, resp_bytes_head , retry )
                for index in range(0,len(method_list)):
                    if retry % len(method_list) == index : requests_stream(method=method_list[index] , scope = scope, target_url= target_url, cookie = cookie, stream=False , timeout=20, retry= retry-1, proxies=proxies)
            else :
                #对比处理,过滤所有错误数据
                if target_dict[scope]["resp_bytes_head"] == resp_bytes_head : requests_print("log_filter", "Normal-By-Bytes",  target_url , resp_status,  resp_content_length,  resp_text_size, resp_bytes_head , retry )
                elif  target_dict[scope]["resp_content_length"] ==  resp_content_length: requests_print("log_filter", "Normal-By-Length",  target_url , resp_status,  resp_content_length,  resp_text_size, resp_bytes_head , retry )
                elif  target_dict[scope]["resp_text_size"] == resp_text_size : requests_print("log_filter", "Normal-By-Size",  target_url , resp_status,  resp_content_length,  resp_text_size, resp_bytes_head , retry )
                else: requests_print("log_result", "Normal-Requests",  target_url , resp_status,  resp_content_length,  resp_text_size, resp_bytes_head , retry )
    except KeyboardInterrupt:
        sys.exit()
    except Exception as e:
        try: resp_status = resp.status_code
        except Exception as tmp: pass
        # 获取三个关键匹配项目
        try: resp_bytes_head = b2a_hex(resp.raw.read(10)).decode() if  b2a_hex(resp.raw.read(10)).decode().strip() !=""  else "NULL"
        except Exception as tmp: pass
        if resp_bytes_head .strip() =="": resp_bytes_head = "NULL"
        try: resp_content_length = int(str(resp.headers.get('Content-Length')))
        except Exception as tmp: pass
        try: resp_text_size = resp_content_length if resp_content_length >1024000 * 5 else  len(resp.text)
        except Exception as tmp: pass

        if "IncompleteRead" in str(e):
            # IncompleteRead #不支持stream , 可能需要尝试重新请求，响应码 000 200 404 503
                if str(resp_status).startswith("0") : 
                    #没有获取到状态码选项,需要重新测试
                    requests_print("log_retry", "Incomplete-NoStatus",  target_url , resp_status,  resp_content_length,  resp_text_size, resp_bytes_head , retry )
                    for index in range(0,len(method_list)):
                        if retry % len(method_list) == index : 
                            requests_stream(method_list[index] , scope = scope, target_url= target_url, cookie = cookie, stream=False , timeout=20, retry= retry-1, proxies=proxies)
                elif str(resp_status).startswith("404") or str(resp_status).startswith("403")  or str(resp_status).startswith("500")  : 
                    requests_print("log_waive", "Incomplete-NotExistUrl",  target_url , resp_status,  resp_content_length,  resp_text_size, resp_bytes_head , retry )
                elif str(resp_status).startswith("503") :
                    requests_print("log_retry", "Incomplete-ServerBad",  target_url , resp_status,  resp_content_length,  resp_text_size, resp_bytes_head , retry)
                    for index in range(0,len(method_list)):
                        if retry % len(method_list) == index : requests_stream(method=method_list[index] , scope = scope, target_url= target_url, cookie = cookie, stream=False , timeout=15, retry= retry-1, proxies=proxies , sleep=random.random())
                else:  
                    #str(resp_status).startswith("200"):  
                   #判断用于匹配的三个关键属性是否为空,是的话就需要重试
                    if (resp_content_length == 0) and (resp_text_size == 0) and ( resp_bytes_head == "NULL" ):
                        requests_print("log_retry", "Incomplete-ALLKeyZero",  target_url , resp_status,  resp_content_length,  resp_text_size, resp_bytes_head , retry )
                        for index in range(0,len(method_list)):
                            if retry % len(method_list) == index : requests_stream(method=method_list[index] , scope = scope,  target_url= target_url, cookie = cookie, stream=False , timeout=20, retry= retry-1, proxies=proxies)
                    else :
                        #对比处理,过滤所有错误数据
                        if target_dict[scope]["resp_bytes_head"] == resp_bytes_head : requests_print("log_filter", "Incomplete-By-Bytes",  target_url , resp_status,  resp_content_length,  resp_text_size, resp_bytes_head , retry )
                        elif  target_dict[scope]["resp_content_length"] ==  resp_content_length: requests_print("log_filter", "Incomplete-By-Length",  target_url , resp_status,  resp_content_length,  resp_text_size, resp_bytes_head , retry )
                        elif  target_dict[scope]["resp_text_size"] == resp_text_size : requests_print("log_filter", "Incomplete-By-Size",  target_url , resp_status,  resp_content_length,  resp_text_size, resp_bytes_head , retry )
                        else: requests_print("log_result", "Incomplete-Requests",  target_url , resp_status,  resp_content_length,  resp_text_size, resp_bytes_head , retry )

        elif "Read timed out" in str(e):
            # Read timed out.  #访问超时 , 需要尝试重新请求
            requests_print("log_retry", "Timedout-NoResult",  target_url , resp_status,  resp_content_length,  resp_text_size, resp_bytes_head , retry )
            for index in range(0,len(method_list)):
                if retry % len(method_list) == index : requests_stream(method=method_list[index] , scope = scope,  target_url= target_url, cookie = cookie, stream=True , timeout=20, retry= retry-1, proxies=proxies)
        else:
            #其他结果
            print("存在其他异常:",str(e))  
            requests_print("log_retry", "Requests-NoResult",  target_url , resp_status,  resp_content_length,  resp_text_size, resp_bytes_head , retry )
            for index in range(0,len(method_list)):
                if retry % len(method_list) == index : requests_stream(method=method_list[index] , scope = scope,  target_url= target_url, cookie = cookie, stream=True , timeout=20, retry= retry-1, proxies=proxies)

def get_version():
    return 'You Tools Version is {} !!!'.format(version)
    
if __name__ == '__main__':
    version = "0.5.9"
    url_list = []
    path_list = []
    target_dict = defaultdict(dict)
    
    parser = argparse.ArgumentParser()
    parser.description = "Spring Boot Unauthorized path access detection tool , supports automatic retry and automatic filtering  ..."
    parser.add_argument("-u", "--url", help="Specifies the destination URL to be scanned", default=None)
    parser.add_argument("-f", "--file", help="Specifies the destination URL file to be scanned", default='springboot_target.txt')
    parser.add_argument("-t", "--thread", help="Specifies the number of threads at request time" , type=int  , default=10)
    parser.add_argument("-c", "--cookie", help="Specify the Cookie field at requests , format: {'parameter1':'value1','parameter2':'value2'}", default=None)
    parser.add_argument("-p", "--proxies", help="Specify the requests proxy address, support Socks5 and HTTP, for example: http://127.0.0.1:8080 or socks5://127.0.0.1:1080", default=None)
    parser.add_argument("-d", "--dictfile", help="Specifies the SpringBoot path dictionary  ", default='springboot_path.txt')
    parser.add_argument("-o", "--output", help="Specifies the result dictionary , default is current [.\result]", default='result')
    parser.add_argument("-v", "--version", action="version", version=get_version(), help= "Display tool version information" )
    args = parser.parse_args()

    # 日志信息输出到文件
    # logging 输出两个日志文件 https://www.cnblogs.com/tastepy/p/13328847.html 

    #当前时间戳
    datef_now = datetime.now().strftime('%Y-%m-%d-%H-%M-%S') 
    #输出结果文件夹
    if args.output == "result" :
        result_dir = args.output+ "_" + datef_now
    else:
        result_dir = args.output
    #输出结果文件名
    if not os.path.exists(result_dir): os.makedirs(result_dir) 
    file_manual   = result_dir +"/" +'scan_manual.txt'   #保存需要手动重试的URL
    file_waive      = result_dir +"/" +'scan_waive.txt'   #保存404等直接放弃URL
    file_result      = result_dir +"/" +'scan_result.txt'  #保存正常的结果文件
    file_retry       = result_dir +"/" +'scan_retry.txt'   #保存503等需要重试的URL
    file_filter       = result_dir +"/" + 'scan_filter.txt'   #保存根据测试URL匹配过滤掉的URL
    
    #设置日志记录器和对应保存文件
    log_result = get_logger('log_result',  file_result )
    log_manual   = get_logger('log_manual',   file_manual)
    log_waive   = get_logger('log_waive',   file_waive)
    log_retry   = get_logger('log_retry',   file_retry)
    log_filter   = get_logger('log_filter',   file_filter)
    
    if args.cookie != None: args.cookie = eval(args.cookie)  # 此处有命令执行风险,请勿对外提供接口
    if args.proxies !=None: args.proxies={ 'http': args.proxies.replace('https://','http://') , 'https': args.proxies.replace('http://','https://')  }

    # 目标URL
    if args.url != None: url_list.append(args.url)
    elif os.path.isfile(args.file): url_list.extend(read_file(args.file))
    else: parser.print_help()
    
    #URL处理,添加http/https头
    tmp_url_list = []
    for host in url_list:
        if host.startswith("http"): tmp_url_list.append(host)
        else: tmp_url_list.append("http://" +host,"https://" + host)
    url_list = list(set(tmp_url_list))
    
    # 路径字典
    if os.path.isfile(args.dictfile): path_list = read_file(args.dictfile)
    path_list = list(set(path_list))
    
    #生成测试URL,并生成对应的响应关键作为对比
    test_path_list = ["/xxx","/xxx/yyy","/xxx/yyy/zzz"]
    test_path_data = dict()
    
    for url in url_list:
        test_path_data[url] = dict() #存放测试路径的返回结果
        target_dict[url]["target_url_list"]=[] #存放每个目标URL和其对应的对比参数
        target_dict[url]["resp_bytes_head"] = "False"
        target_dict[url]["resp_text_size"] = "False"
        target_dict[url]["resp_content_length"] = "False"
        
        ##访问测试路径
        for test_path in test_path_list:
            test_url = url+test_path
            test_path_data[url][test_path] = requests_common( scope = url, target_url=test_url , cookie=args.cookie ,proxies=args.proxies,retry=0)
            #print(test_path_data[url][test_path]) # ['https://xxxx/xxx', 200, 92, 42, 'b7e6b182e8aebfe997ae']

        ##确定各个URL的对比参数
        if ( test_path_data[url]['/xxx'][-1] !="NULL" and  test_path_data[url]['/xxx'][-1] == test_path_data[url]['/xxx/yyy'][-1]  and test_path_data[url]['/xxx/yyy'][-1] == test_path_data[url]['/xxx/yyy/zzz'][-1] ):
            print("[{}] This can be compared by the response header bytes, which is [{}]".format(url,test_path_data[url]['/xxx'][-1]))
            target_dict[url]["resp_bytes_head"] = test_path_data[url]['/xxx'][-1]
        if ( test_path_data[url]['/xxx'][-2] != 0 and test_path_data[url]['/xxx'][-2] == test_path_data[url]['/xxx/yyy'][-2]  == test_path_data[url]['/xxx/yyy/zzz'][-2]) :
            print("[{}] This can be compared by the response text size, which is [{}]".format(url,test_path_data[url]['/xxx'][-2]))
            target_dict[url]["resp_text_size"] = test_path_data[url]['/xxx'][-2]
        if (  test_path_data[url]['/xxx'][-3] != 0 and test_path_data[url]['/xxx'][-3] == test_path_data[url]['/xxx/yyy'][-3]  == test_path_data[url]['/xxx/yyy/zzz'][-3]):
            print("[{}] You can compare it by the response content-length, which is [{}]".format(url,test_path_data[url]['/xxx'][-3]))
            target_dict[url]["resp_content_length"] = test_path_data[url]['/xxx'][-3]
    
    #根据路径字典合并最终的请求URL
    for url in url_list:
        for path in path_list:
            target_dict[url]["target_url_list"].append(url.strip('/')+path)
    
    #逐URL进行多线程请求处理
    for url in url_list:
        if  target_dict[url]["target_url_list"] !=[]:
            # 创建一个最大容纳数量为thread的线程池
            with ThreadPoolExecutor(max_workers=args.thread) as pool:  
                all_task = []
                for  target_url in target_dict[url]["target_url_list"] :
                    task = pool.submit(requests_stream, scope = url , target_url=target_url, cookie=args.cookie ,proxies=args.proxies)
                    all_task.append(task)
                #输出返回的结果
                #for future in as_completed(all_task):print(future.result())  
