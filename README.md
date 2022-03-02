# springboot_scan
Springboot directory scanning  


注意：此工具暂时不能够直接用于不可访问的域名，没有添加对应的报错处理，请确认为springboot框架再使用。


# 项目由来


项目过程中发现现有的工具对springboot路径扫描大多存在误报和遗漏现象。


往往是存在以下几个现象:


1、请求频率过高时，服务器对于返回503等出错结果，此时无法准确判断访问页面是否为正常页面。


2、heapdump等大文件路径如果存在时，会使得扫描工具产生卡顿，从而无法继续扫描。


3、使用浏览器访问时，延迟加载页面成功，使用工具扫描时无法获取所有响应页面，导致漏报。


4、对于200的扫描结果无法判断，产生极大的误报。



尝试试用了大部分公开springboot目录扫描工具，发现都不可避免的产生以上问题，

    [Go]springScan
    [PY]SB-Actuator
    [PY]springboot-check
    [PY]SpringBootScan



在此种情况下，重新编写了一个适用于springboot的目录扫描工具。



目前支持以下功能：


1、使用多种方法【get、post、head】自动重试访问503页面和无结果页面。


2、使用多种关键数据【长度、大小、头部比特】用于自动过滤和辅助手动过滤非404的非正常页面。


3、支持多种方式代理【socks5、https】请求页面代理用于调试和绕过请求限制。


4、使用多个文件记录不同情景下过滤的URL，便于追踪产生的错误和漏报。

    过程及结果文件 默认输出在当前【result-时间戳】目录下，
    其中 scan_waive.txt 存放基于404、403、500状态码 过滤的URL。   （waive 放弃）
    其中 scan_filter.txt  存放基于【长度、大小、头部比特】过滤的URL。（filter 过滤
    其中 scan_retry.txt  存放根据请求结果自动重试的URL和对应重试次数。（retry 重试）
    

    其中 scan_result.txt 存放状态码为200,并且不被过滤的URL，此文件为实际结果文件。     （result 结果）
    其中 scan_manual.txt 存放当重试多次依然无法判断为正常请求时的URL，此文件结果需用户进行手动重试。（manual 手动）



5、通过fofa批量采集了2000站点的mapping路径加入字典文件。



# 快速使用

    1、将目标URL填写在springboot_target.txt，并运行 python3 springboot_scan.py


# TODO:


1、对可能存在漏洞的请求URL进行提示。(极小概率)


2、对敏感的响应内容进行提示。(极小概率，建议使用HAE插件替代)

3、美化代码整体结构

