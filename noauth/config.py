# -*- coding: utf-8 -*-
# @Time    : 2019/7/27 12:39
# @Author  : Mr.x
# @File    : config.py

# 漏洞记录文件存放目录
vullogpath = './vullog/'

# URL去重检测开关, 开启：True，关闭：False
url_hash = True

# 自动清除http请求中head中的身份认证字段,大小写敏感
rm_token_keys = ['token', 'Cookie']

# 自定义response中JSON/XML/JS数据类型的敏感信息字段定义,大小写不敏感
personalinfo_keys = ['identity', 'phone', 'webchat', 'email', 'qq', 'mobile', 'chargename', 'pass', 'bank', 'card']

# 更新匹配中文正则
personalinfo_recmd = '[<"\w]{0,20}(?:%s)[\w]{0,20}[ \:=>"]+.*?[</>"\w]{0,20}[\w]{0,20}[ \:=>"]' %"|".join(personalinfo_keys)

# 自定义搜索出来的敏感信息进行过滤字段,大小写不敏感
re_filter_keys = ['dont_delete_this_default_vaule', 'mobileDisplay', 'highSpeedCardNumber', 'payeeBankCode', 'payeeBankType']

# 自定义忽略文件类型,小写敏感
filter_files = ['.css', '.js', '.jpg', '.jpeg', '.gif', '.png', '.bmp', '.html', '.htm', '.swf', '.svg']

# 自定义一定要进行权限安全检测的URL黑名单，支持正则
black_urls = ['dont_delete_this_default_vaule', '\?auth.\w+']

# 自定义替换身份认证信息如：token、Cookie等信息，用于越权测试，支持正则
replace_auth = {'token':{
                        'recmd': 'token: .*',
                        'replace': 'token: fuckyouman...'
                        }
                }

# 自定义平行越权越权测试规则，支持正则
idor_rule = {
                'param': '\d+', # ID参数值检测规则，只支持int型
                'result': '(?:1[3-9])\d{9}' # 敏感信息的判断标准
            }