# -*- coding: utf-8 -*-
# @Time    : 2019/7/27 12:39
# @Author  : Mr.x
# @File    : config.py

# 漏洞记录文件存放目录
vullogpath = './vullog/'

# 自动清除http请求中head中的身份认证字段
rm_token_keys = ['token', 'Cookie']

# 自定义response中json数据类型的敏感信息字段定义,不区分大小写
personalinfo_json_keys = ['identity', 'phone', 'webchat', 'email', 'qq', 'mobile', 'chargename']

# 自定义搜索出来的敏感信息进行过滤
personalinfo_json_filter_keys = ['AGFHGHJJTRRERFDGJHKJHJKH']

# 自定义替换身份认证信息如：token、Cookie等信息，用于越权测试，支持正则
replace_auth = {'token':{
                        'recmd': 'token: \w+',
                        'replace': 'token: fuckyouman...'
                        }
                }