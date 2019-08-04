# -*- coding: utf-8 -*-
# @Time    : 2019/7/30 23:15
# @Author  : Mr.x
# @File    : unit.py
import config
import time
import urlparse
import hashlib

global global_only_url_hashs
global_only_url_hashs = ''

def writevul(info, type):
    f = open("%s/%s_%s_vul.log" %(config.vullogpath, time.strftime("%Y-%m-%d", time.localtime()), type), 'a')
    vulinfo = "- - " * 30 + "\n%s\n\n" %info.replace('\r\n', '\n')
    f.write(vulinfo)
    f.close()

def checkUrls(url):
    global global_only_url_hashs
    parse = urlparse.urlparse(url)
    try:
        urlhash = hashlib.md5('%s%s%s' % ( parse.hostname, parse.path, ''.join(sorted(urlparse.parse_qs(parse.query).keys())))).hexdigest()
    except:
        urlhash = ''
    if urlhash:
        if global_only_url_hashs.find(urlhash) == -1:
            global_only_url_hashs += urlhash + '|'
            return False
    return True

if __name__ == '__main__':
    pass