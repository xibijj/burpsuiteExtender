# -*- coding: utf-8 -*-
# @Time    : 2019/7/27 9:17
# @Author  : Mr.x
# @File    : Detect.py
import config
import re
import hashlib
import threading
import time
import sys
from hackhttp import hackhttp

reload(sys)
sys.setdefaultencoding('utf8')

def writevul(info, type):
    f = open("%s/%s_%s_vul.log" %(config.vullogpath, time.strftime("%Y-%m-%d", time.localtime()), type), 'a')
    vulinfo = "- - " * 30 + "\n%s\n\n" %info.replace('\r\n', '\n')
    f.write(vulinfo)
    f.close()

class Detect(threading.Thread):
# class Detect(object):
    def __init__(self, httpobj):
        threading.Thread.__init__(self)
        self.http = httpobj

        self.request_obj = self.http["request_obj"]
        self.request = self.http["request"]
        self.request_raw = self.request_obj.tostring()
        self.request_body = self.request_obj[self.request.getBodyOffset():].tostring()

        self.response_obj = self.http["response_obj"]
        self.response = self.http["response"]
        self.response_body = self.http["response_body"]
        self.response_status = self.response.getStatusCode()
        # self.response_hash = hashlib.md5(self.response_body).hexdigest()

        self.url = self.http["url"]
        self.head = self.http["head"]

        # 每次调用都重新加载一次配置文件
        reload(config)


    def find(self, r, t):
        try:
            return re.findall(r, t, re.I)
        except:
            return False

    def replace(self, r, p, t):
        try:
            return re.sub(r, p, t, re.I)
        except:
            return False

    def run(self):
        self.Doit()
    #
    # def start(self):
    #     self.Doit()

    def remove_auth(self):
        remove_auth_head = self.request_raw
        for h in self.head:
            h_arr = h.split(':')
            if len(h_arr) == 2:
                k, v = h_arr[0], h_arr[1]
                if k in config.rm_token_keys:
                    remove_auth_head = remove_auth_head.replace(v, '')
        return remove_auth_head

    def Unauthorized(self):
        # 未授权访问
        rm_auth_raw = self.remove_auth()

        hh = hackhttp()
        code, head, html, redirect, log = hh.http(self.url, raw=rm_auth_raw)
        if code == self.response_status and len(html) == len(self.response_body):
            print("\n[!] Unauthorized: %s" %self.url)
            writevul(rm_auth_raw, 'Unauthorized')

    def CheckPersonalInfo(self):
        # 敏感信息泄漏
        personalinfo_json = "|".join(config.personalinfo_json_keys)
        personalinfo_json_recmd = '"[\w+]{0,20}(?:%s)[\w+]{0,20}"[ \:]+"\w+"' %personalinfo_json
        find_res =  self.find(personalinfo_json_recmd, self.response_body)
        re_cmd_list = []
        if find_res:
            for r_str in find_res:
                if self.find("|".join(config.personalinfo_json_filter_keys), r_str):
                    continue
                else:
                    re_cmd_list.append(r_str)
            if re_cmd_list:
                print("\n[!] PersonalInfo: %s" % self.url)
                writevul(self.request_raw, 'PersonalInfo')
                return True
        return False

    def Check_auth(self):
        # 越权访问
        replace_auths = config.replace_auth
        replace_auth_raw = ''
        for r in replace_auths:
            recmd, replacecmd = replace_auths[r]['recmd'], replace_auths[r]['replace']
            replace_auth_raw = self.replace(recmd, replacecmd, self.request_raw)

        if replace_auth_raw:
            # print replace_auth_raw
            hh = hackhttp()
            code, head, html, redirect, log = hh.http(self.url, raw=replace_auth_raw)

            if code == self.response_status and len(html) == len(self.response_body):
                print("\n[!] Unauthorized_access: %s" % self.url)
                writevul(replace_auth_raw, 'Unauthorized_access')

    def Doit(self):
        if self.CheckPersonalInfo():
            self.Unauthorized()
            self.Check_auth()



if __name__ == '__main__':
    pass