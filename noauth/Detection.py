# -*- coding: utf-8 -*-
# @Time    : 2019/7/27 9:17
# @Author  : Mr.x
# @File    : Detect.py
import config
import re
import urlparse
import threading
import sys
from hackhttp import hackhttp
import unit

reload(sys)
sys.setdefaultencoding('utf8')

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

        self.url = self.http["url"]
        self.head = self.http["head"]
        self.method = self.http["method"]

        # 每次调用都重新加载配置文件
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

    def checkContextByRecmd(self, r, context=''):
        re_cmd_list = []
        if context:
            raw = context
        else:
            raw = self.response_body
        find_res = self.find(r, raw)
        if find_res:
            for r_str in find_res:
                if self.find("|".join(config.re_filter_keys), r_str):
                    continue
                else:
                    re_cmd_list.append(r_str)
        return re_cmd_list


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

    def curl(self, r_url, r_raw, compare=True):
        hh = hackhttp()
        code, head, html, redirect, log = hh.http(r_url, raw=r_raw)
        if compare:
            if code == 200 and len(html) == len(self.response_body):
                return True
            else:
                return False
        return (code, head, html)

    def Unauthorized(self):
        # 未授权访问
        rm_auth_raw = self.remove_auth()
        if self.curl(self.url, rm_auth_raw):
            print("\n[!] Unauthorized: %s" % self.url)
            unit.writevul(rm_auth_raw, 'Unauthorized')

    def CheckPersonalInfo(self):
        # 敏感信息泄漏
        re_res = self.checkContextByRecmd(config.personalinfo_recmd)
        if re_res:
            print("\n[!] PersonalInfo: %s" % self.url)
            print(' | '.join(re_res))
            unit.writevul(self.request_raw, 'PersonalInfo')
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
            if self.curl(self.url, replace_auth_raw):
                print("\n[!] Auth replace: %s" % self.url)
                unit.writevul(replace_auth_raw, 'Auth_replace')

    def creatPayload(self, arrs):
        payload = []
        payload.append(arrs)
        t_p = []
        for i in arrs:
            i_1_int = int(i) + 1
            t_p.append(str(i_1_int))
        payload.append(t_p)
        return payload

    def check_idor(self):
        # 不安全的对象引用（平行越权）
        method = self.method
        orig_replace_raw = ''
        if method == 'GET':
            orig_replace_raw = urlparse.urlparse(self.url).query
        elif method == 'POST':
            orig_replace_raw = self.request_body

        replace_raw = orig_replace_raw
        replace_ids = self.find(config.idor_rule['param'], replace_raw)
        if replace_ids:
            payloads = self.creatPayload(replace_ids)
            original = payloads[0]
            after = payloads[1]
            for i in xrange(len(original)):
                orig_var, aft_var = original[i], after[i]
                var_start_index = replace_raw.find(orig_var)
                var_end_index = var_start_index + len(orig_var)
                replace_body_str = replace_raw[var_start_index:var_end_index]
                replace_body_tmp = replace_raw[:var_end_index].replace(replace_body_str, aft_var)
                replace_raw = replace_raw.replace(replace_raw[:var_end_index], replace_body_tmp)
                code, head, html, replace_id_raw = 0, None, '', ''
                # print orig_replace_raw, replace_raw
                if method == 'GET':
                    replace_id_url = self.url.replace(orig_replace_raw, replace_raw)
                    replace_id_raw = self.request_raw.replace(orig_replace_raw, replace_raw)
                    code, head, html = self.curl(replace_id_url, replace_id_raw, compare=False)
                elif method == 'POST':
                    replace_id_raw = self.request_raw.replace(orig_replace_raw, replace_raw)
                    code, head, html = self.curl(self.url, replace_id_raw, compare=False)
                if code == 200:
                    pinfo = self.checkContextByRecmd(config.idor_rule['result'], html)
                    if pinfo:
                        print("\n[!] IDOR: %s" % self.url)
                        print(' | '.join(pinfo))
                        unit.writevul(replace_id_raw, 'IDOR')

    def Doit(self):
        # print 'Doit.....'
        only_url = False
        if config.url_hash:
            only_url = unit.checkUrls(self.url)

        if only_url is False:
            if len([h for h in config.filter_files if urlparse.urlparse(self.url.lower()).path.endswith(h)]): return
            if self.CheckPersonalInfo():
                # 个人敏感信息泄漏
                self.Unauthorized()
                self.Check_auth()
                self.check_idor()
            elif self.find("|".join(config.black_urls), self.url):
                # 黑名单检测机制,一定要检测的URL名单
                self.Unauthorized()
                self.Check_auth()
                self.check_idor()


if __name__ == '__main__':
    pass