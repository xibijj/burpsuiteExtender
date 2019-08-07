# -*- coding: utf-8 -*-
# @Time    : 2019/7/21 10:25
# @Author  : Mr.x
# @File    : Logical.py

# import sys

# print sys.path
# sys.path.append('C:\\Python27\\DLLs')
# sys.path.append('C:\\Python27\\lib')
# sys.path.append('C:\\Python27\\lib\\plat-win')
# sys.path.append('C:\\Python27\\lib\\lib-tk')
# sys.path.append('C:\\Python27')
# sys.path.append('C:\\Python27\\lib\\site-packages')

import re
import imp
from burp import IBurpExtender  # 定义插件的基本信息类
from burp import IHttpListener  # http流量监听类

res_path = re.compile(r'(GET|POST) ([^ ]*) HTTP/')

class BurpExtender(IBurpExtender, IHttpListener):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()  # 通用函数
        self._callbacks.setExtensionName("Logical Detection")
        print('author: Mr.x 20190807 ver:1.2')
        # register ourselves as an HTTP listener
        callbacks.registerHttpListener(self)

    def import_module(self, mod_name, mod_path):
        ''' 动态调用第三方模块'''
        fn_, path, desc = imp.find_module(mod_name, [mod_path])
        mod = imp.load_module(mod_name, fn_, path, desc)
        return mod

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        # if toolFlag == 64: #if tool 64 is repeater
        if toolFlag == 4 or toolFlag == 8 or toolFlag == 64:  # if tool 4 is Proxy Tab 8 is Spider
            if not messageIsRequest:
                response = messageInfo.getResponse()  # get response
                analyzedResponse = self._helpers.analyzeResponse(response)
                response_body = response[analyzedResponse.getBodyOffset():]
                response_body_string = response_body.tostring()  # get response_body

                request = messageInfo.getRequest()
                analyzedRequest = self._helpers.analyzeResponse(request)
                request_body = request[analyzedRequest.getBodyOffset():]
                request_body_string = request_body.tostring()  # get response_body
                request_header = analyzedRequest.getHeaders()

                trg_url = str(messageInfo.getUrl())
                try:
                    method = re.findall(r"(GET|POST) ", request_header[0])[0]
                except:
                    return None

                # print analyzedResponse, analyzedRequest, request_header, method, trg_url, body_string

                httpobj = {"request": analyzedRequest,
                            "response": analyzedResponse,
                            "request_obj": request,
                            "response_obj": response,
                            "head": request_header,
                            "method": method,
                            "url": trg_url,
                            "request_raw": request_body_string,
                            "response_body": response_body_string,
                          }

                imp_module = self.import_module("Detection", ".")
                t = imp_module.Detect(httpobj)
                t.start()
                # del imp_module