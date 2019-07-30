基于敏感数据IAST模式的Burpsuite插件
===================================
	
#一、说明
	
基于敏感数据IAST模式的Burpsuite插件，用于甲乙方在做渗透测试或是应用系统安全检测时半自动发现接口返回敏感数据，并对该接口进行未授权、越权等简单测试。当前的检测逻辑还是比较简单的，各位可根据自己的实际业务对检测逻辑进行优化。
	
###已完成：
	
+ 敏感信息泄漏检测
+ 垂直越权访问检测
+ 未授权访问检测
	
###计划中：
	
+ 水平越权访问检测(解释请求报文,自动遍历数值类型的ID)
+ 欢迎提建议
	
#二、部署说明

	需要安装jython2.7.0,并在burpsuite启用。
[下载 jython2.7.0](http://search.maven.org/remotecontent?filepath=org/python/jython-installer/2.7.0/jython-installer-2.7.0.jar)
	
#三、目录说明

	.
	│─config.py      检测规则配置文件
	│─Detection.py   检测逻辑主体
	│─hackhttp.py    Http请求方法封装模块
	│─Logical.py     burpsuite插件入口文件
	│
	└─vullog         检测出来的漏洞记录文件存放目录，auth_replace：越权访问、PersonalInfo：敏感信息泄漏、Unauthorized：未授权访问。 
	
#四、检测配置config.py
	
```
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
```
	
#版本
	
+ 作者: Mr.x
+ 版本: 1.0
+ 时间: 20190727