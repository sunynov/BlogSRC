---
title: 使用python请求网页
date: 2025-12-17 11:55:01
tags:
---
使用python请求网页要用到request库

[Python requests 模块](https://www.runoob.com/python3/python-requests.html)

```python
# 导入requests库
import requests
# 获取响应文本
def getStr(session , url , postData:
          
          ):
	# 进行POST请求
	response = session.post(url,postData)
	# 获取POST响应内容
	text =response.text
	# 传入文本处理函数
	textList = textProcessing(text)
	#其它业务逻辑，比方说再次请求
 
	#可选，用于debug
	print(text)
	return text
 
def textProcessing(text):
	#在这里放置你要的文本处理逻辑
	textList = list(map(str,text.split("\n")))
	return textList
 
if __name__=="__main__":
	#使用 requests.session()保存登录状态
	session = requests.session()
	#放入你要请求的网站
	url="http://127.0.0.1:80"
	#放入你要请求的post数据
	postData= {
		"data" : "flag",
		"str" : "1145"
	}
	#使用函数
	getStr(session,url,postData)
```

下面详解一下文本处理

1.匹配标签

