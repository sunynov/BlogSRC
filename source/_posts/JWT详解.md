---
title: JWT详解
date: 2025-12-29 20:26:02
tags:
index_img: https://gitee.com/bobrocket/img/raw/master/img/image-20260304215722498.png
categories: CTF
---

### 参考知识

[JWT基础知识](https://www.wolai.com/ctfhub/hcFRbVUSwDUD1UTrPJbkob)

[JWT CTF实战](https://www.cnblogs.com/xinghaihe/p/19083689)

### [PCTF] Jwt_password_manager

 题目提示仪表盘支持jwt认证，代码发现提示flag在admin用户中

先注册一个普通用户拿到token，再结合secret_key修改权限

![](https://pic1.imgdb.cn/item/69586e0f912e73dbe6128973.png)

修改token拿到flag

![](https://pic1.imgdb.cn/item/69586e23912e73dbe6128977.png)

### [BaseCTF2024] NO JWT 

首先审计代码，发现/login和/flag路径

打开/flag发现要校验身份，那就先去/login获取令牌，根据提示随便传入一个json

![](https://pic1.imgdb.cn/item/69587856912e73dbe6128c46.png)

代码中没有secret_key，但是在后面也没有校验签名，所以采用none攻击

![](https://pic1.imgdb.cn/item/6958783c912e73dbe6128c0f.png)

### [CTFshow] 抽老婆

下载图片发现download后门

![](https://pic1.imgdb.cn/item/6958b179da3df73ea1bbfd4e.png)

仔细观察发现是python flask框架，尝试下载app.py，成功

审计代码发现/secret_path_U_never_know路径，但是还需要绕过身份验证

只需要让session中的isadmin为真就可，这个用的是JWT方式认证，将isadmin的值更改后，使用密钥SECRET_KEY重新加密生成一个session。

![](https://pic1.imgdb.cn/item/6958b210da3df73ea1bbfe7b.png)

使用hackbar传入即可

### [CTFHub]弱签名

如果JWT采用对称加密算法，并且密钥的强度较弱的话，我们可以直接通过蛮力攻击方式来破解密钥

[快速安装 c-jwt-cracker](https://www.cnblogs.com/litluo/p/c-jwt-cracker.html)

![](https://pic1.imgdb.cn/item/695a32c4bee82fbf891bf50f.png)

由此我们便得到了密钥hnqx



### 补充

1.如何判断签名校验

在Jwt_password_manager中，有一个校验签名的函数，并且在用户名赋值时调用了校验函数

![](https://pic1.imgdb.cn/item/695a2ed9bee82fbf891bf308.png)

但是在no_jwt中不进行签名验证和过期验证，仅对 JWT 令牌进行解码

![](https://pic1.imgdb.cn/item/695a2fccbee82fbf891bf386.png)

因此可以使用none攻击

2.如何判断网站是python写的

- 查看请求头的server信息
- 看网站后缀名
