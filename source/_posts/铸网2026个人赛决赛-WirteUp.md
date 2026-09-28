---
title: "铸网2026个人赛决赛-WirteUp"
date: 2026-09-12 13:50:45
tags:
theme: default
themeName: "默认主题"
---

# 前言

Misc和Re的解比较多，Web、Pwn零解，两大方向成为牢房雅座。

第一次打线下CTF，解出了Misc的分析文档和Re的签到，剩下两个Misc也比较简单可惜我不太熟悉流量分析和图片隐写很遗憾没有做出来。

# Misc

## 图来

题目提示stegseek字典爆破，可惜我不是学misc的，没有这个工具

![image-20260911111020765](https://gitee.com/bobrocket/img/raw/master/image-20260911111020765.png)

## 分析文档

一开始零解，后来给出了提示:提取自定义元数据中的 key、IV 与 Base64 密文

用WinRAR打开docx能找到一个名为flag的文件，内容是Base64密文，全局搜索key关键词能找到AES解密需要的key和IV

![image-20260910105842210](https://gitee.com/bobrocket/img/raw/master/image-20260910105842210.png)

## 这是DNS吗

题目不难，可惜我是流量分析小白

查看dns流量，发现查询的域名是flagxxxx.epta.org.cn、da.epta.org.cn、di.epta.org.cn、null.epta.org.cn

![image-20260911140831455](https://gitee.com/bobrocket/img/raw/master/image-20260911140831455.png)

结合提示DNS子域名隐藏信息，摩斯电码可知，flagxxx是干扰项，di、da代表摩斯电码，null相当于分隔符

```
dns.qry.name contains epta.org.cn and not dns.qry.name contains flag
```

排除干扰项，写出摩斯电码并解密。不知道为什么CyberChef一直转圈解不出来。

![image-20260911141400793](https://gitee.com/bobrocket/img/raw/master/image-20260911141400793.png)

# Reverse

## ez_re

签到题

![image-20260911105842446](https://gitee.com/bobrocket/img/raw/master/image-20260911105842446.png)

```python 
anw = [
    0x11, 0x04, 0x0E, 0x14, 0x02, 0x3D, 0x30, 0x24, 0x21, 0x33, 
    0x37, 0x21, 0x26, 0x1E, 0x1B, 0x30, 0x16, 0x18, 0x1C, 0x0C
]

key_str = "whosyourdaddy"
key = [ord(c) for c in key_str]

flag = ""
# 根据代码循环次数 i 从 0 到 19 进行解密
for i in range(20):
    # 核心逻辑：s[i] = anw[i] ^ key[i % 13]
    char_code = anw[i] ^ key[i % 13]
    flag += chr(char_code)

print("Final Flag is:", flag)
```

