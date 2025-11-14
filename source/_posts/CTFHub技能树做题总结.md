---
title: CTFHub技能树做题总结
date: 2025-11-08 21:59:32
tags:
index_img: https://pic1.imgdb.cn/item/690c233e3203f7be00db6444.png
categories: CTF
---

# WEB

## 信息泄露

### 备份文件下载

#### 网页源码
常见的网站源码备份文件后缀
    tar
    tar.gz
    zip
    rar
常见的网站源码备份文件名
    web
    website
    backup
    back
    www
    wwwroot
    temp

#### vim缓存
vim异常退出后，会存储临时文件，如下三种
如编辑 index.php
第一次产生意外退出 保存为 .index.php.swp
第二次产生意外退出 保存为 .index.php.swo
第三次产生意外退出 保存为 .index.php.swn

### Git泄露
主要用到GitHack,Git_Extract


