---
title: CTFSHOW-2026元旦跨年欢乐赛
date: 2026-01-08 10:52:59
tags:
index_img: https://gitee.com/bobrocket/img/raw/master/img/696107bb14866864fecd3f3a.png
categories: CTF
---

## happy2026

```php
<?php
error_reporting(0);
highlight_file(__FILE__);


$happy = $_GET['happy'];
$new = $_GET['new'];
$year = $_GET['year'];

if($year==2026 && $year!==2026 && is_numeric($year)){
    include $happy[$new[$year]];
}

```

利用php弱类型和数组嵌套

![](https://pic1.imgdb.cn/item/695f66f4f6739df2e0ce1e03.png)

## SafePassword

```
$expected = getExpectedHash($channelKey);
md5($accessKey) == $expected //校验机制
```

那么$expected是否可控？

```php
function buildExpectedHash($channelKey): string
{
    try{
        if (!preg_match('/[\x00-\x08\x0B\x0C\x0E-\x1F]/', $channelKey) && strlen($channelKey) < 64) {
            return md5('ctfshow:' . $channelKey . ':verify' . $secret_salt);
        }else{
            throw new RuntimeException('', LENGTH_ERROR);
        }
    }catch(Throwable $e){
        throw new RuntimeException('', VERIFY_FAILED);
    }
       
}
function pickErrorCode(Throwable $e): int
{
    $code = (int)$e->getCode();
    if (inErrorCodes($code)) {
        return $code;
    }
    $idx = abs((int)crc32(get_class($e) . '|' . $e->getMessage())) % count(ERROR_CODES);
    return ERROR_CODES[$idx];
}

function getExpectedHash($channelKey)
{
    try {
        return buildExpectedHash($channelKey);
    } catch (Throwable $e) {
        return pickErrorCode($e);
    }
}
```

通过传入channelKey可以触发异常抛出，使$expected=2025

校验进行弱比较，构造一个$accessKey md5后是2025+字母的即可

简单爆破

```php
<?php
// 目标：md5(accessKey) 前4位 = 2025
$targetPrefix = "2025";
$accessKey = "";
$found = false;

// 从0开始枚举，直到找到符合条件的字符串
for ($i = 0; $i < 1000000; $i++) {
    $testKey = (string)$i;
    $hash = md5($testKey);
    if (substr($hash, 0, 4) === $targetPrefix) {
        $accessKey = $testKey;
        $found = true;
        break;
    }
}

if ($found) {
    echo "找到符合条件的accessKey：{$accessKey}\n";
    echo "其MD5值：" . md5($accessKey) . "\n";
} else {
    echo "未找到（可扩大枚举范围）\n";
}
```

找到了434048

不过这个爆破只找了数字的，局限性比较大，wp里面的更全面一些

![](https://pic1.imgdb.cn/item/695fb0c83379dd736939a923.png)

### 补充——PHP异常抛出

[PHP异常处理](https://www.runoob.com/php/php-exception.html)

Throwable对象$e的用法

```php
try {
    // 可能出错的代码
    throw new RuntimeException("连接失败", 1001);
} catch (Throwable $e) {
    // 常见用法：
    echo "错误消息: " . $e->getMessage();       // "连接失败"
    echo "错误码: " . $e->getCode();            // 1001
    echo "文件: " . $e->getFile();              // /path/to/file.php
    echo "行号: " . $e->getLine();              // 抛出异常的那一行
    echo "堆栈:\n" . $e->getTraceAsString();   // 完整调用栈
}
```

## SafeLock

有点难，我看了wp，只能简单写一下思路，全自动的python脚本目前我还写不出来:(

![](https://pic1.imgdb.cn/item/6960bf8914866864fecc477b.png)

首先观察日志

- BOOT 锁联网上线
- 开始初始化
- 使用出厂密钥和默认salt为123456 设置管理员卡
- 使用一次后就过期
- SALT更新为随机8位数字

主要攻击线路

拉闸->迫使锁用电池->每次验证掉5%的电->电池掉光电->锁完全进入离线状态->恢复供电->开始初始化salt为123456->给自己刷管理员卡->开门禁系统

。。。。。。

回宿舍的时候我突然想到，虽然全自动的我不会写，但可以结合手动啊！

先访问/api/challenge获取nonce

去/api/power关电源

![](https://pic1.imgdb.cn/item/6960ee3914866864fecd0bcd.png)

去/api/verify请求20次用完电量

![](https://pic1.imgdb.cn/item/6960ee9814866864fecd0bf6.png)

再打开电源成功进入工厂模式

获取新的nonce，写一个小脚本计算CRC16签名

```python
from __future__ import annotations

DEVICE_ID = "LOCK-X36D"
FACTORY_SALT = "123456"
ROLE = "admin"

def crc16_ccitt_false(data: bytes) -> int:
    crc = 0xFFFF
    for b in data:
        crc ^= (b << 8)
        for _ in range(8):
            if crc & 0x8000:
                crc = ((crc << 1) ^ 0x1021) & 0xFFFF
            else:
                crc = (crc << 1) & 0xFFFF
    return crc & 0xFFFF

def calc_sig(device_id: str, nonce: str, salt: str, role: str) -> str:
    msg = f"{device_id}|{nonce}|{salt}|{role}".encode("utf-8")
    return f"{crc16_ccitt_false(msg):04X}"

def main():
    nonce=input("nonce:")
    sig = calc_sig(DEVICE_ID, nonce, FACTORY_SALT, ROLE)
    print(sig)

if __name__ == "__main__":
    raise SystemExit(main())
```

验证签名，成功！！！

![](https://pic1.imgdb.cn/item/6960eef814866864fecd0c1f.png)

### 补充——前端操作为什么不能实现？

我一开始想的是直接在前端操作，这样更方便，但是前端每次刷卡消耗1%的电量（上面写的每次消耗5%）,而且burp拦截发现关闭打开电源并不会向/api/power发送请求，校验签名的response里电量一直是100%，当然也无法进入工厂模式

![](https://pic1.imgdb.cn/item/6960efb914866864fecd0c54.png)

用ai分析了一下页面源代码

---

#### 🔍 详细分析

1️⃣ **电量消耗逻辑在前端被硬编码为 1%**

看这段关键代码：
```js
function batteryDrainOnce() {
  const mode = getPowerMode();
  if (mode !== "BATTERY") return;

  state.battery = Math.max(0, state.battery - 1); // ⚠️ 这里固定减 1！
  logLine("meta", `BATTERY → ${state.battery}%`);

  if (state.battery <= 0) {
    state.powered = false;
    logLine("bad", "BATTERY DEPLETED: device shutdown");
    logLine("warn", "HINT: restore mains power to reboot device");
  }
}
```

- **无论后端 API 实际扣多少，前端 UI 每次只模拟 -1%**
- 这个 `batteryDrainOnce()` 是在 `verifySwipe()` 中调用的：
  ```js
  async function verifySwipe() {
    // ...
    batteryDrainOnce(); // ← 前端自己扣 1%
    // ...
    // 然后再去调用 /api/verify
  }
  ```

> 📌 所以前端显示的电量变化 **和后端真实状态无关**！它只是本地模拟。

---

2️⃣ **恢复供电时，前端自动充满电，但不会触发 FACTORY_RESET**

看断电/上电逻辑：
```js
function setMains(on) {
  const prev = state.mains_on;
  state.mains_on = !!on;

  if (!prev && state.mains_on) {
    state.battery = 100; // ⚠️ 直接设为 100%
    state.powered = true;
    logLine("meta", "POWER RESTORED (MAINS)");
    logLine("meta", "BATTERY CHARGED → 100% (policy)");
  }
  // ... 其他逻辑
}
```

- **前端在恢复主电源时，直接把 `battery = 100`**
- **完全没有检查“是否是因为电量耗尽才离线”**
- 因此 **永远不会触发 `FACTORY_RESET_OK` 事件**

> 💥 而后端的真实逻辑是：
> - 只有当设备 **因电池=0 而 powered=false**，
> - 再收到 `mains_on=true`，
> - 才会触发工厂重置，并重置 salt 为 `123456`

但前端完全忽略了这个条件！

---

3️⃣ **前端调用了 `/api/verify`，但没处理关键响应字段**

虽然前端确实发了请求到 `/api/verify`，但它**只关心 `ok` 和 `flag`**，忽略了：
- `state.battery`（后端真实电量）
- `state.powered`
- `events`（比如 `["FACTORY_RESET_OK"]`）
- `rotate_nonce`

前端始终用自己的 `state.battery` 显示，而不是用 API 返回的值！

例如：
```js
const data = await r.json();
// ... 但没更新 state.battery = data.state?.battery
```

所以即使后端已经把电量扣到 0，前端 UI 仍可能显示 80%（因为它是按 1% 扣的）。

---

4️⃣ **出题人的意图：引导你绕过前端**

前端日志中其实有提示：
```js
logLine("meta", "NOTE: verification runs on server-side (salt not available on client)");
logLine("warn", "HINT: after mains cut, device may enter battery mode; repeated attempts drain battery");
```

但**前端故意弱化了耗电效果**，让你以为“刷 100 次就行”，实际上：
- 后端每次扣 5%，20 次就关机
- 前端要刷 100 次才显示关机，但此时后端早就关机了
- 而且前端恢复电源时直接满电，**跳过了重置条件**

> 🎯 所以正确做法是：**不要用前端 UI 操作，直接调用 API**

### 总结

这道题不看wp很难做出来

- 分析js代码找到前后端验证机制区别
- 找到隐藏的/api/power
- 根据json分析出CRC16签名
- 管理员卡
