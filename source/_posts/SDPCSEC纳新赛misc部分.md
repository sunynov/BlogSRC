---
title: SDPCSEC纳新赛misc部分
date: 2026-06-28 20:04:50
tags:
---

最近刚放假，先学点简单的东西，把基础的misc、cry和re学学

# 热身赛

## Saber

附件名称是LSB.png 也就是PNG中的LSB隐写

[PNG - CTF Wiki](https://ctf-wiki.org/misc/picture/png/)

我们用stegsolve分析一下

![image-20260628211902654](https://gitee.com/bobrocket/img/raw/master/image-20260628211902654.png)

这三个通道左上角有异常，分析可以提取出flag

```
sdpcsec{saber_say_Excalibur!!!}
```

## ez_zip

flag.zip被损坏了，用010看一下

![image-20260629104020020](https://gitee.com/bobrocket/img/raw/master/image-20260629104020020.png)

发现文件头缺了504B03,直接补上

![image-20260629104238276](https://gitee.com/bobrocket/img/raw/master/image-20260629104238276.png)

再次打开提示需要密码，看一下zip的本地文件头签名，14000900伪加密，直接用winrar修复即可![flag](https://gitee.com/bobrocket/img/raw/master/flag.jpg)

## 从零开始的异世界生活

零宽隐写，用默认的方式就能解密

![image-20260629113505499](https://gitee.com/bobrocket/img/raw/master/image-20260629113505499.png)

## 天选办公牛马

office文件本质上是一个zip文件，直接把后缀名改成zip即可

## baby_zip

提示：据说flag的密码是由二进制使用的两个数字组成的，有九位

使用掩码攻击

![image-20260629135432564](https://gitee.com/bobrocket/img/raw/master/image-20260629135432564.png)

## 头脑风暴

随波逐流一把梭

![image-20260629142340210](https://gitee.com/bobrocket/img/raw/master/image-20260629142340210.png)

## Arnold_image

从题目名称来看，应该是猫脸变换。用BrainFuck解密hint，提示35次变换，写一个脚本

```python
from pathlib import Path

from PIL import Image

try:
    from pyzbar.pyzbar import decode as zbar_decode
except Exception:
    zbar_decode = None


SRC = Path(r"C:\Users\sun\Desktop\杂\task\enc1 (1).png")
ROUNDS = 35


def transform_once(img: Image.Image, matrix: tuple[int, int, int, int]) -> Image.Image:
    n = img.size[0]
    src = img.load()
    out = Image.new("RGB", (n, n))
    dst = out.load()
    a, b, c, d = matrix
    for x in range(n):
        for y in range(n):
            nx = (a * x + b * y) % n
            ny = (c * x + d * y) % n
            dst[nx, ny] = src[x, y]
    return out


def run_variant(name: str, forward: tuple[int, int, int, int], inverse: tuple[int, int, int, int]) -> None:
    img = Image.open(SRC).convert("RGB")
    cur = img
    for _ in range(ROUNDS):
        cur = transform_once(cur, inverse)
    out = SRC.with_name(f"{name}_reverse_{ROUNDS}.png")
    cur.save(out)
    print(out)


def main() -> None:
    # Common cat-map variants seen in CTF image scramblers.
    variants = {
        "classic": ((1, 1, 1, 2), (2, -1, -1, 1)),
        "swap": ((2, 1, 1, 1), (1, -1, -1, 2)),
    }
    for name, (forward, inverse) in variants.items():
        run_variant(name, forward, inverse)

    targets = [SRC] + [SRC.with_name(f"{name}_reverse_{ROUNDS}.png") for name in variants]
    for path in targets:
        img = Image.open(path).convert("L")
        hist = img.histogram()
        lo = next(i for i, v in enumerate(hist) if v)
        hi = max(i for i, v in enumerate(hist) if v)
        print(f"{path.name}: size={img.size} gray=[{lo},{hi}] bins={sum(1 for v in hist if v)}")
        if zbar_decode:
            decoded = [item.data.decode("utf-8", "ignore") for item in zbar_decode(img)]
            print(f"{path.name}: zbar={decoded}")


if __name__ == "__main__":
    main()
```



# 第一次纳新

## Deadman

将⾳频⽂件放⼊ Audacity 查看频谱图即可看到 flag

![image-20260629181903243](https://gitee.com/bobrocket/img/raw/master/image-20260629181903243.png)

## cat cat cat 

附件的图⽚ foremost 分离⽂件可以得到两张图

![image-20260629223208753](https://gitee.com/bobrocket/img/raw/master/image-20260629223208753.png)

根据题目名称或者观察图片特征可以判断是猫脸变换，在原图的EXIF里面写了a和b都在10-15之间，直接暴力破解即可

![decoded_c2_a14_b12](https://gitee.com/bobrocket/img/raw/master/decoded_c2_a14_b12.png)

## 好想吃炸鸡

附件没有文件类型，先用010看看

注意到文件头是8A514F48而png的文件头是89504E47，正好是PNG文件头+1，然后题目提示里有说今天加一元换购小礼品，用010的运算工具对整个文件进行十六进制减一运算，得到一个PNG

后面是宽高隐写，拖到随波逐流可以一把梭，这里讲解一下如何手搓

首先用stegsolve打开

![image-20260630091328968](https://gitee.com/bobrocket/img/raw/master/image-20260630091328968.png)



发现CRC32值与实际不符，是宽高隐写，用脚本计算一下正常的宽高

```python
import os
import binascii
import struct

crcbp = open("FriedChicken.png", "rb").read()    #打开图片
for i in range(2000):
    for j in range(2000):
        data = crcbp[12:16] + \
            struct.pack('>i', i)+struct.pack('>i', j)+crcbp[24:29]
        crc32 = binascii.crc32(data) & 0xffffffff
        if(crc32 == 0xf4cbf11a):    #图片当前CRC
            print(i, j)
            print('hex:', hex(i), hex(j))
```

hex: 0x12c 0x15f

![image-20260630091748277](https://gitee.com/bobrocket/img/raw/master/image-20260630091748277.png)

在010里面对应这两个值，直接修改即可

![Fried-修复高宽](https://gitee.com/bobrocket/img/raw/master/Fried-修复高宽.png)

## 人类联合之高塔

附加有一个图片和一个被加密的压缩包，图片的EXIF信息里写了key:amiya，用010看一下图片发现后面有文字和很多空格和制表符，是SNOW隐写，把后面的部分提取到txt，然后解密

![image-20260630103650811](https://gitee.com/bobrocket/img/raw/master/image-20260630103650811.png)

用这个密码解密压缩包，得到一个图片，图片内容暗示里面有文件

binwalk一下发现图片后面还有文件，提取出来一个压缩包

![image-20260630103850639](https://gitee.com/bobrocket/img/raw/master/image-20260630103850639.png)

解压之后是两个压缩包

![image-20260630103935595](https://gitee.com/bobrocket/img/raw/master/image-20260630103935595.png)

⽽且 Sarkaz.zip 中的图⽚和另⼀个压缩包中的图⽚的 CRC32 值是⼀样的

![image-20260630103955795](https://gitee.com/bobrocket/img/raw/master/image-20260630103955795.png)

直接明文攻击就出来了
