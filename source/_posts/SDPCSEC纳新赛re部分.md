---
title: SDPCSEC纳新赛re部分
date: 2026-08-07 22:56:18
tags:
---

re更加难上手，我尽量写得详细一些

# 热身赛

## ezida

非常简单，用ida打开附件，Shift+F12打开全部字符串列表窗口，搜索SDPCSEC即可

![image-20260807225840010](https://gitee.com/bobrocket/img/raw/master/image-20260807225840010.png)

## ryo ? soyo？ mio？

用ida打开能看到一串可疑的字符

```
U0RQQ1NFQ3t3ZWxjb21lX05ld1N0YXJzfQ==
```

直接base64解码即可

```
SDPCSEC{welcome_NewStars}
```

## debugme

题目提示：flag在flag变量里面，在合适的地方下个断点看看 flag变量里面有什么

![image-20260807232733526](https://gitee.com/bobrocket/img/raw/master/image-20260807232733526.png)

我们直接在这里F2下一个断点，F9运行程序，然后随便输一个32字符的字符串

![image-20260807232952579](https://gitee.com/bobrocket/img/raw/master/image-20260807232952579.png)

## 不会吧，直接给class文件还不会做吗

用IDEA反编译.class文件

```java
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Scanner;

public class xor3 {
    private static final byte[] TARGET = new byte[]{17, 6, 18, 1, 25, 16, 7, 18, 21, 12, 18, 21, 12, 18, 21, 12, 31};

    public static void hello() {
        System.out.println("Hello, can you reverse it too");
    }

    public static void main(String[] var0) {
        hello();
        System.out.println("please enter your flag");
        Scanner var1 = new Scanner(System.in); //接受键盘输入
        String var2 = var1.nextLine(); //获取第一行的内容
        var1.close();
        byte[] var3 = var2.getBytes(StandardCharsets.ISO_8859_1); //转换成字节数组
        byte[] var4 = new byte[var3.length];

        for(int var5 = 0; var5 < var3.length; ++var5) {
            var4[var5] = (byte)(var3[var5] ^ 98); //进行异或加密
        }

        System.out.print("your xor result is:[");

        for(int var6 = 0; var6 < var4.length; ++var6) {
            if (var6 > 0) {
                System.out.print("");
            }

            System.out.printf("%d", var4[var6] & 255);
        }

        System.out.println("]");
        if (Arrays.equals(var4, TARGET)) {
            System.out.println("Congratulations! You have successfully solved the challenge");
        } else {
            System.out.println("Sorry, you have failed the challenge");
        }

    }
}
```

捋清楚逻辑了我们直接解密即可

```python
a=[17, 6, 18, 1, 25, 16, 7, 18, 21, 12, 18, 21, 12, 18, 21, 12,31]
for i in a:
	print(chr(i^98),end="")
```

## 真的是一点包装都没有的原始版的rc4

ida反编译

![image-20260808172608488](https://gitee.com/bobrocket/img/raw/master/image-20260808172608488.png)

这里找到了密文和密钥，按小端存储，从低地址到高地址，所以我们从右往左换源密文

在rc4函数中我们也看到了加密逻辑，所以我们直接写出加密脚本。（RC4是对称加密，加密即解密）

```python
def rc4_m(data, key):
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]

    i = j = 0
    out = []
    for k in range(len(data)):
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        ks = S[S[(S[i] + S[j]) % 256]]   # 魔改 RC4：双重查表
        out.append(data[k] ^ ks)
    return bytes(out)

# 从反汇编还原的 21 字节密文（小端序拼回）
data = bytes([
    0x8A, 0x91, 0xCF, 0x95, 0x3F, 0x69, 0x66, 0xB9,
    0xEF, 0x48, 0xCB, 0xDA, 0xD9, 0x96, 0x67, 0x63,
    0x7C, 0xB7, 0x81, 0xBF, 0x7B
])
key = b'mysecret'

flag = rc4_m(data, key)
print(flag.decode()) 
```

## base64，只不过换了一个表，没有任何包装，这个总能做了吧

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  int flag_len; // [rsp+4h] [rbp-2Ch]
  char *encoded; // [rsp+8h] [rbp-28h]
  char flag[24]; // [rsp+10h] [rbp-20h] BYREF
  unsigned __int64 v7; // [rsp+28h] [rbp-8h]

  v7 = __readfsqword(0x28u);
  read(0, flag, 0x15u);
  flag_len = strlen(flag);
  encoded = (char *)malloc(4 * flag_len / 3 + 4);
  if ( encoded )
  {
    base64_custom_encode((const unsigned __int8 *)flag, flag_len, encoded);
    if ( !strcmp(encoded, "zNoHvOEJwug8z9sH0NQH0NQH0NQU") )
      puts("success");
    else
      puts("fail");
    free(encoded);
    return 0;
  }
  else
  {
    fwrite("malloc failed\n", 1u, 0xEu, stderr);
    return 1;
  }
}
```

这里看到了密文和加密函数，我们跟进一下base64_custom_encode函数

题目提示了是base64换表，果然我们在函数里面看到一个custom_b64_table，双击我们得到了表

```
XYZabcdefghijklmnopqrstuvwxyz0123456789+/ABCDEFGHIJKLMNOPQRSTUVW
```

找到一个解密网站

[在线自定义base64编解码、在线二进制转可打印字符、在线base2、base4、base8、base16、base32、base64--查错网](http://web.chacuo.net/netbasex)

![image-20260808173503330](https://gitee.com/bobrocket/img/raw/master/image-20260808173503330.png)

## ^ 是什么意思

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  FILE *v3; // rax
  __int64 Buf1; // [rsp+20h] [rbp-50h] BYREF
  __int64 v6; // [rsp+28h] [rbp-48h]
  int v7; // [rsp+30h] [rbp-40h]
  __int16 v8; // [rsp+34h] [rbp-3Ch]
  char Buffer[8]; // [rsp+40h] [rbp-30h] BYREF
  __int64 v10; // [rsp+48h] [rbp-28h]
  __int64 v11; // [rsp+50h] [rbp-20h]
  int v12; // [rsp+58h] [rbp-18h]
  __int16 v13; // [rsp+5Ch] [rbp-14h]
  int v14; // [rsp+6Ch] [rbp-4h]

  _main();
  *(_QWORD *)Buffer = 0;
  v10 = 0;
  v11 = 0;
  v12 = 0;
  v13 = 0;
  Buf1 = 0;
  v6 = 0;
  v7 = 0;
  v8 = 0;
  printf_0("Please input the flag: ");
  v3 = __iob_func();
  fgets_0(Buffer, 30, v3);
  v14 = strlen(Buffer);
  if ( v14 > 0 && Buffer[v14 - 1] == 10 )
    Buffer[--v14] = 0;
  if ( v14 == 22 )
  {
    Buf1 = *(_QWORD *)Buffer;
    v6 = v10;
    v7 = v11;
    v8 = WORD2(v11);
    xor_encrypt(&Buf1, 22, "xor_key"); //异或加密
    if ( !memcmp_0(&Buf1, &CORRECT_CIPHER, 0x16u) ) //加密后的字符串与正确的进行比较
      puts_0(" Correct! Congratulations!");
    else
      puts_0("Result: Wrong! (Cipher mismatch)");
  }
  else
  {
    puts_0("Wrong! ");
  }
  system_0("pause");
  return 0;
}
```

我们先提取一下加密后的字符串

```
2B2B221C38203A030A136D5C3A01481D2D370A0D1805
```

再来看一下加密逻辑，是异或加密直接用工具解密即可

![image-20260808191804479](https://gitee.com/bobrocket/img/raw/master/image-20260808191804479.png)

也可以写脚本

```python
encrypted_hex = "2B2B221C38203A030A136D5C3A01481D2D370A0D1805"
ciphertext_bytes = bytes.fromhex(encrypted_hex)  ##将16进制转换为字节对象
print(f"密文字节数: {len(ciphertext_bytes)}")
key = "xor_key"
decrypted_bytes = []
for i in range(len(ciphertext_bytes)):
    key_char = key[i % len(key)]
    decrypted_byte = ciphertext_bytes[i] ^ ord(key_char)
    decrypted_bytes.append(decrypted_byte)
print("\n解密后的字节列表:", decrypted_bytes)
print("最终解密的flag:", end="")
for byte in decrypted_bytes:
    print(chr(byte), end="")
```

## upx

放到Exeinfo PE看一眼加壳

![image-20260808192300565](https://gitee.com/bobrocket/img/raw/master/image-20260808192300565.png)

使用kali自带的upx脱壳工具

```
upx -d  upx
```

依旧是异或加密，我们跟进一下比较函数

```c
_BOOL8 __fastcall validate_input(const char *a1)
{
  char s2[56]; // [rsp+10h] [rbp-40h] BYREF
  unsigned __int64 v3; // [rsp+48h] [rbp-8h]

  v3 = __readfsqword(0x28u); //防止栈溢出，和业务逻辑无关
  decrypt_flag(s2); //把解密后的 flag 输出写到 s2 缓冲区
  return strcmp(a1, s2) == 0;
}
```

继续跟进decrypt_flag

```c
__int64 __fastcall decrypt_flag(__int64 a1)
{
  __int64 result; // rax
  int i; // [rsp+10h] [rbp-8h]

  for ( i = 0; ; ++i )
  {
    result = encrypted_flag[i];
    if ( !(_BYTE)result )
      break;
    *(_BYTE *)(i + a1) = xor_key[i % 14] ^ encrypted_flag[i];
  }
  return result;
}
```

果然，encrypted_flag里面就是密文，和上题一样解密即可

## aes，用的库封装，逸最简单的一集

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  int i; // [rsp+Ch] [rbp-144h]
  AES_KEY aes_key; // [rsp+20h] [rbp-130h] BYREF
  char buf[16]; // [rsp+120h] [rbp-30h] BYREF
  char ciphertext[24]; // [rsp+130h] [rbp-20h] BYREF
  unsigned __int64 v8; // [rsp+148h] [rbp-8h]

  v8 = __readfsqword(0x28u);
  read(0, buf, 0x10u);
  if ( strlen("sdpc_key_123456_") == 16 )
  {
    AES_set_encrypt_key("sdpc_key_123456_", 128, &aes_key);
    AES_encrypt(buf, ciphertext, &aes_key);
    printf("Ciphertext: ");
    for ( i = 0; i <= 15; ++i )
      printf("%02x", (unsigned __int8)ciphertext[i]);
    putchar(10);
    if ( !strcmp(ciphertext, "ae2f680621fb34d6a8ee7019069ded5e") )
      puts("fail");
    else
      puts("success");
    return 0;
  }
  else
  {
    fwrite("Key must be 16 bytes\n", 1u, 0x15u, stderr);
    return 1;
  }
}
```

aes加密，`AES_encrypt` / `AES_decrypt` 仅支持 ECB 模式，直接用工具解密即可

![image-20260808213736025](https://gitee.com/bobrocket/img/raw/master/image-20260808213736025.png)

## 逸别卷了，喝一杯茶休息一下

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  size_t n; // rax
  size_t n_1; // rax
  uint32_t dest_[2]; // [rsp+18h] [rbp-28h] BYREF
  uint32_t key[4]; // [rsp+20h] [rbp-20h] BYREF
  char buf[8]; // [rsp+30h] [rbp-10h] BYREF
  unsigned __int64 v9; // [rsp+38h] [rbp-8h]

  v9 = __readfsqword(0x28u);
  read(0, buf, 8u);
  memset(key, 0, sizeof(key));
  n = strlen("sdpc");
  memcpy(key, "sdpc", n);
  *(_QWORD *)dest_ = 0;
  n_1 = strlen(buf);
  memcpy(dest_, buf, n_1);
  tea_encrypt(dest_, key); //加密
  printf("Encrypted: %08x%08x\n", dest_[0], dest_[1]);
  if ( !strcmp((const char *)dest_, " 9dcfccd3088d1064") )
    puts("fail");
  else
    puts("success");
  return 0;
}

```

跟进一下加密函数

```c
void __cdecl tea_encrypt(uint32_t *v, const uint32_t *key)
{
  uint32_t v0; // [rsp+1Ch] [rbp-14h]
  uint32_t v1; // [rsp+20h] [rbp-10h]
  uint32_t sum; // [rsp+24h] [rbp-Ch]
  int i; // [rsp+28h] [rbp-8h]

  v0 = *v;
  v1 = v[1];
  sum = 0;
  for ( i = 0; i <= 31; ++i )
  {
    sum -= 1640531527;
    v0 += (v1 + sum) ^ (16 * v1 + *key) ^ ((v1 >> 5) + key[1]);
    v1 += (v0 + sum) ^ (16 * v0 + key[2]) ^ ((v0 >> 5) + key[3]);
  }
  *v = v0;
  v[1] = v1;
}
```

脚本解密即可

```python
import struct

MASK = 0xFFFFFFFF
DELTA = 0x9E3779B9
ROUNDS = 32


def tea_decrypt_block(v0, v1, key):
    k0, k1, k2, k3 = struct.unpack("<4I", key[:16].ljust(16, b"\x00"))
    s = (DELTA * ROUNDS) & MASK
    for _ in range(ROUNDS):
        v1 = (v1 - ((((v0 << 4) + k2) ^ (v0 + s) ^ ((v0 >> 5) + k3)) & MASK)) & MASK
        v0 = (v0 - ((((v1 << 4) + k0) ^ (v1 + s) ^ ((v1 >> 5) + k1)) & MASK)) & MASK
        s = (s - DELTA) & MASK
    return v0, v1


def tea_decrypt(data, key):
    out = b""
    for i in range(0, len(data), 16):
        v0 = int(data[i:i + 8], 16)
        v1 = int(data[i + 8:i + 16], 16)
        p0, p1 = tea_decrypt_block(v0, v1, key)
        out += struct.pack("<2I", p0, p1)
    return out


key = b"sdpc"
cipher = "9dcfccd3088d1064"

plain = tea_decrypt(cipher, key)
print("flag:", plain)
```

## 这么多方程我咋解啊

拿到附件发现是python写的exe

先解包拿到.pyc

```undefined
python pyinstxtractor.py solve_flag.exe
```

再反编译，并保存到1.py

```x86asm
pycdc solve_flag.exe_extracted\solve_flag.pyc -o 1.py
```

打开发现确实很多方程，这里使用z3求解

```python
from z3 import *

flag = [Int(f"f{i}") for i in range(36)]
s = Solver()
for i in range(36): s.add(flag[i] >= 32, flag[i] <= 126)

s.add(
    47 * flag[0] + 41 * flag[1] + 32 * flag[2] + 56 * flag[3] + 52 * flag[4] + 67 * flag[5] + 13 * flag[6] + 25 * flag[7] + 20 * flag[8] +
    98 * flag[9] + 88 * flag[10] + 65 * flag[11] + 82 * flag[12] + 92 * flag[13] + 3 * flag[14] + 29 * flag[15] + 93 * flag[16] + 88 * flag[17] +
    45 * flag[18] + 58 * flag[19] + 40 * flag[20] + 72 * flag[21] + 99 * flag[22] + 10 * flag[23] + 94 * flag[24] + 62 * flag[25] + 82 * flag[26] +
    92 * flag[27] + 23 * flag[28] + 46 * flag[29] + 55 * flag[30] + 72 * flag[31] + 44 * flag[32] + 9 * flag[33] + 65 * flag[34] + 42 * flag[35]
    == 176386)

s.add(
    10 * flag[0] + 98 * flag[1] + 5 * flag[2] + 28 * flag[3] + 68 * flag[4] + 20 * flag[5] + 2 * flag[6] + 22 * flag[7] + 65 * flag[8] +
    44 * flag[9] + 85 * flag[10] + 97 * flag[11] + 33 * flag[12] + 74 * flag[13] + 93 * flag[14] + 74 * flag[15] + 41 * flag[16] + 65 * flag[17] +
    32 * flag[18] + 93 * flag[19] + 22 * flag[20] + 69 * flag[21] + 68 * flag[22] + 57 * flag[23] + 47 * flag[24] + 29 * flag[25] + 74 * flag[26] +
    54 * flag[27] + 91 * flag[28] + 90 * flag[29] + 26 * flag[30] + 11 * flag[31] + 89 * flag[32] + 57 * flag[33] + 100 * flag[34] + 95 * flag[35]
    == 186050)

s.add(
    25 * flag[0] + 22 * flag[1] + 54 * flag[2] + 5 * flag[3] + 8 * flag[4] + 3 * flag[5] + 12 * flag[6] + 70 * flag[7] + 25 * flag[8] +
    61 * flag[9] + 68 * flag[10] + 12 * flag[11] + 27 * flag[12] + 42 * flag[13] + 83 * flag[14] + 91 * flag[15] + 67 * flag[16] + 46 * flag[17] +
    8 * flag[18] + 45 * flag[19] + 94 * flag[20] + 80 * flag[21] + 69 * flag[22] + 95 * flag[23] + 12 * flag[24] + 21 * flag[25] + 94 * flag[26] +
    82 * flag[27] + 93 * flag[28] + 41 * flag[29] + 4 * flag[30] + 56 * flag[31] + 92 * flag[32] + 77 * flag[33] + 15 * flag[34] + 30 * flag[35]
    == 154690)

s.add(
    33 * flag[0] + 49 * flag[1] + 56 * flag[2] + 40 * flag[3] + 90 * flag[4] + 59 * flag[5] + 82 * flag[6] + 6 * flag[7] + 81 * flag[8] +
    32 * flag[9] + 23 * flag[10] + 76 * flag[11] + 93 * flag[12] + 83 * flag[13] + 10 * flag[14] + 44 * flag[15] + 58 * flag[16] + 33 * flag[17] +
    79 * flag[18] + 77 * flag[19] + 82 * flag[20] + 56 * flag[21] + 70 * flag[22] + 34 * flag[23] + 45 * flag[24] + 76 * flag[25] + 57 * flag[26] +
    43 * flag[27] + 100 * flag[28] + 19 * flag[29] + 11 * flag[30] + 90 * flag[31] + 3 * flag[32] + 60 * flag[33] + 57 * flag[34] + 23 * flag[35]
    == 172116)

s.add(
    65 * flag[0] + 70 * flag[1] + 20 * flag[2] + 32 * flag[3] + 75 * flag[4] + 30 * flag[5] + 3 * flag[6] + 78 * flag[7] + 35 * flag[8] +
    45 * flag[9] + 95 * flag[10] + 93 * flag[11] + 52 * flag[12] + 32 * flag[13] + 88 * flag[14] + 94 * flag[15] + 67 * flag[16] + 34 * flag[17] +
    91 * flag[18] + 88 * flag[19] + 31 * flag[20] + 61 * flag[21] + 17 * flag[22] + 99 * flag[23] + 100 * flag[24] + 49 * flag[25] + 4 * flag[26] +
    60 * flag[27] + 81 * flag[28] + 88 * flag[29] + 43 * flag[30] + 34 * flag[31] + 30 * flag[32] + 52 * flag[33] + 18 * flag[34] + 100 * flag[35]
    == 190544)

s.add(
    81 * flag[0] + 42 * flag[1] + 28 * flag[2] + 98 * flag[3] + 31 * flag[4] + 46 * flag[5] + 64 * flag[6] + 15 * flag[7] + 49 * flag[8] +
    13 * flag[9] + 100 * flag[10] + 81 * flag[11] + 32 * flag[12] + 52 * flag[13] + 59 * flag[14] + 24 * flag[15] + 94 * flag[16] + 32 * flag[17] +
    93 * flag[18] + 32 * flag[19] + 13 * flag[20] + 89 * flag[21] + 37 * flag[22] + 30 * flag[23] + 78 * flag[24] + 81 * flag[25] + 9 * flag[26] +
    45 * flag[27] + 93 * flag[28] + 100 * flag[29] + 97 * flag[30] + 10 * flag[31] + 80 * flag[32] + 54 * flag[33] + 88 * flag[34] + 85 * flag[35]
    == 190323)

s.add(
    76 * flag[0] + 54 * flag[1] + 5 * flag[2] + 14 * flag[3] + 62 * flag[4] + 44 * flag[5] + 24 * flag[6] + 29 * flag[7] + 85 * flag[8] +
    87 * flag[9] + 19 * flag[10] + 3 * flag[11] + 65 * flag[12] + 24 * flag[13] + 92 * flag[14] + 37 * flag[15] + 57 * flag[16] + 20 * flag[17] +
    45 * flag[18] + 5 * flag[19] + 13 * flag[20] + 91 * flag[21] + 92 * flag[22] + 75 * flag[23] + 36 * flag[24] + 79 * flag[25] + 12 * flag[26] +
    22 * flag[27] + 75 * flag[28] + 82 * flag[29] + 28 * flag[30] + 82 * flag[31] + 24 * flag[32] + 53 * flag[33] + 56 * flag[34] + 92 * flag[35]
    == 162017)

s.add(
    53 * flag[0] + 52 * flag[1] + 72 * flag[2] + 23 * flag[3] + 26 * flag[4] + 13 * flag[5] + 62 * flag[6] + 96 * flag[7] + 67 * flag[8] +
    96 * flag[9] + 66 * flag[10] + 41 * flag[11] + 5 * flag[12] + 18 * flag[13] + 37 * flag[14] + 13 * flag[15] + 61 * flag[16] + 71 * flag[17] +
    91 * flag[18] + 96 * flag[19] + 56 * flag[20] + 3 * flag[21] + 65 * flag[22] + 14 * flag[23] + 57 * flag[24] + 69 * flag[25] + 75 * flag[26] +
    68 * flag[27] + 10 * flag[28] + 60 * flag[29] + 62 * flag[30] + 95 * flag[31] + 53 * flag[32] + 19 * flag[33] + 7 * flag[34] + 56 * flag[35]
    == 165118)

s.add(
    26 * flag[0] + 7 * flag[1] + 49 * flag[2] + 14 * flag[3] + 36 * flag[4] + 87 * flag[5] + 21 * flag[6] + 35 * flag[7] + 15 * flag[8] +
    91 * flag[9] + 15 * flag[10] + 100 * flag[11] + 8 * flag[12] + 32 * flag[13] + 100 * flag[14] + 35 * flag[15] + 66 * flag[16] + 3 * flag[17] +
    79 * flag[18] + 96 * flag[19] + 82 * flag[20] + 95 * flag[21] + 68 * flag[22] + 13 * flag[23] + 86 * flag[24] + 51 * flag[25] + 24 * flag[26] +
    76 * flag[27] + 30 * flag[28] + 60 * flag[29] + 29 * flag[30] + 70 * flag[31] + 40 * flag[32] + 90 * flag[33] + 44 * flag[34] + 3 * flag[35]
    == 153332)

s.add(
    47 * flag[0] + 19 * flag[1] + 37 * flag[2] + 93 * flag[3] + 73 * flag[4] + 30 * flag[5] + 45 * flag[6] + 47 * flag[7] + 72 * flag[8] +
    85 * flag[9] + 37 * flag[10] + 68 * flag[11] + 89 * flag[12] + 34 * flag[13] + 4 * flag[14] + 50 * flag[15] + 87 * flag[16] + 33 * flag[17] +
    87 * flag[18] + 43 * flag[19] + 9 * flag[20] + 61 * flag[21] + 93 * flag[22] + 49 * flag[23] + 74 * flag[24] + 49 * flag[25] + 68 * flag[26] +
    29 * flag[27] + 54 * flag[28] + 54 * flag[29] + 37 * flag[30] + 79 * flag[31] + 33 * flag[32] + 65 * flag[33] + 59 * flag[34] + 15 * flag[35]
    == 168472)

s.add(
    79 * flag[0] + 73 * flag[1] + 60 * flag[2] + 62 * flag[3] + 25 * flag[4] + 16 * flag[5] + 77 * flag[6] + 81 * flag[7] + 79 * flag[8] +
    31 * flag[9] + 82 * flag[10] + 84 * flag[11] + 62 * flag[12] + 36 * flag[13] + 18 * flag[14] + 20 * flag[15] + 46 * flag[16] + 57 * flag[17] +
    21 * flag[18] + 40 * flag[19] + 3 * flag[20] + 50 * flag[21] + 58 * flag[22] + 80 * flag[23] + 84 * flag[24] + 71 * flag[25] + 87 * flag[26] +
    3 * flag[27] + 13 * flag[28] + 77 * flag[29] + 83 * flag[30] + 39 * flag[31] + 55 * flag[32] + 34 * flag[33] + 41 * flag[34] + 63 * flag[35]
    == 178706)

s.add(
    7 * flag[0] + 50 * flag[1] + 26 * flag[2] + 79 * flag[3] + 21 * flag[4] + 42 * flag[5] + 83 * flag[6] + 94 * flag[7] + 63 * flag[8] +
    83 * flag[9] + 3 * flag[10] + 68 * flag[11] + 25 * flag[12] + 91 * flag[13] + 3 * flag[14] + 5 * flag[15] + 17 * flag[16] + 61 * flag[17] +
    3 * flag[18] + 40 * flag[19] + 87 * flag[20] + 11 * flag[21] + 27 * flag[22] + 74 * flag[23] + 73 * flag[24] + 21 * flag[25] + 56 * flag[26] +
    46 * flag[27] + 36 * flag[28] + 24 * flag[29] + 14 * flag[30] + 63 * flag[31] + 21 * flag[32] + 71 * flag[33] + 30 * flag[34] + 53 * flag[35]
    == 143852)

s.add(
    57 * flag[0] + 51 * flag[1] + 49 * flag[2] + 15 * flag[3] + 94 * flag[4] + 34 * flag[5] + 27 * flag[6] + 5 * flag[7] + 100 * flag[8] +
    68 * flag[9] + 67 * flag[10] + 81 * flag[11] + 10 * flag[12] + 5 * flag[13] + 85 * flag[14] + 70 * flag[15] + 80 * flag[16] + 20 * flag[17] +
    89 * flag[18] + 30 * flag[19] + 84 * flag[20] + 35 * flag[21] + 41 * flag[22] + 87 * flag[23] + 75 * flag[24] + 67 * flag[25] + 20 * flag[26] +
    33 * flag[27] + 29 * flag[28] + 6 * flag[29] + 97 * flag[30] + 25 * flag[31] + 10 * flag[32] + 18 * flag[33] + 23 * flag[34] + 30 * flag[35]
    == 154052)

s.add(
    97 * flag[0] + 93 * flag[1] + 10 * flag[2] + 44 * flag[3] + 28 * flag[4] + 22 * flag[5] + 17 * flag[6] + 41 * flag[7] + 47 * flag[8] +
    62 * flag[9] + 42 * flag[10] + 47 * flag[11] + 61 * flag[12] + 32 * flag[13] + 31 * flag[14] + 52 * flag[15] + 47 * flag[16] + 92 * flag[17] +
    42 * flag[18] + 37 * flag[19] + 7 * flag[20] + 40 * flag[21] + 48 * flag[22] + 40 * flag[23] + 11 * flag[24] + 96 * flag[25] + 51 * flag[26] +
    42 * flag[27] + 66 * flag[28] + 8 * flag[29] + 89 * flag[30] + 64 * flag[31] + 30 * flag[32] + 11 * flag[33] + 8 * flag[34] + 83 * flag[35]
    == 147899)

s.add(
    51 * flag[0] + 94 * flag[1] + 58 * flag[2] + 76 * flag[3] + 21 * flag[4] + 10 * flag[5] + 75 * flag[6] + 4 * flag[7] + 55 * flag[8] +
    37 * flag[9] + 71 * flag[10] + 97 * flag[11] + 27 * flag[12] + 93 * flag[13] + 82 * flag[14] + 94 * flag[15] + 38 * flag[16] + 69 * flag[17] +
    36 * flag[18] + 58 * flag[19] + 93 * flag[20] + 18 * flag[21] + 54 * flag[22] + 59 * flag[23] + 12 * flag[24] + 12 * flag[25] + 54 * flag[26] +
    83 * flag[27] + 73 * flag[28] + 83 * flag[29] + 33 * flag[30] + 12 * flag[31] + 78 * flag[32] + 38 * flag[33] + 45 * flag[34] + 57 * flag[35]
    == 176754)

s.add(
    78 * flag[0] + 29 * flag[1] + 8 * flag[2] + 47 * flag[3] + 48 * flag[4] + 88 * flag[5] + 18 * flag[6] + 88 * flag[7] + 50 * flag[8] +
    58 * flag[9] + 36 * flag[10] + 88 * flag[11] + 9 * flag[12] + 74 * flag[13] + 85 * flag[14] + 5 * flag[15] + 91 * flag[16] + 58 * flag[17] +
    85 * flag[18] + 46 * flag[19] + 89 * flag[20] + 76 * flag[21] + 61 * flag[22] + 6 * flag[23] + 61 * flag[24] + 78 * flag[25] + 4 * flag[26] +
    48 * flag[27] + 50 * flag[28] + 69 * flag[29] + 23 * flag[30] + 70 * flag[31] + 23 * flag[32] + 15 * flag[33] + 22 * flag[34] + 68 * flag[35]
    == 171970)

s.add(
    75 * flag[0] + 2 * flag[1] + 94 * flag[2] + 97 * flag[3] + 72 * flag[4] + 62 * flag[5] + 78 * flag[6] + 42 * flag[7] + 69 * flag[8] +
    11 * flag[9] + 37 * flag[10] + 3 * flag[11] + 29 * flag[12] + 15 * flag[13] + 39 * flag[14] + 33 * flag[15] + 18 * flag[16] + 33 * flag[17] +
    12 * flag[18] + 64 * flag[19] + 6 * flag[20] + 18 * flag[21] + 34 * flag[22] + 15 * flag[23] + 3 * flag[24] + 100 * flag[25] + 85 * flag[26] +
    32 * flag[27] + 97 * flag[28] + 93 * flag[29] + 84 * flag[30] + 73 * flag[31] + 26 * flag[32] + 31 * flag[33] + 71 * flag[34] + 97 * flag[35]
    == 166497)

s.add(
    59 * flag[0] + 26 * flag[1] + 48 * flag[2] + 86 * flag[3] + 58 * flag[4] + 70 * flag[5] + 61 * flag[6] + 100 * flag[7] + 63 * flag[8] +
    74 * flag[9] + 26 * flag[10] + 38 * flag[11] + 24 * flag[12] + 45 * flag[13] + 52 * flag[14] + 32 * flag[15] + 91 * flag[16] + 89 * flag[17] +
    19 * flag[18] + 59 * flag[19] + 87 * flag[20] + 5 * flag[21] + 15 * flag[22] + 68 * flag[23] + 72 * flag[24] + 67 * flag[25] + 2 * flag[26] +
    65 * flag[27] + 46 * flag[28] + 10 * flag[29] + 33 * flag[30] + 79 * flag[31] + 11 * flag[32] + 16 * flag[33] + 73 * flag[34] + 53 * flag[35]
    == 173887)

s.add(
    6 * flag[0] + 66 * flag[1] + 59 * flag[2] + 76 * flag[3] + 86 * flag[4] + 20 * flag[5] + 59 * flag[6] + 34 * flag[7] + 28 * flag[8] +
    48 * flag[9] + 86 * flag[10] + 5 * flag[11] + 87 * flag[12] + 13 * flag[13] + 95 * flag[14] + 87 * flag[15] + 65 * flag[16] + 35 * flag[17] +
    58 * flag[18] + 10 * flag[19] + 98 * flag[20] + 100 * flag[21] + 4 * flag[22] + 78 * flag[23] + 66 * flag[24] + 57 * flag[25] + 34 * flag[26] +
    86 * flag[27] + 62 * flag[28] + 36 * flag[29] + 92 * flag[30] + 28 * flag[31] + 3 * flag[32] + 24 * flag[33] + 49 * flag[34] + 28 * flag[35]
    == 173189)

s.add(
    25 * flag[0] + 48 * flag[1] + 44 * flag[2] + 16 * flag[3] + 99 * flag[4] + 100 * flag[5] + 69 * flag[6] + 26 * flag[7] + 65 * flag[8] +
    32 * flag[9] + 18 * flag[10] + 65 * flag[11] + 58 * flag[12] + 72 * flag[13] + 61 * flag[14] + 56 * flag[15] + 10 * flag[16] + 78 * flag[17] +
    93 * flag[18] + 98 * flag[19] + 39 * flag[20] + 43 * flag[21] + 87 * flag[22] + 12 * flag[23] + 42 * flag[24] + 100 * flag[25] + 100 * flag[26] +
    47 * flag[27] + 31 * flag[28] + 51 * flag[29] + 75 * flag[30] + 10 * flag[31] + 63 * flag[32] + 48 * flag[33] + 22 * flag[34] + 87 * flag[35]
    == 174138)

s.add(
    61 * flag[0] + 13 * flag[1] + 100 * flag[2] + 59 * flag[3] + 31 * flag[4] + 9 * flag[5] + 28 * flag[6] + 7 * flag[7] + 27 * flag[8] +
    63 * flag[9] + 11 * flag[10] + 57 * flag[11] + 95 * flag[12] + 79 * flag[13] + 21 * flag[14] + 30 * flag[15] + 60 * flag[16] + 81 * flag[17] +
    43 * flag[18] + 32 * flag[19] + 30 * flag[20] + 34 * flag[21] + 80 * flag[22] + 53 * flag[23] + 28 * flag[24] + 39 * flag[25] + 74 * flag[26] +
    21 * flag[27] + 18 * flag[28] + 92 * flag[29] + 73 * flag[30] + 60 * flag[31] + 21 * flag[32] + 69 * flag[33] + 76 * flag[34] + 84 * flag[35]
    == 157623)

s.add(
    22 * flag[0] + 62 * flag[1] + 61 * flag[2] + 20 * flag[3] + 66 * flag[4] + 2 * flag[5] + 11 * flag[6] + 82 * flag[7] + 93 * flag[8] +
    13 * flag[9] + 69 * flag[10] + 37 * flag[11] + 92 * flag[12] + 80 * flag[13] + 66 * flag[14] + 47 * flag[15] + 28 * flag[16] + 14 * flag[17] +
    62 * flag[18] + 56 * flag[19] + 89 * flag[20] + 29 * flag[21] + 39 * flag[22] + 38 * flag[23] + 46 * flag[24] + 10 * flag[25] + 6 * flag[26] +
    82 * flag[27] + 77 * flag[28] + 78 * flag[29] + 45 * flag[30] + 50 * flag[31] + 5 * flag[32] + 73 * flag[33] + 17 * flag[34] + 65 * flag[35]
    == 154943)

s.add(
    5 * flag[0] + 84 * flag[1] + 83 * flag[2] + 77 * flag[3] + 76 * flag[4] + 60 * flag[5] + 20 * flag[6] + 48 * flag[7] + 53 * flag[8] +
    14 * flag[9] + 98 * flag[10] + 50 * flag[11] + 37 * flag[12] + 15 * flag[13] + 31 * flag[14] + 69 * flag[15] + 55 * flag[16] + 37 * flag[17] +
    64 * flag[18] + 35 * flag[19] + 26 * flag[20] + 20 * flag[21] + 18 * flag[22] + 67 * flag[23] + 50 * flag[24] + 57 * flag[25] + 60 * flag[26] +
    71 * flag[27] + 4 * flag[28] + 35 * flag[29] + 23 * flag[30] + 52 * flag[31] + 11 * flag[32] + 15 * flag[33] + 83 * flag[34] + 51 * flag[35]
    == 156078)

s.add(
    33 * flag[0] + 47 * flag[1] + 89 * flag[2] + 52 * flag[3] + 89 * flag[4] + 55 * flag[5] + 98 * flag[6] + 28 * flag[7] + 48 * flag[8] +
    90 * flag[9] + 69 * flag[10] + 29 * flag[11] + 68 * flag[12] + 24 * flag[13] + 19 * flag[14] + 18 * flag[15] + 44 * flag[16] + 27 * flag[17] +
    14 * flag[18] + 64 * flag[19] + 15 * flag[20] + 31 * flag[21] + 23 * flag[22] + 2 * flag[23] + 36 * flag[24] + 45 * flag[25] + 37 * flag[26] +
    71 * flag[27] + 61 * flag[28] + 92 * flag[29] + 28 * flag[30] + 64 * flag[31] + 13 * flag[32] + 66 * flag[33] + 98 * flag[34] + 3 * flag[35]
    == 156158)

s.add(
    80 * flag[0] + 88 * flag[1] + 68 * flag[2] + 66 * flag[3] + 46 * flag[4] + 75 * flag[5] + 32 * flag[6] + 19 * flag[7] + 36 * flag[8] +
    83 * flag[9] + 63 * flag[10] + 86 * flag[11] + 79 * flag[12] + 30 * flag[13] + 61 * flag[14] + 50 * flag[15] + 100 * flag[16] + 52 * flag[17] +
    66 * flag[18] + 30 * flag[19] + 20 * flag[20] + 97 * flag[21] + 45 * flag[22] + 46 * flag[23] + 38 * flag[24] + 21 * flag[25] + 32 * flag[26] +
    79 * flag[27] + 68 * flag[28] + 43 * flag[29] + 65 * flag[30] + 47 * flag[31] + 86 * flag[32] + 30 * flag[33] + 74 * flag[34] + 18 * flag[35]
    == 181770)

s.add(
    11 * flag[0] + 58 * flag[1] + 95 * flag[2] + 67 * flag[3] + 96 * flag[4] + 74 * flag[5] + 60 * flag[6] + 11 * flag[7] + 21 * flag[8] +
    14 * flag[9] + 100 * flag[10] + 60 * flag[11] + 70 * flag[12] + 92 * flag[13] + 92 * flag[14] + 39 * flag[15] + 43 * flag[16] + 52 * flag[17] +
    5 * flag[18] + 22 * flag[19] + 90 * flag[20] + 70 * flag[21] + 12 * flag[22] + 52 * flag[23] + 36 * flag[24] + 21 * flag[25] + 45 * flag[26] +
    59 * flag[27] + 74 * flag[28] + 46 * flag[29] + 11 * flag[30] + 60 * flag[31] + 8 * flag[32] + 52 * flag[33] + 14 * flag[34] + 77 * flag[35]
    == 173577)

s.add(
    57 * flag[0] + 37 * flag[1] + 94 * flag[2] + 43 * flag[3] + 53 * flag[4] + 55 * flag[5] + 7 * flag[6] + 83 * flag[7] + 91 * flag[8] +
    61 * flag[9] + 86 * flag[10] + 6 * flag[11] + 44 * flag[12] + 87 * flag[13] + 61 * flag[14] + 92 * flag[15] + 24 * flag[16] + 74 * flag[17] +
    100 * flag[18] + 22 * flag[19] + 12 * flag[20] + 68 * flag[21] + 19 * flag[22] + 88 * flag[23] + 81 * flag[24] + 83 * flag[25] + 70 * flag[26] +
    39 * flag[27] + 30 * flag[28] + 82 * flag[29] + 30 * flag[30] + 35 * flag[31] + 55 * flag[32] + 18 * flag[33] + 27 * flag[34] + 80 * flag[35]
    == 180922)

s.add(
    80 * flag[0] + 14 * flag[1] + 5 * flag[2] + 89 * flag[3] + 71 * flag[4] + 82 * flag[5] + 44 * flag[6] + 8 * flag[7] + 33 * flag[8] +
    26 * flag[9] + 77 * flag[10] + 49 * flag[11] + 36 * flag[12] + 90 * flag[13] + 73 * flag[14] + 71 * flag[15] + 66 * flag[16] + 4 * flag[17] +
    37 * flag[18] + 78 * flag[19] + 38 * flag[20] + 18 * flag[21] + 15 * flag[22] + 79 * flag[23] + 6 * flag[24] + 74 * flag[25] + 18 * flag[26] +
    85 * flag[27] + 56 * flag[28] + 53 * flag[29] + 90 * flag[30] + 75 * flag[31] + 52 * flag[32] + 2 * flag[33] + 13 * flag[34] + 54 * flag[35]
    == 158596)

s.add(
    96 * flag[0] + 29 * flag[1] + 37 * flag[2] + 70 * flag[3] + 92 * flag[4] + 80 * flag[5] + 24 * flag[6] + 36 * flag[7] + 32 * flag[8] +
    29 * flag[9] + 78 * flag[10] + 45 * flag[11] + 58 * flag[12] + 55 * flag[13] + 16 * flag[14] + 92 * flag[15] + 71 * flag[16] + 82 * flag[17] +
    86 * flag[18] + 23 * flag[19] + 4 * flag[20] + 58 * flag[21] + 16 * flag[22] + 18 * flag[23] + 38 * flag[24] + 53 * flag[25] + 82 * flag[26] +
    76 * flag[27] + 83 * flag[28] + 73 * flag[29] + 87 * flag[30] + 36 * flag[31] + 61 * flag[32] + 85 * flag[33] + 61 * flag[34] + 69 * flag[35]
    == 181072)

s.add(
    14 * flag[0] + 71 * flag[1] + 53 * flag[2] + 46 * flag[3] + 59 * flag[4] + 53 * flag[5] + 22 * flag[6] + 69 * flag[7] + 67 * flag[8] +
    43 * flag[9] + 23 * flag[10] + 14 * flag[11] + 77 * flag[12] + 95 * flag[13] + 19 * flag[14] + 83 * flag[15] + 79 * flag[16] + 41 * flag[17] +
    12 * flag[18] + 53 * flag[19] + 3 * flag[20] + 4 * flag[21] + 65 * flag[22] + 92 * flag[23] + 64 * flag[24] + 52 * flag[25] + 3 * flag[26] +
    59 * flag[27] + 89 * flag[28] + 75 * flag[29] + 12 * flag[30] + 46 * flag[31] + 61 * flag[32] + 53 * flag[33] + 97 * flag[34] + 43 * flag[35]
    == 163777)

s.add(
    57 * flag[0] + 99 * flag[1] + 49 * flag[2] + 100 * flag[3] + 68 * flag[4] + 99 * flag[5] + 26 * flag[6] + 65 * flag[7] + 47 * flag[8] +
    65 * flag[9] + 90 * flag[10] + 68 * flag[11] + 84 * flag[12] + 4 * flag[13] + 9 * flag[14] + 43 * flag[15] + 88 * flag[16] + 33 * flag[17] +
    48 * flag[18] + 88 * flag[19] + 37 * flag[20] + 31 * flag[21] + 21 * flag[22] + 94 * flag[23] + 22 * flag[24] + 93 * flag[25] + 70 * flag[26] +
    14 * flag[27] + 13 * flag[28] + 28 * flag[29] + 83 * flag[30] + 12 * flag[31] + 80 * flag[32] + 58 * flag[33] + 43 * flag[34] + 97 * flag[35]
    == 187620)

s.add(
    33 * flag[0] + 94 * flag[1] + 56 * flag[2] + 48 * flag[3] + 13 * flag[4] + 44 * flag[5] + 81 * flag[6] + 42 * flag[7] + 19 * flag[8] +
    96 * flag[9] + 67 * flag[10] + 79 * flag[11] + 12 * flag[12] + 67 * flag[13] + 34 * flag[14] + 72 * flag[15] + 45 * flag[16] + 48 * flag[17] +
    24 * flag[18] + 71 * flag[19] + 65 * flag[20] + 13 * flag[21] + 32 * flag[22] + 97 * flag[23] + 48 * flag[24] + 42 * flag[25] + 65 * flag[26] +
    95 * flag[27] + 54 * flag[28] + 9 * flag[29] + 35 * flag[30] + 57 * flag[31] + 18 * flag[32] + 20 * flag[33] + 83 * flag[34] + 76 * flag[35]
    == 169266)

s.add(
    31 * flag[0] + 38 * flag[1] + 83 * flag[2] + 45 * flag[3] + 28 * flag[4] + 97 * flag[5] + 54 * flag[6] + 11 * flag[7] + 80 * flag[8] +
    45 * flag[9] + 92 * flag[10] + 13 * flag[11] + 52 * flag[12] + 94 * flag[13] + 51 * flag[14] + 30 * flag[15] + 11 * flag[16] + 61 * flag[17] +
    46 * flag[18] + 10 * flag[19] + 28 * flag[20] + 72 * flag[21] + 20 * flag[22] + 95 * flag[23] + 90 * flag[24] + 39 * flag[25] + 32 * flag[26] +
    95 * flag[27] + 19 * flag[28] + 3 * flag[29] + 65 * flag[30] + 71 * flag[31] + 73 * flag[32] + 80 * flag[33] + 23 * flag[34] + 71 * flag[35]
    == 162587)

s.add(
    9 * flag[0] + 81 * flag[1] + 80 * flag[2] + 37 * flag[3] + 96 * flag[4] + 72 * flag[5] + 95 * flag[6] + 93 * flag[7] + 26 * flag[8] +
    98 * flag[9] + 50 * flag[10] + 79 * flag[11] + 57 * flag[12] + 13 * flag[13] + 49 * flag[14] + 96 * flag[15] + 82 * flag[16] + 84 * flag[17] +
    89 * flag[18] + 40 * flag[19] + 38 * flag[20] + 66 * flag[21] + 81 * flag[22] + 81 * flag[23] + 79 * flag[24] + 77 * flag[25] + 86 * flag[26] +
    68 * flag[27] + 26 * flag[28] + 37 * flag[29] + 15 * flag[30] + 56 * flag[31] + 13 * flag[32] + 17 * flag[33] + 50 * flag[34] + 37 * flag[35]
    == 198705)

s.add(
    82 * flag[0] + 57 * flag[1] + 33 * flag[2] + 32 * flag[3] + 79 * flag[4] + 25 * flag[5] + 54 * flag[6] + 27 * flag[7] + 50 * flag[8] +
    14 * flag[9] + 72 * flag[10] + 31 * flag[11] + 28 * flag[12] + 66 * flag[13] + 4 * flag[14] + 6 * flag[15] + 48 * flag[16] + 34 * flag[17] +
    63 * flag[18] + 51 * flag[19] + 12 * flag[20] + 21 * flag[21] + 73 * flag[22] + 66 * flag[23] + 53 * flag[24] + 38 * flag[25] + 54 * flag[26] +
    59 * flag[27] + 76 * flag[28] + 63 * flag[29] + 61 * flag[30] + 30 * flag[31] + 84 * flag[32] + 80 * flag[33] + 98 * flag[34] + 46 * flag[35]
    == 160349)

s.add(
    69 * flag[0] + 15 * flag[1] + 23 * flag[2] + 8 * flag[3] + 46 * flag[4] + 55 * flag[5] + 21 * flag[6] + 91 * flag[7] + 37 * flag[8] +
    9 * flag[9] + 61 * flag[10] + 20 * flag[11] + 23 * flag[12] + 96 * flag[13] + 28 * flag[14] + 67 * flag[15] + 19 * flag[16] + 50 * flag[17] +
    18 * flag[18] + 71 * flag[19] + 30 * flag[20] + 14 * flag[21] + 10 * flag[22] + 24 * flag[23] + 100 * flag[24] + 15 * flag[25] + 91 * flag[26] +
    15 * flag[27] + 93 * flag[28] + 24 * flag[29] + 46 * flag[30] + 61 * flag[31] + 67 * flag[32] + 60 * flag[33] + 56 * flag[34] + 81 * flag[35]
    == 148095)


result = s.check() #验证是否有解，sat或unsat
print(result)
if result == sat:
    m = s.model() #提取结果
    chars = []
    for i in range(36):
        val = m[flag[i]].as_long() #.as_long() 是把 Z3 内部格式转成普通整数
        chars.append(chr(val))
    print("".join(chars))

```

# 第一次纳新

## qiandao

python打包的exe，还是反编译出代码

```python
# Source Generated with Decompyle++
# File: qiandao.pyc (Python 3.11)

a = '53 44 50 43 53 45 43 7b 72 65 76 65 72 73 65 5f 71 69 61 6e 5f 64 61 6f 7d 0a'
correct_flag = bytes.fromhex(a).decode('utf-8').strip()
user_input = input('please input your flag: ')
if user_input == correct_flag:
    print('great')
    return None
print('wrong')
```

非常简单，直接输出flag即可

```python
a = '53 44 50 43 53 45 43 7b 72 65 76 65 72 73 65 5f 71 69 61 6e 5f 64 61 6f 7d 0a'
correct_flag = bytes.fromhex(a).decode('utf-8').strip()
print(correct_flag)
```

## Gift

提示魔改base64，魔改了两处位置

首先是找到了魔改后的base64表

```
ZYXABCDEFGHIJKLMNOPQRSTUVWzyxabcdefghijklmnopqrstuvw0123456789+/
```

看看加密函数，找一下第二处魔改的位置。我们把这个加密函数和之前的base64换表加密对比一下。

![image-20260809173159904](https://gitee.com/bobrocket/img/raw/master/image-20260809173159904.png)

发现在索引位置上进行了异或运算，脚本解密即可

```python
import base64
str1 = "YeBCCdVNCf4eMTNjXjFjXeNHJjNwFNlwWPxHLwZfXdxtFwZkGgZkHC=="
def to_standard_base64(s):
    custom_table = "ZYXABCDEFGHIJKLMNOPQRSTUVWzyxabcdefghijklmnopqrstuvw0123456789+/"
    standard_table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    result = []
    for c in s:
        if c == '=':
            result.append('=')
        else:
            scrambled_idx = custom_table.index(c)
            standard_idx = scrambled_idx ^ 0x15
            result.append(standard_table[standard_idx])
    return ''.join(result)
std = to_standard_base64(str1)
print(std)  
data = base64.b64decode(std)
print(data)
```

## Roses

给孩子难哭了。。。

![image-20260809184646293](https://gitee.com/bobrocket/img/raw/master/image-20260809184646293.png)

首先修复三处花指令，拿到主函数，发现对文件进行了两次加密。

第一次是异或Roses，第二次是base64换表

![image-20260809184955405](https://gitee.com/bobrocket/img/raw/master/image-20260809184955405.png)

