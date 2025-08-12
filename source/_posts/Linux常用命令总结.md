---
title: Linux常用命令总结
date: 2025-08-06 12:31:55
index_img: https://pic1.imgdb.cn/item/6896a8c558cb8da5c8139790.jpg
tags: linux
categories: 常用命令总结
---
# Linux 常用命令总结

Linux 作为最流行的服务器操作系统，掌握其常用命令是每个开发者、运维人员和技术爱好者的必备技能。本文将介绍 Linux 中最常用、最实用的命令，帮助你快速上手 Linux 系统操作。

## 目录与文件操作

### 目录导航

```bash
# 查看当前工作目录
pwd

# 切换目录
cd /path/to/directory
cd ..      # 返回上级目录
cd ~       # 返回用户主目录
cd -       # 返回上一个工作目录

# 列出目录内容
ls
ls -l      # 详细列表
ls -a      # 显示隐藏文件
ls -lh     # 人类可读的文件大小
ls -t      # 按修改时间排序
```

### 文件与目录管理

```bash
# 创建目录
mkdir dirname
mkdir -p parent/child  # 创建多级目录

# 删除目录
rmdir dirname          # 删除空目录
rm -r dirname          # 递归删除目录及内容

# 创建文件
touch filename

# 复制文件/目录
cp file1 file2
cp -r dir1 dir2        # 递归复制目录

# 移动/重命名文件或目录
mv oldname newname
mv file /path/to/dir/

# 删除文件
rm filename
rm -i filename         # 交互式删除
rm -f filename         # 强制删除
```

## 文件查看与编辑

### 查看文件内容

```bash
# 查看文件全部内容
cat filename

# 分页查看文件
less filename
more filename

# 查看文件头部
head filename
head -n 10 filename   # 查看前10行

# 查看文件尾部
tail filename
tail -n 10 filename   # 查看后10行
tail -f filename      # 实时查看日志文件

# 统计文件信息
wc filename           # 行数、单词数、字节数
```

### 文件编辑

```bash
# 使用nano编辑器
nano filename

# 使用vim编辑器
vim filename
# vim基本操作：
# i - 进入插入模式
# Esc - 退出插入模式
# :w - 保存
# :q - 退出
# :wq - 保存并退出
# :q! - 强制退出不保存
```

## 系统信息与进程管理

### 系统信息

```bash
# 查看系统信息
uname -a

# 查看系统版本
cat /etc/os-release

# 查看CPU信息
lscpu
cat /proc/cpuinfo

# 查看内存使用
free -h

# 查看磁盘使用
df -h

# 查看目录占用空间
du -sh /path/to/dir

# 查看系统运行时间
uptime

# 查看系统负载
top
htop       # 更友好的交互式工具
```

### 进程管理

```bash
# 查看进程
ps
ps aux     # 查看所有进程
ps -ef     # 完整格式显示

# 查找进程
pgrep process_name
pidof process_name

# 终止进程
kill pid
kill -9 pid   # 强制终止
killall process_name

# 后台运行程序
command &     # 在后台运行
nohup command &  # 退出终端后继续运行
```

## 用户与权限管理

### 用户管理

```bash
# 查看当前用户
whoami

# 查看登录用户
who
w

# 切换用户
su username
sudo -i      # 切换到root

# 添加用户
sudo adduser username

# 删除用户
sudo deluser username

# 修改密码
passwd
passwd username   # root可修改其他用户密码
```

### 权限管理

```bash
# 查看文件权限
ls -l

# 修改文件权限
chmod 755 filename
chmod u+x filename   # 给所有者添加执行权限

# 修改文件所有者
chown user:group filename
sudo chown -R user:group dirname  # 递归修改

# 修改文件所属组
chgrp group filename
```

## 网络相关命令

```bash
# 查看网络接口
ifconfig
ip addr      # 新版推荐

# 测试网络连通性
ping example.com

# 查看路由表
route -n
ip route

# 查看网络连接
netstat -tulnp
ss -tulnp     # 新版推荐

# 下载文件
wget http://example.com/file
curl -O http://example.com/file

# 域名解析
nslookup example.com
dig example.com

# 追踪网络路径
traceroute example.com
tracepath example.com
```

## 包管理工具

### Debian/Ubuntu (APT)

```bash
# 更新软件包列表
sudo apt update

# 升级已安装的软件包
sudo apt upgrade

# 安装软件包
sudo apt install package_name

# 删除软件包
sudo apt remove package_name
sudo apt purge package_name  # 同时删除配置文件

# 搜索软件包
apt search keyword

# 查看软件包信息
apt show package_name
```

### CentOS/RHEL (YUM/DNF)

```bash
# 更新软件包
sudo yum update
sudo dnf update  # 新版

# 安装软件包
sudo yum install package_name
sudo dnf install package_name

# 删除软件包
sudo yum remove package_name
sudo dnf remove package_name

# 搜索软件包
yum search keyword
dnf search keyword
```

## 文件查找与处理

```bash
# 查找文件
find /path -name "filename"
find /path -type f -name "*.txt"  # 查找所有txt文件

# 查找文件内容
grep "pattern" filename
grep -r "pattern" /path  # 递归搜索
grep -i "pattern" filename  # 忽略大小写

# 排序文件内容
sort filename
sort -u filename  # 去重排序

# 去重
uniq filename
sort filename | uniq  # 先排序再去重

# 比较文件差异
diff file1 file2
```

## 压缩与解压

```bash
# tar打包
tar -cvf archive.tar /path/to/files

# tar.gz压缩
tar -czvf archive.tar.gz /path/to/files

# tar.bz2压缩
tar -cjvf archive.tar.bz2 /path/to/files

# 解压tar.gz
tar -xzvf archive.tar.gz

# 解压tar.bz2
tar -xjvf archive.tar.bz2

# zip压缩
zip -r archive.zip /path/to/files

# unzip解压
unzip archive.zip

# gzip压缩
gzip filename

# gunzip解压
gunzip filename.gz
```

## 总结

这些 Linux 命令涵盖了日常系统管理、文件操作、网络配置和软件安装等基本需求。掌握这些命令后，你将能够高效地在 Linux 环境中工作。

记住几个小技巧：
1. 使用 `man command` 查看命令手册
2. 使用 `command --help` 获取快速帮助
3. 善用 Tab 键补全命令和文件名
4. 使用 `history` 查看命令历史
5. 使用 `!!` 重复上一条命令

随着使用经验的增加，你会逐渐发现 Linux 命令行的强大之处，并能够组合这些命令完成更复杂的任务。