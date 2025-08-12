---
title: Git常用命令总结
date: 2025-08-06 12:30:05
index_img: https://pic1.imgdb.cn/item/6896a85058cb8da5c813975a.jpg
tags: git
categories: 常用命令总结
---
# Git 常用命令总结

Git 是目前最流行的分布式版本控制系统，掌握 Git 的基本操作对于开发者来说至关重要。本文将介绍 Git 的常用命令，帮助你快速上手 Git。

## 基本配置

```bash
# 设置用户名
git config --global user.name "Your Name"

# 设置邮箱
git config --global user.email "your.email@example.com"

# 查看配置
git config --list
```

## 创建仓库

```bash
# 初始化本地仓库
git init

# 克隆远程仓库
git clone <repository_url>

# 克隆指定分支
git clone -b <branch_name> <repository_url>
```

## 基本操作

```bash
# 查看当前状态
git status

# 添加文件到暂存区
git add <file_name>
git add .  # 添加所有更改

# 提交更改
git commit -m "commit message"

# 查看提交历史
git log
git log --oneline  # 简洁显示
git log --graph  # 图形化显示分支
```

## 分支管理

```bash
# 查看分支
git branch
git branch -v  # 查看分支详情
git branch -a  # 查看所有分支（包括远程）

# 创建分支
git branch <branch_name>

# 切换分支
git checkout <branch_name>
git switch <branch_name>  # Git 2.23+ 推荐方式

# 创建并切换分支
git checkout -b <branch_name>
git switch -c <branch_name>  # Git 2.23+ 推荐方式

# 删除分支
git branch -d <branch_name>  # 安全删除
git branch -D <branch_name>  # 强制删除

# 合并分支
git merge <branch_name>

# 变基操作
git rebase <branch_name>
```

## 远程操作

```bash
# 查看远程仓库
git remote -v

# 添加远程仓库
git remote add <remote_name> <repository_url>

# 从远程获取更新
git fetch <remote_name>

# 拉取远程分支并合并
git pull <remote_name> <branch_name>

# 推送本地分支到远程
git push <remote_name> <branch_name>
git push -u <remote_name> <branch_name>  # 设置上游分支

# 删除远程分支
git push <remote_name> --delete <branch_name>
```

## 撤销操作

```bash
# 撤销工作区修改
git checkout -- <file_name>

# 撤销暂存区修改（取消add）
git reset HEAD <file_name>

# 修改最后一次提交
git commit --amend

# 回退到指定提交
git reset --hard <commit_id>

# 撤销某次提交
git revert <commit_id>
```

## 标签管理

```bash
# 查看标签
git tag

# 创建标签
git tag <tag_name>
git tag -a <tag_name> -m "tag message"  # 带注释的标签

# 推送标签到远程
git push <remote_name> <tag_name>
git push <remote_name> --tags  # 推送所有标签

# 删除标签
git tag -d <tag_name>
git push <remote_name> :refs/tags/<tag_name>  # 删除远程标签
```

## 其他实用命令

```bash
# 查看文件差异
git diff
git diff <file_name>
git diff <commit_id1> <commit_id2>

# 储藏当前工作
git stash
git stash list  # 查看储藏列表
git stash apply  # 恢复最近储藏
git stash drop  # 删除最近储藏

# 查看某行代码的修改历史
git blame <file_name>

# 忽略文件（.gitignore）
# 在项目根目录创建.gitignore文件
```

## 总结

这些 Git 命令涵盖了日常开发中的大部分需求。随着使用经验的增加，你会逐渐掌握更多高级用法。记住，Git 是一个强大的工具，熟练使用它将大大提高你的开发效率。

建议初学者多实践这些命令，遇到问题时可以使用 `git help <command>` 查看详细帮助文档。