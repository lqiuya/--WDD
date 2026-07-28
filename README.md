# Warden Defense Deployment    

> **版本**: W-DD.V-0.5.0 | **作者**: LiQiu | **定位**: 云原生安全实验工具

---

## 📦 安装与启动（国内gitee下载速度快）

### 1️⃣ Debian / Ubuntu 系（.deb）

```bash
wget -O /tmp/w-dd.deb "https://gitee.com/wuyudeliqiu/WDD/raw/master/WDD-V-0.5版本/WDD-V.0.5.0_Linux_amd64.deb" && sudo dpkg -i /tmp/w-dd.deb && rm /tmp/w-dd.deb && W-DD
```

> ⚠️ 如果 dpkg 报依赖错误，执行：`sudo apt-get install -f`

---

### 2️⃣ RHEL / CentOS / Fedora 系（.rpm）

```bash
wget -O /tmp/w-dd.rpm "https://gitee.com/wuyudeliqiu/WDD/raw/master/WDD-V-0.5版本/WDD-V.0.5.0_Linux_amd64.rpm" && sudo rpm -ivh /tmp/w-dd.rpm && rm /tmp/w-dd.rpm && W-DD
```

---

## 💡 操作提示

> 📌 **每个功能的操作教程位于界面右上角**，点击即可查看详细使用说明。
>  可以点击上面的文件进行下载
>  选则安装包，其他部分是源代码+介绍
---

## 📑 功能总览

W-DD 看守者-防线部署 共包含 **123 项核心安全检测功能**，分为四大模块：

| 模块 | 数量 |
|:---|:---:|
| 信息收集模块 | 31 |
| 容器权限检查器 | 41 |
| 静态安全检查 | 42 |
| 动态安全检查 | 9 |
| **总计** | **123** |

---

## 第一部分：信息收集模块（31项）

### 🔧 系统检查（10项）

| 序号 | 功能代码 | 功能名称 |
|:---:|:---:|:---|
| 1 | LQ0000 | 进程监控 |
| 2 | LQ0001 | 网络连接 |
| 3 | LQ0002 | 防火墙配置 |
| 4 | LQ0003 | 网络协议 |
| 5 | LQ0004 | 系统服务 |
| 6 | LQ0005 | 端口占用 |
| 7 | LQ0006 | 系统信息 |
| 8 | LQ0007 | 用户账户 |
| 9 | LQ0008 | 定时任务 |
| 10 | LQ0009 | 环境变量 |

### 🌐 IP / 域名（8项）

| 序号 | 功能代码 | 功能名称 |
|:---:|:---:|:---|
| 11 | LQ0010 | 端口扫描 |
| 12 | LQ0011 | 网络连接 |
| 13 | LQ0012 | HTTP状态检查 |
| 14 | LQ0013 | 子域名枚举 |
| 15 | LQ0014 | 目录爆破 |
| 16 | LQ0015 | Whois查询 |
| 17 | LQ0016 | DNS解析 |
| 18 | LQ0017 | Traceroute |

### 🔗 网址（7项）

| 序号 | 功能代码 | 功能名称 |
|:---:|:---:|:---|
| 19 | LQ0018 | HTTP状态检查 |
| 20 | LQ0019 | 目录爆破 |
| 21 | LQ0020 | 子域名枚举 |
| 22 | LQ0021 | 网页截图 |
| 23 | LQ0022 | SSL证书检查 |
| 24 | LQ0023 | 响应头分析 |
| 25 | LQ0024 | 网页内容抓取 |

### 📁 文件（6项）

| 序号 | 功能代码 | 功能名称 |
|:---:|:---:|:---|
| 26 | LQ0025 | 文件哈希 |
| 27 | LQ0026 | 日志分析 |
| 28 | LQ0027 | 配置检查 |
| 29 | LQ0028 | 文件信息 |
| 30 | LQ0029 | 文件权限 |
| 31 | LQ0030 | 文件类型识别 |

---

## 第二部分：容器权限检查器（41项）

> 检测容器拥有的 Linux Capabilities

| 序号 | 英文名 | 中文名 |
|:---:|:---|:---|
| 1 | CAP_CHOWN | 更改文件所有者 |
| 2 | CAP_DAC_OVERRIDE | 绕过文件访问权限 |
| 3 | CAP_DAC_READ_SEARCH | 绕过文件读取与目录搜索权限 |
| 4 | CAP_FOWNER | 绕过文件所有权检查 |
| 5 | CAP_FSETID | 设置文件setuid/setgid位 |
| 6 | CAP_KILL | 发送信号给任意进程 |
| 7 | CAP_SETGID | 设置任意进程的GID |
| 8 | CAP_SETUID | 设置任意进程的UID |
| 9 | CAP_SETPCAP | 修改进程能力集 |
| 10 | CAP_LINUX_IMMUTABLE | 设置文件不可变属性 |
| 11 | CAP_NET_BIND_SERVICE | 绑定特权端口（<1024） |
| 12 | CAP_NET_BROADCAST | 发送网络广播包 |
| 13 | CAP_NET_ADMIN | 网络管理 |
| 14 | CAP_NET_RAW | 使用原始套接字 |
| 15 | CAP_IPC_LOCK | 锁定共享内存 |
| 16 | CAP_IPC_OWNER | 绕过IPC权限检查 |
| 17 | CAP_SYS_MODULE | 加载/卸载内核模块 |
| 18 | CAP_SYS_RAWIO | 直接I/O端口访问 |
| 19 | CAP_SYS_CHROOT | 使用chroot |
| 20 | CAP_SYS_PTRACE | 进程跟踪与调试 |
| 21 | CAP_SYS_PACCT | 启用进程会计 |
| 22 | CAP_SYS_ADMIN | 系统管理 |
| 23 | CAP_SYS_BOOT | 重启系统 |
| 24 | CAP_SYS_NICE | 调整进程优先级 |
| 25 | CAP_SYS_RESOURCE | 调整资源限制 |
| 26 | CAP_SYS_TIME | 修改系统时间 |
| 27 | CAP_SYS_TTY_CONFIG | TTY配置 |
| 28 | CAP_MKNOD | 创建特殊文件 |
| 29 | CAP_LEASE | 建立文件租约 |
| 30 | CAP_AUDIT_WRITE | 写入审计日志 |
| 31 | CAP_AUDIT_CONTROL | 控制审计子系统 |
| 32 | CAP_SETFCAP | 设置文件能力 |
| 33 | CAP_MAC_OVERRIDE | 覆盖强制访问控制 |
| 34 | CAP_MAC_ADMIN | 管理强制访问控制 |
| 35 | CAP_SYSLOG | 读取内核日志 |
| 36 | CAP_WAKE_ALARM | 设置唤醒闹钟 |
| 37 | CAP_BLOCK_SUSPEND | 阻止系统挂起 |
| 38 | CAP_AUDIT_READ | 读取审计日志 |
| 39 | CAP_PERFMON | 性能监控 |
| 40 | CAP_BPF | BPF程序加载 |
| 41 | CAP_CHECKPOINT_RESTORE | 检查点与恢复 |

---

## 第三部分：静态安全检查（42项）

> 基于容器配置的安全基线检查

| 序号 | 检查项 |
|:---:|:---|
| 1 | 特权模式 |
| 2 | 新增能力 |
| 3 | 丢弃能力 |
| 4 | Seccomp |
| 5 | AppArmor |
| 6 | SELinux |
| 7 | NoNewPrivileges |
| 8 | 根文件系统只读 |
| 9 | User Namespace |
| 10 | PID Namespace |
| 11 | 网络模式 |
| 12 | 端口映射 |
| 13 | DNS配置 |
| 14 | Hosts文件 |
| 15 | 挂载卷类型 |
| 16 | 挂载读写权限 |
| 17 | 敏感路径挂载 |
| 18 | 设备映射 |
| 19 | tmpfs大小 |
| 20 | 日志驱动 |
| 21 | 日志大小限制 |
| 22 | CPU限制 |
| 23 | 内存限制 |
| 24 | PIDs限制 |
| 25 | 文件描述符限制 |
| 26 | 磁盘I/O限制 |
| 27 | cgroup配置 |
| 28 | IPC Namespace |
| 29 | UTS Namespace |
| 30 | sysctl修改 |
| 31 | security-opt |
| 32 | 镜像Digest |
| 33 | 镜像来源 |
| 34 | 镜像标签 |
| 35 | 镜像大小 |
| 36 | 镜像构建时间 |
| 37 | 镜像漏洞 |
| 38 | 镜像层历史 |
| 39 | 启动命令 |
| 40 | 环境变量 |
| 41 | K8s SA Token |
| 42 | 云服务元数据 |

---

## 第四部分：动态安全检查（9项）

> 容器运行状态下的实时检测

| 序号 | 检查项 |
|:---:|:---|
| 43 | 容器内进程 |
| 44 | 容器内用户 |
| 45 | SUID/SGID文件 |
| 46 | 计划任务 |
| 47 | SSH服务 |
| 48 | 开放文件描述符 |
| 49 | 网络连接状态 |
| 50 | 实际监听端口 |
| 51 | 出站网络 |

---

*文档生成时间: 2026-07-27 | W-DD 看守者-防线部署 V0.5.0*
