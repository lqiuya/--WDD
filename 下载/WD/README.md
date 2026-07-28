# WD 安全工具箱 (WD Security Toolkit)

## 项目简介

WD 安全工具箱是一个基于 Wails 框架的桌面安全检测应用，面向云原生安全学习者和从业者，整合多个安全检测功能于统一图形界面。

## 功能模块

### 模块一：信息收集
- **系统检查**（10个功能）：进程监控、网络连接、防火墙配置、系统服务等
- **IP/域名**（8个功能）：端口扫描、HTTP检查、子域名枚举、Whois查询等
- **网址**（7个功能）：HTTP检查、目录爆破、SSL证书检查、响应头分析等
- **文件**（6个功能）：文件哈希、日志分析、配置检查、文件权限等

### 模块二：容器检查
- **快速扫描**：基础信息 + 容器检测（约30秒）
- **标准扫描**：快速扫描 + 挂载/网络/文件检查（约2分钟）
- **全面扫描**：标准扫描 + 行为分析 + 深度文件审计（约5分钟）

## 核心交互机制

1. **智能识别**：输入即识别，实时显示分类标签
2. **功能卡片**：分类下展开功能卡片，可点击执行
3. **快捷执行**：输入 `,数字` 直接执行对应编号功能
4. **默认执行**：直接回车执行默认第1个功能
5. **状态保持**：执行后输入框内容不变

## 技术栈

- **后端**：Go + Wails v2
- **前端**：原生 HTML/CSS/JS（无框架依赖）
- **构建**：Vite

## 安装与运行

### 前置要求
- Go 1.23+
- Node.js 18+
- Wails CLI (`go install github.com/wailsapp/wails/v2/cmd/wails@latest`)

### 开发模式
```bash
# 进入项目目录
cd WD-Security-Toolkit

# 安装前端依赖
cd frontend && npm install && cd ..

# 运行开发服务器
wails dev
```

### 构建发布版
```bash
# 构建 Linux 版本
wails build -platform linux

# 构建 Windows 版本
wails build -platform windows

# 构建完成后，可执行文件在 build/bin/ 目录
```

## 项目结构

```
WD-Security-Toolkit/
├── wails.json          # Wails 配置文件
├── go.mod              # Go 模块定义
├── main.go             # 主程序入口
├── app/
│   └── app.go          # Wails 应用结构
├── frontend/
│   ├── package.json    # 前端依赖
│   ├── vite.config.js  # Vite 配置
│   ├── index.html      # 入口 HTML
│   └── src/
│       ├── style.css   # 样式文件
│       ├── main.js     # 前端逻辑
│       └── assets/     # 静态资源
└── build/              # 构建输出
```

## 功能码说明

| 类别 | 功能码范围 | 功能数量 |
|------|-----------|---------|
| 系统检查 | LQ0000-LQ0009 | 10 |
| IP/域名 | LQ0010-LQ0017 | 8 |
| 网址 | LQ0018-LQ0024 | 7 |
| 文件 | LQ0025-LQ0030 | 6 |
| 工具类 | LQ0031-LQ0042 | 12 |

## 作者

- **作者**: LiQiu
- **版本**: v1.0.0
- **构建时间**: 2026-07-21

## 许可证

本项目仅供学习和研究使用。
