#!/bin/bash
# WD Security Toolkit 快速启动脚本
# 作者: LiQiu
# 版本: 1.0.0

set -e

PROJECT_NAME="WD-Security-Toolkit"
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}  WD Security Toolkit 快速启动脚本${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# 检查前置依赖
check_dependency() {
    if command -v $1 &> /dev/null; then
        echo -e "${GREEN}✓${NC} $1 已安装"
        return 0
    else
        echo -e "${RED}✗${NC} $1 未安装"
        return 1
    fi
}

echo "[1/5] 检查前置依赖..."
GO_OK=false
NODE_OK=false
WAILS_OK=false

if check_dependency "go"; then
    GO_VERSION=$(go version | awk '{print $3}')
    echo "    版本: $GO_VERSION"
    GO_OK=true
fi

if check_dependency "node"; then
    NODE_VERSION=$(node --version)
    echo "    版本: $NODE_VERSION"
    NODE_OK=true
fi

if check_dependency "wails"; then
    WAILS_VERSION=$(wails version 2>/dev/null | head -1 || echo "unknown")
    echo "    版本: $WAILS_VERSION"
    WAILS_OK=true
fi

echo ""

# 安装缺失依赖
if [ "$GO_OK" = false ]; then
    echo -e "${YELLOW}⚠ 未检测到 Go，请先安装 Go 1.23+${NC}"
    echo "   安装命令: sudo apt install golang-go"
    exit 1
fi

if [ "$NODE_OK" = false ]; then
    echo -e "${YELLOW}⚠ 未检测到 Node.js，请先安装 Node.js 18+${NC}"
    echo "   安装命令: sudo apt install nodejs npm"
    exit 1
fi

if [ "$WAILS_OK" = false ]; then
    echo -e "${YELLOW}⚠ 未检测到 Wails CLI，正在安装...${NC}"
    go install github.com/wailsapp/wails/v2/cmd/wails@latest
    export PATH=$PATH:$(go env GOPATH)/bin
    echo -e "${GREEN}✓ Wails CLI 安装完成${NC}"
fi

echo ""
echo "[2/5] 进入项目目录..."
cd "$(dirname "$0")/$PROJECT_NAME" || {
    echo -e "${RED}✗ 找不到项目目录 $PROJECT_NAME${NC}"
    echo "   请确保此脚本与 $PROJECT_NAME 目录在同一目录下"
    exit 1
}
echo -e "${GREEN}✓${NC} 已进入项目目录: $(pwd)"

echo ""
echo "[3/5] 安装前端依赖..."
cd frontend
if [ ! -d "node_modules" ]; then
    npm install
    echo -e "${GREEN}✓${NC} 前端依赖安装完成"
else
    echo -e "${GREEN}✓${NC} 前端依赖已存在，跳过安装"
fi
cd ..

echo ""
echo "[4/5] 下载 Go 依赖..."
go mod tidy
echo -e "${GREEN}✓${NC} Go 依赖下载完成"

echo ""
echo "[5/5] 启动开发服务器..."
echo -e "${YELLOW}ℹ 正在启动 wails dev...${NC}"
echo ""
echo -e "${BLUE}========================================${NC}"
echo -e "${GREEN}  WD Security Toolkit 启动成功！${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""
echo "  开发模式: wails dev"
echo "  构建命令: wails build"
echo "  输出目录: build/bin/"
echo ""

wails dev
