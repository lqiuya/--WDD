#!/bin/bash
cd ~/下载/WD/frontend
echo "👁️ 监听 index.html 变化..."

while inotifywait -e modify index.html; do
    echo "🔄 检测到变化，同步到 dist..."
    cp index.html dist/index.html
    echo "✅ 已同步，按 Ctrl+R 刷新窗口"
done
