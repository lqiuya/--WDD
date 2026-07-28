#!/bin/bash

PROJECT_DIR="/home/gcy/下载/WD"
OUTPUT_DIR="$PROJECT_DIR/WDD-V-0.5.0"
VERSION="0.5.0"
APP_NAME="W-DD"
DESC="Warden Defense Deployment - 云原生安全检测工具"

mkdir -p "$OUTPUT_DIR"
cd "$PROJECT_DIR" || exit 1

# 确保依赖
sudo apt-get install -y dpkg rpm 2>/dev/null || true

# ========== amd64 编译（一次编译，复用） ==========
echo ">>> 编译 amd64 二进制 ..."
GOOS=linux GOARCH=amd64 wails build -platform linux/amd64 -ldflags "-s -w" -o "$APP_NAME"

# ========== 1. amd64 + deb ==========
echo ">>> 打包 amd64 deb ..."
mkdir -p deb_amd64/DEBIAN deb_amd64/usr/bin deb_amd64/usr/share/applications
cp "$PROJECT_DIR/build/bin/$APP_NAME" deb_amd64/usr/bin/
chmod +x deb_amd64/usr/bin/$APP_NAME

cat > deb_amd64/DEBIAN/control << EOF
Package: w-dd
Version: $VERSION
Architecture: amd64
Maintainer: W-DD Team
Description: $DESC
Priority: optional
EOF

cat > deb_amd64/usr/share/applications/w-dd.desktop << EOF
[Desktop Entry]
Name=W-DD
Exec=/usr/bin/$APP_NAME
Type=Application
Terminal=false
Categories=System;Security;
EOF

dpkg-deb --build deb_amd64 "$OUTPUT_DIR/WDD-V.${VERSION}_Linux_amd64.deb"
rm -rf deb_amd64

# ========== 2. amd64 + rpm ==========
echo ">>> 打包 amd64 rpm ..."
mkdir -p rpm_amd64/{BUILD,RPMS,SOURCES,SPECS,SRPMS,tmp}

cat > rpm_amd64/SPECS/w-dd.spec << EOF
Name:           w-dd
Version:        $VERSION
Release:        1
Summary:        $DESC
License:        Apache-2.0
BuildArch:      x86_64

%description
$DESC

%install
mkdir -p %{buildroot}/usr/bin
cp $PROJECT_DIR/build/bin/$APP_NAME %{buildroot}/usr/bin/

%files
/usr/bin/$APP_NAME
EOF

rpmbuild --define "_topdir $PROJECT_DIR/rpm_amd64" --define "_tmppath $PROJECT_DIR/rpm_amd64/tmp" -bb rpm_amd64/SPECS/w-dd.spec

# 找生成的 rpm 文件
RPM_FILE=$(find rpm_amd64/RPMS -name "*.rpm" | head -1)
if [ -n "$RPM_FILE" ]; then
    cp "$RPM_FILE" "$OUTPUT_DIR/WDD-V.${VERSION}_Linux_amd64.rpm"
    echo "✓ rpm 已生成"
else
    echo "✗ rpm 生成失败"
fi
rm -rf rpm_amd64

echo ""
echo "✅ 打包完成！"
ls -lh "$OUTPUT_DIR"

