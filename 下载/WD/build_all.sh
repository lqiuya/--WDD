#!/bin/bash

# W-DD 一键打包脚本
# 输出命名: WDD-V.0.5_Linux_{arch}.{deb|rpm}
# 放到 /home/gcy/下载/WD/ 目录下执行

PROJECT_DIR="/home/gcy/下载/WD"
OUTPUT_DIR="$PROJECT_DIR/WDD-V-0.5.0"
VERSION="0.5.0"
APP_NAME="W-DD"
DESC="Warden Defense Deployment - 云原生安全检测工具"

mkdir -p "$OUTPUT_DIR"
cd "$PROJECT_DIR" || exit 1

# 安装打包依赖（如果没有）
sudo apt-get install -y dpkg rpm 2>/dev/null || true

# ========== 1. amd64 + deb ==========
echo ">>> 编译 amd64 deb ..."
GOOS=linux GOARCH=amd64 wails build -platform linux/amd64 -ldflags "-s -w" -o "$APP_NAME"
mkdir -p deb_amd64/DEBIAN deb_amd64/usr/bin deb_amd64/usr/share/applications
cp "$PROJECT_DIR/build/bin/$APP_NAME" deb_amd64/usr/bin/
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
Icon=utilities-terminal
Categories=System;Security;
EOF
dpkg-deb --build deb_amd64 "$OUTPUT_DIR/WDD-V.${VERSION}_Linux_amd64.deb"
rm -rf deb_amd64

# ========== 2. amd64 + rpm ==========
echo ">>> 编译 amd64 rpm ..."
mkdir -p rpm_amd64/{BUILD,RPMS,SOURCES,SPECS,SRPMS}
cat > rpm_amd64/SPECS/w-dd.spec << EOF
Name:           w-dd
Version:        $VERSION
Release:        1%{?dist}
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
rpmbuild --define "_topdir $PROJECT_DIR/rpm_amd64" -bb rpm_amd64/SPECS/w-dd.spec
cp rpm_amd64/RPMS/x86_64/*.rpm "$OUTPUT_DIR/WDD-V.${VERSION}_Linux_amd64.rpm" 2>/dev/null || \
cp rpm_amd64/RPMS/*/*.rpm "$OUTPUT_DIR/WDD-V.${VERSION}_Linux_amd64.rpm"
rm -rf rpm_amd64

# ========== 3. arm64 + deb ==========
echo ">>> 编译 arm64 deb ..."
GOOS=linux GOARCH=arm64 wails build -platform linux/arm64 -ldflags "-s -w" -o "$APP_NAME"
mkdir -p deb_arm64/DEBIAN deb_arm64/usr/bin deb_arm64/usr/share/applications
cp "$PROJECT_DIR/build/bin/$APP_NAME" deb_arm64/usr/bin/
cat > deb_arm64/DEBIAN/control << EOF
Package: w-dd
Version: $VERSION
Architecture: arm64
Maintainer: W-DD Team
Description: $DESC
Priority: optional
EOF
cat > deb_arm64/usr/share/applications/w-dd.desktop << EOF
[Desktop Entry]
Name=W-DD
Exec=/usr/bin/$APP_NAME
Type=Application
Terminal=false
Icon=utilities-terminal
Categories=System;Security;
EOF
dpkg-deb --build deb_arm64 "$OUTPUT_DIR/WDD-V.${VERSION}_Linux_arm64.deb"
rm -rf deb_arm64

# ========== 4. arm64 + rpm ==========
echo ">>> 编译 arm64 rpm ..."
mkdir -p rpm_arm64/{BUILD,RPMS,SOURCES,SPECS,SRPMS}
cat > rpm_arm64/SPECS/w-dd.spec << EOF
Name:           w-dd
Version:        $VERSION
Release:        1%{?dist}
Summary:        $DESC
License:        Apache-2.0
BuildArch:      aarch64

%description
$DESC

%install
mkdir -p %{buildroot}/usr/bin
cp $PROJECT_DIR/build/bin/$APP_NAME %{buildroot}/usr/bin/

%files
/usr/bin/$APP_NAME
EOF
rpmbuild --define "_topdir $PROJECT_DIR/rpm_arm64" -bb rpm_arm64/SPECS/w-dd.spec
cp rpm_arm64/RPMS/aarch64/*.rpm "$OUTPUT_DIR/WDD-V.${VERSION}_Linux_arm64.rpm" 2>/dev/null || \
cp rpm_arm64/RPMS/*/*.rpm "$OUTPUT_DIR/WDD-V.${VERSION}_Linux_arm64.rpm"
rm -rf rpm_arm64

echo ""
echo "✅ 打包完成！输出目录: $OUTPUT_DIR"
ls -lh "$OUTPUT_DIR"
