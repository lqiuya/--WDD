package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

func sendLog(msg string) {
	conn, err := net.Dial("tcp", "127.0.0.1:8083")
	if err != nil {
		return
	}
	defer conn.Close()
	fmt.Fprintf(conn, "[攻击软件] %s\n", msg)
}

func main() {
	sendLog("启动中...监听端口 :8081")

	fmt.Println("[攻击软件] 启动中...")
	fmt.Println("[攻击软件] 监听端口 :8081")

	reader := bufio.NewReader(os.Stdin)
	fmt.Print("请输入启动密码: ")
	password, _ := reader.ReadString('\n')
	password = strings.TrimSpace(password)

	if password != "123" {
		sendLog("密码错误，退出")
		fmt.Println("[攻击软件] 密码错误，退出")
		return
	}
	sendLog("密码正确，开始执行")
	fmt.Println("[攻击软件] 密码正确，开始执行\n")

	fmt.Print("请输入目标容器ID: ")
	containerID, _ := reader.ReadString('\n')
	containerID = strings.TrimSpace(containerID)
	sendLog(fmt.Sprintf("目标容器: %s", containerID))

	fmt.Println("[攻击软件] 扫描目标容器...")
	sendLog("扫描目标容器...")
	time.Sleep(300 * time.Millisecond)
	fmt.Printf("[攻击软件] 发现容器: %s\n", containerID)
	sendLog(fmt.Sprintf("发现容器: %s", containerID))
	time.Sleep(200 * time.Millisecond)

	fmt.Println("[攻击软件] 正在分析容器配置...")
	sendLog("正在分析容器配置...")
	scans := []string{
		"环境探测", "权限检查", "挂载点扫描", "内核版本检测",
		"命名空间分析", "系统调用表扫描", "进程树遍历", "文件系统扫描",
		"网络接口枚举", "安全模块检测", "Capabilities分析", "Seccomp策略检查",
		"AppArmor状态扫描", "SELinux上下文检测", "cgroups层级遍历", "设备节点枚举",
		"IPC命名空间检查", "UTS命名空间分析", "用户命名空间映射", "时间命名空间检测",
	}
	for i, scan := range scans {
		msg := fmt.Sprintf("模块%d: %s... OK", i+1, scan)
		fmt.Printf("[攻击软件] %s\n", msg)
		sendLog(msg)
		time.Sleep(150 * time.Millisecond)
	}

	fmt.Println("\n[攻击软件] 正在构建逃逸Payload...")
	sendLog("正在构建逃逸Payload...")
	time.Sleep(500 * time.Millisecond)
	fmt.Println("[攻击软件] Payload注入中...")
	sendLog("Payload注入中...")
	time.Sleep(300 * time.Millisecond)
	fmt.Println("[攻击软件] 容器内执行中...")
	sendLog("容器内执行中...")
	time.Sleep(400 * time.Millisecond)
	fmt.Println("[攻击软件] 突破PID命名空间...")
	sendLog("突破PID命名空间...")
	time.Sleep(200 * time.Millisecond)
	fmt.Println("[攻击软件] 挂载宿主机根目录...")
	sendLog("挂载宿主机根目录...")
	time.Sleep(200 * time.Millisecond)
	fmt.Println("[攻击软件] 写入crontab...")
	sendLog("写入crontab...")
	time.Sleep(200 * time.Millisecond)
	fmt.Println("[攻击软件] 反弹shell连接中...")
	sendLog("反弹shell连接中...")
	time.Sleep(300 * time.Millisecond)
	fmt.Println("[攻击软件] 权限提升中...")
	sendLog("权限提升中...")
	time.Sleep(200 * time.Millisecond)
	fmt.Println("[攻击软件] 清除日志痕迹...")
	sendLog("清除日志痕迹...")
	time.Sleep(200 * time.Millisecond)

	fmt.Println("\n[攻击软件] 正在通知防御软件...")
	sendLog("正在通知防御软件...")
	// 改成宿主机的Docker网桥IP
	conn, err := net.Dial("tcp", "172.17.0.1:8082")
	if err != nil {
		fmt.Println("[攻击软件] 防御软件未运行，跳过通知")
		sendLog("防御软件未运行，跳过通知")
	} else {
		fmt.Fprintf(conn, "ATTACKED:%s\n", containerID)
		conn.Close()
		fmt.Println("[攻击软件] 通知已发送")
		sendLog("通知已发送")
	}

	fmt.Println("\n[攻击软件] ✅ 逃逸成功！已获得宿主机root权限")
	sendLog("✅ 逃逸成功！已获得宿主机root权限")
	fmt.Println("[攻击软件] 当前权限: uid=0(root) gid=0(root)")
	sendLog("当前权限: uid=0(root) gid=0(root)")
	fmt.Println("[攻击软件] 攻击完成")
	sendLog("攻击完成")

	fmt.Println("\n按回车键退出...")
	reader.ReadString('\n')
}
