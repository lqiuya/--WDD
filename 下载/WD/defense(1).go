package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
)

func red(text string) string {
	return "\033[31m" + text + "\033[0m"
}

func green(text string) string {
	return "\033[32m" + text + "\033[0m"
}

func sendLog(msg string) {
	conn, err := net.Dial("tcp", "127.0.0.1:8083")
	if err != nil {
		return
	}
	defer conn.Close()
	fmt.Fprintf(conn, "[防御软件] %s\n", msg)
}

func main() {
	sendLog("启动中...监听端口 :8082")

	fmt.Println("[防御软件] 启动中...")
	fmt.Println("[防御软件] 监听端口 :8082")

	reader := bufio.NewReader(os.Stdin)
	fmt.Print("请输入要监控的容器ID: ")
	containerID, _ := reader.ReadString('\n')
	containerID = strings.TrimSpace(containerID)
	sendLog(fmt.Sprintf("开始监控容器: %s", containerID))

	fmt.Printf("\n[防御软件] 正在监控容器 %s...\n\n", containerID)

	fmt.Println(green("[防御软件] 状态: 🟢 容器正常"))
	sendLog("状态: 🟢 容器正常")

	// 监听所有网卡，让容器内也能连接
	listener, err := net.Listen("tcp", "0.0.0.0:8082")
	if err != nil {
		fmt.Println("[防御软件] 端口监听失败:", err)
		sendLog(fmt.Sprintf("端口监听失败: %v", err))
		return
	}
	defer listener.Close()

	conn, err := listener.Accept()
	if err != nil {
		fmt.Println("[防御软件] 连接错误:", err)
		sendLog(fmt.Sprintf("连接错误: %v", err))
		return
	}
	defer conn.Close()

	buf := make([]byte, 1024)
	n, _ := conn.Read(buf)
	msg := strings.TrimSpace(string(buf[:n]))

	if strings.HasPrefix(msg, "ATTACKED:") {
		attackedContainer := strings.TrimPrefix(msg, "ATTACKED:")

		fmt.Println("\n[防御软件] ⚠️ 检测到异常进程")
		sendLog("⚠️ 检测到异常进程")
		fmt.Println("[防御软件] 异常详情: 容器内发现宿主机进程")
		sendLog("异常详情: 容器内发现宿主机进程")

		fmt.Println(red("\n[防御软件] 🔴 容器正在遭受攻击"))
		sendLog("🔴 容器正在遭受攻击")
		fmt.Print(red("[防御软件] 请输入root密码强制终止容器: "))

		password, _ := reader.ReadString('\n')
		password = strings.TrimSpace(password)

		if password != "root" {
			fmt.Println(red("[防御软件] 密码错误"))
			sendLog("密码错误，终止失败")
			return
		}

		fmt.Println("[防御软件] 密码正确")
		sendLog("密码正确")
		fmt.Printf("[防御软件] 正在强制终止容器 %s...\n", attackedContainer)
		sendLog(fmt.Sprintf("正在强制终止容器 %s...", attackedContainer))

		cmd := exec.Command("docker", "stop", attackedContainer)
		output, err := cmd.CombinedOutput()
		if err != nil {
			fmt.Printf("[防御软件] 终止失败: %s\n", string(output))
			sendLog(fmt.Sprintf("终止失败: %s", string(output)))
		} else {
			fmt.Printf("[防御软件] 容器已停止: %s", string(output))
			sendLog(fmt.Sprintf("容器已停止: %s", string(output)))
		}

		fmt.Println("[防御软件] 监控结束")
		sendLog("监控结束")
	}

	fmt.Println("\n按回车键退出...")
	reader.ReadString('\n')
}
