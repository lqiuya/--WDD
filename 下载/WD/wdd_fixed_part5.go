
func (a *App) restartWithHarden(containerID string, config ContainerOriginalConfig, optIDs []string) (string, error) {
	var msg strings.Builder

	// 停止容器
	_, err := a.runSudoCommand("docker", "stop", containerID)
	if err != nil {
		return "", fmt.Errorf("停止容器失败: %v", err)
	}

	// 获取容器名称用于新容器
	nameOutput, _ := a.runSudoCommand("docker", "inspect", "--format", "{{.Name}}", containerID)
	containerName := strings.TrimPrefix(strings.TrimSpace(nameOutput), "/")

	// 构建新容器参数
	var args []string
	args = append(args, "run", "-d")

	// 名称
	if containerName != "" {
		args = append(args, "--name", containerName+"_hardened")
	}

	// 环境变量
	for _, env := range config.Env {
		args = append(args, "-e", env)
	}

	// 挂载
	for _, vol := range config.Volumes {
		args = append(args, "-v", vol)
	}

	// 端口
	for _, port := range config.Ports {
		args = append(args, "-p", port)
	}

	// 工作目录
	if config.WorkingDir != "" {
		args = append(args, "-w", config.WorkingDir)
	}

	// 重启策略
	if config.RestartPolicy != "" && config.RestartPolicy != "no" {
		args = append(args, "--restart", config.RestartPolicy)
	}

	// 网络
	for _, net := range config.Networks {
		args = append(args, "--network", net)
	}

	// 应用加固选项
	for _, optID := range optIDs {
		switch optID {
		case "drop_privileged":
			// 不加 --privileged 就是默认非特权
		case "drop_capabilities":
			args = append(args, "--cap-drop=ALL")
		case "non_root_user":
			args = append(args, "--user", "1000:1000")
		case "seccomp":
			seccompPath := filepath.Join(os.TempDir(), "wdd-seccomp.json")
			os.WriteFile(seccompPath, []byte(defaultSeccompProfile), 0644)
			args = append(args, "--security-opt", fmt.Sprintf("seccomp=%s", seccompPath))
		case "apparmor":
			args = append(args, "--security-opt", "apparmor=docker-default")
		case "read_only_rootfs":
			args = append(args, "--read-only")
		case "no_new_privileges":
			args = append(args, "--security-opt", "no-new-privileges:true")
		}
	}

	// 镜像和命令
	args = append(args, config.Image)
	if len(config.Cmd) > 0 {
		args = append(args, config.Cmd...)
	}

	// 启动新容器
	newIDOutput, err := a.runSudoCommand("docker", args...)
	if err != nil {
		// 启动失败，尝试恢复旧容器
		_, restoreErr := a.runSudoCommand("docker", "start", containerID)
		if restoreErr != nil {
			return "", fmt.Errorf("启动新容器失败且无法恢复旧容器: %v / %v", err, restoreErr)
		}
		return "", fmt.Errorf("启动新容器失败，已恢复旧容器: %v", err)
	}

	newID := strings.TrimSpace(newIDOutput)

	// 删除旧容器
	_, _ = a.runSudoCommand("docker", "rm", containerID)

	// 重命名新容器
	if containerName != "" {
		_, _ = a.runSudoCommand("docker", "rename", newID, containerName)
	}

	msg.WriteString(fmt.Sprintf("容器已重启加固，新ID: %s\n", newID))
	msg.WriteString("应用的加固措施:\n")
	for _, opt := range optIDs {
		switch opt {
		case "drop_privileged":
			msg.WriteString("  - 已移除特权模式\n")
		case "drop_capabilities":
			msg.WriteString("  - 已丢弃所有Capabilities\n")
		case "non_root_user":
			msg.WriteString("  - 已切换为非root用户(UID:1000)\n")
		case "seccomp":
			msg.WriteString("  - 已启用seccomp系统调用过滤\n")
		case "apparmor":
			msg.WriteString("  - 已启用AppArmor文件访问控制\n")
		case "read_only_rootfs":
			msg.WriteString("  - 已启用只读根文件系统\n")
		case "no_new_privileges":
			msg.WriteString("  - 已禁止提权(no-new-privileges)\n")
		}
	}

	return msg.String(), nil
}

var defaultSeccompProfile = `{
  "defaultAction": "SCMP_ACT_ERRNO",
  "architectures": ["SCMP_ARCH_X86_64", "SCMP_ARCH_X86", "SCMP_ARCH_AARCH64"],
  "syscalls": [
    {
      "names": [
        "accept", "accept4", "access", "adjtimex", "alarm", "bind",
        "brk", "capget", "capset", "chdir", "chmod", "chown", "chown32",
        "clock_adjtime", "clock_getres", "clock_gettime", "clock_nanosleep",
        "close", "connect", "copy_file_range", "creat", "dup", "dup2",
        "dup3", "epoll_create", "epoll_create1", "epoll_ctl", "epoll_ctl_old",
        "epoll_pwait", "epoll_wait", "epoll_wait_old", "eventfd", "eventfd2",
        "execve", "execveat", "exit", "exit_group", "faccessat", "fadvise64",
        "fadvise64_64", "fallocate", "fanotify_mark", "fchdir", "fchmod",
        "fchmodat", "fchown", "fchown32", "fchownat", "fcntl", "fcntl64",
        "fdatasync", "fgetxattr", "flistxattr", "flock", "fork", "fremovexattr",
        "fsetxattr", "fstat", "fstat64", "fstatat64", "fstatfs", "fstatfs64",
        "fsync", "ftruncate", "ftruncate64", "futex", "getcpu", "getcwd",
        "getdents", "getdents64", "getegid", "getegid32", "geteuid",
        "geteuid32", "getgid", "getgid32", "getgroups", "getgroups32",
        "getitimer", "getpeername", "getpgid", "getpgrp", "getpid",
        "getppid", "getpriority", "getrandom", "getresgid", "getresgid32",
        "getresuid", "getresuid32", "getrlimit", "get_robust_list", "getrusage",
        "getsid", "getsockname", "getsockopt", "get_thread_area", "gettid",
        "gettimeofday", "getuid", "getuid32", "getxattr", "inotify_add_watch",
        "inotify_init", "inotify_init1", "inotify_rm_watch", "io_cancel",
        "ioctl", "io_destroy", "io_getevents", "io_pgetevents", "ioprio_get",
        "ioprio_set", "io_setup", "io_submit", "io_uring_enter", "io_uring_register",
        "io_uring_setup", "kill", "lchown", "lchown32", "lgetxattr", "link",
        "linkat", "listen", "listxattr", "llistxattr", "lremovexattr",
        "lseek", "lsetxattr", "lstat", "lstat64", "madvise", "memfd_create",
        "mincore", "mkdir", "mkdirat", "mknod", "mknodat", "mlock", "mlock2",
        "mlockall", "mmap", "mmap2", "mprotect", "mq_getsetattr", "mq_notify",
        "mq_open", "mq_timedreceive", "mq_timedsend", "mq_unlink", "mremap",
        "msgctl", "msgget", "msgrcv", "msgsnd", "msync", "munlock", "munlockall",
        "munmap", "nanosleep", "newfstatat", "open", "openat", "pause",
        "pidfd_open", "pidfd_send_signal", "pipe", "pipe2", "pivot_root",
        "poll", "ppoll", "prctl", "pread64", "preadv", "preadv2", "prlimit64",
        "pselect6", "pwrite64", "pwritev", "pwritev2", "read", "readahead",
        "readdir", "readlink", "readlinkat", "readv", "recv", "recvfrom",
        "recvmmsg", "recvmsg", "remap_file_pages", "removexattr", "rename",
        "renameat", "renameat2", "restart_syscall", "rmdir", "rseq", "rt_sigaction",
        "rt_sigpending", "rt_sigprocmask", "rt_sigqueueinfo", "rt_sigreturn",
        "rt_sigsuspend", "rt_sigtimedwait", "rt_tgsigqueueinfo", "sched_getaffinity",
        "sched_getattr", "sched_getparam", "sched_get_priority_max",
        "sched_get_priority_min", "sched_getscheduler", "sched_rr_get_interval",
        "sched_setaffinity", "sched_setattr", "sched_setparam", "sched_setscheduler",
        "sched_yield", "seccomp", "select", "semctl", "semget", "semop",
        "semtimedop", "send", "sendfile", "sendfile64", "sendmmsg", "sendmsg",
        "sendto", "setfsgid", "setfsgid32", "setfsuid", "setfsuid32", "setgid",
        "setgid32", "setgroups", "setgroups32", "setitimer", "setpgid", "setpriority",
        "setregid", "setregid32", "setresgid", "setresgid32", "setresuid",
        "setresuid32", "setreuid", "setreuid32", "setrlimit", "set_robust_list",
        "setsid", "setsockopt", "set_thread_area", "set_tid_address", "setuid",
        "setuid32", "setxattr", "shmat", "shmctl", "shmdt", "shmget", "shutdown",
        "sigaltstack", "signalfd", "signalfd4", "sigpending", "sigprocmask",
        "sigreturn", "socket", "socketcall", "socketpair", "splice", "stat",
        "stat64", "statfs", "statfs64", "statx", "symlink", "symlinkat", "sync",
        "sync_file_range", "syncfs", "sysinfo", "tee", "tgkill", "time",
        "timer_create", "timer_delete", "timer_getoverrun", "timer_gettime",
        "timer_settime", "timerfd_create", "timerfd_gettime", "timerfd_settime",
        "times", "tkill", "truncate", "truncate64", "ugetrlimit", "umask",
        "uname", "unlink", "unlinkat", "utime", "utimensat", "utimes", "vfork",
        "wait4", "waitid", "waitpid", "write", "writev"
      ],
      "action": "SCMP_ACT_ALLOW"
    }
  ]
}`

// ==================== 工具检查 ====================

type ToolStatus struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Installed   bool   `json:"installed"`
	Version     string `json:"version"`
	InstallCmd  string `json:"installCmd"`
}

func (a *App) CheckTools() []ToolStatus {
	tools := []ToolStatus{
		{
			Name:        "nmap",
			Description: "网络扫描和安全审计工具",
			InstallCmd:  "sudo apt-get install -y nmap",
		},
		{
			Name:        "whois",
			Description: "域名信息查询工具",
			InstallCmd:  "sudo apt-get install -y whois",
		},
		{
			Name:        "chromium",
			Description: "网页截图和浏览器工具",
			InstallCmd:  "sudo apt-get install -y chromium",
		},
		{
			Name:        "docker",
			Description: "容器运行时环境",
			InstallCmd:  "curl -fsSL https://get.docker.com | sh",
		},
		{
			Name:        "dig",
			Description: "DNS查询工具(dnsutils包)",
			InstallCmd:  "sudo apt-get install -y dnsutils",
		},
		{
			Name:        "traceroute",
			Description: "路由追踪工具",
			InstallCmd:  "sudo apt-get install -y traceroute",
		},
	}

	for i := range tools {
		cmd := exec.Command("which", tools[i].Name)
		output, err := cmd.CombinedOutput()
		if err == nil && strings.TrimSpace(string(output)) != "" {
			tools[i].Installed = true
			versionCmd := exec.Command(tools[i].Name, "--version")
			versionOutput, _ := versionCmd.CombinedOutput()
			versionStr := string(versionOutput)
			lines := strings.Split(versionStr, "\n")
			if len(lines) > 0 {
				tools[i].Version = strings.TrimSpace(lines[0])
			}
		} else {
			if tools[i].Name == "dig" {
				cmd = exec.Command("dpkg", "-l", "dnsutils")
				output, err = cmd.CombinedOutput()
				if err == nil && strings.Contains(string(output), "ii") {
					tools[i].Installed = true
					tools[i].Version = "dnsutils已安装"
				}
			}
			if tools[i].Name == "docker" {
				cmd = exec.Command("docker", "--version")
				output, err = cmd.CombinedOutput()
				if err == nil {
					tools[i].Installed = true
					versionStr := string(output)
					lines := strings.Split(versionStr, "\n")
					if len(lines) > 0 {
						tools[i].Version = strings.TrimSpace(lines[0])
					}
				}
			}
		}
	}

	return tools
}

func (a *App) InstallTool(name string) string {
	tools := a.CheckTools()
	for _, tool := range tools {
		if tool.Name == name {
			if tool.Installed {
				return fmt.Sprintf("%s 已经安装", name)
			}
			cmd := exec.Command("bash", "-c", tool.InstallCmd)
			output, err := cmd.CombinedOutput()
			if err != nil {
				return fmt.Sprintf("安装失败: %v\n%s", err, string(output))
			}
			return fmt.Sprintf("%s 安装成功\n%s", name, string(output))
		}
	}
	return fmt.Sprintf("未找到工具: %s", name)
}

// ==================== Root状态检查 ====================

type RootStatus struct {
	HasRoot bool `json:"hasRoot"`
}

func (a *App) CheckRootStatus() RootStatus {
	return RootStatus{HasRoot: a.rootPassword != ""}
}

// ==================== 通用命令执行 ====================

func (a *App) runCommand(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	cmd.Env = os.Environ()
	output, err := cmd.CombinedOutput()
	return string(output), err
}

// ==================== main ====================

func main() {
	app := NewApp()

	err := wails.Run(&options.App{
		Title:  "W-DD 看守者-防线部署",
		Width:  1200,
		Height: 800,
		AssetServer: &assetserver.Options{
			Assets: assets,
		},
		BackgroundColour: &options.RGBA{R: 10, G: 10, B: 15, A: 1},
		OnStartup:        app.startup,
		Bind: []interface{}{
			app,
		},
	})

	if err != nil {
		println("Error:", err.Error())
	}
}
