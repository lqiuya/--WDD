
// ==================== 容器扫描 ====================

type ContainerScanResult struct {
	Success    bool              `json:"success"`
	TotalProcs int               `json:"totalProcs"`
	RiskStats  map[string]int    `json:"riskStats"`
	Processes  []ContainerProcess `json:"processes"`
	Error      string            `json:"error"`
}

type ContainerProcess struct {
	Name          string   `json:"name"`
	PID           int      `json:"pid"`
	User          string   `json:"user"`
	Status        string   `json:"status"`
	RiskLevel     string   `json:"riskLevel"`
	RiskScore     int      `json:"riskScore"`
	RiskFlags     []string `json:"riskFlags"`
	ContainerType string   `json:"containerType"`
	InnerInfo     string   `json:"innerInfo"`
	ID            string   `json:"id"`
}

func (a *App) ScanContainers(scanType string) ContainerScanResult {
	result := ContainerScanResult{
		Success:   true,
		RiskStats: make(map[string]int),
		Processes: []ContainerProcess{},
	}

	if a.rootPassword == "" {
		result.Success = false
		result.Error = "请先赋予root权限"
		return result
	}

	// 统一使用sudo执行docker ps
	dockerOutput, err := a.runSudoCommand("docker", "ps", "-a", "--format", "{{.ID}}|{{.Image}}|{{.Names}}|{{.Status}}|{{.Ports}}")
	if err != nil || strings.Contains(dockerOutput, "Cannot connect") {
		result.Success = true
		result.Error = "Docker服务未运行或未安装"
		return result
	}

	dockerOutput = strings.ReplaceAll(dockerOutput, "\r", "")
	lines := strings.Split(dockerOutput, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		parts := strings.Split(line, "|")
		if len(parts) < 3 {
			continue
		}

		containerID := parts[0]
		image := parts[1]
		name := parts[2]
		status := "exited"
		ports := ""
		if len(parts) >= 4 {
			statusStr := strings.ToLower(parts[3])
			if strings.HasPrefix(statusStr, "up") {
				status = "running"
			} else if strings.Contains(statusStr, "paused") {
				status = "paused"
			} else if strings.Contains(statusStr, "created") {
				status = "created"
			}
		}
		if len(parts) >= 5 {
			ports = parts[4]
		}

		process := ContainerProcess{
			Name:          name,
			ID:            containerID,
			User:          "root",
			Status:        status,
			ContainerType: "docker",
			RiskFlags:     []string{},
		}

		// 风险评估
		score := 0
		flags := []string{}

		// 快速扫描
		inspectOutput, _ := a.runSudoCommand("docker", "inspect", "--format", "{{.HostConfig.Privileged}}|{{.HostConfig.PidMode}}|{{.HostConfig.NetworkMode}}|{{.HostConfig.IpcMode}}", containerID)
		inspectParts := strings.Split(strings.TrimSpace(inspectOutput), "|")
		if len(inspectParts) >= 1 && inspectParts[0] == "true" {
			score += 50
			flags = append(flags, "特权模式")
		}
		if len(inspectParts) >= 2 && inspectParts[1] == "host" {
			score += 30
			flags = append(flags, "Host PID命名空间")
		}
		if len(inspectParts) >= 3 && inspectParts[2] == "host" {
			score += 20
			flags = append(flags, "Host网络模式")
		}
		if len(inspectParts) >= 4 && inspectParts[3] == "host" {
			score += 20
			flags = append(flags, "Host IPC命名空间")
		}

		// 端口暴露检查
		if ports != "" && ports != "<no value>" {
			portList := strings.Split(ports, ", ")
			for _, p := range portList {
				if strings.Contains(p, "0.0.0.0:") {
					score += 5
					flags = append(flags, "端口暴露: "+p)
				}
			}
		}

		// 标准扫描
		if scanType == "standard" || scanType == "full" {
			capOutput, _ := a.runSudoCommand("docker", "inspect", "--format", "{{.HostConfig.CapAdd}}", containerID)
			if capOutput != "<no value>" && capOutput != "[]" && capOutput != "" {
				score += 15
				flags = append(flags, "额外Capabilities")
			}

			mountOutput, _ := a.runSudoCommand("docker", "inspect", "--format", "{{range .Mounts}}{{.Source}}:{{.Destination}}|{{end}}", containerID)
			if strings.Contains(mountOutput, "/") {
				mounts := strings.Split(mountOutput, "|")
				for _, m := range mounts {
					if m == "" {
						continue
					}
					if strings.Contains(m, ":/etc") || strings.Contains(m, ":/var") || strings.Contains(m, ":/usr") {
						score += 10
						flags = append(flags, "敏感目录挂载: "+m)
					}
					if strings.Contains(m, "docker.sock") {
						score += 40
						flags = append(flags, "Docker Socket挂载!")
					}
				}
			}

			userOutput, _ := a.runSudoCommand("docker", "inspect", "--format", "{{.Config.User}}", containerID)
			if userOutput == "" || userOutput == "root" || userOutput == "<no value>" {
				score += 10
				flags = append(flags, "以root运行")
			}
		}

		// 完整扫描
		if scanType == "full" {
			envOutput, _ := a.runSudoCommand("docker", "inspect", "--format", "{{range .Config.Env}}{{.}}\n{{end}}", containerID)
			envLines := strings.Split(envOutput, "\n")
			for _, env := range envLines {
				envUpper := strings.ToUpper(env)
				if (strings.Contains(envUpper, "PASSWORD") || strings.Contains(envUpper, "SECRET") || 
				    strings.Contains(envUpper, "TOKEN") || strings.Contains(envUpper, "API_KEY") ||
				    strings.Contains(envUpper, "PRIVATE_KEY") || strings.Contains(envUpper, "CREDENTIAL")) &&
				   !strings.Contains(envUpper, "SSH_AUTH_SOCK") && !strings.Contains(envUpper, "GPG_AGENT") {
					score += 15
					flags = append(flags, "敏感环境变量")
					break
				}
			}

			roOutput, _ := a.runSudoCommand("docker", "inspect", "--format", "{{.HostConfig.ReadonlyRootfs}}", containerID)
			if roOutput != "true" {
				score += 5
				flags = append(flags, "根目录可写")
			}

			nnpOutput, _ := a.runSudoCommand("docker", "inspect", "--format", "{{.HostConfig.SecurityOpt}}", containerID)
			if !strings.Contains(nnpOutput, "no-new-privileges") {
				score += 5
				flags = append(flags, "未限制提权")
			}
		}

		// 确定风险等级
		if status != "running" {
			process.RiskLevel = "已停止"
			process.RiskScore = 0
		} else if score >= 60 {
			process.RiskLevel = "严重"
			process.RiskScore = score
		} else if score >= 40 {
			process.RiskLevel = "高危"
			process.RiskScore = score
		} else if score >= 20 {
			process.RiskLevel = "中危"
			process.RiskScore = score
		} else {
			process.RiskLevel = "安全"
			process.RiskScore = score
		}
		process.RiskFlags = flags

		// 生成innerInfo
		var info strings.Builder
		info.WriteString(fmt.Sprintf("容器: %s (ID: %s)\n", name, containerID))
		info.WriteString(fmt.Sprintf("镜像: %s\n", image))
		info.WriteString(fmt.Sprintf("状态: %s\n", status))
		info.WriteString(fmt.Sprintf("端口: %s\n", ports))
		info.WriteString(fmt.Sprintf("风险评分: %d\n", score))
		info.WriteString(fmt.Sprintf("风险等级: %s\n", process.RiskLevel))
		if len(flags) > 0 {
			info.WriteString("风险标记:\n")
			for _, f := range flags {
				info.WriteString(fmt.Sprintf("  - %s\n", f))
			}
		}
		process.InnerInfo = info.String()

		result.Processes = append(result.Processes, process)
		result.RiskStats[process.RiskLevel]++
	}

	result.TotalProcs = len(result.Processes)
	return result
}
