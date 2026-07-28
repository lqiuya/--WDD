
// ==================== 容器加固 ====================

type HardenContainer struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Image  string `json:"image"`
	Status string `json:"status"`
}

func (a *App) GetHardenContainers() []HardenContainer {
	var containers []HardenContainer

	if a.rootPassword == "" {
		return containers
	}

	// 统一使用sudo
	output, err := a.runSudoCommand("docker", "ps", "-a", "--format", "{{.ID}}|{{.Names}}|{{.Image}}|{{.Status}}")
	if err != nil {
		return containers
	}

	output = strings.ReplaceAll(output, "\r", "")
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.Split(line, "|")
		if len(parts) >= 3 {
			status := "exited"
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
			containers = append(containers, HardenContainer{
				ID:     parts[0],
				Name:   parts[1],
				Image:  parts[2],
				Status: status,
			})
		}
	}
	return containers
}

type HardenTask struct {
	ContainerID   string   `json:"container_id"`
	ContainerName string   `json:"container_name"`
	Options       []string `json:"options"`
}

type HardenRequest struct {
	Tasks []HardenTask `json:"tasks"`
}

type HardenResult struct {
	Success       bool   `json:"success"`
	ContainerID   string `json:"container_id"`
	ContainerName string `json:"container_name"`
	Message       string `json:"message"`
}

type HardenResponse struct {
	Results []HardenResult `json:"results"`
}

func (a *App) DoHarden(req HardenRequest) HardenResponse {
	var response HardenResponse

	for _, task := range req.Tasks {
		result := HardenResult{
			ContainerID:   task.ContainerID,
			ContainerName: task.ContainerName,
		}

		// 获取容器原始配置
		config, err := a.getContainerOriginalConfig(task.ContainerID)
		if err != nil {
			result.Success = false
			result.Message = fmt.Sprintf("获取配置失败: %v", err)
			response.Results = append(response.Results, result)
			continue
		}

		// 分离动态和重启加固选项
		var dynamicOpts []string
		var restartOpts []string
		for _, opt := range task.Options {
			switch opt {
			case "network_isolate", "cgroups_limit", "pause":
				dynamicOpts = append(dynamicOpts, opt)
			default:
				restartOpts = append(restartOpts, opt)
			}
		}

		// 执行动态加固
		for _, opt := range dynamicOpts {
			switch opt {
			case "network_isolate":
				_, err := a.runSudoCommand("docker", "network", "disconnect", "bridge", task.ContainerID)
				if err != nil {
					result.Message += "网络隔离失败; "
				} else {
					result.Message += "网络隔离成功; "
				}
			case "cgroups_limit":
				_, err := a.runSudoCommand("docker", "update", "--cpus", "0.5", "--memory", "512m", task.ContainerID)
				if err != nil {
					result.Message += "资源限制失败; "
				} else {
					result.Message += "资源限制成功; "
				}
			case "pause":
				_, err := a.runSudoCommand("docker", "pause", task.ContainerID)
				if err != nil {
					result.Message += "容器暂停失败; "
				} else {
					result.Message += "容器暂停成功; "
				}
			}
		}

		// 执行重启加固
		if len(restartOpts) > 0 {
			msg, err := a.restartWithHarden(task.ContainerID, config, restartOpts)
			if err != nil {
				result.Success = false
				result.Message += fmt.Sprintf("重启加固失败: %v", err)
			} else {
				result.Success = true
				result.Message += msg
			}
		} else {
			result.Success = true
			if result.Message == "" {
				result.Message = "动态加固完成"
			}
		}

		response.Results = append(response.Results, result)
	}

	return response
}

type ContainerOriginalConfig struct {
	Image         string   `json:"image"`
	Cmd           []string `json:"cmd"`
	Env           []string `json:"env"`
	Volumes       []string `json:"volumes"`
	Ports         []string `json:"ports"`
	WorkingDir    string   `json:"working_dir"`
	RestartPolicy string   `json:"restart_policy"`
	Networks      []string `json:"networks"`
	Privileged    bool     `json:"privileged"`
	CapAdd        []string `json:"cap_add"`
	CapDrop       []string `json:"cap_drop"`
	User          string   `json:"user"`
	SecurityOpt   []string `json:"security_opt"`
	ReadonlyRootfs bool    `json:"readonly_rootfs"`
}

func (a *App) getContainerOriginalConfig(containerID string) (ContainerOriginalConfig, error) {
	var config ContainerOriginalConfig

	// 获取镜像
	imageOutput, err := a.runSudoCommand("docker", "inspect", "--format", "{{.Config.Image}}", containerID)
	if err != nil {
		return config, err
	}
	config.Image = strings.TrimSpace(imageOutput)

	// 获取命令
	cmdOutput, err := a.runSudoCommand("docker", "inspect", "--format", "{{json .Config.Cmd}}", containerID)
	if err == nil {
		var cmd []string
		json.Unmarshal([]byte(cmdOutput), &cmd)
		config.Cmd = cmd
	}

	// 获取环境变量
	envOutput, err := a.runSudoCommand("docker", "inspect", "--format", "{{json .Config.Env}}", containerID)
	if err == nil {
		var env []string
		json.Unmarshal([]byte(envOutput), &env)
		config.Env = env
	}

	// 获取挂载
	mountOutput, err := a.runSudoCommand("docker", "inspect", "--format", "{{json .Mounts}}", containerID)
	if err == nil {
		var mounts []map[string]interface{}
		json.Unmarshal([]byte(mountOutput), &mounts)
		for _, m := range mounts {
			if src, ok := m["Source"].(string); ok {
				if dst, ok := m["Destination"].(string); ok {
					config.Volumes = append(config.Volumes, fmt.Sprintf("%s:%s", src, dst))
				}
			}
		}
	}

	// 获取端口映射 - 修复变量覆盖bug
	portOutput, err := a.runSudoCommand("docker", "inspect", "--format", "{{json .HostConfig.PortBindings}}", containerID)
	if err == nil {
		var portBindings map[string]interface{}
		json.Unmarshal([]byte(portOutput), &portBindings)
		for portKey, bindings := range portBindings {
			if bindingsList, ok := bindings.([]interface{}); ok {
				for _, b := range bindingsList {
					if binding, ok := b.(map[string]interface{}); ok {
						hostIP := "0.0.0.0"
						hostPort := ""
						if ip, ok := binding["HostIp"].(string); ok && ip != "" {
							hostIP = ip
						}
						if port, ok := binding["HostPort"].(string); ok {
							hostPort = port
						}
						// 使用portKey（外层的键）而不是内层变量
						config.Ports = append(config.Ports, fmt.Sprintf("%s:%s:%s", hostIP, hostPort, portKey))
					}
				}
			}
		}
	}

	// 获取工作目录
	wdOutput, err := a.runSudoCommand("docker", "inspect", "--format", "{{.Config.WorkingDir}}", containerID)
	if err == nil {
		config.WorkingDir = strings.TrimSpace(wdOutput)
		if config.WorkingDir == "<no value>" {
			config.WorkingDir = ""
		}
	}

	// 获取重启策略
	restartOutput, err := a.runSudoCommand("docker", "inspect", "--format", "{{.HostConfig.RestartPolicy.Name}}", containerID)
	if err == nil {
		config.RestartPolicy = strings.TrimSpace(restartOutput)
		if config.RestartPolicy == "<no value>" {
			config.RestartPolicy = ""
		}
	}

	// 获取网络
	networkOutput, err := a.runSudoCommand("docker", "inspect", "--format", "{{json .NetworkSettings.Networks}}", containerID)
	if err == nil {
		var networks map[string]interface{}
		json.Unmarshal([]byte(networkOutput), &networks)
		for netName := range networks {
			config.Networks = append(config.Networks, netName)
		}
	}

	// 获取privileged
	privOutput, err := a.runSudoCommand("docker", "inspect", "--format", "{{.HostConfig.Privileged}}", containerID)
	if err == nil {
		config.Privileged = strings.TrimSpace(privOutput) == "true"
	}

	// 获取CapAdd
	capAddOutput, err := a.runSudoCommand("docker", "inspect", "--format", "{{json .HostConfig.CapAdd}}", containerID)
	if err == nil {
		var capAdd []string
		json.Unmarshal([]byte(capAddOutput), &capAdd)
		config.CapAdd = capAdd
	}

	// 获取CapDrop
	capDropOutput, err := a.runSudoCommand("docker", "inspect", "--format", "{{json .HostConfig.CapDrop}}", containerID)
	if err == nil {
		var capDrop []string
		json.Unmarshal([]byte(capDropOutput), &capDrop)
		config.CapDrop = capDrop
	}

	// 获取User
	userOutput, err := a.runSudoCommand("docker", "inspect", "--format", "{{.Config.User}}", containerID)
	if err == nil {
		config.User = strings.TrimSpace(userOutput)
		if config.User == "<no value>" {
			config.User = ""
		}
	}

	// 获取SecurityOpt
	secOptOutput, err := a.runSudoCommand("docker", "inspect", "--format", "{{json .HostConfig.SecurityOpt}}", containerID)
	if err == nil {
		var secOpt []string
		json.Unmarshal([]byte(secOptOutput), &secOpt)
		config.SecurityOpt = secOpt
	}

	// 获取ReadonlyRootfs
	roOutput, err := a.runSudoCommand("docker", "inspect", "--format", "{{.HostConfig.ReadonlyRootfs}}", containerID)
	if err == nil {
		config.ReadonlyRootfs = strings.TrimSpace(roOutput) == "true"
	}

	return config, nil
}
