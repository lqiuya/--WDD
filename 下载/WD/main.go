package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/md5"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
	"github.com/wailsapp/wails/v2/pkg/runtime"
)

//go:embed all:frontend/dist
var assets embed.FS

//go:embed.gitkeep
var seccompProfileData []byte

type App struct {
	ctx          context.Context
	rootPassword string
}

func NewApp() *App {
	return &App{}
}

func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
}

func (a *App) OpenFileDialog() string {
	selection, err := runtime.OpenFileDialog(a.ctx, runtime.OpenDialogOptions{
		Title: "选择文件",
		Filters: []runtime.FileFilter{
			{DisplayName: "所有文件", Pattern: "*"},
		},
	})
	if err != nil {
		return ""
	}
	return selection
}

func (a *App) OpenDirectoryDialog() string {
	selection, err := runtime.OpenDirectoryDialog(a.ctx, runtime.OpenDialogOptions{
		Title: "选择文件夹",
	})
	if err != nil {
		return ""
	}
	return selection
}

func (a *App) SetRootPassword(password string) bool {
	// 先清除之前的密码
	a.rootPassword = ""

	// 使用 sudo -S -k id 来验证密码，检查 uid=0(root)
	cmd := exec.Command("sudo", "-S", "-k", "id")
	cmd.Stdin = strings.NewReader(password + "\n")
	output, err := cmd.CombinedOutput()
	outputStr := strings.TrimSpace(string(output))

	// 密码错误时 sudo 会返回错误
	if err != nil {
		// 检查是否是密码错误（sudo 的典型错误输出）
		if strings.Contains(outputStr, "incorrect password") ||
			strings.Contains(outputStr, "sorry, try again") ||
			strings.Contains(outputStr, "authentication failure") ||
			strings.Contains(outputStr, "password is required") ||
			strings.Contains(outputStr, "no password was provided") ||
			strings.Contains(outputStr, "3 incorrect password attempts") {
			return false
		}
		// 其他错误也视为失败
		return false
	}

	// 成功时检查输出中是否包含 root 标识
	outputLower := strings.ToLower(outputStr)
	isRoot := strings.Contains(outputLower, "uid=0") ||
		strings.Contains(outputLower, "root") ||
		strings.Contains(outputLower, "gid=0")

	if !isRoot {
		return false
	}

	a.rootPassword = password
	return true
}

func (a *App) ClearRootPassword() bool {
	a.rootPassword = ""
	return true
}

func (a *App) HasRootPassword() bool {
	return a.rootPassword != ""
}

func (a *App) CheckRootStatus() map[string]interface{} {
	return map[string]interface{}{
		"hasRoot": a.rootPassword != "",
	}
}

func (a *App) runSudoCommand(name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if a.rootPassword == "" {
		return "", fmt.Errorf("NEED_ROOT|未设置root密码，请先赋予权限")
	}
	allArgs := append([]string{"-S", "-k", name}, args...)
	cmd := exec.CommandContext(ctx, "sudo", allArgs...)
	cmd.Stdin = strings.NewReader(a.rootPassword + "\n")
	cmd.Env = os.Environ()

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()

	output := stdout.String()
	if err != nil && stderr.String() != "" {
		output = output + "\n[STDERR] " + stderr.String()
	}
	return output, err
}

func isContainerIDLine(line string) bool {
	line = strings.TrimSpace(line)
	if line == "" {
		return false
	}
	lower := strings.ToLower(line)
	if strings.HasPrefix(lower, "sudo") ||
		strings.HasPrefix(lower, "[sudo]") ||
		strings.HasPrefix(lower, "password") ||
		strings.HasPrefix(lower, "sorry") ||
		strings.HasPrefix(lower, "gcy") ||
		strings.Contains(lower, "password for") {
		return false
	}
	parts := strings.Split(line, "|")
	if len(parts) < 1 {
		return false
	}
	id := strings.TrimSpace(parts[0])
	matched, _ := regexp.MatchString(`^[a-f0-9]{12}$`, id)
	return matched
}

type InputType struct {
	Type        string `json:"type"`
	Category    string `json:"category"`
	Description string `json:"description"`
}

func (a *App) DetectInputType(rawInput string) InputType {
	input := strings.TrimSpace(rawInput)
	re := regexp.MustCompile(`[,，]\d+$`)
	input = re.ReplaceAllString(input, "")
	re2 := regexp.MustCompile(`[,，]$`)
	input = re2.ReplaceAllString(input, "")
	input = strings.TrimSpace(input)

	if input == "" {
		return InputType{Type: "empty", Category: "系统检查", Description: "空输入 - 显示系统检查功能"}
	}

	if matched, _ := regexp.MatchString(`^\d{1,3}(\.\d{1,3}){0,3}\.?$`, input); matched {
		return InputType{Type: "ip", Category: "IP/域名", Description: "IP地址"}
	}

	if matched, _ := regexp.MatchString(`^(\d{1,3}\.){3}\d{1,3}$`, input); matched {
		return InputType{Type: "ip", Category: "IP/域名", Description: "IP地址"}
	}

	if matched, _ := regexp.MatchString(`^[a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,}$`, input); matched {
		return InputType{Type: "domain", Category: "IP/域名", Description: "域名"}
	}

	if matched, _ := regexp.MatchString(`^https?://`, input); matched {
		return InputType{Type: "url", Category: "网址", Description: "网址"}
	}

	if strings.HasPrefix(input, "/") || strings.HasPrefix(input, "~/") || strings.HasPrefix(input, "./") {
		return InputType{Type: "file", Category: "文件", Description: "文件路径"}
	}

	return InputType{Type: "unknown", Category: "未知", Description: "未知类型"}
}

type FunctionItem struct {
	Code        string `json:"code"`
	Name        string `json:"name"`
	Number      int    `json:"number"`
	Category    string `json:"category"`
	Description string `json:"description"`
}

func (a *App) GetFunctions(category string) []FunctionItem {
	var functions []FunctionItem

	switch category {
	case "系统检查":
		functions = []FunctionItem{
			{Code: "LQ0000", Name: "进程监控", Number: 1, Category: "系统检查", Description: "查看系统进程信息"},
			{Code: "LQ0001", Name: "网络连接", Number: 2, Category: "系统检查", Description: "查看网络连接状态"},
			{Code: "LQ0002", Name: "防火墙配置", Number: 3, Category: "系统检查", Description: "查看防火墙规则"},
			{Code: "LQ0003", Name: "网络协议", Number: 4, Category: "系统检查", Description: "查看网络协议统计"},
			{Code: "LQ0004", Name: "系统服务", Number: 5, Category: "系统检查", Description: "查看系统服务状态"},
			{Code: "LQ0005", Name: "端口占用", Number: 6, Category: "系统检查", Description: "查看端口占用情况"},
			{Code: "LQ0006", Name: "系统信息", Number: 7, Category: "系统检查", Description: "查看系统基本信息"},
			{Code: "LQ0007", Name: "用户账户", Number: 8, Category: "系统检查", Description: "查看用户账户信息"},
			{Code: "LQ0008", Name: "定时任务", Number: 9, Category: "系统检查", Description: "查看定时任务配置"},
			{Code: "LQ0009", Name: "环境变量", Number: 10, Category: "系统检查", Description: "查看环境变量"},
		}
	case "IP/域名":
		functions = []FunctionItem{
			{Code: "LQ0010", Name: "端口扫描", Number: 1, Category: "IP/域名", Description: "扫描目标端口"},
			{Code: "LQ0011", Name: "网络连接", Number: 2, Category: "IP/域名", Description: "测试网络连接"},
			{Code: "LQ0012", Name: "HTTP状态检查", Number: 3, Category: "IP/域名", Description: "检查HTTP响应状态"},
			{Code: "LQ0013", Name: "子域名枚举", Number: 4, Category: "IP/域名", Description: "枚举子域名"},
			{Code: "LQ0014", Name: "目录爆破", Number: 5, Category: "IP/域名", Description: "爆破Web目录"},
			{Code: "LQ0015", Name: "Whois查询", Number: 6, Category: "IP/域名", Description: "查询Whois信息"},
			{Code: "LQ0016", Name: "DNS解析", Number: 7, Category: "IP/域名", Description: "DNS解析查询"},
			{Code: "LQ0017", Name: "Traceroute", Number: 8, Category: "IP/域名", Description: "路由追踪"},
		}
	case "网址":
		functions = []FunctionItem{
			{Code: "LQ0018", Name: "HTTP状态检查", Number: 1, Category: "网址", Description: "检查HTTP响应状态"},
			{Code: "LQ0019", Name: "目录爆破", Number: 2, Category: "网址", Description: "爆破Web目录"},
			{Code: "LQ0020", Name: "子域名枚举", Number: 3, Category: "网址", Description: "枚举子域名"},
			{Code: "LQ0021", Name: "网页截图", Number: 4, Category: "网址", Description: "网页截图"},
			{Code: "LQ0022", Name: "SSL证书检查", Number: 5, Category: "网址", Description: "检查SSL证书"},
			{Code: "LQ0023", Name: "响应头分析", Number: 6, Category: "网址", Description: "分析HTTP响应头"},
			{Code: "LQ0024", Name: "网页内容抓取", Number: 7, Category: "网址", Description: "抓取网页内容"},
		}
	case "文件":
		functions = []FunctionItem{
			{Code: "LQ0025", Name: "文件哈希", Number: 1, Category: "文件", Description: "计算文件哈希值"},
			{Code: "LQ0026", Name: "日志分析", Number: 2, Category: "文件", Description: "分析日志文件"},
			{Code: "LQ0027", Name: "配置检查", Number: 3, Category: "文件", Description: "检查配置文件"},
			{Code: "LQ0028", Name: "文件信息", Number: 4, Category: "文件", Description: "查看文件信息"},
			{Code: "LQ0029", Name: "文件权限", Number: 5, Category: "文件", Description: "查看文件权限"},
			{Code: "LQ0030", Name: "文件类型识别", Number: 6, Category: "文件", Description: "识别文件类型"},
		}
	}

	return functions
}

type ExecuteResult struct {
	Success   bool   `json:"success"`
	Function  string `json:"function"`
	Output    string `json:"output"`
	Error     string `json:"error"`
	Timestamp string `json:"timestamp"`
	NeedRoot  bool   `json:"needRoot"`
	RootMsg   string `json:"rootMsg"`
}

func (a *App) ExecuteFunction(code string, input string) ExecuteResult {
	result := ExecuteResult{
		Function:  code,
		Timestamp: time.Now().Format("2006-01-02 15:04:05"),
	}

	needRootFuncs := map[string]bool{
		"LQ0002": true, "LQ0005": true, "LQ0008": true,
		"LQ0010": true, "LQ0017": true,
	}

	if needRootFuncs[code] && a.rootPassword == "" {
		result.Success = false
		result.NeedRoot = true
		result.RootMsg = "该功能需要root权限，请先赋予权限"
		result.Error = "权限不足：需要root权限执行"
		return result
	}

	var output string
	var err error

	switch code {
	case "LQ0000":
		output, err = a.runCommand("ps", "aux", "--sort=-%cpu")
	case "LQ0001":
		output, err = a.runCommand("ss", "-tunap")
	case "LQ0002":
		output, err = a.runSudoCommand("iptables", "-L", "-n", "-v")
		if err != nil {
			output, err = a.runSudoCommand("nft", "list", "ruleset")
		}
	case "LQ0003":
		output, err = a.runCommand("ss", "-s")
	case "LQ0004":
		output, err = a.runCommand("systemctl", "list-units", "--type=service", "--state=running")
	case "LQ0005":
		output, err = a.runSudoCommand("ss", "-tlnp")
	case "LQ0006":
		output, err = a.runCommand("uname", "-a")
		if err == nil {
			out2, _ := a.runCommand("cat", "/etc/os-release")
			output += "\n\n" + out2
		}
	case "LQ0007":
		output, err = a.runCommand("cat", "/etc/passwd")
	case "LQ0008":
		output, err = a.runSudoCommand("crontab", "-l")
		if err != nil {
			output, err = a.runSudoCommand("cat", "/etc/crontab")
		}
	case "LQ0009":
		output, err = a.runCommand("env")
	case "LQ0010":
		goOutput, _ := a.goPortScan(input)
		if a.rootPassword != "" {
			nmapOutput, nmapErr := a.runSudoCommand("nmap", "-sS", "-p", "21,22,23,25,53,80,110,143,443,445,3306,3389,5432,8080,8443,8888,9000,9200,27017", input)
			if nmapErr == nil {
				output = "===== Go端口扫描 =====\n" + goOutput + "\n===== Nmap详细扫描 =====\n" + nmapOutput
			} else {
				output = goOutput + "\n\n[Nmap扫描需要root权限或nmap未安装]"
			}
		} else {
			output = goOutput + "\n\n[提示：赋予root权限后可使用nmap进行更详细的SYN扫描]"
		}
	case "LQ0011":
		output, err = a.runCommand("ping", "-c", "4", input)
	case "LQ0012":
		output, err = a.runCommand("curl", "-I", "-s", "-o", "/dev/null", "-w", "HTTP Code: %{http_code}\nTime: %{time_total}s\nSize: %{size_download}\n", "http://"+input)
	case "LQ0013":
		output, err = a.goSubdomainEnum(input)
	case "LQ0014":
		output, err = a.goDirBrute(input)
	case "LQ0015":
		output, err = a.runCommand("whois", input)
	case "LQ0016":
		output, err = a.runCommand("dig", input)
		if err != nil {
			output, err = a.runCommand("nslookup", input)
		}
	case "LQ0017":
		output, err = a.runSudoCommand("traceroute", input)
		if err != nil {
			output, err = a.runSudoCommand("tracepath", input)
		}
	case "LQ0018":
		output, err = a.runCommand("curl", "-I", "-s", "-o", "/dev/null", "-w", "HTTP Code: %{http_code}\nTime: %{time_total}s\nSize: %{size_download}\n", input)
	case "LQ0019":
		output, err = a.goDirBrute(input)
	case "LQ0020":
		output, err = a.goSubdomainEnum(input)
	case "LQ0021":
		output, err = a.runCommand("chromium", "--headless", "--screenshot=/tmp/screenshot.png", "--window-size=1920,1080", input)
		if err != nil {
			output, err = a.runCommand("chromium-browser", "--headless", "--screenshot=/tmp/screenshot.png", "--window-size=1920,1080", input)
		}
		if err == nil {
			output = "截图已保存至 /tmp/screenshot.png"
		}
	case "LQ0022":
		output, err = a.runCommand("openssl", "s_client", "-connect", strings.Replace(input, "https://", "", 1)+":443", "-servername", strings.Replace(input, "https://", "", 1), "-no_ign_eof")
	case "LQ0023":
		output, err = a.runCommand("curl", "-I", "-s", input)
	case "LQ0024":
		output, err = a.runCommand("curl", "-s", "-L", input)
	case "LQ0025":
		output, err = a.goFileHash(input)
	case "LQ0026":
		output, err = a.goLogAnalysis(input)
	case "LQ0027":
		output, err = a.goConfigCheck(input)
	case "LQ0028":
		output, err = a.runCommand("ls", "-lah", input)
		if err == nil {
			out2, _ := a.runCommand("file", input)
			output += "\n" + out2
		}
	case "LQ0029":
		output, err = a.runCommand("ls", "-la", input)
	case "LQ0030":
		output, err = a.runCommand("file", input)
	default:
		output = fmt.Sprintf("功能 %s 暂未实现", code)
	}

	if err != nil {
		result.Success = false
		result.Error = err.Error()
		result.Output = output
	} else {
		result.Success = true
		result.Output = output
	}

	return result
}

func (a *App) goPortScan(host string) (string, error) {
	var result strings.Builder
	result.WriteString(fmt.Sprintf("端口扫描 - 目标: %s\n", host))
	result.WriteString("扫描常用端口...\n\n")

	commonPorts := []int{21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 8080, 8443, 8888, 9000, 9200, 27017}
	openPorts := []int{}

	for _, port := range commonPorts {
		address := fmt.Sprintf("%s:%d", host, port)
		conn, err := net.DialTimeout("tcp", address, 2*time.Second)
		if err == nil {
			conn.Close()
			openPorts = append(openPorts, port)
			result.WriteString(fmt.Sprintf("[OPEN] %d/tcp\n", port))
		}
	}

	result.WriteString(fmt.Sprintf("\n扫描完成，共发现 %d 个开放端口\n", len(openPorts)))
	return result.String(), nil
}

func (a *App) goSubdomainEnum(domain string) (string, error) {
	var result strings.Builder
	result.WriteString(fmt.Sprintf("子域名枚举 - 目标: %s\n", domain))
	result.WriteString("使用DNS查询枚举...\n\n")

	subdomains := []string{"www", "mail", "ftp", "admin", "api", "blog", "shop", "test", "dev", "staging", "portal", "vpn", "cdn", "img", "static", "m", "mobile", "app", "webmail", "remote"}
	found := []string{}

	for _, sub := range subdomains {
		testDomain := fmt.Sprintf("%s.%s", sub, domain)
		_, err := net.LookupHost(testDomain)
		if err == nil {
			found = append(found, testDomain)
			result.WriteString(fmt.Sprintf("[FOUND] %s\n", testDomain))
		}
	}

	result.WriteString(fmt.Sprintf("\n枚举完成，共发现 %d 个子域名\n", len(found)))
	return result.String(), nil
}

func (a *App) goDirBrute(target string) (string, error) {
	var result strings.Builder
	result.WriteString(fmt.Sprintf("目录爆破 - 目标: %s\n", target))
	result.WriteString("使用HTTP请求爆破...\n\n")

	paths := []string{"/", "/admin", "/login", "/api", "/config", "/backup", "/test", "/dev", "/tmp", "/upload", "/images", "/css", "/js", "/robots.txt", "/.git", "/.env", "/phpmyadmin", "/wp-admin", "/admin.php", "/config.php"}
	found := []string{}

	client := &http.Client{Timeout: 5 * time.Second}

	for _, path := range paths {
		url := target
		if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
			url = "http://" + url
		}
		url = url + path

		resp, err := client.Head(url)
		if err != nil {
			continue
		}
		resp.Body.Close()

		if resp.StatusCode != 404 && resp.StatusCode != 403 {
			found = append(found, fmt.Sprintf("%s [%d]", path, resp.StatusCode))
			result.WriteString(fmt.Sprintf("[FOUND] %s - HTTP %d\n", path, resp.StatusCode))
		}
	}

	result.WriteString(fmt.Sprintf("\n爆破完成，共发现 %d 个目录\n", len(found)))
	return result.String(), nil
}

func (a *App) goFileHash(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	md5Hash := md5.New()
	sha256Hash := sha256.New()

	if _, err := io.Copy(md5Hash, file); err != nil {
		return "", err
	}

	file.Seek(0, 0)
	if _, err := io.Copy(sha256Hash, file); err != nil {
		return "", err
	}

	result := fmt.Sprintf("MD5:    %s\nSHA256: %s", hex.EncodeToString(md5Hash.Sum(nil)), hex.EncodeToString(sha256Hash.Sum(nil)))
	return result, nil
}

func (a *App) goLogAnalysis(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	var result strings.Builder
	result.WriteString(fmt.Sprintf("日志分析 - 文件: %s\n\n", filePath))

	scanner := bufio.NewScanner(file)
	lineCount := 0
	errorCount := 0
	warningCount := 0

	for scanner.Scan() && lineCount < 100 {
		line := scanner.Text()
		lineCount++
		if strings.Contains(strings.ToLower(line), "error") {
			errorCount++
			result.WriteString(fmt.Sprintf("[ERROR] %s\n", line))
		} else if strings.Contains(strings.ToLower(line), "warn") {
			warningCount++
			result.WriteString(fmt.Sprintf("[WARN]  %s\n", line))
		}
	}

	result.WriteString(fmt.Sprintf("\n分析完成: 共 %d 行, %d 个错误, %d 个警告\n", lineCount, errorCount, warningCount))
	return result.String(), nil
}

func (a *App) goConfigCheck(filePath string) (string, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return "", err
	}

	content := string(data)
	var result strings.Builder
	result.WriteString(fmt.Sprintf("配置检查 - 文件: %s\n\n", filePath))

	checks := []struct {
		pattern string
		msg     string
	}{
		{"password", "发现密码关键词"},
		{"secret", "发现密钥关键词"},
		{"token", "发现Token关键词"},
		{"api_key", "发现API Key关键词"},
		{"private_key", "发现私钥关键词"},
		{"root", "发现root关键词"},
		{"chmod 777", "发现危险权限配置"},
		{"0.0.0.0", "发现开放监听配置"},
	}

	issues := 0
	for _, check := range checks {
		if strings.Contains(strings.ToLower(content), check.pattern) {
			issues++
			result.WriteString(fmt.Sprintf("[!] %s\n", check.msg))
		}
	}

	result.WriteString(fmt.Sprintf("\n检查完成: 发现 %d 个潜在问题\n", issues))
	return result.String(), nil
}

var allCapabilities = []string{
	"CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_DAC_READ_SEARCH", "CAP_FOWNER",
	"CAP_FSETID", "CAP_KILL", "CAP_SETGID", "CAP_SETUID", "CAP_SETPCAP",
	"CAP_LINUX_IMMUTABLE", "CAP_NET_BIND_SERVICE", "CAP_NET_BROADCAST",
	"CAP_NET_ADMIN", "CAP_NET_RAW", "CAP_IPC_LOCK", "CAP_IPC_OWNER",
	"CAP_SYS_MODULE", "CAP_SYS_RAWIO", "CAP_SYS_CHROOT", "CAP_SYS_PTRACE",
	"CAP_SYS_PACCT", "CAP_SYS_ADMIN", "CAP_SYS_BOOT", "CAP_SYS_NICE",
	"CAP_SYS_RESOURCE", "CAP_SYS_TIME", "CAP_SYS_TTY_CONFIG", "CAP_MKNOD",
	"CAP_LEASE", "CAP_AUDIT_WRITE", "CAP_AUDIT_CONTROL", "CAP_SETFCAP",
	"CAP_MAC_OVERRIDE", "CAP_MAC_ADMIN", "CAP_SYSLOG", "CAP_WAKE_ALARM",
	"CAP_BLOCK_SUSPEND", "CAP_AUDIT_READ", "CAP_PERFMON", "CAP_BPF",
	"CAP_CHECKPOINT_RESTORE",
}

var defaultCapabilities = map[string]bool{
	"CAP_CHOWN": true, "CAP_DAC_OVERRIDE": true, "CAP_FSETID": true,
	"CAP_FOWNER": true, "CAP_MKNOD": true, "CAP_NET_RAW": true,
	"CAP_SETGID": true, "CAP_SETUID": true, "CAP_SETFCAP": true,
	"CAP_SETPCAP": true, "CAP_NET_BIND_SERVICE": true, "CAP_SYS_CHROOT": true,
	"CAP_KILL": true, "CAP_AUDIT_WRITE": true,
}

type ContainerPermission struct {
	Name      string `json:"name"`
	Has       bool   `json:"has"`
	Dangerous bool   `json:"dangerous"`
}

type ContainerDetailResult struct {
	ID              string                `json:"id"`
	Name            string                `json:"name"`
	Image           string                `json:"image"`
	Status          string                `json:"status"`
	SecurityScore   int                   `json:"securityScore"`
	RiskLevel       string                `json:"riskLevel"`
	User            string                `json:"user"`
	Privileged      bool                  `json:"privileged"`
	ReadonlyRootfs  bool                  `json:"readonlyRootfs"`
	NoNewPrivileges bool                  `json:"noNewPrivileges"`
	Seccomp         bool                  `json:"seccomp"`
	AppArmor        bool                  `json:"apparmor"`
	CapAdd          []string              `json:"capAdd"`
	CapDrop         []string              `json:"capDrop"`
	Permissions     []ContainerPermission `json:"permissions"`
	Ports           []string              `json:"ports"`
	Mounts          []string              `json:"mounts"`
	Env             []string              `json:"env"`
	Flags           []string              `json:"flags"`
	NetworkMode     string                `json:"networkMode"`
	PidMode         string                `json:"pidMode"`
	IpcMode         string                `json:"ipcMode"`

	SecurityChecks map[string]SecurityCheck `json:"securityChecks"`
}

type SecurityCheck struct {
	Passed bool   `json:"passed"`
	Detail string `json:"detail"`
	Value  string `json:"value"`
}

func (a *App) GetContainerDetail(containerID string) ContainerDetailResult {
	result := ContainerDetailResult{
		ID:             containerID,
		Permissions:    []ContainerPermission{},
		CapAdd:         []string{},
		CapDrop:        []string{},
		Ports:          []string{},
		Mounts:         []string{},
		Env:            []string{},
		Flags:          []string{},
		SecurityChecks: make(map[string]SecurityCheck),
	}

	if a.rootPassword == "" {
		return result
	}
	containerID = strings.TrimSpace(containerID)
	if matched, _ := regexp.MatchString(`^[a-f0-9]{12,64}$`, containerID); !matched {
		result.Name = "错误：无效的容器ID格式"
		return result
	}

	inspectJSON, err := a.runSudoCommand("docker", "inspect", "--format", "{{json .}}", containerID)
	if err != nil {
		result.Name = "错误：无法获取容器信息: " + err.Error()
		return result
	}

	var inspectData map[string]interface{}
	if err := json.Unmarshal([]byte(strings.TrimSpace(inspectJSON)), &inspectData); err != nil {
		result.Name = "错误：解析容器JSON失败: " + err.Error()
		return result
	}

	getStr := func(m map[string]interface{}, key string) string {
		if v, ok := m[key].(string); ok {
			return v
		}
		return ""
	}

	result.Name = strings.TrimPrefix(strings.TrimSpace(getStr(inspectData, "Name")), "/")

	configObj, _ := inspectData["Config"].(map[string]interface{})
	if configObj != nil {
		result.Image = strings.TrimSpace(getStr(configObj, "Image"))
		result.User = strings.TrimSpace(getStr(configObj, "User"))
		if result.User == "" || result.User == "<no value>" {
			result.User = "root"
		}
		if envArr, ok := configObj["Env"].([]interface{}); ok {
			for _, e := range envArr {
				if s, ok := e.(string); ok {
					result.Env = append(result.Env, s)
				}
			}
		}
	}

	stateObj, _ := inspectData["State"].(map[string]interface{})
	if stateObj != nil {
		result.Status = strings.TrimSpace(getStr(stateObj, "Status"))
	}

	var secOpts []string
	hostConfig, _ := inspectData["HostConfig"].(map[string]interface{})
	if hostConfig != nil {
		result.Privileged = getStr(hostConfig, "Privileged") == "true"
		result.ReadonlyRootfs = getStr(hostConfig, "ReadonlyRootfs") == "true"
		result.NetworkMode = strings.TrimSpace(getStr(hostConfig, "NetworkMode"))
		result.PidMode = strings.TrimSpace(getStr(hostConfig, "PidMode"))
		result.IpcMode = strings.TrimSpace(getStr(hostConfig, "IpcMode"))

		if secOptArr, ok := hostConfig["SecurityOpt"].([]interface{}); ok {
			for _, s := range secOptArr {
				if str, ok := s.(string); ok {
					secOpts = append(secOpts, str)
				}
			}
		}
		result.NoNewPrivileges = false
		result.Seccomp = false
		result.AppArmor = false
		for _, opt := range secOpts {
			if strings.Contains(opt, "no-new-privileges") {
				result.NoNewPrivileges = true
			}
			if strings.Contains(opt, "seccomp") {
				result.Seccomp = true
			}
			if strings.Contains(opt, "apparmor") {
				result.AppArmor = true
			}
		}

		parseCapList := func(key string) []string {
			var caps []string
			if arr, ok := hostConfig[key].([]interface{}); ok {
				for _, c := range arr {
					if s, ok := c.(string); ok {
						caps = append(caps, strings.ToUpper(strings.TrimPrefix(s, "CAP_")))
					}
				}
			}
			return caps
		}
		result.CapAdd = parseCapList("CapAdd")
		result.CapDrop = parseCapList("CapDrop")

		if portBindings, ok := hostConfig["PortBindings"].(map[string]interface{}); ok {
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
							result.Ports = append(result.Ports, fmt.Sprintf("%s:%s -> %s", hostIP, hostPort, portKey))
						}
					}
				}
			}
		}
	}

	if mountsArr, ok := inspectData["Mounts"].([]interface{}); ok {
		for _, m := range mountsArr {
			if mObj, ok := m.(map[string]interface{}); ok {
				if src, ok := mObj["Source"].(string); ok {
					if dst, ok := mObj["Destination"].(string); ok {
						result.Mounts = append(result.Mounts, fmt.Sprintf("%s:%s", src, dst))
					}
				}
			}
		}
	}

	currentCaps := make(map[string]bool)
	for cap := range defaultCapabilities {
		currentCaps[cap] = true
	}
	for _, c := range result.CapAdd {
		capName := c
		if !strings.HasPrefix(capName, "CAP_") {
			capName = "CAP_" + capName
		}
		currentCaps[capName] = true
	}
	for _, c := range result.CapDrop {
		capName := c
		if !strings.HasPrefix(capName, "CAP_") {
			capName = "CAP_" + capName
		}
		delete(currentCaps, capName)
	}

	dangerousCaps := map[string]bool{
		"CAP_SYS_ADMIN": true, "CAP_NET_ADMIN": true, "CAP_SYS_PTRACE": true,
		"CAP_SYS_MODULE": true, "CAP_SYS_RAWIO": true, "CAP_DAC_READ_SEARCH": true,
		"CAP_LINUX_IMMUTABLE": true, "CAP_NET_BROADCAST": true, "CAP_IPC_OWNER": true,
		"CAP_SYS_BOOT": true, "CAP_SYS_RESOURCE": true, "CAP_SYS_TIME": true,
		"CAP_MAC_OVERRIDE": true, "CAP_MAC_ADMIN": true, "CAP_BPF": true,
		"CAP_PERFMON": true, "CAP_CHECKPOINT_RESTORE": true,
	}

	for _, cap := range allCapabilities {
		result.Permissions = append(result.Permissions, ContainerPermission{
			Name:      cap,
			Has:       currentCaps[cap],
			Dangerous: dangerousCaps[cap],
		})
	}

	result.SecurityChecks["Privileged"] = SecurityCheck{
		Passed: !result.Privileged,
		Detail: map[bool]string{true: "容器以特权模式运行（危险）", false: "未启用特权模式（安全）"}[result.Privileged],
		Value:  map[bool]string{true: "false", false: "true"}[result.Privileged],
	}

	hasCapAdd := len(result.CapAdd) > 0
	result.SecurityChecks["CapAdd"] = SecurityCheck{
		Passed: !hasCapAdd,
		Detail: map[bool]string{true: "存在额外添加的Capabilities（危险）: " + strings.Join(result.CapAdd, ", "), false: "未添加额外Capabilities（安全）"}[hasCapAdd],
		Value:  strings.Join(result.CapAdd, ", "),
	}

	hasCapDrop := len(result.CapDrop) > 0
	result.SecurityChecks["CapDrop"] = SecurityCheck{
		Passed: hasCapDrop,
		Detail: map[bool]string{true: "已丢弃Capabilities（安全）: " + strings.Join(result.CapDrop, ", "), false: "未丢弃任何Capabilities（危险）"}[hasCapDrop],
		Value:  strings.Join(result.CapDrop, ", "),
	}

	seccompUnconfined := false
	for _, opt := range secOpts {
		if strings.Contains(opt, "unconfined") {
			seccompUnconfined = true
		}
	}
	result.SecurityChecks["Seccomp"] = SecurityCheck{
		Passed: !seccompUnconfined,
		Detail: map[bool]string{true: "Seccomp未限制（危险）", false: "Seccomp已启用限制（安全）"}[seccompUnconfined],
		Value:  map[bool]string{true: "unconfined", false: "enabled"}[seccompUnconfined],
	}

	apparmorUnconfined := false
	apparmorEmpty := true
	for _, opt := range secOpts {
		if strings.Contains(opt, "apparmor") {
			apparmorEmpty = false
			if strings.Contains(opt, "unconfined") {
				apparmorUnconfined = true
			}
		}
	}
	result.SecurityChecks["AppArmor"] = SecurityCheck{
		Passed: !apparmorUnconfined && !apparmorEmpty,
		Detail: func() string {
			if apparmorEmpty {
				return "AppArmor未配置（危险）"
			}
			if apparmorUnconfined {
				return "AppArmor未限制（危险）"
			}
			return "AppArmor已启用（安全）"
		}(),
		Value: map[bool]string{true: "unconfined", false: map[bool]string{true: "disabled", false: "enabled"}[apparmorEmpty]}[apparmorUnconfined],
	}

	selinuxDisabled := false
	for _, opt := range secOpts {
		if strings.Contains(opt, "selinux") && strings.Contains(opt, "disabled") {
			selinuxDisabled = true
		}
	}
	result.SecurityChecks["SELinux"] = SecurityCheck{
		Passed: !selinuxDisabled,
		Detail: map[bool]string{true: "SELinux已禁用（危险）", false: "SELinux状态正常（安全）"}[selinuxDisabled],
		Value:  map[bool]string{true: "disabled", false: "enabled/enforcing"}[selinuxDisabled],
	}

	result.SecurityChecks["NoNewPrivileges"] = SecurityCheck{
		Passed: result.NoNewPrivileges,
		Detail: map[bool]string{true: "已启用（安全）", false: "未启用（危险）"}[result.NoNewPrivileges],
		Value:  map[bool]string{true: "true", false: "false"}[result.NoNewPrivileges],
	}

	result.SecurityChecks["ReadonlyRootfs"] = SecurityCheck{
		Passed: result.ReadonlyRootfs,
		Detail: map[bool]string{true: "已启用（安全）", false: "未启用（危险）"}[result.ReadonlyRootfs],
		Value:  map[bool]string{true: "true", false: "false"}[result.ReadonlyRootfs],
	}

	usernsMode := strings.TrimSpace(getStr(hostConfig, "UsernsMode"))
	usernsEnabled := usernsMode != "" && usernsMode != "<no value>"
	result.SecurityChecks["Userns"] = SecurityCheck{
		Passed: usernsEnabled,
		Detail: map[bool]string{true: "已启用（安全）: " + usernsMode, false: "未启用（危险）"}[usernsEnabled],
		Value:  usernsMode,
	}

	result.SecurityChecks["PidMode"] = SecurityCheck{
		Passed: result.PidMode != "host",
		Detail: map[bool]string{true: "共享宿主机（危险）", false: "已隔离（安全）"}[result.PidMode == "host"],
		Value:  result.PidMode,
	}

	result.SecurityChecks["NetworkMode"] = SecurityCheck{
		Passed: result.NetworkMode != "host",
		Detail: map[bool]string{true: "Host模式（危险）", false: "已隔离（安全）: " + result.NetworkMode}[result.NetworkMode == "host"],
		Value:  result.NetworkMode,
	}

	highRiskPorts := []string{"22", "3306", "6379", "5432", "9200", "27017", "3389", "445", "1433"}
	hasHighRiskPort := false
	highRiskPortList := []string{}
	for _, p := range result.Ports {
		for _, hrp := range highRiskPorts {
			if strings.Contains(p, ":"+hrp) || strings.Contains(p, "->"+hrp) {
				hasHighRiskPort = true
				highRiskPortList = append(highRiskPortList, hrp)
			}
		}
	}
	result.SecurityChecks["PortMappings"] = SecurityCheck{
		Passed: !hasHighRiskPort,
		Detail: map[bool]string{true: "映射了高危端口（危险）: " + strings.Join(highRiskPortList, ", "), false: "未映射高危端口（安全）"}[hasHighRiskPort],
		Value:  strings.Join(highRiskPortList, ", "),
	}

	dnsList := []string{}
	if dnsArr, ok := hostConfig["DNS"].([]interface{}); ok {
		for _, d := range dnsArr {
			if s, ok := d.(string); ok {
				dnsList = append(dnsList, s)
			}
		}
	}
	dnsMalicious := false
	for _, dns := range dnsList {
		if dns != "" && dns != "8.8.8.8" && dns != "8.8.4.4" && dns != "1.1.1.1" && dns != "114.114.114.114" {
			dnsMalicious = true
		}
	}
	result.SecurityChecks["DNSConfig"] = SecurityCheck{
		Passed: !dnsMalicious,
		Detail: map[bool]string{true: "DNS配置可能指向外部DNS（危险）: " + strings.Join(dnsList, ", "), false: "DNS配置正常（安全）"}[dnsMalicious],
		Value:  strings.Join(dnsList, ", "),
	}

	extraHosts := []string{}
	if ehArr, ok := hostConfig["ExtraHosts"].([]interface{}); ok {
		for _, h := range ehArr {
			if s, ok := h.(string); ok {
				extraHosts = append(extraHosts, s)
			}
		}
	}
	hasAbnormalHosts := false
	for _, h := range extraHosts {
		if strings.Contains(h, "google") || strings.Contains(h, "github") || strings.Contains(h, "malicious") {
			hasAbnormalHosts = true
		}
	}
	result.SecurityChecks["HostsFile"] = SecurityCheck{
		Passed: !hasAbnormalHosts,
		Detail: map[bool]string{true: "Hosts文件存在异常解析（危险）: " + strings.Join(extraHosts, ", "), false: "Hosts文件无异常（安全）"}[hasAbnormalHosts],
		Value:  strings.Join(extraHosts, ", "),
	}

	hasBindMount := false
	for _, m := range result.Mounts {
		if strings.Contains(m, ":") && !strings.HasPrefix(m, "/var/lib/docker/volumes/") {
			hasBindMount = true
		}
	}
	result.SecurityChecks["BindMount"] = SecurityCheck{
		Passed: !hasBindMount,
		Detail: map[bool]string{true: "存在bind mount（危险）", false: "无bind mount（安全）"}[hasBindMount],
		Value:  map[bool]string{true: "有", false: "无"}[hasBindMount],
	}

	hasRwMount := false
	rwMounts := []string{}
	if mountsArr, ok := inspectData["Mounts"].([]interface{}); ok {
		for _, m := range mountsArr {
			if mObj, ok := m.(map[string]interface{}); ok {
				if mObj["Type"] == "bind" {
					if rw, ok := mObj["RW"].(bool); ok && rw {
						hasRwMount = true
						if src, ok := mObj["Source"].(string); ok {
							rwMounts = append(rwMounts, src)
						}
					}
				}
			}
		}
	}
	result.SecurityChecks["MountRW"] = SecurityCheck{
		Passed: !hasRwMount,
		Detail: map[bool]string{true: "读写模式（危险）: " + strings.Join(rwMounts, ", "), false: "只读或不存（安全）"}[hasRwMount],
		Value:  strings.Join(rwMounts, ", "),
	}

	sensitivePaths := []string{"/", "/etc", "/proc", "/sys", "/var/run/docker.sock", "/root/.ssh", "/var/lib/kubelet"}
	hasSensitiveMount := false
	sensitiveMountList := []string{}
	for _, m := range result.Mounts {
		for _, sp := range sensitivePaths {
			if strings.Contains(m, sp+":") || strings.HasPrefix(m, sp+":") {
				hasSensitiveMount = true
				sensitiveMountList = append(sensitiveMountList, sp)
			}
		}
	}
	result.SecurityChecks["SensitiveMount"] = SecurityCheck{
		Passed: !hasSensitiveMount,
		Detail: map[bool]string{true: "挂载了敏感路径（危险）: " + strings.Join(sensitiveMountList, ", "), false: "未挂载（安全）"}[hasSensitiveMount],
		Value:  strings.Join(sensitiveMountList, ", "),
	}

	hasDevice := false
	deviceList := []string{}
	if devArr, ok := hostConfig["Devices"].([]interface{}); ok && len(devArr) > 0 {
		hasDevice = true
		for _, d := range devArr {
			if dObj, ok := d.(map[string]interface{}); ok {
				if path, ok := dObj["PathOnHost"].(string); ok {
					deviceList = append(deviceList, path)
				}
			}
		}
	}
	result.SecurityChecks["DeviceMapping"] = SecurityCheck{
		Passed: !hasDevice,
		Detail: map[bool]string{true: "存在设备映射（危险）: " + strings.Join(deviceList, ", "), false: "无设备映射（安全）"}[hasDevice],
		Value:  strings.Join(deviceList, ", "),
	}

	tmpfsUnlimited := false
	tmpfsPaths := []string{}
	if tmpfsMap, ok := hostConfig["Tmpfs"].(map[string]interface{}); ok {
		for k, v := range tmpfsMap {
			vStr := fmt.Sprintf("%v", v)
			tmpfsPaths = append(tmpfsPaths, k+"="+vStr)
			if vStr == "" || !strings.Contains(vStr, "size=") {
				tmpfsUnlimited = true
			}
		}
	}
	result.SecurityChecks["TmpfsSize"] = SecurityCheck{
		Passed: !tmpfsUnlimited,
		Detail: map[bool]string{true: "tmpfs未设置大小限制（危险）", false: "tmpfs已设置大小限制（安全）"}[tmpfsUnlimited],
		Value:  strings.Join(tmpfsPaths, "; "),
	}

	logConfig, _ := hostConfig["LogConfig"].(map[string]interface{})
	logDriver := ""
	if logConfig != nil {
		logDriver = strings.TrimSpace(getStr(logConfig, "Type"))
	}
	logNone := logDriver == "none" || logDriver == ""
	result.SecurityChecks["LogDriver"] = SecurityCheck{
		Passed: !logNone,
		Detail: map[bool]string{true: "无日志审计（危险）", false: "已配置日志驱动（安全）: " + logDriver}[logNone],
		Value:  logDriver,
	}

	logOpts := map[string]string{}
	if logConfig != nil {
		if logOptsObj, ok := logConfig["Config"].(map[string]interface{}); ok {
			for k, v := range logOptsObj {
				if s, ok := v.(string); ok {
					logOpts[k] = s
				}
			}
		}
	}
	hasMaxSize := logOpts["max-size"] != ""
	result.SecurityChecks["LogMaxSize"] = SecurityCheck{
		Passed: hasMaxSize,
		Detail: map[bool]string{true: "已设置日志大小限制（安全）: " + logOpts["max-size"], false: "未设置日志大小限制（危险）"}[hasMaxSize],
		Value:  logOpts["max-size"],
	}

	getNumStr := func(key string) string {
		if v, ok := hostConfig[key]; ok {
			switch n := v.(type) {
			case float64:
				return fmt.Sprintf("%d", int64(n))
			case string:
				return n
			}
		}
		return "0"
	}
	cpuShares := getNumStr("CpuShares")
	cpuPeriod := getNumStr("CpuPeriod")
	cpuQuota := getNumStr("CpuQuota")
	cpuSet := cpuShares != "0" && cpuShares != "" && cpuShares != "<no value>"
	cpuSet = cpuSet || (cpuPeriod != "0" && cpuPeriod != "" && cpuPeriod != "<no value>")
	cpuSet = cpuSet || (cpuQuota != "0" && cpuQuota != "" && cpuQuota != "<no value>")
	result.SecurityChecks["CPULimit"] = SecurityCheck{
		Passed: cpuSet,
		Detail: map[bool]string{true: "已设置（安全）", false: "未设置（危险）"}[cpuSet],
		Value:  "shares=" + cpuShares + " period=" + cpuPeriod + " quota=" + cpuQuota,
	}

	memLimit := getNumStr("Memory")
	memSet := memLimit != "0" && memLimit != "" && memLimit != "<no value>"
	result.SecurityChecks["MemoryLimit"] = SecurityCheck{
		Passed: memSet,
		Detail: map[bool]string{true: "已设置（安全）: " + memLimit, false: "未设置（危险）"}[memSet],
		Value:  memLimit,
	}

	pidsLimit := getNumStr("PidsLimit")
	pidsSet := pidsLimit != "0" && pidsLimit != "" && pidsLimit != "<no value>"
	result.SecurityChecks["PidsLimit"] = SecurityCheck{
		Passed: pidsSet,
		Detail: map[bool]string{true: "已设置（安全）: " + pidsLimit, false: "未设置（危险）"}[pidsSet],
		Value:  pidsLimit,
	}

	nofileSet := false
	if ulimitArr, ok := hostConfig["Ulimits"].([]interface{}); ok {
		for _, u := range ulimitArr {
			if uObj, ok := u.(map[string]interface{}); ok {
				if name, ok := uObj["Name"].(string); ok && name == "nofile" {
					nofileSet = true
				}
			}
		}
	}
	result.SecurityChecks["UlimitNofile"] = SecurityCheck{
		Passed: nofileSet,
		Detail: map[bool]string{true: "已设置（安全）", false: "未设置（危险）"}[nofileSet],
		Value:  map[bool]string{true: "已设置", false: "未设置"}[nofileSet],
	}

	readBpsArr, hasReadBps := hostConfig["BlkioDeviceReadBps"].([]interface{})
	writeBpsArr, hasWriteBps := hostConfig["BlkioDeviceWriteBps"].([]interface{})
	ioSet := hasReadBps && len(readBpsArr) > 0
	ioSet = ioSet || (hasWriteBps && len(writeBpsArr) > 0)
	result.SecurityChecks["DeviceIO"] = SecurityCheck{
		Passed: ioSet,
		Detail: map[bool]string{true: "已设置（安全）", false: "未设置（危险）"}[ioSet],
		Value:  map[bool]string{true: "已设置", false: "未设置"}[ioSet],
	}

	cgroupMode := strings.TrimSpace(getStr(hostConfig, "Cgroup"))
	cgroupShared := cgroupMode == "host" || cgroupMode == ""
	result.SecurityChecks["CgroupNs"] = SecurityCheck{
		Passed: !cgroupShared,
		Detail: map[bool]string{true: "cgroup与宿主机共享", false: "cgroup已隔离: " + cgroupMode}[cgroupShared],
		Value:  cgroupMode,
	}

	result.SecurityChecks["IpcMode"] = SecurityCheck{
		Passed: result.IpcMode != "host",
		Detail: map[bool]string{true: "IPC Namespace与宿主机共享", false: "IPC Namespace已隔离"}[result.IpcMode == "host"],
		Value:  result.IpcMode,
	}

	utsMode := strings.TrimSpace(getStr(hostConfig, "UTSMode"))
	utsShared := utsMode == "host"
	result.SecurityChecks["UtsMode"] = SecurityCheck{
		Passed: !utsShared,
		Detail: map[bool]string{true: "UTS Namespace与宿主机共享主机名", false: "UTS Namespace已隔离"}[utsShared],
		Value:  utsMode,
	}

	sysctls := map[string]string{}
	if sysctlObj, ok := hostConfig["Sysctls"].(map[string]interface{}); ok {
		for k, v := range sysctlObj {
			if s, ok := v.(string); ok {
				sysctls[k] = s
			}
		}
	}
	hasSysctl := len(sysctls) > 0
	sysctlList := []string{}
	for k, v := range sysctls {
		sysctlList = append(sysctlList, k+"="+v)
	}
	result.SecurityChecks["Sysctl"] = SecurityCheck{
		Passed: !hasSysctl,
		Detail: map[bool]string{true: "存在sysctl修改: " + strings.Join(sysctlList, ", "), false: "无sysctl修改"}[hasSysctl],
		Value:  strings.Join(sysctlList, ", "),
	}

	hasSecurityOpt := len(secOpts) > 0
	result.SecurityChecks["SecurityOpt"] = SecurityCheck{
		Passed: hasSecurityOpt,
		Detail: map[bool]string{true: "存在自定义安全选项", false: "无自定义安全选项(缺少额外加固)"}[!hasSecurityOpt],
		Value:  strings.Join(secOpts, ", "),
	}

	repoDigests := []string{}
	if rdArr, ok := inspectData["RepoDigests"].([]interface{}); ok {
		for _, rd := range rdArr {
			if s, ok := rd.(string); ok {
				repoDigests = append(repoDigests, s)
			}
		}
	}
	hasDigest := len(repoDigests) > 0
	result.SecurityChecks["ImageDigest"] = SecurityCheck{
		Passed: hasDigest,
		Detail: map[bool]string{true: "镜像有Digest可验证完整性", false: "镜像无Digest(无法验证完整性)"}[hasDigest],
		Value:  strings.Join(repoDigests, ", "),
	}

	imageName := result.Image
	isOfficial := strings.HasPrefix(imageName, "docker.io/library/") || strings.HasPrefix(imageName, "registry-1.docker.io/library/")
	result.SecurityChecks["ImageSource"] = SecurityCheck{
		Passed: isOfficial,
		Detail: map[bool]string{true: "镜像来自官方仓库", false: "镜像非官方来源: " + imageName}[isOfficial],
		Value:  imageName,
	}

	isLatest := strings.HasSuffix(imageName, ":latest") || !strings.Contains(imageName, ":")
	result.SecurityChecks["ImageTag"] = SecurityCheck{
		Passed: !isLatest,
		Detail: map[bool]string{true: "镜像标签为latest(不可复现)", false: "镜像使用固定标签"}[isLatest],
		Value:  map[bool]string{true: "latest", false: "fixed"}[isLatest],
	}

	imageSizeOutput, _ := a.runSudoCommand("docker", "inspect", "-s", "--format", "{{.Size}}", containerID)
	imageSize := strings.TrimSpace(imageSizeOutput)
	sizeBytes := int64(0)
	if _, err := fmt.Sscanf(imageSize, "%d", &sizeBytes); err != nil {
		sizeBytes = 0
	}
	sizeGB := float64(sizeBytes) / (1024 * 1024 * 1024)
	isOversized := sizeGB > 1
	result.SecurityChecks["ImageSize"] = SecurityCheck{
		Passed: !isOversized,
		Detail: map[bool]string{true: fmt.Sprintf("镜像异常大 (%.2f GB，可能藏恶意文件)", sizeGB), false: fmt.Sprintf("镜像大小正常 (%.2f GB)", sizeGB)}[isOversized],
		Value:  fmt.Sprintf("%.2f GB", sizeGB),
	}

	createdTime := strings.TrimSpace(getStr(inspectData, "Created"))
	created, err := time.Parse(time.RFC3339Nano, createdTime)
	if err != nil {
		created = time.Now()
	}
	oneYearAgo := time.Now().AddDate(-1, 0, 0)
	isOld := created.Before(oneYearAgo)
	result.SecurityChecks["ImageBuildTime"] = SecurityCheck{
		Passed: !isOld,
		Detail: map[bool]string{true: "镜像超过1年未更新(漏洞未修复)", false: "镜像构建时间较新"}[isOld],
		Value:  created.Format("2006-01-02"),
	}

	author := strings.TrimSpace(getStr(inspectData, "Author"))
	if author == "" || author == "<no value>" {
		if configObj != nil {
			if labelsObj, ok := configObj["Labels"].(map[string]interface{}); ok && len(labelsObj) > 0 {
				for k, v := range labelsObj {
					if strings.Contains(strings.ToLower(k), "maintainer") || strings.Contains(strings.ToLower(k), "author") {
						if s, ok := v.(string); ok {
							author = s
							break
						}
					}
				}
			}
		}
	}
	vulnerableBases := []string{"alpine:3.10", "alpine:3.11", "ubuntu:16.04", "ubuntu:18.04", "debian:9", "centos:7"}
	hasCVE := false
	for _, vb := range vulnerableBases {
		if strings.Contains(imageName, vb) {
			hasCVE = true
		}
	}
	result.SecurityChecks["ImageCVE"] = SecurityCheck{
		Passed: !hasCVE,
		Detail: map[bool]string{true: "基础镜像可能存在已知漏洞", false: "基础镜像较新"}[hasCVE],
		Value:  map[bool]string{true: "存在风险", false: "较安全"}[hasCVE],
	}

	historyOutput, _ := a.runSudoCommand("docker", "history", "--no-trunc", "--format", "{{.CreatedBy}}", result.Image)
	historyLines := strings.Split(historyOutput, "\n")
	hasSuspiciousHistory := false
	suspiciousCmds := []string{}
	for _, line := range historyLines {
		line = strings.ToLower(line)
		if strings.Contains(line, "curl") && strings.Contains(line, "bash") {
			hasSuspiciousHistory = true
			suspiciousCmds = append(suspiciousCmds, "curl | bash")
		}
		if strings.Contains(line, "wget") && strings.Contains(line, "sh") {
			hasSuspiciousHistory = true
			suspiciousCmds = append(suspiciousCmds, "wget | sh")
		}
		if strings.Contains(line, "add") && strings.Contains(line, "http") {
			hasSuspiciousHistory = true
			suspiciousCmds = append(suspiciousCmds, "ADD from remote URL")
		}
	}
	result.SecurityChecks["ImageHistory"] = SecurityCheck{
		Passed: !hasSuspiciousHistory,
		Detail: map[bool]string{true: "镜像层存在可疑构建指令: " + strings.Join(suspiciousCmds, ", "), false: "镜像层构建指令正常"}[hasSuspiciousHistory],
		Value:  strings.Join(suspiciousCmds, ", "),
	}

	entrypoint := []string{}
	cmd := []string{}
	if configObj != nil {
		if epArr, ok := configObj["Entrypoint"].([]interface{}); ok {
			for _, e := range epArr {
				if s, ok := e.(string); ok {
					entrypoint = append(entrypoint, s)
				}
			}
		}
		if cmdArr, ok := configObj["Cmd"].([]interface{}); ok {
			for _, c := range cmdArr {
				if s, ok := c.(string); ok {
					cmd = append(cmd, s)
				}
			}
		}
	}
	allCmds := append(entrypoint, cmd...)
	cmdStr := strings.Join(allCmds, " ")
	cmdStrLower := strings.ToLower(cmdStr)
	isSuspiciousCmd := strings.Contains(cmdStrLower, "/bin/bash") && strings.Contains(cmdStrLower, "-c") &&
		(strings.Contains(cmdStrLower, "bash -i") || strings.Contains(cmdStrLower, "nc ") || strings.Contains(cmdStrLower, "ncat") || strings.Contains(cmdStrLower, "socat"))
	result.SecurityChecks["Entrypoint"] = SecurityCheck{
		Passed: !isSuspiciousCmd,
		Detail: map[bool]string{true: "启动命令可疑: " + cmdStr, false: "启动命令正常"}[isSuspiciousCmd],
		Value:  cmdStr,
	}

	hasSensitiveEnv := false
	sensitiveEnvList := []string{}
	for _, env := range result.Env {
		envUpper := strings.ToUpper(env)
		if (strings.Contains(envUpper, "PASSWORD") || strings.Contains(envUpper, "SECRET") ||
			strings.Contains(envUpper, "TOKEN") || strings.Contains(envUpper, "KEY") ||
			(strings.Contains(envUpper, "AWS_ACCESS_KEY_ID") || strings.Contains(envUpper, "AWS_SECRET_ACCESS_KEY") ||
				strings.Contains(envUpper, "AWS_SESSION_TOKEN") || strings.Contains(envUpper, "AWS_SECURITY_TOKEN")) ||
			strings.Contains(envUpper, "AZURE") || strings.Contains(envUpper, "GCP")) &&
			!strings.Contains(envUpper, "SSH_AUTH_SOCK") && !strings.Contains(envUpper, "GPG_AGENT") {
			hasSensitiveEnv = true
			sensitiveEnvList = append(sensitiveEnvList, env)
		}
	}
	result.SecurityChecks["EnvVars"] = SecurityCheck{
		Passed: !hasSensitiveEnv,
		Detail: map[bool]string{true: "存在敏感环境变量: " + strings.Join(sensitiveEnvList, ", "), false: "无敏感环境变量"}[hasSensitiveEnv],
		Value:  strings.Join(sensitiveEnvList, ", "),
	}

	saTokenPath := "/var/run/secrets/kubernetes.io/serviceaccount/token"
	saTokenOutput, _ := a.runSudoCommand("docker", "exec", containerID, "cat", saTokenPath, "2>/dev/null || echo 'NOT_FOUND'")
	hasK8sToken := !strings.Contains(saTokenOutput, "NOT_FOUND") && strings.TrimSpace(saTokenOutput) != ""
	result.SecurityChecks["K8sToken"] = SecurityCheck{
		Passed: !hasK8sToken,
		Detail: map[bool]string{true: "存在K8s ServiceAccount Token(K8s环境下风险)", false: "无K8s Token"}[hasK8sToken],
		Value:  map[bool]string{true: "存在", false: "不存在"}[hasK8sToken],
	}

	metadataOutput, _ := a.runSudoCommand("docker", "exec", containerID, "sh", "-c", "curl -s --connect-timeout 2 http://169.254.169.254/latest/meta-data/ 2>/dev/null || echo 'NO_ACCESS'")
	canAccessMetadata := !strings.Contains(metadataOutput, "NO_ACCESS") && strings.TrimSpace(metadataOutput) != ""
	result.SecurityChecks["CloudMetadata"] = SecurityCheck{
		Passed: !canAccessMetadata,
		Detail: map[bool]string{true: "能访问云服务元数据接口 (169.254.169.254)", false: "无法访问云服务元数据"}[canAccessMetadata],
		Value:  map[bool]string{true: "可访问", false: "不可访问"}[canAccessMetadata],
	}

	if result.Status == "running" {
		psOutput, _ := a.runSudoCommand("docker", "exec", containerID, "ps", "aux")
		psLines := strings.Split(psOutput, "\n")
		hasAbnormalProcess := false
		abnormalProcs := []string{}
		for _, line := range psLines {
			lineLower := strings.ToLower(line)
			if strings.Contains(lineLower, "xmrig") || strings.Contains(lineLower, "minerd") ||
				strings.Contains(lineLower, "stratum") || strings.Contains(lineLower, "nc ") ||
				strings.Contains(lineLower, "ncat") || strings.Contains(lineLower, "socat") {
				hasAbnormalProcess = true
				parts := strings.Fields(line)
				if len(parts) > 0 {
					abnormalProcs = append(abnormalProcs, parts[len(parts)-1])
				}
			}
		}
		result.SecurityChecks["InnerProcesses"] = SecurityCheck{
			Passed: !hasAbnormalProcess,
			Detail: map[bool]string{true: "发现异常进程: " + strings.Join(abnormalProcs, ", "), false: "无异常进程"}[hasAbnormalProcess],
			Value:  strings.Join(abnormalProcs, ", "),
		}

		usersOutput, _ := a.runSudoCommand("docker", "exec", containerID, "cat", "/etc/passwd")
		userLines := strings.Split(usersOutput, "\n")
		nonRootUsers := []string{}
		for _, line := range userLines {
			parts := strings.Split(line, ":")
			if len(parts) >= 3 {
				uid := parts[2]
				if uid != "0" && uid != "" && uid != "65534" {
					nonRootUsers = append(nonRootUsers, parts[0])
				}
			}
		}
		hasMultiUser := len(nonRootUsers) > 0
		result.SecurityChecks["InnerUsers"] = SecurityCheck{
			Passed: !hasMultiUser,
			Detail: map[bool]string{true: "除root外存在其他用户: " + strings.Join(nonRootUsers, ", "), false: "仅root用户"}[hasMultiUser],
			Value:  strings.Join(nonRootUsers, ", "),
		}

		suidOutput, _ := a.runSudoCommand("docker", "exec", containerID, "sh", "-c", "find / -perm -4000 -o -perm -2000 2>/dev/null | head -20")
		suidFiles := strings.Split(strings.TrimSpace(suidOutput), "\n")
		hasAbnormalSuid := false
		abnormalSuidList := []string{}
		for _, f := range suidFiles {
			if f != "" && !strings.Contains(f, "/usr/bin/sudo") && !strings.Contains(f, "/usr/bin/passwd") &&
				!strings.Contains(f, "/usr/bin/su") && !strings.Contains(f, "/usr/bin/chsh") {
				hasAbnormalSuid = true
				abnormalSuidList = append(abnormalSuidList, f)
			}
		}
		result.SecurityChecks["SuidFiles"] = SecurityCheck{
			Passed: !hasAbnormalSuid,
			Detail: map[bool]string{true: "发现异常SUID/SGID文件", false: "SUID/SGID文件正常"}[hasAbnormalSuid],
			Value:  strings.Join(abnormalSuidList, ", "),
		}

		crontabOutput, _ := a.runSudoCommand("docker", "exec", containerID, "sh", "-c", "crontab -l 2>/dev/null; cat /etc/crontab 2>/dev/null; ls /etc/cron.d/ 2>/dev/null")
		hasCrontab := strings.TrimSpace(crontabOutput) != "" && !strings.Contains(crontabOutput, "no crontab")
		isAbnormalCron := hasCrontab && (strings.Contains(crontabOutput, "curl") || strings.Contains(crontabOutput, "wget") || strings.Contains(crontabOutput, "bash"))
		result.SecurityChecks["InnerCrontab"] = SecurityCheck{
			Passed: !isAbnormalCron,
			Detail: map[bool]string{true: "存在异常定时任务", false: "定时任务正常"}[isAbnormalCron],
			Value:  map[bool]string{true: "异常", false: "正常"}[isAbnormalCron],
		}

		sshdOutput, _ := a.runSudoCommand("docker", "exec", containerID, "sh", "-c", "ps aux | grep sshd | grep -v grep || echo 'NO_SSHD'")
		hasSSH := !strings.Contains(sshdOutput, "NO_SSHD")
		result.SecurityChecks["InnerSSH"] = SecurityCheck{
			Passed: !hasSSH,
			Detail: map[bool]string{true: "容器内运行sshd(多一个入口)", false: "未运行sshd"}[hasSSH],
			Value:  map[bool]string{true: "运行中", false: "未运行"}[hasSSH],
		}

		fdOutput, _ := a.runSudoCommand("docker", "exec", containerID, "sh", "-c", "ls -la /proc/self/fd/ 2>/dev/null | head -20")
		hasAbnormalFd := strings.Contains(fdOutput, "/etc/shadow") || strings.Contains(fdOutput, "/proc/kcore") || strings.Contains(fdOutput, "/dev/mem")
		result.SecurityChecks["OpenFD"] = SecurityCheck{
			Passed: !hasAbnormalFd,
			Detail: map[bool]string{true: "发现异常文件描述符指向敏感文件", false: "文件描述符正常"}[hasAbnormalFd],
			Value:  map[bool]string{true: "异常", false: "正常"}[hasAbnormalFd],
		}

		netConnOutput, _ := a.runSudoCommand("docker", "exec", containerID, "sh", "-c", "ss -tunap 2>/dev/null || netstat -tunap 2>/dev/null || echo 'NO_DATA'")
		hasAbnormalConn := false
		connDetail := "无异常外连"
		if !strings.Contains(netConnOutput, "NO_DATA") {
			knownPools := []string{"xmr", "pool", "stratum", "minexmr", "supportxmr"}
			for _, pool := range knownPools {
				if strings.Contains(strings.ToLower(netConnOutput), pool) {
					hasAbnormalConn = true
					connDetail = "发现异常外连(可能连接矿池/C2服务器)"
				}
			}
		}
		result.SecurityChecks["NetConnections"] = SecurityCheck{
			Passed: !hasAbnormalConn,
			Detail: connDetail,
			Value:  map[bool]string{true: "异常", false: "正常"}[hasAbnormalConn],
		}

		listenOutput, _ := a.runSudoCommand("docker", "exec", containerID, "sh", "-c", "ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null || echo 'NO_DATA'")
		listenPorts := []string{}
		if !strings.Contains(listenOutput, "NO_DATA") {
			lines := strings.Split(listenOutput, "\n")
			for _, line := range lines {
				if strings.Contains(line, "LISTEN") {
					parts := strings.Fields(line)
					if len(parts) >= 4 {
						listenPorts = append(listenPorts, parts[3])
					}
				}
			}
		}
		hiddenService := len(listenPorts) > len(result.Ports)
		result.SecurityChecks["ListenPorts"] = SecurityCheck{
			Passed: !hiddenService,
			Detail: map[bool]string{true: "发现隐藏监听端口(与映射端口不一致)", false: "监听端口与映射一致"}[hiddenService],
			Value:  strings.Join(listenPorts, ", "),
		}

		outboundOutput, _ := a.runSudoCommand("docker", "exec", containerID, "sh", "-c", "curl -s --connect-timeout 3 -o /dev/null -w '%{http_code}' http://1.1.1.1 2>/dev/null || echo 'NO_NET'")
		canOutbound := !strings.Contains(outboundOutput, "NO_NET") && outboundOutput != ""
		result.SecurityChecks["OutboundNet"] = SecurityCheck{
			Passed: !canOutbound,
			Detail: map[bool]string{true: "容器能访问外网(数据外泄/C2风险)", false: "容器无法访问外网"}[canOutbound],
			Value:  map[bool]string{true: "可访问", false: "不可访问"}[canOutbound],
		}
	}

	score := 0

	highRiskItems := map[string]int{
		"Privileged":     12,
		"SensitiveMount": 12,
		"CapAdd":         10,
		"PidMode":        8,
		"NetworkMode":    8,
		"Seccomp":        8,
		"AppArmor":       8,
		"DeviceMapping":  8,
		"Entrypoint":     8,
		"EnvVars":        8,
		"ImageHistory":   8,
		"InnerProcesses": 10,
		"NetConnections": 10,
		"InnerCrontab":   8,
		"K8sToken":       8,
		"CloudMetadata":  10,
		"OpenFD":         6,
		"ListenPorts":    6,
	}
	mediumRiskItems := map[string]int{
		"NoNewPrivileges": 4,
		"ReadonlyRootfs":  4,
		"PortMappings":    3,
		"BindMount":       3,
		"MountRW":         3,
		"LogDriver":       2,
		"Sysctl":          2,
		"InnerSSH":        2,
		"SuidFiles":       3,
		"HostsFile":       2,
		"SELinux":         3,
	}
	lowRiskItems := map[string]int{
		"Userns":      1,
		"CgroupNs":    1,
		"IpcMode":     1,
		"UtsMode":     1,
		"OutboundNet": 1,
	}
	for name, weight := range highRiskItems {
		if check, ok := result.SecurityChecks[name]; ok && !check.Passed {
			score += weight
		}
	}
	for name, weight := range mediumRiskItems {
		if check, ok := result.SecurityChecks[name]; ok && !check.Passed {
			score += weight
		}
	}
	for name, weight := range lowRiskItems {
		if check, ok := result.SecurityChecks[name]; ok && !check.Passed {
			score += weight
		}
	}

	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}
	result.SecurityScore = score

	if score == 0 {
		result.RiskLevel = "安全"
	} else if score <= 8 {
		result.RiskLevel = "安全"
	} else if score <= 20 {
		result.RiskLevel = "低危"
	} else if score <= 35 {
		result.RiskLevel = "中危"
	} else if score <= 55 {
		result.RiskLevel = "高危"
	} else {
		result.RiskLevel = "严重"
	}
	return result
}

type ContainerScanResult struct {
	Success    bool               `json:"success"`
	TotalProcs int                `json:"totalProcs"`
	RiskStats  map[string]int     `json:"riskStats"`
	Processes  []ContainerProcess `json:"processes"`
	Error      string             `json:"error"`
}

type ContainerProcess struct {
	Name          string   `json:"name"`
	PID           int      `json:"pid"`
	User          string   `json:"user"`
	Status        string   `json:"status"`
	RiskLevel     string   `json:"riskLevel"`
	RiskScore     int      `json:"riskScore"`
	SecurityScore int      `json:"securityScore"`
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

	dockerOutput, err := a.runSudoCommand("docker", "ps", "-a", "--format", "{{.ID}}|{{.Image}}|{{.Names}}|{{.Status}}|{{.Ports}}")
	if err != nil {
		result.Success = false
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
		if !isContainerIDLine(line) {
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

		score := 0
		flags := []string{}

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

		if ports != "" && ports != "<no value>" {
			portList := strings.Split(ports, ", ")
			for _, p := range portList {
				if strings.Contains(p, "0.0.0.0:") {
					score += 5
					flags = append(flags, "端口暴露: "+p)
				}
			}
		}

		if scanType == "standard" || scanType == "full" {
			capOutput, _ := a.runSudoCommand("docker", "inspect", "--format", "{{.HostConfig.CapAdd}}", containerID)
			capOutput = strings.TrimSpace(capOutput)
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

		if status != "running" {
			process.RiskLevel = "已停止"
			process.RiskScore = 0
			process.SecurityScore = 0
		} else if score >= 60 {
			process.RiskLevel = "严重"
			process.RiskScore = score
			process.SecurityScore = score
		} else if score >= 40 {
			process.RiskLevel = "高危"
			process.RiskScore = score
			process.SecurityScore = score
		} else if score >= 20 {
			process.RiskLevel = "中危"
			process.RiskScore = score
			process.SecurityScore = score
		} else {
			process.RiskLevel = "安全"
			process.RiskScore = score
			process.SecurityScore = score
		}
		process.RiskFlags = flags

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
		if !isContainerIDLine(line) {
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

		config, err := a.getContainerOriginalConfig(task.ContainerID)
		if err != nil {
			result.Success = false
			result.Message = fmt.Sprintf("获取配置失败: %v", err)
			response.Results = append(response.Results, result)
			continue
		}

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
				memLimit := "512m"
				cpuLimit := "0.5"

				if config.Memory > 0 {
					halfMem := config.Memory / 2
					if halfMem < 128*1024*1024 {
						halfMem = 128 * 1024 * 1024
					}
					memLimit = fmt.Sprintf("%dm", halfMem/(1024*1024))
				}

				if config.NanoCpus > 0 {
					halfCpu := config.NanoCpus / 2
					if halfCpu < 100000000 {
						halfCpu = 100000000
					}
					cpuLimit = fmt.Sprintf("%.1f", float64(halfCpu)/1e9)
				} else if config.CpuQuota > 0 && config.CpuPeriod > 0 {
					originalCpus := float64(config.CpuQuota) / float64(config.CpuPeriod)
					halfCpus := originalCpus / 2
					if halfCpus < 0.1 {
						halfCpus = 0.1
					}
					cpuLimit = fmt.Sprintf("%.1f", halfCpus)
				}

				_, err := a.runSudoCommand("docker", "update", "--cpus", cpuLimit, "--memory", memLimit, task.ContainerID)
				if err != nil {
					result.Message += fmt.Sprintf("资源限制失败(尝试: cpu=%s mem=%s); ", cpuLimit, memLimit)
				} else {
					result.Message += fmt.Sprintf("资源限制成功(cpu=%s mem=%s); ", cpuLimit, memLimit)
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
	Image          string   `json:"image"`
	Cmd            []string `json:"cmd"`
	Env            []string `json:"env"`
	Volumes        []string `json:"volumes"`
	Ports          []string `json:"ports"`
	WorkingDir     string   `json:"working_dir"`
	RestartPolicy  string   `json:"restart_policy"`
	Networks       []string `json:"networks"`
	Privileged     bool     `json:"privileged"`
	CapAdd         []string `json:"cap_add"`
	CapDrop        []string `json:"cap_drop"`
	User           string   `json:"user"`
	SecurityOpt    []string `json:"security_opt"`
	ReadonlyRootfs bool     `json:"readonly_rootfs"`
	Memory         int64    `json:"memory"`
	CpuQuota       int64    `json:"cpu_quota"`
	CpuPeriod      int64    `json:"cpu_period"`
	CpuShares      int64    `json:"cpu_shares"`
	NanoCpus       int64    `json:"nano_cpus"`
}

func (a *App) getContainerOriginalConfig(containerID string) (ContainerOriginalConfig, error) {
	var config ContainerOriginalConfig

	inspectJSON, err := a.runSudoCommand("docker", "inspect", "--format", "{{json .}}", containerID)
	if err != nil {
		return config, err
	}

	var inspectData map[string]interface{}
	if err := json.Unmarshal([]byte(strings.TrimSpace(inspectJSON)), &inspectData); err != nil {
		return config, fmt.Errorf("解析容器JSON失败: %v", err)
	}

	getStr := func(m map[string]interface{}, key string) string {
		if v, ok := m[key].(string); ok {
			return v
		}
		return ""
	}
	toStringSlice := func(arr []interface{}) []string {
		var result []string
		for _, v := range arr {
			if s, ok := v.(string); ok {
				result = append(result, s)
			}
		}
		return result
	}
	getNum := func(m map[string]interface{}, key string) int64 {
		if v, ok := m[key]; ok {
			switch n := v.(type) {
			case float64:
				return int64(n)
			case int64:
				return n
			case int:
				return int64(n)
			case json.Number:
				if i, err := n.Int64(); err == nil {
					return i
				}
			case string:
			}
		}
		return 0
	}

	configObj, _ := inspectData["Config"].(map[string]interface{})
	if configObj != nil {
		config.Image = strings.TrimSpace(getStr(configObj, "Image"))
		config.User = strings.TrimSpace(getStr(configObj, "User"))
		if config.User == "<no value>" {
			config.User = ""
		}
		config.WorkingDir = strings.TrimSpace(getStr(configObj, "WorkingDir"))
		if config.WorkingDir == "<no value>" {
			config.WorkingDir = ""
		}
		if cmdArr, ok := configObj["Cmd"].([]interface{}); ok {
			config.Cmd = toStringSlice(cmdArr)
		}
		if envArr, ok := configObj["Env"].([]interface{}); ok {
			config.Env = toStringSlice(envArr)
		}
	}

	hostConfig, _ := inspectData["HostConfig"].(map[string]interface{})
	if hostConfig != nil {
		config.Privileged = getStr(hostConfig, "Privileged") == "true"
		config.ReadonlyRootfs = getStr(hostConfig, "ReadonlyRootfs") == "true"

		config.Memory = getNum(hostConfig, "Memory")
		config.CpuQuota = getNum(hostConfig, "CpuQuota")
		config.CpuPeriod = getNum(hostConfig, "CpuPeriod")
		config.CpuShares = getNum(hostConfig, "CpuShares")
		config.NanoCpus = getNum(hostConfig, "NanoCpus")

		if capAddArr, ok := hostConfig["CapAdd"].([]interface{}); ok {
			config.CapAdd = toStringSlice(capAddArr)
		}
		if capDropArr, ok := hostConfig["CapDrop"].([]interface{}); ok {
			config.CapDrop = toStringSlice(capDropArr)
		}
		if secOptArr, ok := hostConfig["SecurityOpt"].([]interface{}); ok {
			config.SecurityOpt = toStringSlice(secOptArr)
		}
		if rpObj, ok := hostConfig["RestartPolicy"].(map[string]interface{}); ok {
			config.RestartPolicy = strings.TrimSpace(getStr(rpObj, "Name"))
			if config.RestartPolicy == "<no value>" {
				config.RestartPolicy = ""
			}
		}
		if portBindings, ok := hostConfig["PortBindings"].(map[string]interface{}); ok {
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
							config.Ports = append(config.Ports, fmt.Sprintf("%s:%s:%s", hostIP, hostPort, portKey))
						}
					}
				}
			}
		}
	}

	if mountsArr, ok := inspectData["Mounts"].([]interface{}); ok {
		for _, m := range mountsArr {
			if mObj, ok := m.(map[string]interface{}); ok {
				if src, ok := mObj["Source"].(string); ok {
					if dst, ok := mObj["Destination"].(string); ok {
						config.Volumes = append(config.Volumes, fmt.Sprintf("%s:%s", src, dst))
					}
				}
			}
		}
	}

	if netSettings, ok := inspectData["NetworkSettings"].(map[string]interface{}); ok {
		if networks, ok := netSettings["Networks"].(map[string]interface{}); ok {
			for netName := range networks {
				config.Networks = append(config.Networks, netName)
			}
		}
	}

	return config, nil
}

var hardenOptMessages = map[string]string{
	"drop_privileged":   "已移除特权模式",
	"drop_capabilities": "已丢弃所有Capabilities",
	"non_root_user":     "已切换为非root用户(UID:1000)",
	"seccomp":           "已启用seccomp系统调用过滤",
	"apparmor":          "已启用AppArmor文件访问控制",
	"read_only_rootfs":  "已启用只读根文件系统",
	"no_new_privileges": "已禁止提权(no-new-privileges)",
}

var hardenOptSecurityArgs = map[string]string{
	"apparmor":          "apparmor=docker-default",
	"no_new_privileges": "no-new-privileges:true",
}

func (a *App) restartWithHarden(containerID string, config ContainerOriginalConfig, optIDs []string) (string, error) {
	var msg strings.Builder

	_, err := a.runSudoCommand("docker", "stop", containerID)
	if err != nil {
		return "", fmt.Errorf("停止容器失败: %v", err)
	}

	nameOutput, _ := a.runSudoCommand("docker", "inspect", "--format", "{{.Name}}", containerID)
	containerName := strings.TrimPrefix(strings.TrimSpace(nameOutput), "/")

	var args []string
	args = append(args, "run", "-d")

	if containerName != "" {
		args = append(args, "--name", containerName+"_hardened")
	}

	for _, env := range config.Env {
		args = append(args, "-e", env)
	}

	for _, vol := range config.Volumes {
		args = append(args, "-v", vol)
	}

	for _, port := range config.Ports {
		args = append(args, "-p", port)
	}

	if config.WorkingDir != "" {
		args = append(args, "-w", config.WorkingDir)
	}

	if config.RestartPolicy != "" && config.RestartPolicy != "no" {
		args = append(args, "--restart", config.RestartPolicy)
	}

	for _, net := range config.Networks {
		args = append(args, "--network", net)
	}

	hardenOpts := map[string]bool{}
	for _, optID := range optIDs {
		hardenOpts[optID] = true
	}

	if !hardenOpts["drop_privileged"] && config.Privileged {
		args = append(args, "--privileged")
	}

	if !hardenOpts["drop_capabilities"] {
		for _, cap := range config.CapAdd {
			args = append(args, "--cap-add", cap)
		}
		for _, cap := range config.CapDrop {
			args = append(args, "--cap-drop", cap)
		}
	} else {
		args = append(args, "--cap-drop=ALL")
	}

	if !hardenOpts["non_root_user"] {
		if config.User != "" && config.User != "root" {
			args = append(args, "--user", config.User)
		}
	} else {
		args = append(args, "--user", "1000:1000")
	}

	if !hardenOpts["read_only_rootfs"] {
		if config.ReadonlyRootfs {
			args = append(args, "--read-only")
		}
	} else {
		args = append(args, "--read-only")
	}

	if !hardenOpts["no_new_privileges"] && !hardenOpts["seccomp"] && !hardenOpts["apparmor"] {
		for _, opt := range config.SecurityOpt {
			args = append(args, "--security-opt", opt)
		}
	}

	var seccompFile string
	for _, optID := range optIDs {
		if optID == "seccomp" {
			tmpFile, err := os.CreateTemp("", "wdd-seccomp-*.json")
			if err != nil {
				return "", fmt.Errorf("创建seccomp临时文件失败: %v", err)
			}
			seccompFile = tmpFile.Name()
			if err := os.WriteFile(seccompFile, []byte(defaultSeccompProfile()), 0644); err != nil {
				os.Remove(seccompFile)
				return "", fmt.Errorf("写入seccomp配置失败: %v", err)
			}
			tmpFile.Close()
			args = append(args, "--security-opt", fmt.Sprintf("seccomp=%s", seccompFile))
			continue
		}
		if secArg, ok := hardenOptSecurityArgs[optID]; ok {
			args = append(args, "--security-opt", secArg)
		}
	}
	if seccompFile != "" {
		defer os.Remove(seccompFile)
	}

	args = append(args, "--")
	args = append(args, config.Image)
	if len(config.Cmd) > 0 {
		args = append(args, config.Cmd...)
	}

	newIDOutput, err := a.runSudoCommand("docker", args...)
	if err != nil {
		_, restoreErr := a.runSudoCommand("docker", "start", containerID)
		if restoreErr != nil {
			return "", fmt.Errorf("启动新容器失败且无法恢复旧容器: %v / %v", err, restoreErr)
		}
		return "", fmt.Errorf("启动新容器失败，已恢复旧容器: %v", err)
	}

	newID := strings.TrimSpace(newIDOutput)

	_, rmErr := a.runSudoCommand("docker", "rm", containerID)
	if rmErr != nil {
		msg.WriteString(fmt.Sprintf("警告: 删除旧容器失败(%v)，新容器已创建但旧容器残留\n", rmErr))
	}

	if containerName != "" {
		_, renameErr := a.runSudoCommand("docker", "rename", newID, containerName)
		if renameErr != nil {
			msg.WriteString(fmt.Sprintf("警告: 重命名新容器失败(%v)，新容器名仍为 %s_hardened\n", renameErr, containerName))
		}
	}

	msg.WriteString(fmt.Sprintf("容器已重启加固，新ID: %s\n", newID))
	msg.WriteString("应用的加固措施:\n")
	for _, opt := range optIDs {
		if desc, ok := hardenOptMessages[opt]; ok {
			msg.WriteString("  - " + desc + "\n")
		}
	}

	return msg.String(), nil
}

func defaultSeccompProfile() string {
	return string(seccompProfileData)
}

type ToolStatus struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Installed   bool   `json:"installed"`
	Version     string `json:"version"`
	InstallCmd  string `json:"installCmd"`
}

type toolInstallSpec struct {
	name        string
	description string
	installCmd  string
	checkBin    string
	installArgs []string
	useSudo     bool
	pipeScript  string
}

var toolSpecs = []toolInstallSpec{
	{
		name:        "nmap",
		description: "网络扫描和安全审计工具",
		installCmd:  "apt-get install -y nmap",
		checkBin:    "nmap",
		installArgs: []string{"apt-get", "install", "-y", "nmap"},
		useSudo:     true,
	},
	{
		name:        "whois",
		description: "域名信息查询工具",
		installCmd:  "apt-get install -y whois",
		checkBin:    "whois",
		installArgs: []string{"apt-get", "install", "-y", "whois"},
		useSudo:     true,
	},
	{
		name:        "chromium",
		description: "网页截图和浏览器工具",
		installCmd:  "apt-get install -y chromium",
		checkBin:    "chromium",
		installArgs: []string{"apt-get", "install", "-y", "chromium"},
		useSudo:     true,
	},
	{
		name:        "docker",
		description: "容器运行时环境",
		installCmd:  "curl -fsSL https://get.docker.com | sh",
		checkBin:    "docker",
		pipeScript:  "curl -fsSL https://get.docker.com | sh",
	},
	{
		name:        "dig",
		description: "DNS查询工具(dnsutils包)",
		installCmd:  "apt-get install -y dnsutils",
		checkBin:    "dig",
		installArgs: []string{"apt-get", "install", "-y", "dnsutils"},
		useSudo:     true,
	},
	{
		name:        "traceroute",
		description: "路由追踪工具",
		installCmd:  "apt-get install -y traceroute",
		checkBin:    "traceroute",
		installArgs: []string{"apt-get", "install", "-y", "traceroute"},
		useSudo:     true,
	},
}

func (a *App) CheckTools() []ToolStatus {
	tools := make([]ToolStatus, 0, len(toolSpecs))
	for _, spec := range toolSpecs {
		tool := ToolStatus{
			Name:        spec.name,
			Description: spec.description,
			InstallCmd:  spec.installCmd,
		}

		installed := false
		versionStr := ""
		if spec.checkBin != "" {
			cmd := exec.Command("which", spec.checkBin)
			output, err := cmd.CombinedOutput()
			if err == nil && strings.TrimSpace(string(output)) != "" {
				installed = true
				versionCmd := exec.Command(spec.checkBin, "--version")
				versionOutput, _ := versionCmd.CombinedOutput()
				versionStr = string(versionOutput)
				lines := strings.Split(versionStr, "\n")
				if len(lines) > 0 {
					tool.Version = strings.TrimSpace(lines[0])
				}
			}
		}

		if !installed && spec.name == "dig" {
			cmd := exec.Command("dpkg", "-l", "dnsutils")
			output, err := cmd.CombinedOutput()
			if err == nil && strings.Contains(string(output), "ii") {
				installed = true
				tool.Version = "dnsutils已安装"
			}
		}
		if !installed && spec.name == "docker" {
			cmd := exec.Command("docker", "--version")
			output, err := cmd.CombinedOutput()
			if err == nil {
				installed = true
				versionStr = string(output)
				lines := strings.Split(versionStr, "\n")
				if len(lines) > 0 {
					tool.Version = strings.TrimSpace(lines[0])
				}
			}
		}

		tool.Installed = installed
		tools = append(tools, tool)
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
			break
		}
	}

	var spec *toolInstallSpec
	for i := range toolSpecs {
		if toolSpecs[i].name == name {
			spec = &toolSpecs[i]
			break
		}
	}
	if spec == nil {
		return fmt.Sprintf("未找到工具: %s", name)
	}

	if spec.useSudo && len(spec.installArgs) > 0 {
		output, err := a.runSudoCommand(spec.installArgs[0], spec.installArgs[1:]...)
		if err != nil {
			return fmt.Sprintf("安装失败: %v\n%s", err, output)
		}
		return fmt.Sprintf("%s 安装成功\n风险等级: 高危", name)
	}

	if spec.pipeScript != "" {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		cmd := exec.CommandContext(ctx, "bash", "-c", spec.pipeScript)
		cmd.Env = []string{
			"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
			"HOME=" + os.Getenv("HOME"),
		}
		output, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Sprintf("安装失败: %v\n%s", err, string(output))
		}
		return fmt.Sprintf("%s 安装成功\n风险等级: 高危", name)
	}

	return fmt.Sprintf("未找到工具: %s", name)
}

func (a *App) runCommand(name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = []string{
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"HOME=" + os.Getenv("HOME"),
		"LANG=" + os.Getenv("LANG"),
	}

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()

	output := stdout.String()
	if stderr.Len() > 0 {
		output += "\n[STDERR] " + stderr.String()
	}

	if ctx.Err() == context.DeadlineExceeded {
		return output, fmt.Errorf("命令执行超时(超过5分钟): %s %v", name, args)
	}

	return output, err
}

func main() {
	app := NewApp()

	err := wails.Run(&options.App{
		Title:  "W-DD 看守者-防线部署",
		Width:  1200,
		Height: 800,

		// ========== 全屏配置 ==========
		WindowStartState: options.Fullscreen,
		// ==============================

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
		log.Fatalf("W-DD 看守者启动失败: %v", err)
	}
}
// 2026-7-26留言：整体确认，无需修改