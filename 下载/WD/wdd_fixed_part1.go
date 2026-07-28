package main

import (
	"bufio"
	"context"
	"crypto/md5"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
	"github.com/wailsapp/wails/v2/pkg/runtime"
)

//go:embed all:frontend/dist
var assets embed.FS

// ==================== App 结构 ====================

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

// ==================== 文件选择 ====================

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

// ==================== Root 密码管理 ====================

func (a *App) SetRootPassword(password string) bool {
	cmd := exec.Command("sudo", "-S", "-k", "whoami")
	cmd.Stdin = strings.NewReader(password + "\n")
	output, err := cmd.CombinedOutput()
	if err != nil || !strings.Contains(string(output), "root") {
		return false
	}
	a.rootPassword = password
	return true
}

func (a *App) HasRootPassword() bool {
	return a.rootPassword != ""
}

func (a *App) runSudoCommand(name string, args ...string) (string, error) {
	if a.rootPassword == "" {
		return "", fmt.Errorf("NEED_ROOT|未设置root密码，请先赋予权限")
	}
	allArgs := append([]string{"-S", "-k", name}, args...)
	cmd := exec.Command("sudo", allArgs...)
	cmd.Stdin = strings.NewReader(a.rootPassword + "\n")
	cmd.Env = os.Environ()
	output, err := cmd.CombinedOutput()
	return string(output), err
}

// ==================== 输入识别 ====================

type InputType struct {
	Type        string `json:"type"`
	Category    string `json:"category"`
	Description string `json:"description"`
}

func (a *App) DetectInputType(rawInput string) InputType {
	input := strings.TrimSpace(rawInput)
	re := regexp.MustCompile(`[,，]\d+$`)
	input = re.ReplaceAllString(input, "")
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

// ==================== 功能列表 ====================

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

// ==================== 功能执行 ====================

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
