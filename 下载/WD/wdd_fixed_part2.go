
// ==================== 纯Go实现的功能 ====================

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

func (a *App) goFileHash(filepath string) (string, error) {
	file, err := os.Open(filepath)
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

func (a *App) goLogAnalysis(filepath string) (string, error) {
	file, err := os.Open(filepath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	var result strings.Builder
	result.WriteString(fmt.Sprintf("日志分析 - 文件: %s\n\n", filepath))

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

func (a *App) goConfigCheck(filepath string) (string, error) {
	data, err := os.ReadFile(filepath)
	if err != nil {
		return "", err
	}

	content := string(data)
	var result strings.Builder
	result.WriteString(fmt.Sprintf("配置检查 - 文件: %s\n\n", filepath))

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
