package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/term"
	"gopkg.in/yaml.v3"
)

// ===================== 常量定义 =====================
const (
	DefaultRDPPort    = 3389
	DefaultSSHPort    = 22
	MaxPort           = 65535
	XfreerdpCmd       = "xfreerdp3"
	SSHCmd            = "ssh"
	TrzszCmd          = "trzsz"
	SshpassCmd        = "sshpass"
	ConfigFileName    = "config.yaml"
	HistoryFileName   = "./rdp_manager_history"
	AuditLogPath      = "./rdp_manager.log"
	TrzszDeployedFile = "./rdp_manager_trzsz_deployed"
	DirPermission     = 0700
	FilePermission    = 0600
	HostTypeRDP       = "rdp"
	HostTypeSSH       = "ssh"
	MaxConcurrency    = 20
	LogMaxSize        = 100 * 1024 * 1024
)

// 自定义错误类型
type (
	ConfigError     struct{ Msg string }
	ConnectError    struct{ Msg string }
	ValidationError struct{ Msg string }
)

func (e *ConfigError) Error() string     { return fmt.Sprintf("配置错误: %s", e.Msg) }
func (e *ConnectError) Error() string    { return fmt.Sprintf("连接错误: %s", e.Msg) }
func (e *ValidationError) Error() string { return fmt.Sprintf("验证错误: %s", e.Msg) }

// Host 核心结构体（明文密码，按要求保留）
type Host struct {
	Name     string `yaml:"name"`
	IP       string `yaml:"ip"`
	Port     int    `yaml:"port"`
	Username string `yaml:"username"`
	Password string `yaml:"password"`
	Drive    string `yaml:"drive"`
	KeyPath  string `yaml:"key_path"`
	Type     string `yaml:"type"`
}

// History 记录
type History struct {
	Name      string    `yaml:"name"`
	Timestamp time.Time `yaml:"timestamp"`
}

// Config 整体配置
type Config struct {
	Hosts []Host `yaml:"hosts"`
}

// 全局变量
var (
	configPath        string
	historyPath       string
	trzszDeployedPath string
	activeSessions    = make(map[string]*exec.Cmd)
	sessionsMutex     sync.Mutex
	trzszMutex        sync.Mutex
)

func init() {
	exePath, err := os.Executable()
	if err != nil {
		exePath = os.Args[0]
	}
	exeDir := filepath.Dir(exePath)
	configPath = filepath.Join(exeDir, ConfigFileName)
	historyPath = filepath.Join(exeDir, HistoryFileName)
	trzszDeployedPath = filepath.Join(exeDir, TrzszDeployedFile)

	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-c
		fmt.Println("\n\n🛑 收到退出信号，正在优雅退出...")
		cleanupAllSessions()
		fmt.Println("👋 再见！")
		os.Exit(0)
	}()

	logDir := filepath.Dir(AuditLogPath)
	if err := os.MkdirAll(logDir, DirPermission); err != nil {
		fmt.Printf("⚠️ 初始化审计日志目录失败: %v\n", err)
	} else {
		if _, err := os.Stat(AuditLogPath); err == nil {
			_ = os.Chmod(AuditLogPath, FilePermission)
		}
	}
}

// ===================== 工具函数 =====================
func getHomeDir() string {
	if usr, err := user.Current(); err == nil {
		return usr.HomeDir
	}
	if home := os.Getenv("HOME"); home != "" {
		return home
	}
	return "/tmp"
}

func GetRealPort(port int, hostType string) int {
	if port <= 0 || port > MaxPort {
		if hostType == HostTypeSSH {
			return DefaultSSHPort
		}
		return DefaultRDPPort
	}
	return port
}

func GetAddr(ip string, port int, hostType string) string {
	return net.JoinHostPort(ip, strconv.Itoa(GetRealPort(port, hostType)))
}

func IsValidAddr(addr string) bool {
	if addr == "" {
		return false
	}
	if ip := net.ParseIP(addr); ip != nil {
		return true
	}
	_, err := net.LookupIP(addr)
	return err == nil
}

func IsDirExist(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

func IsFileExist(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func ExpandPath(path string) string {
	if path == "" || !strings.HasPrefix(path, "~") {
		return path
	}
	home := getHomeDir()
	return filepath.Join(home, path[1:])
}

func IsProcessAlive(cmd *exec.Cmd) bool {
	if cmd == nil || cmd.Process == nil {
		return false
	}
	err := cmd.Process.Signal(syscall.Signal(0))
	return err != syscall.ESRCH
}

func CleanDeadSessions() {
	sessionsMutex.Lock()
	defer sessionsMutex.Unlock()

	for key, cmd := range activeSessions {
		if !IsProcessAlive(cmd) {
			delete(activeSessions, key)
		}
	}
}

func cleanupAllSessions() {
	sessionsMutex.Lock()
	defer sessionsMutex.Unlock()

	for key, cmd := range activeSessions {
		if cmd.Process != nil {
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			fmt.Printf("✅ 关闭残留连接: %s (PID: %d)\n", key, cmd.Process.Pid)
		}
	}
	activeSessions = make(map[string]*exec.Cmd)
}

func IsCommandExist(cmd string) bool {
	_, err := exec.LookPath(cmd)
	return err == nil
}

func getEffectiveHostType(h Host) string {
	if h.Type == "" {
		return HostTypeRDP
	}
	return h.Type
}

func hostKey(h Host) string {
	hostType := getEffectiveHostType(h)
	port := GetRealPort(h.Port, hostType)
	return fmt.Sprintf("[%s]%s|%s:%d", hostType, h.Name, h.IP, port)
}

func readInput(prompt string) string {
	if prompt != "" {
		fmt.Print(prompt)
	}
	reader := bufio.NewReader(os.Stdin)
	input, err := reader.ReadString('\n')
	if err != nil && err != io.EOF {
		return ""
	}
	return strings.TrimSpace(input)
}

func readPasswordWithPrompt(hostType string) string {
	var prompt string
	if hostType == HostTypeRDP {
		prompt = "密码（必填）: "
	} else {
		prompt = "如使用密钥，可回车跳过: "
	}

	fmt.Print(prompt)

	oldState, err := term.MakeRaw(int(os.Stdin.Fd()))
	if err != nil {
		fmt.Println("\n⚠️ 无法隐藏输入，将明文显示密码")
		return readInput("")
	}
	defer term.Restore(int(os.Stdin.Fd()), oldState)

	reader := bufio.NewReader(os.Stdin)
	var password []byte
	buf := make([]byte, 1)

	for {
		n, err := reader.Read(buf)
		if err != nil || n == 0 {
			break
		}

		char := buf[0]

		if char == '\r' || char == '\n' {
			break
		}

		if char == 127 || char == 8 {
			if len(password) > 0 {
				password = password[:len(password)-1]
				fmt.Print("\b \b")
			}
			continue
		}

		password = append(password, char)
		fmt.Print("•")
	}

	fmt.Println()
	return string(password)
}

func startCmdAndTrack(cmd *exec.Cmd, sessionKey string) error {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	if err := cmd.Start(); err != nil {
		return &ConnectError{Msg: fmt.Sprintf("启动进程失败: %v", err)}
	}

	go func() {
		_ = cmd.Wait()
		sessionsMutex.Lock()
		delete(activeSessions, sessionKey)
		sessionsMutex.Unlock()
	}()

	sessionsMutex.Lock()
	activeSessions[sessionKey] = cmd
	sessionsMutex.Unlock()
	return nil
}

// ===================== 日志与历史 =====================
func logAudit(action, host, status string) {
	logLine := fmt.Sprintf("%s | %s | %s | %s\n",
		time.Now().Format("2006-01-02T15:04:05Z07:00"),
		action, host, status)

	if info, err := os.Stat(AuditLogPath); err == nil && info.Size() > LogMaxSize {
		tmpPath := AuditLogPath + ".old"
		_ = os.Rename(AuditLogPath, tmpPath)
	}

	f, err := os.OpenFile(AuditLogPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, FilePermission)
	if err != nil {
		fmt.Printf("⚠️ 写入审计日志失败: %v\n", err)
		return
	}
	defer f.Close()
	_, _ = f.WriteString(logLine)
}

func saveHistory(name string) {
	var history []History
	if data, err := os.ReadFile(historyPath); err == nil {
		_ = yaml.Unmarshal(data, &history)
	}

	newHistory := []History{{Name: name, Timestamp: time.Now()}}
	seen := map[string]bool{name: true}
	count := 1
	for _, h := range history {
		if !seen[h.Name] && count < 10 {
			newHistory = append(newHistory, h)
			seen[h.Name] = true
			count++
		}
	}

	data, err := yaml.Marshal(newHistory)
	if err != nil {
		fmt.Printf("⚠️ 保存历史记录失败: %v\n", err)
		return
	}
	_ = os.WriteFile(historyPath, data, FilePermission)
}

func loadHistory() []History {
	var history []History
	if data, err := os.ReadFile(historyPath); err == nil {
		_ = yaml.Unmarshal(data, &history)
	}
	return history
}

// ===================== trzsz 部署状态管理 =====================
func isTrzszDeployed(hostID string) bool {
	data, err := os.ReadFile(trzszDeployedPath)
	if err != nil {
		return false
	}
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		if strings.TrimSpace(line) == hostID {
			return true
		}
	}
	return false
}

func markTrzszDeployed(hostID string) {
	trzszMutex.Lock()
	defer trzszMutex.Unlock()

	f, err := os.OpenFile(trzszDeployedPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, FilePermission)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = f.WriteString(hostID + "\n")
}

// ===================== 配置管理 =====================
func ensureConfigExists() error {
	dir := filepath.Dir(configPath)
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		if err := os.MkdirAll(dir, DirPermission); err != nil {
			return &ConfigError{Msg: fmt.Sprintf("无法创建配置目录: %v", err)}
		}
	}

	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		cfg := &Config{Hosts: []Host{}}
		if err := saveConfig(cfg); err != nil {
			return err
		}
		fmt.Printf("✅ 配置文件已创建: %s\n", configPath)

		// 强制同步文件系统
		syncCmd := exec.Command("sync")
		_ = syncCmd.Run()
	}
	return nil
}

func saveConfig(cfg *Config) error {
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return &ConfigError{Msg: fmt.Sprintf("序列化配置失败: %v", err)}
	}

	// 使用原子写入，避免部分写入
	tempPath := configPath + ".tmp"
	if err := os.WriteFile(tempPath, data, FilePermission); err != nil {
		return &ConfigError{Msg: fmt.Sprintf("写入配置文件失败: %v", err)}
	}

	// 确保文件内容写入磁盘
	tempFile, err := os.OpenFile(tempPath, os.O_RDONLY, 0)
	if err != nil {
		os.Remove(tempPath)
		return &ConfigError{Msg: fmt.Sprintf("打开临时配置文件失败: %v", err)}
	}
	tempFile.Sync()
	tempFile.Close()

	// 重命名确保原子性
	if err := os.Rename(tempPath, configPath); err != nil {
		os.Remove(tempPath)
		return &ConfigError{Msg: fmt.Sprintf("重命名配置文件失败: %v", err)}
	}

	// 立即设置权限
	if err := os.Chmod(configPath, FilePermission); err != nil {
		return &ConfigError{Msg: fmt.Sprintf("设置配置文件权限失败: %v", err)}
	}

	return nil
}

func loadConfig() (*Config, error) {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, &ConfigError{Msg: fmt.Sprintf("读取配置文件失败: %v", err)}
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, &ConfigError{Msg: fmt.Sprintf("配置文件格式错误: %v", err)}
	}

	for i, host := range cfg.Hosts {
		if host.Name == "" {
			return nil, &ValidationError{Msg: fmt.Sprintf("第%d个主机名称不能为空", i+1)}
		}
		if !IsValidAddr(host.IP) {
			return nil, &ValidationError{Msg: fmt.Sprintf("主机[%s]的IP/域名无效", host.Name)}
		}
	}

	return &cfg, nil
}

func filterHosts(cfg *Config, hostType string) []Host {
	var filtered []Host
	for _, h := range cfg.Hosts {
		if getEffectiveHostType(h) == hostType {
			filtered = append(filtered, h)
		}
	}
	return filtered
}

// ===================== FZF 单选 =====================
func runFzf(input, header string) (string, error) {
	if !IsCommandExist("fzf") {
		return "", &ConnectError{Msg: "未检测到fzf工具，请安装：sudo apt install fzf"}
	}

	cmd := exec.Command("fzf",
		"--header="+header,
		"--prompt=🔍 ",
		"--height=80%",
		"--layout=reverse",
		"--border",
		"--info=inline",
		"--preview-window=right:50%:wrap",
		"--no-multi",
	)
	cmd.Stdin = strings.NewReader(input)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 130 {
			return "", fmt.Errorf("cancelled")
		}
		return "", &ConnectError{Msg: fmt.Sprintf("FZF执行失败: %v", err)}
	}

	result := strings.TrimSpace(out.String())
	if result == "" {
		return "", fmt.Errorf("no selection")
	}
	return result, nil
}

func selectHostWithFzf(hosts []Host, hostType string) *Host {
	if len(hosts) == 0 {
		hostTypeName := "Windows(RDP)"
		if hostType == HostTypeSSH {
			hostTypeName = "Linux(SSH)"
		}
		fmt.Printf("ostringstream 当前无任何【%s】主机配置。\n", hostTypeName)
		return nil
	}

	history := loadHistory()
	historyMap := make(map[string]bool)
	var inputLines []string

	for _, h := range history {
		historyMap[h.Name] = true
		for _, host := range hosts {
			if host.Name == h.Name {
				addr := GetAddr(host.IP, host.Port, hostType)
				inputLines = append(inputLines, fmt.Sprintf("⭐ %s (%s)", host.Name, addr))
				break
			}
		}
	}

	if len(inputLines) > 0 {
		inputLines = append(inputLines, "--- 最近连接 ---")
	}

	for _, h := range hosts {
		if !historyMap[h.Name] {
			addr := GetAddr(h.IP, h.Port, hostType)
			inputLines = append(inputLines, fmt.Sprintf("%s (%s)", h.Name, addr))
		}
	}

	input := strings.Join(inputLines, "\n")
	header := "↑/↓: Navigate | Enter: Connect | Esc: Cancel"
	selection, err := runFzf(input, header)
	if err != nil {
		return nil
	}

	cleanSelection := strings.TrimPrefix(selection, "⭐ ")
	parts := strings.SplitN(cleanSelection, " ", 2) // 只分割第一个空格
	if len(parts) > 0 {
		cleanSelection = parts[0]
	}

	for i := range hosts {
		if hosts[i].Name == cleanSelection {
			return &hosts[i]
		}
	}
	return nil
}

// ===================== FZF 多选 =====================
func runFzfMulti(input, header string) ([]string, error) {
	if !IsCommandExist("fzf") {
		return nil, &ConnectError{Msg: "未检测到fzf工具，请安装：sudo apt install fzf"}
	}

	cmd := exec.Command("fzf",
		"--header="+header,
		"--prompt=🔍 ",
		"--height=80%",
		"--layout=reverse",
		"--border",
		"--info=inline",
		"--preview-window=right:50%:wrap",
		"--multi",
	)
	cmd.Stdin = strings.NewReader(input)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 130 {
			return nil, fmt.Errorf("cancelled")
		}
		return nil, &ConnectError{Msg: fmt.Sprintf("FZF执行失败: %v", err)}
	}

	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	var result []string
	for _, line := range lines {
		if line != "" {
			result = append(result, line)
		}
	}
	return result, nil
}

func selectHostsWithFzfMulti(hosts []Host, hostType string) []*Host {
	if len(hosts) == 0 {
		hostTypeName := "Linux(SSH)"
		fmt.Printf("ostringstream 当前无任何【%s】主机配置。\n", hostTypeName)
		return nil
	}

	var inputLines []string
	for _, h := range hosts {
		addr := GetAddr(h.IP, h.Port, hostType)
		inputLines = append(inputLines, fmt.Sprintf("%s (%s)", h.Name, addr))
	}

	input := strings.Join(inputLines, "\n")
	header := "↑/↓: Navigate | Space: Select | Enter: Confirm | Esc: Cancel"
	selections, err := runFzfMulti(input, header)
	if err != nil {
		return nil
	}

	selectedHosts := []*Host{}
	for _, selection := range selections {
		parts := strings.SplitN(selection, " ", 2) // 只分割第一个空格
		if len(parts) > 0 {
			name := parts[0]
			for i := range hosts {
				if hosts[i].Name == name {
					selectedHosts = append(selectedHosts, &hosts[i])
					break
				}
			}
		}
	}
	return selectedHosts
}

// ===================== 主机管理 =====================
func addNewHost(cfg *Config, hostType string) {
	var name string
	for {
		name = readInput("主机名称（不可为空）: ")
		if name != "" {
			break
		}
		fmt.Println("⚠️ 主机名称不能为空，请重新输入。")
	}

	var ip string
	for {
		ip = readInput("IP地址: ")
		if IsValidAddr(ip) {
			break
		}
		fmt.Println("⚠️ IP地址格式无效，请输入合法的IPv4/IPv6地址。")
	}

	defaultPort := DefaultRDPPort
	portTip := "3389"
	if hostType == HostTypeSSH {
		defaultPort = DefaultSSHPort
		portTip = "22"
	}
	portStr := readInput(fmt.Sprintf("端口号（默认 %s）: ", portTip))
	port := defaultPort
	if portStr != "" {
		if p, err := strconv.Atoi(portStr); err == nil && p > 0 && p < MaxPort {
			port = p
		} else {
			fmt.Printf("⚠️ 端口无效，使用默认 %s\n", portTip)
		}
	}

	tempHost := Host{Name: name, IP: ip, Port: port, Type: hostType}
	for _, h := range cfg.Hosts {
		if hostKey(h) == hostKey(tempHost) {
			fmt.Println("⚠️ 该主机（类型+名称+IP:端口）已存在，无需重复添加。")
			return
		}
	}

	var username string
	if hostType == HostTypeRDP {
		username = readInput("用户名（回车默认 Administrator）: ")
		if username == "" {
			username = "Administrator"
		}
	} else {
		username = readInput("用户名: ")
	}

	password := readPasswordWithPrompt(hostType)

	if hostType == HostTypeRDP && password == "" {
		fmt.Println("⚠️ RDP 连接必须提供密码！确定要留空吗？(y/N)")
		if readInput("") != "y" {
			fmt.Println("添加已取消。")
			return
		}
	}

	var ext1 string
	if hostType == HostTypeRDP {
		ext1 = readInput("本地共享路径（回车默认 家目录）: ")
		if ext1 == "" {
			ext1 = getHomeDir()
		}
		ext1 = ExpandPath(ext1)
		if !IsDirExist(ext1) {
			fmt.Printf("⚠️ 路径 %s 不存在，仍要使用吗？(y/N): ", ext1)
			if readInput("") != "y" {
				fmt.Println("添加已取消。")
				return
			}
		}
	} else {
		fmt.Print("\r密钥文件路径（回车则密码登录，例：~/.ssh/id_rsa）: ")
		ext1Raw := readInput("")
		ext1 = ExpandPath(ext1Raw)
		if ext1 != "" && !IsFileExist(ext1) {
			fmt.Printf("⚠️ 密钥文件 %s 不存在，仍要使用吗？(y/N): ", ext1)
			if readInput("") != "y" {
				fmt.Println("添加已取消。")
				return
			}
		}
	}

	fmt.Println("⚠️ 温馨提示：密码将以明文形式存储在配置文件中！")

	newHost := Host{
		Name:     name,
		IP:       ip,
		Port:     port,
		Username: username,
		Password: password,
		Type:     hostType,
	}
	if hostType == HostTypeRDP {
		newHost.Drive = ext1
	} else {
		newHost.KeyPath = ext1
	}

	if hostType == HostTypeSSH && password != "" {
		fmt.Println("🔍 正在测试 SSH 连通性...")
		addr := GetAddr(ip, port, HostTypeSSH)
		conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
		if err != nil {
			fmt.Printf("❌ TCP 连接失败: %v\n", err)
		} else {
			conn.Close()

			testCmd := exec.Command(SSHCmd,
				"-o", "StrictHostKeyChecking=no",
				"-o", "ConnectTimeout=5",
				"-p", strconv.Itoa(port),
				fmt.Sprintf("%s@%s", username, ip),
				"exit",
			)
			sshpassCmd := exec.Command(SshpassCmd, "-p", password)
			stdin, _ := testCmd.StdinPipe()
			sshpassCmd.Stdout = stdin
			testCmd.Stderr = os.Stderr

			if err := testCmd.Start(); err != nil {
				fmt.Printf("❌ SSH 启动失败: %v\n", err)
			} else {
				sshpassCmd.Run()
				testErr := testCmd.Wait()
				if testErr != nil {
					fmt.Printf("❌ SSH 握手失败: %v\n", testErr)
				} else {
					fmt.Println("✅ SSH 连通性正常")

					checkCmd := exec.Command(SSHCmd,
						"-o", "StrictHostKeyChecking=no",
						"-p", strconv.Itoa(port),
						fmt.Sprintf("%s@%s", username, ip),
						"which trz tsz",
					)
					sshpassCheckCmd := exec.Command(SshpassCmd, "-p", password)
					stdin2, _ := checkCmd.StdinPipe()
					sshpassCheckCmd.Stdout = stdin2
					var checkOut bytes.Buffer
					checkCmd.Stdout = &checkOut
					_ = checkCmd.Start()
					_ = sshpassCheckCmd.Run()
					_ = checkCmd.Wait()

					output := checkOut.String()
					if strings.Contains(output, "/trz") && strings.Contains(output, "/tsz") {
						fmt.Println("✅ 远程已安装 trz/tsz")
					} else {
						fmt.Println("📤 远程未安装 trz/tsz，正在部署...")

						exePath, _ := os.Executable()
						exeDir := filepath.Dir(exePath)
						localTrzszDir := filepath.Join(exeDir, "trzsz")
						trzPath := filepath.Join(localTrzszDir, "trz")
						tszPath := filepath.Join(localTrzszDir, "tsz")

						if !IsFileExist(trzPath) || !IsFileExist(tszPath) {
							fmt.Printf("❌ 本地 trzsz 目录缺失，请确保存在:\n  %s/trz\n  %s/tsz\n", localTrzszDir, localTrzszDir)
						} else {
							mkdirCmd := exec.Command(SSHCmd,
								"-o", "StrictHostKeyChecking=no",
								"-p", strconv.Itoa(port),
								fmt.Sprintf("%s@%s", username, ip),
								"mkdir -p ~/.local/bin",
							)
							sshpassMkdirCmd := exec.Command(SshpassCmd, "-p", password)
							stdin3, _ := mkdirCmd.StdinPipe()
							sshpassMkdirCmd.Stdout = stdin3
							_ = mkdirCmd.Start()
							_ = sshpassMkdirCmd.Run()
							_ = mkdirCmd.Wait()

							for _, file := range []string{"trz", "tsz"} {
								src := filepath.Join(localTrzszDir, file)
								dst := fmt.Sprintf("%s@%s:~/.local/bin/%s", username, ip, file)
								scpCmd := exec.Command("scp",
									"-P", strconv.Itoa(port),
									"-o", "StrictHostKeyChecking=no",
									src, dst,
								)
								sshpassScpCmd := exec.Command(SshpassCmd, "-p", password)
								stdin4, _ := scpCmd.StdinPipe()
								sshpassScpCmd.Stdout = stdin4
								_ = scpCmd.Start()
								_ = sshpassScpCmd.Run()
								_ = scpCmd.Wait()
							}

							chmodCmd := exec.Command(SSHCmd,
								"-o", "StrictHostKeyChecking=no",
								"-p", strconv.Itoa(port),
								fmt.Sprintf("%s@%s", username, ip),
								"chmod +x ~/.local/bin/trz ~/.local/bin/tsz",
							)
							sshpassChmodCmd := exec.Command(SshpassCmd, "-p", password)
							stdin5, _ := chmodCmd.StdinPipe()
							sshpassChmodCmd.Stdout = stdin5
							_ = chmodCmd.Start()
							_ = sshpassChmodCmd.Run()
							_ = chmodCmd.Wait()

							pathCmd := exec.Command(SSHCmd,
								"-o", "StrictHostKeyChecking=no",
								"-p", strconv.Itoa(port),
								fmt.Sprintf("%s@%s", username, ip),
								`grep -q 'export PATH.*\.local/bin' ~/.bashrc || echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc`,
							)
							sshpassPathCmd := exec.Command(SshpassCmd, "-p", password)
							stdin6, _ := pathCmd.StdinPipe()
							sshpassPathCmd.Stdout = stdin6
							_ = pathCmd.Start()
							_ = sshpassPathCmd.Run()
							_ = pathCmd.Wait()

							hostID := fmt.Sprintf("%s@%s:%d", username, ip, port)
							markTrzszDeployed(hostID)

							fmt.Println("✅ trz/tsz 已部署到远程")
						}
					}
				}
			}
		}
	}

	cfg.Hosts = append(cfg.Hosts, newHost)
	if err := saveConfig(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "❌ %v\n", err)
		return
	}
	fmt.Println("✅ 主机添加成功！")

	// 添加后强制刷新配置
	fmt.Println("🔄 配置已保存，下次操作将使用最新配置")
}

func editHost(cfg *Config, hostType string) {
	hosts := filterHosts(cfg, hostType)
	if len(hosts) == 0 {
		hostTypeName := "Windows(RDP)"
		if hostType == HostTypeSSH {
			hostTypeName = "Linux(SSH)"
		}
		fmt.Printf("ostringstream 当前无任何【%s】主机可编辑。\n", hostTypeName)
		return
	}

	selected := selectHostWithFzf(hosts, hostType)
	if selected == nil {
		return
	}

	originalKey := hostKey(*selected)

	fmt.Printf("\n📝 正在编辑主机: %s\n", selected.Name)
	fmt.Println("（直接回车表示不修改）")

	newName := readInput(fmt.Sprintf("新名称（当前: %s）: ", selected.Name))
	if newName != "" {
		selected.Name = newName
	}

	newIP := readInput(fmt.Sprintf("新 IP/域名（当前: %s）: ", selected.IP))
	if newIP != "" {
		if IsValidAddr(newIP) {
			selected.IP = newIP
		} else {
			fmt.Println("⚠️ IP/域名无效，保持原值不变。")
		}
	}

	currentPort := GetRealPort(selected.Port, hostType)
	newPortStr := readInput(fmt.Sprintf("新端口（当前: %d）: ", currentPort))
	if newPortStr != "" {
		if p, err := strconv.Atoi(newPortStr); err == nil && p > 0 && p < MaxPort {
			selected.Port = p
		} else {
			fmt.Println("⚠️ 端口无效，保持原值不变。")
		}
	}

	newUser := readInput(fmt.Sprintf("新用户名（当前: %s）: ", selected.Username))
	if newUser != "" {
		selected.Username = newUser
	}

	if readInput("是否修改密码？(y/N): ") == "y" {
		newPwd := readPasswordWithPrompt(hostType)
		if hostType == HostTypeRDP && newPwd == "" {
			fmt.Println("⚠️ RDP 密码为空！确定保存吗？(y/N)")
			if readInput("") != "y" {
				fmt.Println("密码未更新。")
			} else {
				selected.Password = newPwd
				fmt.Println("⚠️ 温馨提示：密码将以明文形式存储！")
			}
		} else {
			selected.Password = newPwd
			fmt.Println("⚠️ 温馨提示：密码将以明文形式存储！")
		}
	}

	if hostType == HostTypeRDP {
		newDrive := readInput(fmt.Sprintf("新共享路径（当前: %s）: ", selected.Drive))
		if newDrive != "" {
			newDrive = ExpandPath(newDrive)
			if !IsDirExist(newDrive) {
				fmt.Printf("⚠️ 路径 %s 不存在，仍要使用吗？(y/N): ", newDrive)
				if readInput("") != "y" {
					fmt.Println("路径未更新。")
				} else {
					selected.Drive = newDrive
				}
			} else {
				selected.Drive = newDrive
			}
		}
	} else {
		fmt.Print("新密钥路径（当前: ")
		if selected.KeyPath == "" {
			fmt.Print("<无>")
		} else {
			fmt.Print(selected.KeyPath)
		}
		fmt.Print("）: ")
		newKeyRaw := readInput("")
		if newKeyRaw != "" {
			newKey := ExpandPath(newKeyRaw)
			if !IsFileExist(newKey) {
				fmt.Printf("⚠️ 密钥文件 %s 不存在，仍要使用吗？(y/N): ", newKey)
				if readInput("") != "y" {
					fmt.Println("密钥路径未更新。")
				} else {
					selected.KeyPath = newKey
				}
			} else {
				selected.KeyPath = newKey
			}
		}
	}

	for i, h := range cfg.Hosts {
		if hostKey(h) == originalKey {
			cfg.Hosts[i] = *selected
			if err := saveConfig(cfg); err != nil {
				fmt.Fprintf(os.Stderr, "❌ %v\n", err)
				return
			}
			fmt.Println("✅ 主机更新成功！")
			return
		}
	}
	fmt.Println("❌ 未找到原始主机记录。")
}

func deleteHost(cfg *Config, hostType string) {
	hosts := filterHosts(cfg, hostType)
	if len(hosts) == 0 {
		hostTypeName := "Windows(RDP)"
		if hostType == HostTypeSSH {
			hostTypeName = "Linux(SSH)"
		}
		fmt.Printf("ostringstream 当前无任何【%s】主机可删除。\n", hostTypeName)
		return
	}

	selected := selectHostWithFzf(hosts, hostType)
	if selected == nil {
		return
	}

	confirm := readInput(fmt.Sprintf("⚠️ 确认要删除主机 [%s] 吗？(y/N): ", selected.Name))
	if confirm != "y" && confirm != "Y" {
		fmt.Println("✅ 删除操作已取消。")
		return
	}

	newHosts := make([]Host, 0, len(cfg.Hosts)-1)
	for _, h := range cfg.Hosts {
		if hostKey(h) != hostKey(*selected) {
			newHosts = append(newHosts, h)
		}
	}
	cfg.Hosts = newHosts

	if err := saveConfig(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "❌ %v\n", err)
		return
	}
	fmt.Println("✅ 主机已删除。")
}

// ===================== 连接管理 =====================
func connectRDPHost(h Host) {
	// 在连接前清理死会话
	CleanDeadSessions()

	drivePath := ExpandPath(h.Drive)
	if drivePath == "" {
		drivePath = getHomeDir()
	}
	if !IsDirExist(drivePath) {
		fmt.Printf("❌ 共享路径不存在或不是目录: %s\n", drivePath)
		fmt.Println("请先编辑主机修正路径。")
		return
	}

	if !IsCommandExist(XfreerdpCmd) {
		fmt.Println("❌ 未检测到 xfreerdp3，请先安装：sudo apt install xfreerdp3")
		return
	}

	addr := GetAddr(h.IP, h.Port, HostTypeRDP)
	fmt.Printf("🔌 正在连接 RDP 主机: %s (%s)\n", h.Name, addr)

	fmt.Println("\n🖥️  多监视器功能设置")
	fmt.Println("1. 开启")
	fmt.Println("2. 不开启")
	multimonChoice := readInput("请选择 [1/2] (默认 2): ")
	var multimonArg string
	if multimonChoice == "1" {
		multimonArg = "/multimon:force"
		fmt.Println("✅ 已选择开启多监视器功能")
	} else {
		fmt.Println("✅ 已选择不开启多监视器功能")
	}

	cmdArgs := []string{
		"/u:" + h.Username,
		"/p:" + h.Password,
		"/v:" + addr,
		"/t:" + h.Name,
		"/drive:local," + drivePath,
		"/cert:ignore",
		"+clipboard",
		"/sound:sys:pulse",
		"+f",
	}
	if multimonArg != "" {
		cmdArgs = append(cmdArgs, multimonArg)
	}

	cmd := createCleanCommand(XfreerdpCmd, cmdArgs)

	sessionKey := hostKey(h)
	if err := startCmdAndTrack(cmd, sessionKey); err != nil {
		fmt.Fprintf(os.Stderr, "❌ %v\n", err)
		logAudit("RDP_CONNECT", h.Name, "FAILED")
		return
	}

	fmt.Printf("✅ 已启动RDP独立窗口: %s (%s) [PID %d]\n", h.Name, addr, cmd.Process.Pid)
	logAudit("RDP_CONNECT", h.Name, "SUCCESS")
	saveHistory(h.Name)
}

func connectSSHHost(h Host) {
	// 在连接前清理死会话
	CleanDeadSessions()

	if !IsCommandExist(TrzszCmd) {
		fmt.Println("❌ 未检测到 trzsz 工具，请安装：pip3 install --user trzsz")
		return
	}

	var termCmd string
	termCmds := []string{"gnome-terminal", "xfce4-terminal", "xterm", "kitty"}
	for _, cmd := range termCmds {
		if IsCommandExist(cmd) {
			termCmd = cmd
			break
		}
	}
	if termCmd == "" {
		fmt.Println("❌ 未检测到终端软件，推荐安装：sudo apt install gnome-terminal")
		return
	}

	realPort := GetRealPort(h.Port, HostTypeSSH)
	hostAddr := fmt.Sprintf("%s:%d", h.IP, realPort)
	fmt.Printf("🔌 正在连接 SSH 主机: %s (%s)\n", h.Name, hostAddr)

	hostID := fmt.Sprintf("%s@%s:%d", h.Username, h.IP, realPort)
	if !isTrzszDeployed(hostID) {
		fmt.Print("🔍 检测 trzsz 状态... ")
		checkCmd := exec.Command(SSHCmd,
			"-p", strconv.Itoa(realPort),
			"-o", "StrictHostKeyChecking=no",
			"-o", "UserKnownHostsFile=/dev/null",
			"-o", "ConnectTimeout=5",
			fmt.Sprintf("%s@%s", h.Username, h.IP),
			"which trz tsz",
		)

		var checkOut bytes.Buffer
		checkCmd.Stdout = &checkOut
		checkCmd.Stderr = io.Discard

		err := checkCmd.Run()
		output := checkOut.String()
		if err != nil || !strings.Contains(output, "/trz") || !strings.Contains(output, "/tsz") {
			fmt.Println("未安装")

			exePath, _ := os.Executable()
			exeDir := filepath.Dir(exePath)
			localTrzszDir := filepath.Join(exeDir, "trzsz")
			trzPath := filepath.Join(localTrzszDir, "trz")
			tszPath := filepath.Join(localTrzszDir, "tsz")

			if !IsFileExist(trzPath) || !IsFileExist(tszPath) {
				fmt.Printf("⚠️ 本地 trzsz 二进制缺失，跳过部署（请放置 trz/tsz 到 %s/）\n", localTrzszDir)
			} else {
				fmt.Print("📤 正在部署 trzsz... ")

				mkdirCmd := exec.Command(SSHCmd,
					"-p", strconv.Itoa(realPort),
					"-o", "StrictHostKeyChecking=no",
					"-o", "UserKnownHostsFile=/dev/null",
					fmt.Sprintf("%s@%s", h.Username, h.IP),
					"mkdir -p ~/.local/bin",
				)
				mkdirCmd.Stderr = io.Discard
				_ = mkdirCmd.Run()

				deploySuccess := true
				for _, file := range []string{"trz", "tsz"} {
					src := filepath.Join(localTrzszDir, file)
					dst := fmt.Sprintf("%s@%s:~/.local/bin/%s", h.Username, h.IP, file)
					scpCmd := exec.Command("scp",
						"-P", strconv.Itoa(realPort),
						"-o", "StrictHostKeyChecking=no",
						"-o", "ConnectTimeout=10",
						src, dst,
					)
					scpCmd.Stderr = io.Discard
					if err := scpCmd.Run(); err != nil {
						deploySuccess = false
						break
					}
				}

				if deploySuccess {
					chmodCmd := exec.Command(SSHCmd,
						"-p", strconv.Itoa(realPort),
						"-o", "StrictHostKeyChecking=no",
						"-o", "UserKnownHostsFile=/dev/null",
						fmt.Sprintf("%s@%s", h.Username, h.IP),
						"chmod +x ~/.local/bin/trz ~/.local/bin/tsz",
					)
					chmodCmd.Stderr = io.Discard
					_ = chmodCmd.Run()

					pathCmd := exec.Command(SSHCmd,
						"-p", strconv.Itoa(realPort),
						"-o", "StrictHostKeyChecking=no",
						"-o", "UserKnownHostsFile=/dev/null",
						fmt.Sprintf("%s@%s", h.Username, h.IP),
						`grep -q 'export PATH.*\.local/bin' ~/.bashrc || echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc`,
					)
					pathCmd.Stderr = io.Discard
					_ = pathCmd.Run()

					markTrzszDeployed(hostID)
					fmt.Println("✅ 部署成功")
				} else {
					fmt.Println("❌ 部署失败")
				}
			}
		} else {
			fmt.Println("✅ 已安装")
			markTrzszDeployed(hostID)
		}
	} else {
		fmt.Println("✅ trzsz 状态正常（已缓存）")
	}

	sshArgs := []string{
		"-p", strconv.Itoa(realPort),
		"-l", h.Username,
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "LogLevel=quiet",
		h.IP,
	}

	var finalCmd *exec.Cmd
	hasPassword := h.Password != ""
	useKey := h.KeyPath != "" && IsFileExist(ExpandPath(h.KeyPath))

	if useKey {
		keyPath := ExpandPath(h.KeyPath)
		finalCmd = exec.Command(TrzszCmd, append([]string{SSHCmd, "-i", keyPath}, sshArgs...)...)
		fmt.Printf("🔑 密钥登录 + trzsz文件传输\n")
	} else if hasPassword {
		if !IsCommandExist(SshpassCmd) {
			fmt.Println("\n❌ 缺少 sshpass 依赖，请安装：sudo apt install sshpass")
			return
		}
		finalCmd = exec.Command(SshpassCmd, append([]string{"-p", h.Password, TrzszCmd, SSHCmd}, sshArgs...)...)
		fmt.Printf("🔐 密码登录 + trzsz文件传输\n")
	} else {
		finalCmd = exec.Command(TrzszCmd, append([]string{SSHCmd}, sshArgs...)...)
		fmt.Printf("👤 手动输密码 + trzsz文件传输\n")
	}

	// 修复：使用正确的命令构建方式
	cmdStr := fmt.Sprintf("%s %s; read -n1 -p '连接断开，按任意键关闭窗口...'",
		finalCmd.Path,
		strings.Join(finalCmd.Args[1:], " "))

	var termArgs []string
	switch termCmd {
	case "gnome-terminal":
		termArgs = []string{
			"--title", fmt.Sprintf("SSH-%s(%s) trzsz传输", h.Name, hostAddr),
			"--", "bash", "-c", cmdStr,
		}
	case "xfce4-terminal":
		termArgs = []string{
			"--title", fmt.Sprintf("SSH-%s(%s) trzsz传输", h.Name, hostAddr),
			"-x", "bash", "-c", cmdStr,
		}
	default:
		termArgs = []string{
			"-T", fmt.Sprintf("SSH-%s(%s) trzsz传输", h.Name, hostAddr),
			"-e", cmdStr,
		}
	}

	termCmdObj := createCleanCommand(termCmd, termArgs)
	sessionKey := hostKey(h)
	if err := startCmdAndTrack(termCmdObj, sessionKey); err != nil {
		fmt.Fprintf(os.Stderr, "❌ %v\n", err)
		logAudit("SSH_CONNECT", h.Name, "FAILED")
		return
	}

	fmt.Printf("✅ 连接成功！PID: %d → 输入命令立即弹窗传输文件\n", termCmdObj.Process.Pid)
	logAudit("SSH_CONNECT", h.Name, "SUCCESS")
	saveHistory(h.Name)
}

func createCleanCommand(cmdName string, args []string) *exec.Cmd {
	cmd := exec.Command(cmdName, args...)
	cleanEnv := os.Environ()
	proxyEnvList := []string{"http_proxy", "https_proxy", "all_proxy"}
	newEnv := make([]string, 0, len(cleanEnv))
envFilter:
	for _, env := range cleanEnv {
		for _, proxyEnv := range proxyEnvList {
			if strings.HasPrefix(strings.ToLower(env), proxyEnv+"=") {
				continue envFilter
			}
		}
		newEnv = append(newEnv, env)
	}
	cmd.Env = newEnv
	return cmd
}

// ===================== 连通性测试 =====================
func testConnectivity(hosts []Host) {
	if len(hosts) == 0 {
		fmt.Println("ostringstream 无主机可测试。")
		return
	}

	fmt.Printf("🧪 测试 %d 台主机连通性（最大并发%d）...\n", len(hosts), MaxConcurrency)
	sem := make(chan struct{}, MaxConcurrency)
	var wg sync.WaitGroup

	var successCount, failCount int
	var countMutex sync.Mutex
	var failedHosts []string
	var failedMutex sync.Mutex

	for i := range hosts {
		wg.Add(1)
		go func(h *Host) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			addr := GetAddr(h.IP, h.Port, getEffectiveHostType(*h))
			start := time.Now()
			conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
			elapsed := time.Since(start)

			countMutex.Lock()
			if err != nil {
				failCount++
				fmt.Printf("[✗] %s (%s) - %v (耗时: %v)\n", h.Name, addr, err, elapsed)
				failedMutex.Lock()
				failedHosts = append(failedHosts, fmt.Sprintf("%s (%s)", h.Name, h.IP))
				failedMutex.Unlock()
			} else {
				successCount++
				conn.Close()
				fmt.Printf("[✓] %s (%s) (耗时: %v)\n", h.Name, addr, elapsed)
			}
			countMutex.Unlock()
		}(&hosts[i])
	}

	wg.Wait()
	fmt.Printf("✅ 测试完成：\033[32m%d 台成功\033[0m，\033[31m%d 台失败\033[0m\n", successCount, failCount)

	if len(failedHosts) > 0 {
		fmt.Println("\n❌ 连接失败的主机列表:")
		for _, host := range failedHosts {
			fmt.Printf("  • %s\n", host)
		}
	}
}

// ===================== 断开连接 =====================
func disconnectHost() {
	CleanDeadSessions()
	sessionsMutex.Lock()
	defer sessionsMutex.Unlock()

	if len(activeSessions) == 0 {
		fmt.Println("ostringstream 当前无活跃连接。")
		return
	}

	fmt.Println("\n🔌 所有活跃远程连接:")
	fmt.Println("序号 | 连接信息                          | 进程PID")
	fmt.Println("-----------------------------------------------------------")
	keys := make([]string, 0, len(activeSessions))
	for k := range activeSessions {
		keys = append(keys, k)
	}
	for i, key := range keys {
		cmd := activeSessions[key]
		pid := 0
		if cmd.Process != nil {
			pid = cmd.Process.Pid
		}
		fmt.Printf("%-4d | %-35s | %d\n", i+1, key, pid)
	}

	idxStr := readInput("请输入要断开的连接序号: ")
	idx, err := strconv.Atoi(idxStr)
	if err != nil || idx < 1 || idx > len(keys) {
		fmt.Println("❌ 无效序号。")
		return
	}

	selectedKey := keys[idx-1]
	cmd := activeSessions[selectedKey]
	pid := cmd.Process.Pid

	confirm := readInput(fmt.Sprintf("⚠️ 确认要断开 [%s] (PID:%d) 吗？(y/N): ", selectedKey, pid))
	if confirm != "y" && confirm != "Y" {
		fmt.Println("✅ 断开操作已取消。")
		return
	}

	_ = syscall.Kill(-pid, syscall.SIGKILL)
	delete(activeSessions, selectedKey)
	fmt.Printf("✅ 已断开连接: %s (PID %d)\n", selectedKey, pid)
	logAudit("DISCONNECT", selectedKey, "SUCCESS")
}

// ===================== 批量执行命令（底层） =====================
func executeRemoteCommandOnHosts(hosts []*Host, command string) {
	if len(hosts) == 0 {
		fmt.Println("ostringstream 未选择任何主机。")
		return
	}

	sem := make(chan struct{}, MaxConcurrency)
	var wg sync.WaitGroup

	for _, h := range hosts {
		wg.Add(1)
		go func(host *Host) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			realPort := GetRealPort(host.Port, HostTypeSSH)
			var cmd *exec.Cmd

			if host.KeyPath != "" && IsFileExist(ExpandPath(host.KeyPath)) {
				keyPath := ExpandPath(host.KeyPath)
				cmd = exec.Command(SSHCmd,
					"-p", strconv.Itoa(realPort),
					"-i", keyPath,
					"-o", "StrictHostKeyChecking=no",
					"-o", "UserKnownHostsFile=/dev/null",
					fmt.Sprintf("%s@%s", host.Username, host.IP),
					command,
				)
			} else if host.Password != "" {
				if !IsCommandExist(SshpassCmd) {
					fmt.Printf("[%s] ❌ 缺少 sshpass\n", host.IP)
					return
				}
				args := []string{
					"-p", host.Password,
					SSHCmd,
					"-p", strconv.Itoa(realPort),
					"-o", "StrictHostKeyChecking=no",
					"-o", "UserKnownHostsFile=/dev/null",
					fmt.Sprintf("%s@%s", host.Username, host.IP),
					command,
				}
				cmd = exec.Command(SshpassCmd, args...)
			} else {
				cmd = exec.Command(SSHCmd,
					"-p", strconv.Itoa(realPort),
					"-o", "StrictHostKeyChecking=no",
					"-o", "UserKnownHostsFile=/dev/null",
					fmt.Sprintf("%s@%s", host.Username, host.IP),
					command,
				)
			}

			var out bytes.Buffer
			cmd.Stdout = &out
			cmd.Stderr = &out

			err := cmd.Run()
			output := strings.TrimSpace(out.String())
			if err != nil {
				fmt.Printf("[%s] ❌ %v\n", host.IP, err)
				if output != "" {
					fmt.Printf("[%s] 输出: %s\n", host.IP, output)
				}
			} else {
				if output == "" {
					fmt.Printf("[%s] ✅ 执行成功（无输出）\n", host.IP)
				} else {
					fmt.Printf("[%s] ✅\n%s\n", host.IP, output)
				}
			}
		}(h)
	}

	wg.Wait()
}

// ===================== 交互式批量执行 =====================
func interactiveBatchExec(cfg *Config) {
	sshHosts := filterHosts(cfg, HostTypeSSH)
	if len(sshHosts) == 0 {
		fmt.Println("ostringstream 无任何 SSH 主机可执行命令。")
		return
	}

	fmt.Println("\n🎯 批量远程执行命令 (SSH)")
	fmt.Println("1. 单台主机")
	fmt.Println("2. 多台主机（FZF 多选）")
	fmt.Println("3. 所有主机")
	choice := readInput("请选择 [1-3]: ")

	var selectedHosts []*Host
	switch choice {
	case "1":
		selected := selectHostWithFzf(sshHosts, HostTypeSSH)
		if selected != nil {
			selectedHosts = []*Host{selected}
		}
	case "2":
		selectedHosts = selectHostsWithFzfMulti(sshHosts, HostTypeSSH)
	case "3":
		for i := range sshHosts {
			selectedHosts = append(selectedHosts, &sshHosts[i])
		}
	default:
		fmt.Println("❌ 无效选项。")
		return
	}

	if len(selectedHosts) == 0 {
		fmt.Println("ostringstream 未选择任何主机。")
		return
	}

	command := readInput("请输入要执行的命令: ")
	if command == "" {
		fmt.Println("⚠️ 命令不能为空。")
		return
	}

	fmt.Printf("\n🚀 正在对 %d 台主机执行命令: %s\n", len(selectedHosts), command)
	executeRemoteCommandOnHosts(selectedHosts, command)
}

// ===================== 主菜单 =====================
func showMainMenu() {
	for {
		CleanDeadSessions()

		// 每次循环都重新加载配置，确保数据最新
		cfg, err := loadConfig()
		if err != nil {
			fmt.Fprintf(os.Stderr, "❌ 配置加载失败: %v\n", err)
			return
		}

		rdpCount := len(filterHosts(cfg, HostTypeRDP))
		sshCount := len(filterHosts(cfg, HostTypeSSH))

		fmt.Println("\n=====================================================")
		fmt.Println("🚀 全能远程管理工具 [RDP+SSH+trzsz+FZF] ✨")
		fmt.Println("=====================================================")
		fmt.Printf("1. Windows 远程管理 (RDP) [共 %d 台]\n", rdpCount)
		fmt.Printf("2. Linux   远程管理 (SSH) [共 %d 台]\n", sshCount)
		fmt.Println("3. 添加主机")
		fmt.Println("4. 编辑主机")
		fmt.Println("5. 删除主机")
		fmt.Println("6. 批量连通性测试")
		fmt.Println("7. 断开连接")
		fmt.Println("8. 批量远程执行命令 (SSH)")
		fmt.Println("q. 退出程序")
		choice := readInput("请选择操作 [1-8/q]: ")

		switch choice {
		case "1":
			hosts := filterHosts(cfg, HostTypeRDP)
			selected := selectHostWithFzf(hosts, HostTypeRDP)
			if selected != nil {
				connectRDPHost(*selected)
			}
		case "2":
			hosts := filterHosts(cfg, HostTypeSSH)
			selected := selectHostWithFzf(hosts, HostTypeSSH)
			if selected != nil {
				connectSSHHost(*selected)
			}
		case "3":
			fmt.Println("1. 添加 RDP 主机")
			fmt.Println("2. 添加 SSH 主机")
			typeChoice := readInput("请选择 [1/2]: ")
			if typeChoice == "1" {
				addNewHost(cfg, HostTypeRDP)
			} else if typeChoice == "2" {
				addNewHost(cfg, HostTypeSSH)
			}
		case "4":
			fmt.Println("1. 编辑 RDP 主机")
			fmt.Println("2. 编辑 SSH 主机")
			typeChoice := readInput("请选择 [1/2]: ")
			if typeChoice == "1" {
				editHost(cfg, HostTypeRDP)
			} else if typeChoice == "2" {
				editHost(cfg, HostTypeSSH)
			}
		case "5":
			fmt.Println("1. 删除 RDP 主机")
			fmt.Println("2. 删除 SSH 主机")
			typeChoice := readInput("请选择 [1/2]: ")
			if typeChoice == "1" {
				deleteHost(cfg, HostTypeRDP)
			} else if typeChoice == "2" {
				deleteHost(cfg, HostTypeSSH)
			}
		case "6":
			allHosts := append(filterHosts(cfg, HostTypeRDP), filterHosts(cfg, HostTypeSSH)...)
			testConnectivity(allHosts)
		case "7":
			disconnectHost()
		case "8":
			interactiveBatchExec(cfg)
		case "q", "Q":
			fmt.Println("\n👋 感谢使用，再见！")
			return
		default:
			fmt.Println("❌ 无效选项，请重试。")
		}
	}
}

// ===================== 命令行子命令支持 =====================
func executeRemoteCommand(target, command string) {
	cfg, err := loadConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ 加载配置失败: %v\n", err)
		os.Exit(1)
	}

	sshHosts := filterHosts(cfg, HostTypeSSH)
	if len(sshHosts) == 0 {
		fmt.Println("ostringstream 无任何 SSH 主机配置。")
		os.Exit(0)
	}

	var targets []string
	if target == "all" {
		for _, h := range sshHosts {
			targets = append(targets, h.IP)
		}
	} else {
		targets = strings.Split(target, ",")
		for i := range targets {
			targets[i] = strings.TrimSpace(targets[i])
		}
	}

	hostMap := make(map[string]*Host)
	for i := range sshHosts {
		hostMap[sshHosts[i].IP] = &sshHosts[i]
	}

	var selectedHosts []*Host
	for _, ip := range targets {
		if h, ok := hostMap[ip]; ok {
			selectedHosts = append(selectedHosts, h)
		} else {
			fmt.Printf("⚠️ 未找到 IP 为 %s 的 SSH 主机\n", ip)
		}
	}

	executeRemoteCommandOnHosts(selectedHosts, command)
}

// ===================== 主函数 =====================
func main() {
	if len(os.Args) >= 3 && os.Args[1] == "exec" {
		target := os.Args[2]
		command := strings.Join(os.Args[3:], " ")
		if command == "" {
			os.Exit(1)
		}
		executeRemoteCommand(target, command)
		return
	}

	if err := ensureConfigExists(); err != nil {
		fmt.Fprintf(os.Stderr, "❌ %v\n", err)
		os.Exit(1)
	}

	// 直接调用showMainMenu，不需要先加载配置
	showMainMenu()
}
