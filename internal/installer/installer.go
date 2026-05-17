package installer

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"text/template"
)

const (
	installDir  = "/opt/zeek-bzar-ocsf"
	configDir   = "/etc/zeek-bzar-ocsf"
	logDir      = "/var/log/zeek-bzar-ocsf"
	evidenceDir = "/var/lib/zeek-bzar-ocsf/evidence"
	serviceFile = "/etc/systemd/system/zeek-bzar-ocsf.service"
	binaryName  = "zeek-bzar-ocsf"
)

// Install copies the binary and config, creates directories, and installs a systemd unit.
func Install(binaryPath, configSrc string) error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("install is only supported on Linux")
	}
	if os.Getuid() != 0 {
		return fmt.Errorf("install requires root privileges")
	}

	steps := []struct {
		name string
		fn   func() error
	}{
		{"creating directories", createDirectories},
		{"copying binary", func() error { return copyBinary(binaryPath) }},
		{"installing config", func() error { return installConfig(configSrc) }},
		{"installing systemd service", installSystemdService},
		{"reloading systemd", reloadSystemd},
	}

	for _, step := range steps {
		fmt.Printf("[install] %s...\n", step.name)
		if err := step.fn(); err != nil {
			return fmt.Errorf("%s: %w", step.name, err)
		}
		fmt.Printf("[install] %s OK\n", step.name)
	}

	fmt.Println("\nInstallation complete!")
	fmt.Println("Edit the configuration file at:", filepath.Join(configDir, "config.yaml"))
	fmt.Println("Then start the service with:  systemctl start zeek-bzar-ocsf")
	fmt.Println("Enable on boot with:          systemctl enable zeek-bzar-ocsf")
	return nil
}

// Uninstall stops and removes the service, binary, and config files.
func Uninstall(removeConfig bool) error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("uninstall is only supported on Linux")
	}
	if os.Getuid() != 0 {
		return fmt.Errorf("uninstall requires root privileges")
	}

	steps := []struct {
		name string
		fn   func() error
	}{
		{"stopping service", stopService},
		{"disabling service", disableService},
		{"removing service file", func() error { return removeFile(serviceFile) }},
		{"reloading systemd", reloadSystemd},
		{"removing binary", func() error { return removeFile(filepath.Join(installDir, binaryName)) }},
		{"removing install dir", func() error { return removeDir(installDir) }},
		{"removing log dir", func() error { return removeDir(logDir) }},
	}

	if removeConfig {
		steps = append(steps, struct {
			name string
			fn   func() error
		}{
			"removing config dir",
			func() error { return removeDir(configDir) },
		})
	}

	for _, step := range steps {
		fmt.Printf("[uninstall] %s...\n", step.name)
		if err := step.fn(); err != nil {
			fmt.Printf("[uninstall] warning: %s: %v\n", step.name, err)
		} else {
			fmt.Printf("[uninstall] %s OK\n", step.name)
		}
	}

	fmt.Println("\nUninstallation complete!")
	if !removeConfig {
		fmt.Println("Config preserved at:", configDir, "(use --purge to remove)")
	}
	return nil
}

func createDirectories() error {
	dirs := []string{installDir, configDir, logDir, evidenceDir}
	for _, d := range dirs {
		if err := os.MkdirAll(d, 0750); err != nil {
			return fmt.Errorf("mkdir %s: %w", d, err)
		}
	}
	return nil
}

func copyBinary(src string) error {
	if src == "" {
		// Use the currently running executable
		var err error
		src, err = os.Executable()
		if err != nil {
			return fmt.Errorf("locating executable: %w", err)
		}
	}

	dst := filepath.Join(installDir, binaryName)
	data, err := os.ReadFile(src)
	if err != nil {
		return fmt.Errorf("reading binary: %w", err)
	}
	if err := os.WriteFile(dst, data, 0750); err != nil {
		return fmt.Errorf("writing binary: %w", err)
	}
	return nil
}

func installConfig(src string) error {
	dst := filepath.Join(configDir, "config.yaml")

	// Don't overwrite existing config
	if _, err := os.Stat(dst); err == nil {
		fmt.Printf("[install] config already exists at %s, skipping\n", dst)
		return nil
	}

	if src != "" {
		data, err := os.ReadFile(src)
		if err != nil {
			return fmt.Errorf("reading config: %w", err)
		}
		return os.WriteFile(dst, data, 0640)
	}

	// Write the embedded default config
	return os.WriteFile(dst, []byte(defaultConfigYAML), 0640)
}

func installSystemdService() error {
	tmpl, err := template.New("service").Parse(serviceTemplate)
	if err != nil {
		return err
	}

	f, err := os.OpenFile(serviceFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("creating service file: %w", err)
	}
	defer f.Close()

	data := struct {
		BinaryPath string
		ConfigPath string
	}{
		BinaryPath: filepath.Join(installDir, binaryName),
		ConfigPath: filepath.Join(configDir, "config.yaml"),
	}
	return tmpl.Execute(f, data)
}

func reloadSystemd() error {
	return runCmd("systemctl", "daemon-reload")
}

func stopService() error {
	return runCmd("systemctl", "stop", "zeek-bzar-ocsf")
}

func disableService() error {
	return runCmd("systemctl", "disable", "zeek-bzar-ocsf")
}

func removeFile(path string) error {
	err := os.Remove(path)
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

func removeDir(path string) error {
	err := os.RemoveAll(path)
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

func runCmd(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		if strings.Contains(string(out), "not loaded") ||
			strings.Contains(string(out), "not found") {
			return nil // Service wasn't running or doesn't exist
		}
		return fmt.Errorf("%s %v: %s", name, args, string(out))
	}
	return nil
}

const serviceTemplate = `[Unit]
Description=Zeek BZAR OCSF Integration Service
Documentation=https://github.com/zeekurity/zeek-bzar-ocsf
After=network.target
Wants=network.target

[Service]
Type=simple
ExecStart={{.BinaryPath}} start --config {{.ConfigPath}}
Restart=on-failure
RestartSec=5s
StandardOutput=journal
StandardError=journal
SyslogIdentifier=zeek-bzar-ocsf

# Security hardening
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/log/zeek-bzar-ocsf /var/lib/zeek-bzar-ocsf
ReadOnlyPaths=/opt/zeek/logs
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
`

const defaultConfigYAML = `# zeek-bzar-ocsf configuration file
# Documentation: https://github.com/zeekurity/zeek-bzar-ocsf

zeek:
  # Directory containing current Zeek logs
  log_dir: /opt/zeek/logs/current
  # Log format: tsv (default) or json
  log_format: tsv
  # Zeek log files to monitor
  logs:
    - conn
    - dns
    - http
    - ssl
    - smb_files
    - smb_mapping
    - dce_rpc
    - notice

bzar:
  # Enable BZAR detection parsing from notice.log
  enabled: true

evidence:
  # Enable evidence collection for detections
  enabled: true
  # Directory for persisted evidence files
  output_dir: /var/lib/zeek-bzar-ocsf/evidence
  # Days to retain evidence files
  retention_days: 30
  # Maximum evidence storage in MB
  max_size_mb: 1024
  # Maximum log entries buffered per connection UID
  buffer_size: 500

ocsf:
  version: "1.1.0"
  producer:
    name: zeek-bzar-ocsf
    version: "1.0.0"
    url: https://github.com/zeekurity/zeek-bzar-ocsf

forwarder:
  outputs:
    # File output (always enabled as baseline)
    - type: file
      path: /var/log/zeek-bzar-ocsf/events.json

    # Syslog output (uncomment to enable)
    # - type: syslog
    #   host: 192.168.1.100
    #   port: 514
    #   protocol: udp  # or tcp

    # HTTP/HTTPS output (uncomment to enable)
    # - type: http
    #   url: https://siem.example.com/api/v1/events
    #   timeout_seconds: 10
    #   max_retries: 3
    #   insecure: false
    #   headers:
    #     Authorization: "Bearer YOUR_TOKEN_HERE"
    #     X-Source: zeek-bzar-ocsf

logging:
  # Log level: debug, info, warn, error
  level: info
  # Output: stdout, stderr, or a file path
  output: stdout
`
