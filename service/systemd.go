package service

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"text/template"
)

const systemdTemplate = `[Unit]
Description=ICMP Tunnel - {{.Name}}
After=network.target
Wants=network-online.target

[Service]
Type=simple
ExecStart={{.BinaryPath}} {{.Mode}} --config {{.ConfigPath}}
Restart=on-failure
RestartSec=5
LimitNOFILE=65535
AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN
{{if .Debug}}Environment=ICMPTUNNEL_DEBUG=1{{end}}

[Install]
WantedBy=multi-user.target
`

// ServiceUnit holds configuration for a systemd service unit.
type ServiceUnit struct {
	Name       string
	Mode       string // "server", "client", "relay"
	ConfigPath string
	BinaryPath string
	Debug      bool
}

// GenerateUnit creates a systemd service unit file.
func GenerateUnit(name, mode, configPath string, debug bool) error {
	unit := &ServiceUnit{
		Name:       name,
		Mode:       mode,
		ConfigPath: configPath,
		BinaryPath: BinaryPath,
		Debug:      debug,
	}

	tmpl, err := template.New("systemd").Parse(systemdTemplate)
	if err != nil {
		return fmt.Errorf("parsing template: %w", err)
	}

	unitPath := filepath.Join(SystemdDir, fmt.Sprintf("icmptunnel@%s.service", name))
	f, err := os.Create(unitPath)
	if err != nil {
		return fmt.Errorf("creating unit file: %w", err)
	}
	defer f.Close()

	if err := tmpl.Execute(f, unit); err != nil {
		return fmt.Errorf("writing unit file: %w", err)
	}

	// Also register in the service registry
	if err := RegisterService(name, mode, configPath); err != nil {
		return fmt.Errorf("registering service: %w", err)
	}

	fmt.Printf("Created systemd service: icmptunnel@%s.service\n", name)

	// Reload systemd
	exec.Command("systemctl", "daemon-reload").Run()

	return nil
}

// StartService starts a managed service.
func StartService(name string) error {
	serviceName := fmt.Sprintf("icmptunnel@%s.service", name)
	cmd := exec.Command("systemctl", "start", serviceName)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// StopService stops a managed service.
func StopService(name string) error {
	serviceName := fmt.Sprintf("icmptunnel@%s.service", name)
	cmd := exec.Command("systemctl", "stop", serviceName)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// RestartService restarts a managed service.
func RestartService(name string) error {
	serviceName := fmt.Sprintf("icmptunnel@%s.service", name)
	cmd := exec.Command("systemctl", "restart", serviceName)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// StatusService shows the status of a managed service.
func StatusService(name string) error {
	serviceName := fmt.Sprintf("icmptunnel@%s.service", name)
	cmd := exec.Command("systemctl", "status", serviceName)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// LogsService shows the logs of a managed service.
func LogsService(name string, follow bool) error {
	args := []string{"-u", fmt.Sprintf("icmptunnel@%s.service", name), "-n", "100"}
	if follow {
		args = append(args, "-f")
	}
	cmd := exec.Command("journalctl", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// RemoveService stops and removes a managed service.
func RemoveService(name string) error {
	serviceName := fmt.Sprintf("icmptunnel@%s.service", name)

	// Stop the service
	exec.Command("systemctl", "stop", serviceName).Run()
	exec.Command("systemctl", "disable", serviceName).Run()

	// Remove the unit file
	unitPath := filepath.Join(SystemdDir, serviceName)
	os.Remove(unitPath)

	// Remove from registry
	UnregisterService(name)

	// Reload systemd
	exec.Command("systemctl", "daemon-reload").Run()

	fmt.Printf("Removed service: %s\n", name)
	return nil
}

// EnableService enables a service to start on boot.
func EnableService(name string) error {
	serviceName := fmt.Sprintf("icmptunnel@%s.service", name)
	cmd := exec.Command("systemctl", "enable", serviceName)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
