// Package service provides installation and systemd service management.
package service

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
)

const (
	// BinaryPath is the installation path for the binary.
	BinaryPath = "/usr/local/bin/icmptunnel"
	// ConfigDir is the directory for configuration files.
	ConfigDir = "/etc/icmptunnel"
	// ServiceDir is the directory for service definitions.
	ServiceDir = "/etc/icmptunnel/services"
	// SystemdDir is the systemd service directory.
	SystemdDir = "/etc/systemd/system"
)

// Install copies the binary and sets up configuration directories.
func Install(binaryPath string) error {
	// Create config directories
	for _, dir := range []string{ConfigDir, ServiceDir} {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("creating directory %s: %w", dir, err)
		}
		fmt.Printf("Created directory: %s\n", dir)
	}

	// Copy binary
	if binaryPath == "" {
		// Use the current executable
		exe, err := os.Executable()
		if err != nil {
			return fmt.Errorf("finding current executable: %w", err)
		}
		binaryPath = exe
	}

	if err := copyFile(binaryPath, BinaryPath, 0755); err != nil {
		return fmt.Errorf("installing binary: %w", err)
	}
	fmt.Printf("Installed binary: %s\n", BinaryPath)

	// Copy example configs if they exist
	examplesDir := filepath.Join(filepath.Dir(binaryPath), "examples")
	if _, err := os.Stat(examplesDir); err == nil {
		entries, _ := os.ReadDir(examplesDir)
		for _, entry := range entries {
			src := filepath.Join(examplesDir, entry.Name())
			dst := filepath.Join(ConfigDir, entry.Name())
			if _, err := os.Stat(dst); os.IsNotExist(err) {
				if err := copyFile(src, dst, 0644); err != nil {
					fmt.Printf("Warning: could not copy %s: %v\n", entry.Name(), err)
				} else {
					fmt.Printf("Installed config: %s\n", dst)
				}
			}
		}
	}

	fmt.Println("\nInstallation complete!")
	fmt.Printf("  Binary:  %s\n", BinaryPath)
	fmt.Printf("  Config:  %s\n", ConfigDir)
	fmt.Printf("  Services: %s\n", ServiceDir)
	fmt.Println("\nNext steps:")
	fmt.Println("  1. Edit your configuration files in /etc/icmptunnel/")
	fmt.Println("  2. Generate a service: icmptunnel service create <name> --config /etc/icmptunnel/<config>.toml --mode <server|client|relay>")
	fmt.Println("  3. Start the service:  icmptunnel service start <name>")

	return nil
}

func copyFile(src, dst string, perm os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, in)
	return err
}
