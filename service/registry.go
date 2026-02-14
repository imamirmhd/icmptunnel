package service

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// ServiceEntry represents a registered service.
type ServiceEntry struct {
	Name       string `json:"name"`
	Mode       string `json:"mode"`
	ConfigPath string `json:"config_path"`
}

// RegisterService adds a service to the registry.
func RegisterService(name, mode, configPath string) error {
	if err := os.MkdirAll(ServiceDir, 0755); err != nil {
		return err
	}

	entry := &ServiceEntry{
		Name:       name,
		Mode:       mode,
		ConfigPath: configPath,
	}

	data, err := json.MarshalIndent(entry, "", "  ")
	if err != nil {
		return err
	}

	regPath := filepath.Join(ServiceDir, name+".json")
	return os.WriteFile(regPath, data, 0644)
}

// UnregisterService removes a service from the registry.
func UnregisterService(name string) {
	regPath := filepath.Join(ServiceDir, name+".json")
	os.Remove(regPath)
}

// ListServices returns all registered services.
func ListServices() ([]*ServiceEntry, error) {
	entries, err := os.ReadDir(ServiceDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var services []*ServiceEntry
	for _, entry := range entries {
		if filepath.Ext(entry.Name()) != ".json" {
			continue
		}

		data, err := os.ReadFile(filepath.Join(ServiceDir, entry.Name()))
		if err != nil {
			continue
		}

		svc := &ServiceEntry{}
		if err := json.Unmarshal(data, svc); err != nil {
			continue
		}

		services = append(services, svc)
	}

	return services, nil
}

// PrintServices prints all registered services in a table format.
func PrintServices() error {
	services, err := ListServices()
	if err != nil {
		return err
	}

	if len(services) == 0 {
		fmt.Println("No services registered.")
		return nil
	}

	fmt.Printf("%-20s %-10s %s\n", "NAME", "MODE", "CONFIG")
	fmt.Printf("%-20s %-10s %s\n", "----", "----", "------")
	for _, svc := range services {
		fmt.Printf("%-20s %-10s %s\n", svc.Name, svc.Mode, svc.ConfigPath)
	}

	return nil
}
