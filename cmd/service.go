package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/user/icmptunnel/service"
)

var serviceCmd = &cobra.Command{
	Use:   "service",
	Short: "Manage systemd tunnel services",
	Long:  `Create, start, stop, restart, and manage ICMP tunnel systemd services.`,
}

var serviceCreateCmd = &cobra.Command{
	Use:   "create [name]",
	Short: "Create a new managed service",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		mode, _ := cmd.Flags().GetString("mode")
		config, _ := cmd.Flags().GetString("config")
		debug, _ := cmd.Flags().GetBool("debug")
		if config == "" {
			return fmt.Errorf("--config is required")
		}
		if mode == "" {
			return fmt.Errorf("--mode is required (server, client, relay)")
		}
		return service.GenerateUnit(args[0], mode, config, debug)
	},
}

var serviceStartCmd = &cobra.Command{
	Use:   "start [name]",
	Short: "Start a managed service",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return service.StartService(args[0])
	},
}

var serviceStopCmd = &cobra.Command{
	Use:   "stop [name]",
	Short: "Stop a managed service",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return service.StopService(args[0])
	},
}

var serviceRestartCmd = &cobra.Command{
	Use:   "restart [name]",
	Short: "Restart a managed service",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return service.RestartService(args[0])
	},
}

var serviceStatusCmd = &cobra.Command{
	Use:   "status [name]",
	Short: "Show service status",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return service.StatusService(args[0])
	},
}

var serviceLogsCmd = &cobra.Command{
	Use:   "logs [name]",
	Short: "Show service logs",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		follow, _ := cmd.Flags().GetBool("follow")
		return service.LogsService(args[0], follow)
	},
}

var serviceRemoveCmd = &cobra.Command{
	Use:   "remove [name]",
	Short: "Remove a managed service",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return service.RemoveService(args[0])
	},
}

var serviceListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all managed services",
	RunE: func(cmd *cobra.Command, args []string) error {
		return service.PrintServices()
	},
}

func init() {
	serviceCreateCmd.Flags().String("mode", "", "service mode (server, client, relay)")
	serviceCreateCmd.Flags().String("config", "", "path to config file")
	serviceCreateCmd.Flags().Bool("debug", false, "enable debug mode")
	serviceLogsCmd.Flags().BoolP("follow", "f", false, "follow log output")

	serviceCmd.AddCommand(serviceCreateCmd)
	serviceCmd.AddCommand(serviceStartCmd)
	serviceCmd.AddCommand(serviceStopCmd)
	serviceCmd.AddCommand(serviceRestartCmd)
	serviceCmd.AddCommand(serviceStatusCmd)
	serviceCmd.AddCommand(serviceLogsCmd)
	serviceCmd.AddCommand(serviceRemoveCmd)
	serviceCmd.AddCommand(serviceListCmd)

	rootCmd.AddCommand(serviceCmd)
}
