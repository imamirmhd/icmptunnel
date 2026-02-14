package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/user/icmptunnel/service"
)

var installCmd = &cobra.Command{
	Use:   "install",
	Short: "Install icmptunnel on the system",
	Long: `Install the icmptunnel binary to /usr/local/bin, create configuration
directories in /etc/icmptunnel, and set up the service management infrastructure.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		binaryPath, _ := cmd.Flags().GetString("binary")
		if err := service.Install(binaryPath); err != nil {
			return fmt.Errorf("installation failed: %w", err)
		}
		return nil
	},
}

func init() {
	installCmd.Flags().String("binary", "", "path to binary to install (default: current executable)")
	rootCmd.AddCommand(installCmd)
}
