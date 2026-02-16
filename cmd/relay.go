package cmd

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
	"github.com/imamirmhd/icmptunnel/config"
	"github.com/imamirmhd/icmptunnel/relay"
)

var relayCmd = &cobra.Command{
	Use:   "relay",
	Short: "Start the ICMP relay server",
	Long: `Start a lightweight ICMP relay server for IP spoofing scenarios.
The relay receives ICMP packets and echoes replies back to the (spoofed) source address.`,
	RunE: runRelay,
}

func init() {
	rootCmd.AddCommand(relayCmd)
}

func runRelay(cmd *cobra.Command, args []string) error {
	if cfgFile == "" {
		return fmt.Errorf("--config flag is required")
	}

	cfg, err := config.LoadRelayConfig(cfgFile)
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	srv, err := relay.NewServer(cfg)
	if err != nil {
		return err
	}

	if err := srv.Start(); err != nil {
		return err
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	fmt.Println("\nShutting down relay...")
	srv.Stop()
	return nil
}
