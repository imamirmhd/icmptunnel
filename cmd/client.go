package cmd

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
	"github.com/user/icmptunnel/config"
	"github.com/user/icmptunnel/tunnel"
)

var clientCmd = &cobra.Command{
	Use:   "client",
	Short: "Start the ICMP tunnel client",
	Long:  `Start the client-side ICMP tunnel with SOCKS5 proxy and/or port forwarding.`,
	RunE:  runClient,
}

func init() {
	clientCmd.Flags().BoolVar(&dryRun, "dry-run", false, "validate config and exit")
	rootCmd.AddCommand(clientCmd)
}

func runClient(cmd *cobra.Command, args []string) error {
	if cfgFile == "" {
		return fmt.Errorf("--config flag is required")
	}

	cfg, err := config.LoadClientConfig(cfgFile)
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	if dryRun {
		fmt.Println("Configuration is valid.")
		fmt.Printf("  Server: %s\n", cfg.ServerAddr)
		fmt.Printf("  Encryption: %v (%s)\n", cfg.Encryption.Enabled, cfg.Encryption.Method)
		fmt.Printf("  SOCKS5 proxies: %d\n", len(cfg.Socks5))
		for _, s := range cfg.Socks5 {
			auth := "no auth"
			if s.Username != "" {
				auth = "with auth"
			}
			fmt.Printf("    - %s (%s)\n", s.Listen, auth)
		}
		fmt.Printf("  Forwarding rules: %d\n", len(cfg.Forwards))
		for _, f := range cfg.Forwards {
			fmt.Printf("    - %s -> %s (%s)\n", f.Listen, f.Destination, f.Protocol)
		}
		fmt.Printf("  Spoofing: %v\n", cfg.Spoof.Enabled)
		return nil
	}

	if logLevel != "info" || cfg.Logging.Level == "" {
		cfg.Logging.Level = logLevel
	}
	if verbose {
		cfg.Logging.Level = "debug"
	}

	client, err := tunnel.NewClient(cfg)
	if err != nil {
		return err
	}

	if err := client.Start(); err != nil {
		return err
	}

	// Wait for signal
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	sig := <-sigCh
	fmt.Printf("\nReceived %v, shutting down...\n", sig)

	// Listen for a second signal for force exit
	go func() {
		sig2 := <-sigCh
		fmt.Printf("\nReceived %v again, force exiting...\n", sig2)
		os.Exit(1)
	}()

	client.Stop()
	return nil
}
