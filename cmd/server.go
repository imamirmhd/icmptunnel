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

var serverCmd = &cobra.Command{
	Use:   "server",
	Short: "Start the ICMP tunnel server",
	Long:  `Start the server-side ICMP tunnel that receives tunneled traffic and forwards it to destinations.`,
	RunE:  runServer,
}

var dryRun bool

func init() {
	serverCmd.Flags().BoolVar(&dryRun, "dry-run", false, "validate config and exit")
	rootCmd.AddCommand(serverCmd)
}

func runServer(cmd *cobra.Command, args []string) error {
	if cfgFile == "" {
		return fmt.Errorf("--config flag is required")
	}

	cfg, err := config.LoadServerConfig(cfgFile)
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	// Override log level if flag provided
	logLevel, _ := cmd.Root().PersistentFlags().GetString("log-level")
	if logLevel != "" {
		cfg.Logging.Level = logLevel
	}

	if dryRun {
		fmt.Println("Configuration is valid.")
		fmt.Printf("  Listen: %s\n", cfg.Listen)
		fmt.Printf("  Auth tokens: %d configured\n", len(cfg.AuthTokens))
		fmt.Printf("  Encryption: %v (%s)\n", cfg.Encryption.Enabled, cfg.Encryption.Method)
		fmt.Printf("  Max packet size: %d\n", cfg.ICMP.MaxPacketSize)
		return nil
	}

	srv, err := tunnel.NewServer(cfg)
	if err != nil {
		return err
	}

	if err := srv.Start(); err != nil {
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

	srv.Stop()
	return nil
}
