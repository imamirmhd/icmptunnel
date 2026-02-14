// Package cmd implements the CLI commands using cobra.
package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var (
	cfgFile  string
	verbose  bool
	logLevel string
)

var rootCmd = &cobra.Command{
	Use:   "icmptunnel",
	Short: "ICMP tunnel - tunnel network traffic through ICMP packets",
	Long: `icmptunnel tunnels TCP/UDP traffic through ICMP echo/reply packets,
bypassing firewalls and captive portals that allow ICMP traffic.

Features:
  • SOCKS5 proxy with optional authentication
  • TCP/UDP port forwarding
  • Multiple encryption methods (AES-256-GCM, ChaCha20-Poly1305, XOR)
  • DPI evasion techniques (fragmentation, padding, jitter, mimicry)
  • ICMP spoofing with relay server support
  • Comprehensive diagnostics and debugging
  • systemd service management`,
}

// Execute runs the root command.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file path")
	rootCmd.PersistentFlags().BoolVar(&verbose, "verbose", false, "enable verbose output")
	rootCmd.PersistentFlags().StringVar(&logLevel, "log-level", "info", "log level (debug, info, warn, error)")
}
