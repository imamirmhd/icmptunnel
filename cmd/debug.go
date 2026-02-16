package cmd

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"
	"github.com/imamirmhd/icmptunnel/config"
	"github.com/imamirmhd/icmptunnel/diag"
)

var debugCmd = &cobra.Command{
	Use:   "debug",
	Short: "Run diagnostics and debugging tools",
	Long:  `Run various diagnostic tests to verify ICMP tunnel connectivity, throughput, and DPI interference.`,
}

var pingCmd = &cobra.Command{
	Use:   "ping [target]",
	Short: "Test ICMP connectivity",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		count, _ := cmd.Flags().GetInt("count")
		d, err := diag.New()
		if err != nil {
			return err
		}
		defer d.Close()
		loadToken(d, cmd)
		_, err = d.Ping(args[0], count)
		return err
	},
}

var throughputCmd = &cobra.Command{
	Use:   "throughput [target]",
	Short: "Measure ICMP throughput",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		duration, _ := cmd.Flags().GetInt("duration")
		d, err := diag.New()
		if err != nil {
			return err
		}
		defer d.Close()
		loadToken(d, cmd)
		_, err = d.Throughput(args[0], duration)
		return err
	},
}

var lossCmd = &cobra.Command{
	Use:   "loss [target]",
	Short: "Measure packet loss",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		count, _ := cmd.Flags().GetInt("count")
		d, err := diag.New()
		if err != nil {
			return err
		}
		defer d.Close()
		loadToken(d, cmd)
		_, err = d.PacketLoss(args[0], count)
		return err
	},
}

var detectCmd = &cobra.Command{
	Use:   "detect [target]",
	Short: "Detect DPI/firewall interference",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		d, err := diag.New()
		if err != nil {
			return err
		}
		defer d.Close()
		loadToken(d, cmd)
		_, err = d.DPIDetect(args[0])
		return err
	},
}

var spoofTestCmd = &cobra.Command{
	Use:   "spoof-test [relay] [server]",
	Short: "Test ICMP spoofing through relay",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		d, err := diag.New()
		if err != nil {
			return err
		}
		defer d.Close()
		return d.SpoofTest(args[0], args[1])
	},
}

var statusCmd = &cobra.Command{
	Use:   "status [target]",
	Short: "Check tunnel server status",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		d, err := diag.New()
		if err != nil {
			return err
		}
		defer d.Close()
		loadToken(d, cmd)
		return d.StatusCheck(args[0])
	},
}

var stressCmd = &cobra.Command{
	Use:   "stress [target]",
	Short: "Run stress test against a target",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		level, _ := cmd.Flags().GetString("level")
		duration, _ := cmd.Flags().GetDuration("duration")

		d, err := diag.New()
		if err != nil {
			return err
		}
		defer d.Close()
		loadToken(d, cmd)

		_, err = d.StressTest(args[0], level, duration)
		return err
	},
}

func loadToken(d *diag.Diagnostics, cmd *cobra.Command) {
	cfgPath, _ := cmd.Flags().GetString("config")
	if cfgPath == "" {
		cfgPath, _ = cmd.Root().PersistentFlags().GetString("config")
	}

	if cfgPath != "" {
		clientCfg, err := config.LoadClientConfig(cfgPath)
		if err == nil {
			d.SetAuthToken(clientCfg.AuthToken)
		}
	}
}

func init() {
	pingCmd.Flags().IntP("count", "c", 4, "number of pings")
	throughputCmd.Flags().IntP("duration", "d", 5, "test duration in seconds")
	lossCmd.Flags().IntP("count", "c", 100, "number of packets")

	stressCmd.Flags().StringP("level", "l", "low", "stress level (low, medium, high)")
	stressCmd.Flags().DurationP("duration", "d", 10*time.Second, "test duration")

	debugCmd.AddCommand(pingCmd)
	debugCmd.AddCommand(throughputCmd)
	debugCmd.AddCommand(lossCmd)
	debugCmd.AddCommand(detectCmd)
	debugCmd.AddCommand(spoofTestCmd)
	debugCmd.AddCommand(statusCmd)
	debugCmd.AddCommand(stressCmd)

	rootCmd.AddCommand(debugCmd)

	_ = fmt.Sprintf // avoid unused import
}
