package cmd

import (
	"encoding/hex"
	"fmt"

	"github.com/spf13/cobra"
	"github.com/user/icmptunnel/auth"
)

var keygenCmd = &cobra.Command{
	Use:   "keygen",
	Short: "Generate encryption keys and authentication tokens",
	Long: `Generate cryptographic keys for encryption and authentication tokens
for securing tunnel communication.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		method, _ := cmd.Flags().GetString("method")
		genToken, _ := cmd.Flags().GetBool("token")

		if genToken {
			token, err := auth.GenerateToken()
			if err != nil {
				return err
			}
			fmt.Printf("Authentication Token: %s\n", token)
			fmt.Println("\nAdd this token to:")
			fmt.Println("  Server config: auth_tokens = [\"" + token + "\"]")
			fmt.Println("  Client config: auth_token = \"" + token + "\"")
			return nil
		}

		var keySize int
		switch method {
		case "aes-256-gcm", "chacha20-poly1305":
			keySize = 32
		case "xor":
			keySize = 16
		default:
			keySize = 32
			method = "aes-256-gcm"
		}

		key := make([]byte, keySize)
		if _, err := hex.DecodeString(hex.EncodeToString(key)); err != nil {
			return err
		}

		// Generate random key
		challenge, err := auth.GenerateChallenge()
		if err != nil {
			return err
		}
		// Use challenge generation as entropy source for key
		token1, _ := auth.GenerateToken()
		token2, _ := auth.GenerateToken()
		keyHex := (token1 + token2)[:keySize*2]
		_ = challenge

		fmt.Printf("Encryption Method: %s\n", method)
		fmt.Printf("Key: %s\n", keyHex)
		fmt.Printf("Key Size: %d bytes (%d bits)\n", keySize, keySize*8)
		fmt.Println("\nAdd to config files:")
		fmt.Println("  [encryption]")
		fmt.Println("  enabled = true")
		fmt.Printf("  method = \"%s\"\n", method)
		fmt.Printf("  key = \"%s\"\n", keyHex)

		return nil
	},
}

func init() {
	keygenCmd.Flags().String("method", "aes-256-gcm", "encryption method (aes-256-gcm, chacha20-poly1305, xor)")
	keygenCmd.Flags().Bool("token", false, "generate an authentication token instead of encryption key")
	rootCmd.AddCommand(keygenCmd)
}
