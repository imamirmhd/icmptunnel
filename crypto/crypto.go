// Package crypto provides encryption interfaces and implementations for tunnel traffic.
package crypto

import "fmt"

// Encryptor defines the interface for encrypting and decrypting tunnel payloads.
type Encryptor interface {
	Encrypt(plaintext []byte) ([]byte, error)
	Decrypt(ciphertext []byte) ([]byte, error)
	Name() string
	Overhead() int
}

// NewEncryptor creates a new Encryptor based on the method name.
func NewEncryptor(method string, key []byte) (Encryptor, error) {
	switch method {
	case "aes-256-gcm":
		return NewAESEncryptor(key)
	case "chacha20-poly1305":
		return NewChaChaEncryptor(key)
	case "xor":
		return NewXOREncryptor(key)
	default:
		return nil, fmt.Errorf("unsupported encryption method: %s", method)
	}
}

// NopEncryptor is a no-op encryptor that passes data through unchanged.
type NopEncryptor struct{}

func (n *NopEncryptor) Encrypt(plaintext []byte) ([]byte, error)  { return plaintext, nil }
func (n *NopEncryptor) Decrypt(ciphertext []byte) ([]byte, error) { return ciphertext, nil }
func (n *NopEncryptor) Name() string                              { return "none" }
func (n *NopEncryptor) Overhead() int                             { return 0 }
