package crypto

import (
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
)

// ChaChaEncryptor implements ChaCha20-Poly1305 encryption.
type ChaChaEncryptor struct {
	aead cipher.AEAD
}

// NewChaChaEncryptor creates a new ChaCha20-Poly1305 encryptor.
func NewChaChaEncryptor(key []byte) (*ChaChaEncryptor, error) {
	if len(key) != chacha20poly1305.KeySize {
		return nil, fmt.Errorf("ChaCha20-Poly1305 requires a %d-byte key, got %d bytes",
			chacha20poly1305.KeySize, len(key))
	}

	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, fmt.Errorf("creating ChaCha20-Poly1305: %w", err)
	}

	return &ChaChaEncryptor{aead: aead}, nil
}

// Encrypt encrypts plaintext using ChaCha20-Poly1305.
func (c *ChaChaEncryptor) Encrypt(plaintext []byte) ([]byte, error) {
	nonce := make([]byte, c.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("generating nonce: %w", err)
	}

	ciphertext := c.aead.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// Decrypt decrypts ciphertext using ChaCha20-Poly1305.
func (c *ChaChaEncryptor) Decrypt(ciphertext []byte) ([]byte, error) {
	nonceSize := c.aead.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ct := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := c.aead.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypting: %w", err)
	}

	return plaintext, nil
}

func (c *ChaChaEncryptor) Name() string  { return "chacha20-poly1305" }
func (c *ChaChaEncryptor) Overhead() int { return c.aead.NonceSize() + c.aead.Overhead() }
