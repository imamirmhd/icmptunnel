package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"sync"
)

// AESEncryptor implements AES-256-GCM encryption with nonce pooling.
type AESEncryptor struct {
	gcm      cipher.AEAD
	noncePool sync.Pool
}

// NewAESEncryptor creates a new AES-256-GCM encryptor.
func NewAESEncryptor(key []byte) (*AESEncryptor, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("AES-256-GCM requires a 32-byte key, got %d bytes", len(key))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("creating AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("creating GCM: %w", err)
	}

	enc := &AESEncryptor{gcm: gcm}
	enc.noncePool = sync.Pool{
		New: func() interface{} {
			return make([]byte, enc.gcm.NonceSize())
		},
	}

	return enc, nil
}

// Encrypt encrypts plaintext using AES-256-GCM.
func (a *AESEncryptor) Encrypt(plaintext []byte) ([]byte, error) {
	nonce := a.noncePool.Get().([]byte)
	defer a.noncePool.Put(nonce)

	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("generating nonce: %w", err)
	}

	ciphertext := a.gcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// Decrypt decrypts ciphertext using AES-256-GCM.
func (a *AESEncryptor) Decrypt(ciphertext []byte) ([]byte, error) {
	nonceSize := a.gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ct := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := a.gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypting: %w", err)
	}

	return plaintext, nil
}

func (a *AESEncryptor) Name() string  { return "aes-256-gcm" }
func (a *AESEncryptor) Overhead() int { return a.gcm.NonceSize() + a.gcm.Overhead() }
