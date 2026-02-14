package crypto

import "fmt"

// XOREncryptor implements simple repeating-key XOR obfuscation.
// WARNING: This is NOT cryptographically secure. Use only for basic obfuscation.
type XOREncryptor struct {
	key []byte
}

// NewXOREncryptor creates a new XOR encryptor.
func NewXOREncryptor(key []byte) (*XOREncryptor, error) {
	if len(key) == 0 {
		return nil, fmt.Errorf("XOR key must not be empty")
	}
	keyCopy := make([]byte, len(key))
	copy(keyCopy, key)
	return &XOREncryptor{key: keyCopy}, nil
}

// Encrypt XORs the plaintext with the repeating key.
func (x *XOREncryptor) Encrypt(plaintext []byte) ([]byte, error) {
	result := make([]byte, len(plaintext))
	for i, b := range plaintext {
		result[i] = b ^ x.key[i%len(x.key)]
	}
	return result, nil
}

// Decrypt XORs the ciphertext with the repeating key (same operation as encrypt).
func (x *XOREncryptor) Decrypt(ciphertext []byte) ([]byte, error) {
	return x.Encrypt(ciphertext) // XOR is symmetric
}

// Name returns the encryptor name.
func (x *XOREncryptor) Name() string {
	return "xor"
}
