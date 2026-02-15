package crypto

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func makeKey(t *testing.T, size int) []byte {
	t.Helper()
	key := make([]byte, size)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}
	return key
}

// --- AES-256-GCM ---

func TestAESEncryptDecrypt(t *testing.T) {
	key := makeKey(t, 32)
	enc, err := NewAESEncryptor(key)
	if err != nil {
		t.Fatalf("NewAESEncryptor: %v", err)
	}

	plaintext := []byte("Hello, AES-256-GCM tunnel encryption!")
	ciphertext, err := enc.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	// Ciphertext should be different from plaintext
	if bytes.Equal(ciphertext, plaintext) {
		t.Error("Ciphertext should differ from plaintext")
	}

	// Ciphertext should be longer (nonce + tag)
	if len(ciphertext) <= len(plaintext) {
		t.Error("Ciphertext should be longer than plaintext")
	}

	decrypted, err := enc.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Error("Decrypted data does not match plaintext")
	}
}

func TestAESWrongKeySize(t *testing.T) {
	_, err := NewAESEncryptor([]byte("short"))
	if err == nil {
		t.Error("Expected error for wrong key size")
	}
}

func TestAESDecryptTampered(t *testing.T) {
	key := makeKey(t, 32)
	enc, _ := NewAESEncryptor(key)

	plaintext := []byte("tamper test data")
	ciphertext, _ := enc.Encrypt(plaintext)

	// Flip a byte in the ciphertext
	ciphertext[len(ciphertext)-1] ^= 0xFF

	_, err := enc.Decrypt(ciphertext)
	if err == nil {
		t.Error("Decrypt should fail for tampered ciphertext")
	}
}

func TestAESNameAndOverhead(t *testing.T) {
	key := makeKey(t, 32)
	enc, _ := NewAESEncryptor(key)

	if enc.Name() != "aes-256-gcm" {
		t.Errorf("Name: got %q, want %q", enc.Name(), "aes-256-gcm")
	}
	if enc.Overhead() <= 0 {
		t.Errorf("Overhead should be positive, got %d", enc.Overhead())
	}
}

func TestAESEmptyPlaintext(t *testing.T) {
	key := makeKey(t, 32)
	enc, _ := NewAESEncryptor(key)

	ciphertext, err := enc.Encrypt([]byte{})
	if err != nil {
		t.Fatalf("Encrypt empty: %v", err)
	}

	decrypted, err := enc.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("Decrypt empty: %v", err)
	}

	if len(decrypted) != 0 {
		t.Errorf("Expected empty decrypted, got %d bytes", len(decrypted))
	}
}

// --- ChaCha20-Poly1305 ---

func TestChaChaEncryptDecrypt(t *testing.T) {
	key := makeKey(t, 32)
	enc, err := NewChaChaEncryptor(key)
	if err != nil {
		t.Fatalf("NewChaChaEncryptor: %v", err)
	}

	plaintext := []byte("Hello, ChaCha20-Poly1305 tunnel encryption!")
	ciphertext, err := enc.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	if bytes.Equal(ciphertext, plaintext) {
		t.Error("Ciphertext should differ from plaintext")
	}

	decrypted, err := enc.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Error("Decrypted data does not match plaintext")
	}
}

func TestChaChaDecryptTampered(t *testing.T) {
	key := makeKey(t, 32)
	enc, _ := NewChaChaEncryptor(key)

	ciphertext, _ := enc.Encrypt([]byte("tamper test"))
	ciphertext[len(ciphertext)-1] ^= 0xFF

	_, err := enc.Decrypt(ciphertext)
	if err == nil {
		t.Error("Decrypt should fail for tampered ciphertext")
	}
}

func TestChaChaNameAndOverhead(t *testing.T) {
	key := makeKey(t, 32)
	enc, _ := NewChaChaEncryptor(key)

	if enc.Name() != "chacha20-poly1305" {
		t.Errorf("Name: got %q, want %q", enc.Name(), "chacha20-poly1305")
	}
	if enc.Overhead() <= 0 {
		t.Errorf("Overhead should be positive, got %d", enc.Overhead())
	}
}

func TestChaChaWrongKeySize(t *testing.T) {
	_, err := NewChaChaEncryptor([]byte("short"))
	if err == nil {
		t.Error("Expected error for wrong key size")
	}
}

// --- XOR ---

func TestXOREncryptDecrypt(t *testing.T) {
	key := makeKey(t, 16)
	enc, err := NewXOREncryptor(key)
	if err != nil {
		t.Fatalf("NewXOREncryptor: %v", err)
	}

	plaintext := []byte("Hello, XOR obfuscation!")
	ciphertext, err := enc.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	// XOR should produce different output (unless key is all zeros)
	if bytes.Equal(ciphertext, plaintext) {
		t.Error("Ciphertext should differ from plaintext")
	}

	decrypted, err := enc.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Error("Decrypted data does not match plaintext")
	}
}

func TestXOREmptyKey(t *testing.T) {
	_, err := NewXOREncryptor([]byte{})
	if err == nil {
		t.Error("Expected error for empty key")
	}
}

func TestXORNameAndOverhead(t *testing.T) {
	enc, _ := NewXOREncryptor([]byte{0x42})
	if enc.Name() != "xor" {
		t.Errorf("Name: got %q, want %q", enc.Name(), "xor")
	}
	if enc.Overhead() != 0 {
		t.Errorf("XOR overhead should be 0, got %d", enc.Overhead())
	}
}

// --- NopEncryptor ---

func TestNopEncryptor(t *testing.T) {
	enc := &NopEncryptor{}

	plaintext := []byte("passthrough data")
	ciphertext, err := enc.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if !bytes.Equal(ciphertext, plaintext) {
		t.Error("NopEncryptor should pass data through unchanged")
	}

	decrypted, err := enc.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Error("NopEncryptor decrypt should pass data through unchanged")
	}

	if enc.Name() != "none" {
		t.Errorf("Name: got %q, want %q", enc.Name(), "none")
	}
	if enc.Overhead() != 0 {
		t.Errorf("NopEncryptor overhead should be 0, got %d", enc.Overhead())
	}
}

// --- NewEncryptor factory ---

func TestNewEncryptorFactory(t *testing.T) {
	key := makeKey(t, 32)

	tests := []struct {
		method      string
		shouldWork  bool
	}{
		{"aes-256-gcm", true},
		{"chacha20-poly1305", true},
		{"xor", true},
		{"unknown-method", false},
		{"", false},
	}

	for _, tc := range tests {
		enc, err := NewEncryptor(tc.method, key)
		if tc.shouldWork {
			if err != nil {
				t.Errorf("NewEncryptor(%q): unexpected error: %v", tc.method, err)
			}
			if enc == nil {
				t.Errorf("NewEncryptor(%q): returned nil", tc.method)
			}
		} else {
			if err == nil {
				t.Errorf("NewEncryptor(%q): expected error, got nil", tc.method)
			}
		}
	}
}

// --- Large data round-trip ---

func TestAESLargeData(t *testing.T) {
	key := makeKey(t, 32)
	enc, _ := NewAESEncryptor(key)

	// 64KB payload (typical large tunnel packet)
	plaintext := make([]byte, 65536)
	rand.Read(plaintext)

	ciphertext, err := enc.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt 64KB: %v", err)
	}

	decrypted, err := enc.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("Decrypt 64KB: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Error("64KB round-trip failed")
	}
}

// --- Cross-encryptor isolation ---

func TestDifferentKeysCannotDecrypt(t *testing.T) {
	key1 := makeKey(t, 32)
	key2 := makeKey(t, 32)

	enc1, _ := NewAESEncryptor(key1)
	enc2, _ := NewAESEncryptor(key2)

	ciphertext, _ := enc1.Encrypt([]byte("secret"))
	_, err := enc2.Decrypt(ciphertext)
	if err == nil {
		t.Error("Decryption with wrong key should fail")
	}
}
