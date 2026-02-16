// Package auth provides token-based authentication with HMAC-SHA256.
package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// Validator validates authentication tokens.
type Validator struct {
	validTokens map[string]bool
}

// NewValidator creates a new token validator.
func NewValidator(tokens []string) *Validator {
	v := &Validator{
		validTokens: make(map[string]bool),
	}
	for _, t := range tokens {
		v.validTokens[t] = true
	}
	return v
}

// IsValid checks if a token is valid.
func (v *Validator) IsValid(token string) bool {
	return v.validTokens[token]
}

// GenerateToken generates a new random auth token (32 hex chars).
func GenerateToken() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generating token: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// GenerateChallenge creates a random challenge for HMAC auth.
func GenerateChallenge() ([]byte, error) {
	challenge := make([]byte, 32)
	if _, err := rand.Read(challenge); err != nil {
		return nil, fmt.Errorf("generating challenge: %w", err)
	}
	return challenge, nil
}

// ComputeResponse computes HMAC-SHA256 response to a challenge.
func ComputeResponse(secret, challenge []byte) []byte {
	mac := hmac.New(sha256.New, secret)
	mac.Write(challenge)
	return mac.Sum(nil)
}

// VerifyResponse verifies a challenge-response.
func VerifyResponse(secret, challenge, response []byte) bool {
	expected := ComputeResponse(secret, challenge)
	return hmac.Equal(expected, response)
}
