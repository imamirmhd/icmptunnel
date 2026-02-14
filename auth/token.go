// Package auth provides token-based authentication for ICMP tunnel clients.
package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

const (
	// TokenLength is the length of generated tokens in bytes (before hex encoding).
	TokenLength = 32
	// ChallengeLength is the length of auth challenges in bytes.
	ChallengeLength = 16
	// AuthTimeout is the maximum time allowed for authentication handshake.
	AuthTimeout = 10 * time.Second
)

// GenerateToken generates a cryptographically secure random authentication token.
func GenerateToken() (string, error) {
	bytes := make([]byte, TokenLength)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("generating random token: %w", err)
	}
	return hex.EncodeToString(bytes), nil
}

// GenerateChallenge generates a random challenge for HMAC-based auth.
func GenerateChallenge() ([]byte, error) {
	challenge := make([]byte, ChallengeLength)
	if _, err := rand.Read(challenge); err != nil {
		return nil, fmt.Errorf("generating challenge: %w", err)
	}
	return challenge, nil
}

// ComputeResponse computes the HMAC-SHA256 response for a challenge using the token.
func ComputeResponse(token string, challenge []byte) []byte {
	tokenBytes, _ := hex.DecodeString(token)
	mac := hmac.New(sha256.New, tokenBytes)
	mac.Write(challenge)
	return mac.Sum(nil)
}

// VerifyResponse verifies an HMAC-SHA256 response against a set of valid tokens.
func VerifyResponse(tokens []string, challenge []byte, response []byte) (bool, string) {
	for _, token := range tokens {
		expected := ComputeResponse(token, challenge)
		if hmac.Equal(expected, response) {
			return true, token
		}
	}
	return false, ""
}

// Validator manages server-side token validation.
type Validator struct {
	tokens []string
}

// NewValidator creates a new token validator with the given authorized tokens.
func NewValidator(tokens []string) *Validator {
	return &Validator{tokens: tokens}
}

// IsValid checks if a token is in the authorized list.
func (v *Validator) IsValid(token string) bool {
	for _, t := range v.tokens {
		if t == token {
			return true
		}
	}
	return false
}

// IsValidPrefix checks if any authorized token is a prefix of the provided payload.
// Returns success boolean and the length of the matched token.
func (v *Validator) IsValidPrefix(payload string) (bool, int) {
	for _, t := range v.tokens {
		if strings.HasPrefix(payload, t) {
			return true, len(t)
		}
	}
	return false, 0
}

// Verify performs HMAC-based challenge-response verification.
func (v *Validator) Verify(challenge []byte, response []byte) (bool, string) {
	return VerifyResponse(v.tokens, challenge, response)
}
