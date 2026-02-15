package auth

import (
	"encoding/hex"
	"testing"
)

func TestGenerateToken(t *testing.T) {
	token, err := GenerateToken()
	if err != nil {
		t.Fatalf("GenerateToken failed: %v", err)
	}

	// Token should be hex-encoded 32 bytes = 64 hex chars
	if len(token) != TokenLength*2 {
		t.Errorf("Token length: got %d chars, want %d", len(token), TokenLength*2)
	}

	// Should be valid hex
	_, err = hex.DecodeString(token)
	if err != nil {
		t.Errorf("Token is not valid hex: %v", err)
	}

	// Two tokens should be different
	token2, _ := GenerateToken()
	if token == token2 {
		t.Error("Two generated tokens should not be identical")
	}
}

func TestGenerateChallenge(t *testing.T) {
	challenge, err := GenerateChallenge()
	if err != nil {
		t.Fatalf("GenerateChallenge failed: %v", err)
	}
	if len(challenge) != ChallengeLength {
		t.Errorf("Challenge length: got %d, want %d", len(challenge), ChallengeLength)
	}
}

func TestChallengeResponse(t *testing.T) {
	token, _ := GenerateToken()
	challenge, _ := GenerateChallenge()

	response := ComputeResponse(token, challenge)
	if len(response) == 0 {
		t.Fatal("Response should not be empty")
	}

	// Verify with correct token
	ok, matched := VerifyResponse([]string{token}, challenge, response)
	if !ok {
		t.Error("VerifyResponse should succeed with correct token")
	}
	if matched != token {
		t.Errorf("Matched token: got %q, want %q", matched, token)
	}
}

func TestInvalidResponse(t *testing.T) {
	token, _ := GenerateToken()
	wrongToken, _ := GenerateToken()
	challenge, _ := GenerateChallenge()

	response := ComputeResponse(wrongToken, challenge)

	ok, _ := VerifyResponse([]string{token}, challenge, response)
	if ok {
		t.Error("VerifyResponse should fail with wrong token")
	}
}

func TestVerifyResponseMultipleTokens(t *testing.T) {
	token1, _ := GenerateToken()
	token2, _ := GenerateToken()
	token3, _ := GenerateToken()
	challenge, _ := GenerateChallenge()

	// Respond with token2
	response := ComputeResponse(token2, challenge)
	ok, matched := VerifyResponse([]string{token1, token2, token3}, challenge, response)
	if !ok {
		t.Error("Should match token2 in the list")
	}
	if matched != token2 {
		t.Errorf("Matched: got %q, want %q", matched, token2)
	}
}

func TestValidatorIsValid(t *testing.T) {
	tokens := []string{"abc123", "def456", "ghi789"}
	v := NewValidator(tokens)

	if !v.IsValid("def456") {
		t.Error("IsValid should return true for valid token")
	}
	if v.IsValid("invalid") {
		t.Error("IsValid should return false for invalid token")
	}
	if v.IsValid("") {
		t.Error("IsValid should return false for empty string")
	}
}

func TestValidatorIsValidPrefix(t *testing.T) {
	v := NewValidator([]string{"secret123"})

	ok, length := v.IsValidPrefix("secret123extradata")
	if !ok {
		t.Error("IsValidPrefix should match prefix")
	}
	if length != 9 {
		t.Errorf("Prefix length: got %d, want 9", length)
	}

	ok, _ = v.IsValidPrefix("wrongprefix")
	if ok {
		t.Error("IsValidPrefix should not match wrong prefix")
	}
}

func TestValidatorVerify(t *testing.T) {
	token, _ := GenerateToken()
	v := NewValidator([]string{token})
	challenge, _ := GenerateChallenge()

	response := ComputeResponse(token, challenge)
	ok, matched := v.Verify(challenge, response)
	if !ok {
		t.Error("Validator.Verify should succeed")
	}
	if matched != token {
		t.Errorf("Matched: got %q, want %q", matched, token)
	}

	// Wrong response
	badResponse := make([]byte, 32)
	ok, _ = v.Verify(challenge, badResponse)
	if ok {
		t.Error("Validator.Verify should fail with wrong response")
	}
}
