package server

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"testing"
	"time"
)

// buildMorphTokenAt reconstructs the client-side token for verifyMorphAuth at
// a given minute-bucket offset from now, mirroring stego.go's token scheme.
func buildMorphTokenAt(secret []byte, offsetMinutes int64) []byte {
	currentMinute := time.Now().Unix() / 60
	timestamp := make([]byte, 8)
	binary.BigEndian.PutUint64(timestamp, uint64(currentMinute+offsetMinutes))

	h := hmac.New(sha256.New, secret)
	h.Write(timestamp)
	h.Write([]byte("http2-stego-auth"))
	return h.Sum(nil)[:32]
}

// buildH2AuthAt reconstructs the client-side apiKey/requestID pair for
// verifyH2Auth at a given minute-bucket offset from now.
func buildH2AuthAt(secret []byte, offsetMinutes int64) (apiKey, requestID string) {
	token := buildMorphTokenAt(secret, offsetMinutes)
	return hex.EncodeToString(token[:16]), hex.EncodeToString(token[16:32])
}

func TestVerifyMorphAuth_ClockSkewWindow(t *testing.T) {
	secret := []byte("test-secret-clock-skew")

	tests := []struct {
		name          string
		offsetMinutes int64
		wantOK        bool
	}{
		{"current bucket", 0, true},
		{"1 minute drift (old window edge)", 1, true},
		{"9 minutes drift (within new window)", 9, true},
		{"10 minutes drift (new window edge)", 10, true},
		{"-10 minutes drift (new window edge, negative)", -10, true},
		{"11 minutes drift (beyond new window)", 11, false},
		{"-11 minutes drift (beyond new window, negative)", -11, false},
		{"30 minutes drift (well beyond)", 30, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token := buildMorphTokenAt(secret, tt.offsetMinutes)
			got := verifyMorphAuth(token, secret)
			if got != tt.wantOK {
				t.Errorf("verifyMorphAuth at offset=%dmin = %v, want %v", tt.offsetMinutes, got, tt.wantOK)
			}
		})
	}
}

func TestVerifyH2Auth_ClockSkewWindow(t *testing.T) {
	secret := []byte("test-secret-clock-skew")

	tests := []struct {
		name          string
		offsetMinutes int64
		wantOK        bool
	}{
		{"current bucket", 0, true},
		{"9 minutes drift (within new window)", 9, true},
		{"10 minutes drift (new window edge)", 10, true},
		{"11 minutes drift (beyond new window)", 11, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			apiKey, requestID := buildH2AuthAt(secret, tt.offsetMinutes)
			got := verifyH2Auth(apiKey, requestID, secret)
			if got != tt.wantOK {
				t.Errorf("verifyH2Auth at offset=%dmin = %v, want %v", tt.offsetMinutes, got, tt.wantOK)
			}
		})
	}
}
