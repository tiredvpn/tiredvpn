package server

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"testing"
	"time"
)

// F1 (S22): the server verifiers fold the TLS session exporter into the HMAC, so
// a token minted on one session is rejected on another. Each test mints a token
// on exporter A and asserts verify(A) passes while verify(B) fails. Predelivered
// to the pre-binding code (drop h.Write(ekm) in the matching verifier) each goes
// green-to-red — the binding, not the token, is what is pinned here.

func mintBoundH2Token(secret, ekm []byte) (apiKey, requestID string) {
	timestamp := make([]byte, 8)
	binary.BigEndian.PutUint64(timestamp, uint64(time.Now().Unix()/60))
	h := hmac.New(sha256.New, secret)
	h.Write(timestamp)
	h.Write([]byte("http2-stego-auth"))
	h.Write(ekm)
	tok := h.Sum(nil)[:32]
	return hex.EncodeToString(tok[:16]), hex.EncodeToString(tok[16:32])
}

func mintBoundMorphToken(secret, ekm []byte) []byte {
	timestamp := make([]byte, 8)
	binary.BigEndian.PutUint64(timestamp, uint64(time.Now().Unix()/60))
	h := hmac.New(sha256.New, secret)
	h.Write(timestamp)
	h.Write([]byte("http2-stego-auth"))
	h.Write(ekm)
	return h.Sum(nil)[:32]
}

func mintBoundPollingToken(secret, ekm []byte, sessionID string) string {
	data := fmt.Sprintf("%s:%d", sessionID, time.Now().Unix())
	h := hmac.New(sha256.New, secret)
	h.Write([]byte(data))
	h.Write(ekm)
	return base64.StdEncoding.EncodeToString(h.Sum(nil))[:16]
}

func TestVerifyH2AuthBindsToSession(t *testing.T) {
	secret := []byte("h2-bind-secret")
	ekmA := []byte("h2-exporter-A-0123456789abcdef012")
	ekmB := []byte("h2-exporter-B-0123456789abcdef012")

	apiKey, requestID := mintBoundH2Token(secret, ekmA)
	if !verifyH2Auth(apiKey, requestID, secret, ekmA) {
		t.Fatal("token minted on session A rejected on session A")
	}
	if verifyH2Auth(apiKey, requestID, secret, ekmB) {
		t.Fatal("token minted on session A verified on session B; not session-bound")
	}
}

func TestVerifyMorphAuthBindsToSession(t *testing.T) {
	secret := []byte("morph-bind-secret")
	ekmA := []byte("morph-exporter-A-0123456789abcdef")
	ekmB := []byte("morph-exporter-B-0123456789abcdef")

	tok := mintBoundMorphToken(secret, ekmA)
	if !verifyMorphAuth(tok, secret, ekmA) {
		t.Fatal("token minted on session A rejected on session A")
	}
	if verifyMorphAuth(tok, secret, ekmB) {
		t.Fatal("token minted on session A verified on session B; not session-bound")
	}
}

func TestVerifyPollingAuthBindsToSession(t *testing.T) {
	secret := []byte("polling-bind-secret")
	sessionID := "sess-bind-0123456789"
	ekmA := []byte("polling-exporter-A-0123456789abcd")
	ekmB := []byte("polling-exporter-B-0123456789abcd")

	tok := mintBoundPollingToken(secret, ekmA, sessionID)
	if !verifyPollingAuth(tok, sessionID, secret, ekmA) {
		t.Fatal("token minted on session A rejected on session A")
	}
	if verifyPollingAuth(tok, sessionID, secret, ekmB) {
		t.Fatal("token minted on session A verified on session B; not session-bound")
	}
}
