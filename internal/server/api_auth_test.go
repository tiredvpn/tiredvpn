package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// newAuthTestServer builds an APIServer with only the token set; the auth
// middleware does not touch registry/store, so they can stay nil.
func newAuthTestServer(token string) *APIServer {
	return &APIServer{token: token}
}

func doAuth(t *testing.T, s *APIServer, authHeader string) int {
	t.Helper()
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})
	req := httptest.NewRequest(http.MethodGet, "/clients", nil)
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}
	rec := httptest.NewRecorder()
	s.authMiddleware(next).ServeHTTP(rec, req)
	// When unauthorized the next handler must not run.
	if rec.Code == http.StatusOK && !called {
		t.Fatalf("got 200 but next handler was not called")
	}
	if rec.Code != http.StatusOK && called {
		t.Fatalf("got %d but next handler ran anyway", rec.Code)
	}
	return rec.Code
}

func TestAPIAuth_TokenSet(t *testing.T) {
	s := newAuthTestServer("s3cr3t-token")

	if code := doAuth(t, s, ""); code != http.StatusUnauthorized {
		t.Errorf("missing token: want 401, got %d", code)
	}
	if code := doAuth(t, s, "Bearer wrong"); code != http.StatusUnauthorized {
		t.Errorf("wrong token: want 401, got %d", code)
	}
	if code := doAuth(t, s, "s3cr3t-token"); code != http.StatusUnauthorized {
		t.Errorf("token without Bearer prefix: want 401, got %d", code)
	}
	if code := doAuth(t, s, "Bearer s3cr3t-token"); code != http.StatusOK {
		t.Errorf("correct token: want 200, got %d", code)
	}
}

func TestAPIAuth_NoToken_DefaultUnchanged(t *testing.T) {
	s := newAuthTestServer("")

	// With no token configured every request passes through, with or without
	// an Authorization header, exactly as before.
	if code := doAuth(t, s, ""); code != http.StatusOK {
		t.Errorf("no token, no header: want 200, got %d", code)
	}
	if code := doAuth(t, s, "Bearer anything"); code != http.StatusOK {
		t.Errorf("no token, with header: want 200, got %d", code)
	}
}

func TestAPIAddrIsLoopback(t *testing.T) {
	cases := map[string]bool{
		"127.0.0.1:8080": true,
		"localhost:8080": true,
		"[::1]:8080":     true,
		":8080":          false,
		"0.0.0.0:8080":   false,
		"10.8.0.1:8080":  false,
	}
	for addr, want := range cases {
		if got := apiAddrIsLoopback(addr); got != want {
			t.Errorf("apiAddrIsLoopback(%q) = %v, want %v", addr, got, want)
		}
	}
}
