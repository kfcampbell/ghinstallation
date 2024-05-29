package ghinstallation

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/google/go-cmp/cmp"
)

func TestNewAppsTransportKeyFromFile(t *testing.T) {
	tmpfile, err := os.CreateTemp("", "example")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpfile.Name()) // clean up

	if _, err := tmpfile.Write(key); err != nil {
		t.Fatal(err)
	}
	if err := tmpfile.Close(); err != nil {
		t.Fatal(err)
	}

	_, err = NewAppsTransportKeyFromFile(&http.Transport{}, clientID, tmpfile.Name())
	if err != nil {
		t.Fatal("unexpected error:", err)
	}
}

func TestNewAppsTransportKeyFromFileErrorCase(t *testing.T) {
	_, err := NewAppsTransportKeyFromFile(&http.Transport{}, clientID, "this/file/does/not/exist")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestNewAppsTransportKeyFromFileWithAppID(t *testing.T) {
	tmpfile, err := os.CreateTemp("", "example")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpfile.Name()) // clean up

	if _, err := tmpfile.Write(key); err != nil {
		t.Fatal(err)
	}
	if err := tmpfile.Close(); err != nil {
		t.Fatal(err)
	}

	_, err = NewAppsTransportKeyFromFileWithAppID(&http.Transport{}, appID, tmpfile.Name())
	if err != nil {
		t.Fatal("unexpected error:", err)
	}
}

func TestNewAppsTransportKeyFromFileWithAppIDErrorCase(t *testing.T) {
	_, err := NewAppsTransportKeyFromFileWithAppID(&http.Transport{}, appID, "this/file/does/not/exist")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

type RoundTrip struct {
	rt func(*http.Request) (*http.Response, error)
}

func (r RoundTrip) RoundTrip(req *http.Request) (*http.Response, error) {
	return r.rt(req)
}

func TestAppsTransport(t *testing.T) {
	customHeader := "my-header"
	check := RoundTrip{
		rt: func(req *http.Request) (*http.Response, error) {
			h, ok := req.Header["Accept"]
			if !ok {
				t.Error("Header Accept not set")
			}
			want := []string{customHeader, acceptHeader}
			if diff := cmp.Diff(want, h); diff != "" {
				t.Errorf("HTTP Accept headers want->got: %s", diff)
			}
			return nil, nil
		},
	}

	tr, err := NewAppsTransport(check, clientID, key)
	if err != nil {
		t.Fatalf("error creating transport: %v", err)
	}

	if tr.clientID != clientID {
		t.Errorf("clientID want->got: %s->%s", clientID, tr.clientID)
	}

	req := httptest.NewRequest(http.MethodGet, "http://example.com", new(bytes.Buffer))
	req.Header.Add("Accept", customHeader)
	if _, err := tr.RoundTrip(req); err != nil {
		t.Fatalf("error calling RoundTrip: %v", err)
	}
}

func TestAppsTransportErrorInitializing(t *testing.T) {
	_, err := NewAppsTransport(http.DefaultTransport, clientID, []byte{})
	if err == nil {
		t.Fatalf("expected error creating transport, got nil")
	}
}

func TestAppsTransportWithAppID(t *testing.T) {
	customHeader := "my-header"
	check := RoundTrip{
		rt: func(req *http.Request) (*http.Response, error) {
			h, ok := req.Header["Accept"]
			if !ok {
				t.Error("Header Accept not set")
			}
			want := []string{customHeader, acceptHeader}
			if diff := cmp.Diff(want, h); diff != "" {
				t.Errorf("HTTP Accept headers want->got: %s", diff)
			}
			return nil, nil
		},
	}

	tr, err := NewAppsTransportWithAppID(check, appID, key)
	if err != nil {
		t.Fatalf("error creating transport: %v", err)
	}

	if tr.appID != appID {
		t.Errorf("appID want->got: %d->%d", appID, tr.appID)
	}

	req := httptest.NewRequest(http.MethodGet, "http://example.com", new(bytes.Buffer))
	req.Header.Add("Accept", customHeader)
	if _, err := tr.RoundTrip(req); err != nil {
		t.Fatalf("error calling RoundTrip: %v", err)
	}
}

func TestAppsTransportWithAppIDErrorInitializing(t *testing.T) {
	_, err := NewAppsTransportWithAppID(http.DefaultTransport, appID, []byte{})
	if err == nil {
		t.Fatalf("expected error creating transport, got nil")
	}
}

func TestJWTExpiry(t *testing.T) {
	key, err := jwt.ParseRSAPrivateKeyFromPEM(key)
	if err != nil {
		t.Fatal(err)
	}

	customHeader := "my-header"
	check := RoundTrip{
		rt: func(req *http.Request) (*http.Response, error) {
			token := strings.Fields(req.Header.Get("Authorization"))[1]
			tok, err := jwt.ParseWithClaims(token, &jwt.RegisteredClaims{}, func(t *jwt.Token) (interface{}, error) {
				if t.Header["alg"] != "RS256" {
					return nil, fmt.Errorf("unexpected signing method: %v, expected: %v", t.Header["alg"], "RS256")
				}
				return &key.PublicKey, nil
			})
			if err != nil {
				t.Fatalf("jwt parse: %v", err)
			}

			c := tok.Claims.(*jwt.RegisteredClaims)
			if c.ExpiresAt.IsZero() {
				t.Fatalf("missing exp claim")
			}
			return nil, nil
		},
	}

	tr := NewAppsTransportFromPrivateKey(check, clientID, key)
	req := httptest.NewRequest(http.MethodGet, "http://example.com", new(bytes.Buffer))
	req.Header.Add("Accept", customHeader)
	if _, err := tr.RoundTrip(req); err != nil {
		t.Fatalf("error calling RoundTrip: %v", err)
	}
}

func TestJWTExpiryWithAppID(t *testing.T) {
	key, err := jwt.ParseRSAPrivateKeyFromPEM(key)
	if err != nil {
		t.Fatal(err)
	}

	customHeader := "my-header"
	check := RoundTrip{
		rt: func(req *http.Request) (*http.Response, error) {
			token := strings.Fields(req.Header.Get("Authorization"))[1]
			tok, err := jwt.ParseWithClaims(token, &jwt.RegisteredClaims{}, func(t *jwt.Token) (interface{}, error) {
				if t.Header["alg"] != "RS256" {
					return nil, fmt.Errorf("unexpected signing method: %v, expected: %v", t.Header["alg"], "RS256")
				}
				return &key.PublicKey, nil
			})
			if err != nil {
				t.Fatalf("jwt parse: %v", err)
			}

			c := tok.Claims.(*jwt.RegisteredClaims)
			if c.ExpiresAt.IsZero() {
				t.Fatalf("missing exp claim")
			}
			return nil, nil
		},
	}

	tr := NewAppsTransportFromPrivateKeyWithAppID(check, appID, key)
	req := httptest.NewRequest(http.MethodGet, "http://example.com", new(bytes.Buffer))
	req.Header.Add("Accept", customHeader)
	if _, err := tr.RoundTrip(req); err != nil {
		t.Fatalf("error calling RoundTrip: %v", err)
	}
}

func TestCustomSigner(t *testing.T) {
	check := RoundTrip{
		rt: func(req *http.Request) (*http.Response, error) {
			h, ok := req.Header["Authorization"]
			if !ok {
				t.Error("Header Accept not set")
			}
			want := []string{"Bearer hunter2"}
			if diff := cmp.Diff(want, h); diff != "" {
				t.Errorf("HTTP Accept headers want->got: %s", diff)
			}
			return nil, nil
		},
	}

	tr, err := NewAppsTransportWithOptions(check, clientID, WithSigner(&noopSigner{}))
	if err != nil {
		t.Fatalf("NewAppsTransportWithOptions: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "http://example.com", new(bytes.Buffer))
	if _, err := tr.RoundTrip(req); err != nil {
		t.Fatalf("error calling RoundTrip: %v", err)
	}
}

func TestCustomSignerErrorInitializing(t *testing.T) {
	_, err := NewAppsTransportWithOptions(http.DefaultTransport, clientID)
	if err == nil {
		t.Fatalf("expected error creating transport, got nil")
	}
}

func TestCustomSignerErrorOnSigning(t *testing.T) {
	tr, err := NewAppsTransportWithOptions(http.DefaultTransport, clientID, WithSigner(&errSigner{}))
	if err != nil {
		t.Fatalf("NewAppsTransportWithOptions: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "http://example.com", new(bytes.Buffer))
	if _, err := tr.RoundTrip(req); err == nil {
		t.Fatalf("expected error calling RoundTrip, got nil")
	}
}

func TestCustomSignerWithAppID(t *testing.T) {
	check := RoundTrip{
		rt: func(req *http.Request) (*http.Response, error) {
			h, ok := req.Header["Authorization"]
			if !ok {
				t.Error("Header Accept not set")
			}
			want := []string{"Bearer hunter2"}
			if diff := cmp.Diff(want, h); diff != "" {
				t.Errorf("HTTP Accept headers want->got: %s", diff)
			}
			return nil, nil
		},
	}

	tr, err := NewAppsTransportWithAppIDWithOptions(check, appID, WithSigner(&noopSigner{}))
	if err != nil {
		t.Fatalf("NewAppsTransportWithOptions: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "http://example.com", new(bytes.Buffer))
	if _, err := tr.RoundTrip(req); err != nil {
		t.Fatalf("error calling RoundTrip: %v", err)
	}
}

func TestCustomSignerWithAppIDErrorCase(t *testing.T) {
	_, err := NewAppsTransportWithAppIDWithOptions(http.DefaultTransport, appID)
	if err == nil {
		t.Fatalf("expected error creating transport, got nil")
	}
}

func TestAppID(t *testing.T) {
	tr := &AppsTransport{appID: appID}
	id := tr.AppID()

	if id != appID {
		t.Errorf("AppID want->got: %d->%d", appID, id)
	}
}

func TestClientID(t *testing.T) {
	tr := &AppsTransport{clientID: clientID}
	id := tr.ClientID()

	if id != clientID {
		t.Errorf("ClientID want->got: %s->%s", clientID, id)
	}
}

type noopSigner struct{}

func (noopSigner) Sign(jwt.Claims) (string, error) {
	return "hunter2", nil
}

type errSigner struct{}

func (errSigner) Sign(jwt.Claims) (string, error) {
	return "", fmt.Errorf("this signer is for test purposes and always returns an error")
}
