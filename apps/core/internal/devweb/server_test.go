package devweb

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPrivateCertificateAndNoOverwrite(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := GenerateCertificate(dir, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := GenerateCertificate(dir, time.Now()); err == nil {
		t.Fatal("overwrote existing key")
	}
	cert, err := tls.LoadX509KeyPair(filepath.Join(dir, "localhost.crt"), filepath.Join(dir, "localhost.key"))
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := leaf.VerifyHostname("localhost"); err != nil {
		t.Fatal(err)
	}
	if err := leaf.VerifyHostname("stead.example"); err == nil {
		t.Fatal("development certificate escaped local identity")
	}
	info, _ := os.Stat(filepath.Join(dir, "localhost.key"))
	if info.Mode().Perm() != 0600 {
		t.Fatal("private key permissions")
	}
}

func TestProxyBoundaryAndStaticRoutes(t *testing.T) {
	upstreamCalls := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls++
		if r.Host != "localhost:7443" || r.Header.Get("Forwarded") != "" || r.Header.Get("X-Forwarded-For") != "" {
			t.Error("untrusted forwarding survived")
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"ok":true}`)
	}))
	defer upstream.Close()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "index.html"), []byte("Stead browser"), 0600); err != nil {
		t.Fatal(err)
	}
	config := Config{Origin: "https://localhost:7443", Upstream: upstream.URL, Assets: dir}
	handler, err := Handler(config)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		target, host string
		status       int
		body         string
	}{
		{"/", "localhost:7443", 200, "Stead browser"},
		{"/projects", "localhost:7443", 200, "Stead browser"},
		{"/api/v1/session", "localhost:7443", 200, `{"ok":true}`},
		{"/health/ready", "localhost:7443", 200, `{"ok":true}`},
		{"/assets/missing.js", "localhost:7443", 404, ""},
		{"/api/v1/session", "rebind.invalid", 400, ""},
		{"/api/v1/../secrets", "localhost:7443", 400, ""},
		{"http://attacker.invalid/api/v1/session", "localhost:7443", 400, ""},
	} {
		r := httptest.NewRequest(http.MethodGet, tc.target, nil)
		r.Host = tc.host
		r.Header.Set("Forwarded", "host=attacker.invalid")
		r.Header.Set("X-Forwarded-For", "attacker.invalid")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if w.Code != tc.status || (tc.body != "" && !strings.Contains(w.Body.String(), tc.body)) {
			t.Errorf("%s => %d %s", tc.target, w.Code, w.Body.String())
		}
		if w.Header().Get("Cache-Control") != "no-store" {
			t.Error("missing no-store")
		}
	}
	if upstreamCalls != 2 {
		t.Fatalf("unexpected provider/proxy calls: %d", upstreamCalls)
	}
	for _, bad := range []string{"http://localhost:7443", "https://user@localhost:7443", "https://localhost:7443/", "https://localhost:7443?redirect=bad"} {
		config.Origin = bad
		if _, err := Handler(config); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
	config.Origin = "https://localhost:7443"
	config.Upstream = "http://external.invalid"
	if _, err := Handler(config); err == nil {
		t.Fatal("arbitrary upstream")
	}
}

func TestRunRejectsMissingBuild(t *testing.T) {
	if err := Run(context.Background(), Config{Origin: "https://localhost", Upstream: "http://localhost:9000", Assets: t.TempDir()}); err == nil {
		t.Fatal("missing browser build allowed")
	}
}
