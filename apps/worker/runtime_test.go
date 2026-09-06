// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func protocolFixture(t *testing.T, reply string) natsCredential {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	credential := natsCredential{"nats://" + listener.Addr().String(), "publisher", strings.Repeat("a", 64)}
	go func() {
		connection, err := listener.Accept()
		if err != nil {
			return
		}
		defer connection.Close()
		_ = connection.SetDeadline(time.Now().Add(time.Second))
		_, _ = io.WriteString(connection, "INFO {\"auth_required\":true,\"jetstream\":true,\"version\":\"2.14.6\"}\r\n")
		reader := bufio.NewScanner(connection)
		if !reader.Scan() || !strings.HasPrefix(reader.Text(), "CONNECT ") {
			t.Error("missing CONNECT frame")
			return
		}
		var connect map[string]any
		if json.Unmarshal([]byte(strings.TrimPrefix(reader.Text(), "CONNECT ")), &connect) != nil || connect["user"] != credential.Username || connect["pass"] != credential.Password {
			t.Error("missing service authentication")
			return
		}
		if !reader.Scan() || reader.Text() != "PING" {
			t.Error("probe performed a non-health operation")
			return
		}
		_, _ = io.WriteString(connection, reply)
	}()
	return credential
}

func TestNATSAuthenticatedTransportProbe(t *testing.T) {
	if err := probeNATS(context.Background(), protocolFixture(t, "+OK\r\nPONG\r\n")); err != nil {
		t.Fatal(err)
	}
}

func TestWorkerReadinessRejectsAuthenticationAndDoesNotLeakDetails(t *testing.T) {
	credential := protocolFixture(t, "-ERR 'Authorization violation with secret details'\r\n")
	response := httptest.NewRecorder()
	workerHandler(context.Background(), credential).ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/health/ready", nil))
	if response.Code != 503 || strings.Contains(response.Body.String(), "secret") || strings.Contains(response.Body.String(), credential.Password) || !strings.Contains(response.Body.String(), "transport_health_only") {
		t.Fatal("readiness failed to return a minimized denial")
	}
}

func TestWorkerLiveDoesNotClaimTransportReadiness(t *testing.T) {
	response := httptest.NewRecorder()
	workerHandler(context.Background(), natsCredential{}).ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/health/live", nil))
	if response.Code != 200 || response.Body.String() != "{\"healthy\":true}\n" {
		t.Fatal("unexpected liveness result")
	}
}

func TestNATSProbeRefusesUnboundedOrIncompatibleGreetings(t *testing.T) {
	for _, greeting := range []string{
		"INFO {\"auth_required\":false,\"jetstream\":true,\"version\":\"2.14.6\"}\r\n",
		"INFO {\"auth_required\":true,\"jetstream\":false,\"version\":\"2.14.6\"}\r\n",
		"INFO {\"auth_required\":true,\"jetstream\":true,\"version\":\"0.0.0\"}\r\n",
		"INFO " + strings.Repeat("x", 9000) + "\r\n",
	} {
		listener, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		go func() {
			connection, err := listener.Accept()
			if err == nil {
				defer connection.Close()
				_, _ = io.WriteString(connection, greeting)
			}
		}()
		credential := natsCredential{"nats://" + listener.Addr().String(), "publisher", strings.Repeat("b", 64)}
		if err := probeNATS(context.Background(), credential); err == nil {
			t.Error("incompatible greeting accepted")
		}
		_ = listener.Close()
	}
}

func TestNATSProbeCancelsStalledConnection(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		connection, err := listener.Accept()
		if err == nil {
			defer connection.Close()
			_, _ = io.Copy(io.Discard, connection)
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	started := time.Now()
	err = probeNATS(ctx, natsCredential{"nats://" + listener.Addr().String(), "publisher", strings.Repeat("c", 64)})
	if err == nil || time.Since(started) > time.Second {
		t.Fatal("stalled connection was not canceled")
	}
}

func TestWorkerCredentialFileIsPrivateClosedAndLocal(t *testing.T) {
	directory := t.TempDir()
	filename := filepath.Join(directory, "credential.json")
	valid := fmt.Sprintf(`{"url":"nats://127.0.0.1:14222","username":"publisher","password":"%s"}`, strings.Repeat("d", 64))
	if err := os.WriteFile(filename, []byte(valid), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readNATSCredential(filename); err != nil {
		t.Fatal(err)
	}
	for _, invalid := range []string{
		strings.Replace(valid, "127.0.0.1", "example.com", 1),
		strings.Replace(valid, "nats://", "nats://user:password@", 1),
		strings.Replace(valid, "14222", "14222?credential=unsafe", 1),
		strings.Replace(valid, `"username":"publisher"`, `"username":"publisher","username":"maintenance"`, 1),
		strings.Replace(valid, `"url":`, `"unknown":true,"url":`, 1),
		valid + `{}`,
	} {
		if err := os.WriteFile(filename, []byte(invalid), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := readNATSCredential(filename); err == nil {
			t.Error("unsafe credential accepted")
		}
	}
	_ = os.WriteFile(filename, []byte(valid), 0o600)
	_ = os.Chmod(filename, 0o644)
	if _, err := readNATSCredential(filename); err == nil {
		t.Error("public credential file accepted")
	}
	_ = os.Chmod(filename, 0o600)
	link := filepath.Join(directory, "link")
	if err := os.Symlink(filename, link); err != nil {
		t.Fatal(err)
	}
	if _, err := readNATSCredential(link); err == nil {
		t.Error("symlink credential accepted")
	}
}

func TestWorkerStartupRefusesNonlocalListener(t *testing.T) {
	t.Setenv("STEAD_WORKER_LISTEN", "0.0.0.0:18001")
	var output bytes.Buffer
	if runWorker(&output) != 1 || strings.Contains(output.String(), "password") {
		t.Fatal("nonlocal startup accepted or error leaked credentials")
	}
}
