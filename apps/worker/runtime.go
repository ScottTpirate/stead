// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

const natsProbeTimeout = 3 * time.Second

type natsCredential struct {
	URL      string `json:"url"`
	Username string `json:"username"`
	Password string `json:"password"`
}

func (credential natsCredential) address() (string, error) {
	u, err := url.Parse(credential.URL)
	if err != nil || u.Scheme != "nats" || u.Hostname() != "127.0.0.1" || u.Port() == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || credential.Username != "publisher" || len(credential.Password) != 64 {
		return "", errors.New("invalid local NATS configuration")
	}
	for _, character := range credential.Password {
		if !strings.ContainsRune("0123456789abcdef", character) {
			return "", errors.New("invalid generated local credential")
		}
	}
	address, err := net.ResolveTCPAddr("tcp4", u.Host)
	if err != nil || address.Port < 1024 || address.Port > 65535 {
		return "", errors.New("invalid local NATS address")
	}
	return address.String(), nil
}

func readNATSCredential(filename string) (natsCredential, error) {
	var credential natsCredential
	file, err := os.OpenFile(filename, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return credential, errors.New("private NATS configuration unavailable")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || info.Size() > 2048 {
		return credential, errors.New("NATS configuration must be a private regular file")
	}
	identity, ok := info.Sys().(*syscall.Stat_t)
	if !ok || identity.Uid != uint32(os.Getuid()) {
		return credential, errors.New("NATS configuration must belong to this user")
	}
	data, err := io.ReadAll(io.LimitReader(file, 2049))
	if err != nil || len(data) > 2048 {
		return credential, errors.New("invalid NATS configuration size")
	}
	// Reject duplicate keys as well as unknown fields: credential selection must
	// not depend on JSON parser overwrite behavior.
	decoder := json.NewDecoder(bytes.NewReader(data))
	if token, err := decoder.Token(); err != nil || token != json.Delim('{') {
		return credential, errors.New("invalid NATS configuration object")
	}
	seen := map[string]bool{}
	values := map[string]string{}
	for decoder.More() {
		token, err := decoder.Token()
		key, ok := token.(string)
		if err != nil || !ok || seen[key] || (key != "url" && key != "username" && key != "password") {
			return credential, errors.New("invalid NATS configuration fields")
		}
		seen[key] = true
		var value string
		if err := decoder.Decode(&value); err != nil {
			return credential, errors.New("invalid NATS configuration value")
		}
		values[key] = value
	}
	if token, err := decoder.Token(); err != nil || token != json.Delim('}') {
		return credential, errors.New("invalid NATS configuration ending")
	}
	if _, err := decoder.Token(); err != io.EOF {
		return credential, errors.New("extra NATS configuration content")
	}
	credential = natsCredential{values["url"], values["username"], values["password"]}
	_, err = credential.address()
	return credential, err
}

// probeNATS performs only authenticated transport readiness. It creates no
// stream, consumer or event, and is not an outbox publication implementation.
func probeNATS(ctx context.Context, credential natsCredential) error {
	address, err := credential.address()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, natsProbeTimeout)
	defer cancel()
	connection, err := (&net.Dialer{}).DialContext(ctx, "tcp4", address)
	if err != nil {
		return errors.New("NATS unavailable")
	}
	defer connection.Close()
	stop := context.AfterFunc(ctx, func() { _ = connection.Close() })
	defer stop()
	deadline, _ := ctx.Deadline()
	if err := connection.SetDeadline(deadline); err != nil {
		return errors.New("NATS deadline unavailable")
	}
	reader := bufio.NewScanner(connection)
	reader.Buffer(make([]byte, 1024), 8192)
	if !reader.Scan() || !strings.HasPrefix(reader.Text(), "INFO ") {
		return errors.New("NATS greeting rejected")
	}
	var info struct {
		Authentication bool   `json:"auth_required"`
		TLSRequired    bool   `json:"tls_required"`
		JetStream      bool   `json:"jetstream"`
		Version        string `json:"version"`
	}
	if json.Unmarshal([]byte(strings.TrimPrefix(reader.Text(), "INFO ")), &info) != nil || !info.Authentication || !info.JetStream || info.TLSRequired || info.Version != "2.14.6" {
		return errors.New("NATS server does not match the local transport contract")
	}
	connect, err := json.Marshal(map[string]any{"user": credential.Username, "pass": credential.Password, "name": "stead-worker-health", "lang": "go", "version": "0.1.0", "protocol": 1, "verbose": false, "pedantic": true})
	if err != nil {
		return errors.New("NATS connection encoding failed")
	}
	if _, err := connection.Write(append(append([]byte("CONNECT "), connect...), []byte("\r\nPING\r\n")...)); err != nil {
		return errors.New("NATS authentication unavailable")
	}
	for lines := 0; lines < 8 && reader.Scan(); lines++ {
		switch reader.Text() {
		case "PONG":
			return nil
		case "+OK":
			continue
		case "PING":
			if _, err := io.WriteString(connection, "PONG\r\n"); err != nil {
				return errors.New("NATS connection failed")
			}
		default:
			return errors.New("NATS authentication or protocol rejected")
		}
	}
	return errors.New("NATS readiness deadline or frame limit exceeded")
}

func workerHandler(ctx context.Context, credential natsCredential) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health/live", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, "{\"healthy\":true}\n")
	})
	mux.HandleFunc("GET /health/ready", func(w http.ResponseWriter, request *http.Request) {
		requestContext, cancel := context.WithCancel(request.Context())
		defer cancel()
		stop := context.AfterFunc(ctx, cancel)
		defer stop()
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		if err := probeNATS(requestContext, credential); err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = io.WriteString(w, "{\"healthy\":false,\"nats\":\"unavailable\",\"scope\":\"transport_health_only\"}\n")
			return
		}
		_, _ = io.WriteString(w, "{\"healthy\":true,\"nats\":\"ready\",\"scope\":\"transport_health_only\"}\n")
	})
	return mux
}

func runWorker(stderr io.Writer) int {
	listen := os.Getenv("STEAD_WORKER_LISTEN")
	if listen != "127.0.0.1:18001" {
		fmt.Fprintln(stderr, "stead-worker: explicit local listen address required")
		return 1
	}
	credential, err := readNATSCredential(os.Getenv("STEAD_NATS_PUBLISHER_FILE"))
	if err != nil {
		fmt.Fprintln(stderr, "stead-worker: private local transport configuration rejected")
		return 1
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	server := &http.Server{Addr: listen, Handler: workerHandler(ctx, credential), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 8192}
	go func() {
		<-ctx.Done()
		shutdown, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		_ = server.Shutdown(shutdown)
	}()
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		fmt.Fprintln(stderr, "stead-worker: local transport health server failed")
		return 1
	}
	return 0
}
