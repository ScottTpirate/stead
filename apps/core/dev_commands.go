package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ScottTpirate/stead/apps/core/internal/devweb"
)

func runDevWeb(args []string, stderr io.Writer) int {
	flags := flag.NewFlagSet("stead-api dev-web", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var config devweb.Config
	flags.StringVar(&config.Listen, "listen", "127.0.0.1:7443", "local HTTPS listen address")
	flags.StringVar(&config.Origin, "origin", "https://localhost:7443", "exact public HTTPS origin")
	flags.StringVar(&config.Upstream, "upstream", "http://127.0.0.1:7080", "fixed private Stead API origin")
	flags.StringVar(&config.Assets, "assets", "apps/web/dist", "built browser assets directory")
	flags.StringVar(&config.Certificate, "tls-cert", "", "local TLS certificate")
	flags.StringVar(&config.Key, "tls-key", "", "private local TLS key")
	if flags.Parse(args) != nil || flags.NArg() != 0 {
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := devweb.Run(ctx, config); err != nil {
		fmt.Fprintln(stderr, "stead-api: local HTTPS web startup failed")
		return 1
	}
	return 0
}

func runDevCertificate(args []string, stderr io.Writer) int {
	flags := flag.NewFlagSet("stead-api dev-certificate", flag.ContinueOnError)
	flags.SetOutput(stderr)
	directory := flags.String("directory", "", "existing private TLS directory")
	if flags.Parse(args) != nil || flags.NArg() != 0 || *directory == "" {
		return 2
	}
	if err := devweb.GenerateCertificate(*directory, time.Now().UTC()); err != nil {
		fmt.Fprintln(stderr, "stead-api: local certificate creation failed; existing material was not overwritten")
		return 1
	}
	return 0
}

// The scratch service images reuse this original, bounded local readiness
// probe; it never follows redirects or prints response bodies/credentials.
func runDevProbe(args []string, stderr io.Writer) int {
	flags := flag.NewFlagSet("stead-api dev-probe", flag.ContinueOnError)
	flags.SetOutput(stderr)
	address := flags.String("url", "", "loopback health URL")
	ca := flags.String("ca", "", "exact local HTTPS certificate")
	if flags.Parse(args) != nil || flags.NArg() != 0 {
		return 2
	}
	u, err := url.Parse(*address)
	if err != nil || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Scheme != "http" && u.Scheme != "https") {
		return 2
	}
	ip := net.ParseIP(u.Hostname())
	if u.Hostname() != "localhost" && (ip == nil || !ip.IsLoopback()) {
		return 2
	}
	allowed := map[string]bool{"/health/live": true, "/health/ready": true, "/healthz": true, "/health": true, "/api/healthz": true}
	if !allowed[u.Path] {
		return 2
	}
	transport := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13}}
	if *ca != "" {
		data, err := os.ReadFile(*ca)
		if err != nil {
			return 1
		}
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(data) {
			return 1
		}
		transport.TLSClientConfig.RootCAs = roots
	}
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Get(*address)
	if err != nil {
		return 1
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return 1
	}
	return 0
}
