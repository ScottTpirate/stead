// Package devweb serves the original Stead browser build over local HTTPS. It is
// a development-only BFF transport, not an infrastructure browser proxy.
package devweb

import (
	"context"
	"crypto/tls"
	"errors"
	"io/fs"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path"
	"strings"
	"time"
)

type Config struct {
	Listen, Origin, Upstream, Assets, Certificate, Key string
}

func origin(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" || u.RawPath != "" {
		return nil, errors.New("an exact HTTPS public origin is required")
	}
	return u, nil
}

// Handler routes only /api/v1 and health to a fixed trusted upstream. Request
// Host, forwarding headers, URLs, and paths cannot select another destination.
func Handler(config Config) (http.Handler, error) {
	public, err := origin(config.Origin)
	if err != nil {
		return nil, err
	}
	upstream, err := url.Parse(config.Upstream)
	if err != nil || upstream.Scheme != "http" || upstream.Host == "" || upstream.User != nil || upstream.Path != "" || upstream.RawQuery != "" || upstream.Fragment != "" {
		return nil, errors.New("a fixed private development API upstream is required")
	}
	// Compose uses the fixed service name api. No arbitrary remote HTTP origin.
	if host := upstream.Hostname(); host != "api" && host != "localhost" && (net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback()) {
		return nil, errors.New("development API upstream must be loopback or the fixed api service")
	}
	assets, err := os.OpenRoot(config.Assets)
	if err != nil {
		return nil, errors.New("browser assets unavailable")
	}
	assetFS := assets.FS()
	if _, err := fs.Stat(assetFS, "index.html"); err != nil {
		assets.Close()
		return nil, errors.New("browser build missing")
	}
	proxy := &httputil.ReverseProxy{
		Rewrite: func(request *httputil.ProxyRequest) {
			request.SetURL(upstream)
			request.Out.Host = public.Host
			request.Out.Header.Del("Forwarded")
			request.Out.Header.Del("X-Forwarded-For")
			request.Out.Header.Del("X-Forwarded-Host")
			request.Out.Header.Del("X-Forwarded-Proto")
		},
		Transport: &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: 3 * time.Second}).DialContext, ResponseHeaderTimeout: 20 * time.Second, MaxIdleConns: 16, MaxConnsPerHost: 32},
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, _ error) {
			http.Error(w, "Stead API unavailable", http.StatusBadGateway)
		},
	}
	files := http.FileServerFS(assetFS)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		w.Header().Set("Cache-Control", "no-store")
		if r.Host != public.Host || r.URL.IsAbs() || r.URL.RawPath != "" || strings.ContainsAny(r.URL.Path, "\\\x00") || path.Clean(r.URL.Path) != r.URL.Path {
			http.Error(w, "Request unavailable", http.StatusBadRequest)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/api/v1/") || r.URL.Path == "/health/live" || r.URL.Path == "/health/ready" {
			proxy.ServeHTTP(w, r)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		name := strings.TrimPrefix(r.URL.Path, "/")
		if name == "" {
			name = "index.html"
		}
		if strings.HasPrefix(name, "assets/") {
			if info, err := fs.Stat(assetFS, name); err != nil || info.IsDir() {
				http.NotFound(w, r)
				return
			}
		} else {
			// The SPA recognizes canonical routes; never expose arbitrary build files.
			name = "index.html"
		}
		copy := r.Clone(r.Context())
		copy.URL.Path = "/" + name
		if name == "index.html" {
			copy.URL.Path = "/"
		}
		files.ServeHTTP(w, copy)
	}), nil
}

func Run(ctx context.Context, config Config) error {
	handler, err := Handler(config)
	if err != nil {
		return err
	}
	server := &http.Server{Addr: config.Listen, Handler: handler, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13}, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 * 1024}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdown)
	}()
	err = server.ListenAndServeTLS(config.Certificate, config.Key)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
