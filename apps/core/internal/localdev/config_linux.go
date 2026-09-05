//go:build linux

// Package localdev owns explicitly non-distributed local process configuration.
// It is not a production deployment configuration or a source of authorization.
package localdev

import (
	"errors"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/ScottTpirate/stead/modules/identity"
)

var ErrConfiguration = errors.New("local development configuration rejected")

type Config struct {
	StateDirectory, PolicyDirectory, InstanceID, SecurityDomain string
	Origin, Listen, OpenFGAURL, OpenFGAToken, StoreID, ModelID  string
	DatabaseURL, DatabaseAdminURL, DatabasePassword             string
}

// PrivateDirectory refuses aliases, foreign owners and shared state. The
// launcher may create a new directory but startup never repairs permissions.
func PrivateDirectory(directory string) error {
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory {
		return ErrConfiguration
	}
	resolved, err := filepath.EvalSymlinks(directory)
	if err != nil || resolved != directory {
		return ErrConfiguration
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
		return ErrConfiguration
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Getuid()) {
		return ErrConfiguration
	}
	return nil
}

func ReadPrivate(path string, maximum int64) ([]byte, error) {
	if maximum < 1 || maximum > 64<<20 || PrivateDirectory(filepath.Dir(path)) != nil {
		return nil, ErrConfiguration
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, ErrConfiguration
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() > maximum {
		return nil, ErrConfiguration
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Getuid()) || stat.Nlink != 1 {
		return nil, ErrConfiguration
	}
	data, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(data)) > maximum {
		return nil, ErrConfiguration
	}
	return data, nil
}

// WriteExclusive preserves all existing files, including invalid partial state.
func WriteExclusive(path string, data []byte) error {
	if len(data) == 0 || len(data) > 64<<20 || PrivateDirectory(filepath.Dir(path)) != nil {
		return ErrConfiguration
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return ErrConfiguration
	}
	_, err = file.Write(data)
	if err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil || closeErr != nil {
		return ErrConfiguration
	}
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return ErrConfiguration
	}
	defer directory.Close()
	if directory.Sync() != nil {
		return ErrConfiguration
	}
	return nil
}

func loopback(host string) bool {
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func ValidateListen(address string) error {
	host, port, err := net.SplitHostPort(address)
	if err != nil || !loopback(host) {
		return ErrConfiguration
	}
	number, err := strconv.ParseUint(port, 10, 16)
	if err != nil || number == 0 {
		return ErrConfiguration
	}
	return nil
}

func validEndpoint(raw, scheme string) bool {
	u, err := url.Parse(raw)
	return err == nil && u.Scheme == scheme && loopback(u.Hostname()) && u.User == nil && u.Path == "" && u.RawQuery == "" && u.Fragment == "" && !u.ForceQuery && u.Port() != ""
}

func validDatabase(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "postgresql" || !loopback(u.Hostname()) || u.Port() == "" || u.User == nil || u.User.Username() == "" || u.Path != "/stead" || u.RawPath != "" || u.Fragment != "" {
		return false
	}
	password, present := u.User.Password()
	query, err := url.ParseQuery(u.RawQuery)
	return present && len(password) >= 24 && err == nil && len(query) >= 1 && len(query) <= 2 && len(query["sslmode"]) == 1 && query.Get("sslmode") == "disable" &&
		(len(query) == 1 || (len(query["connect_timeout"]) == 1 && query.Get("connect_timeout") == "5"))
}

func Load(getenv func(string) string, bootstrap bool) (Config, error) {
	config := Config{StateDirectory: getenv("STEAD_BOOTSTRAP_STATE_DIR"), PolicyDirectory: getenv("STEAD_POLICY_DIR"), InstanceID: getenv("STEAD_INSTANCE_ID"), SecurityDomain: getenv("STEAD_SECURITY_DOMAIN"), Origin: getenv("STEAD_PUBLIC_ORIGIN"), Listen: getenv("STEAD_LISTEN"), OpenFGAURL: getenv("STEAD_OPENFGA_URL"), StoreID: getenv("STEAD_OPENFGA_STORE_ID"), ModelID: getenv("STEAD_OPENFGA_MODEL_ID")}
	if PrivateDirectory(config.StateDirectory) != nil || config.PolicyDirectory != filepath.Join(config.StateDirectory, "policy") || !identity.ValidID(config.InstanceID) || config.SecurityDomain != "stead-local-development" || config.Origin != "https://localhost:18443" || !validEndpoint(config.OpenFGAURL, "http") {
		return Config{}, ErrConfiguration
	}
	secret := func(variable, expected string, maximum int64) (string, error) {
		path := getenv(variable)
		if path != filepath.Join(config.StateDirectory, expected) {
			return "", ErrConfiguration
		}
		data, err := ReadPrivate(path, maximum)
		if err != nil || len(data) == 0 || strings.ContainsAny(string(data), "\x00\r\n") {
			return "", ErrConfiguration
		}
		return string(data), nil
	}
	var err error
	config.OpenFGAToken, err = secret("STEAD_OPENFGA_TOKEN_FILE", "openfga-key", 1024)
	if err != nil || len(config.OpenFGAToken) < 24 {
		return Config{}, ErrConfiguration
	}
	if bootstrap {
		config.DatabaseAdminURL, err = secret("STEAD_DATABASE_ADMIN_URL_FILE", "database-admin-url", 8192)
		if err != nil || !validDatabase(config.DatabaseAdminURL) {
			return Config{}, ErrConfiguration
		}
		config.DatabasePassword, err = secret("STEAD_DATABASE_PASSWORD_FILE", "database-password", 1024)
		if err != nil || len(config.DatabasePassword) < 24 {
			return Config{}, ErrConfiguration
		}
	} else {
		if getenv("STEAD_DATABASE_ADMIN_URL_FILE") != "" || getenv("STEAD_DATABASE_PASSWORD_FILE") != "" || ValidateListen(config.Listen) != nil || config.StoreID == "" || config.ModelID == "" {
			return Config{}, ErrConfiguration
		}
		config.DatabaseURL, err = secret("STEAD_DATABASE_URL_FILE", "database-url", 8192)
		if err != nil || !validDatabase(config.DatabaseURL) {
			return Config{}, ErrConfiguration
		}
	}
	return config, nil
}

func RuntimeDatabaseURL(admin, username, password string) (string, error) {
	if !validDatabase(admin) || username == "" || len(password) < 24 {
		return "", ErrConfiguration
	}
	u, _ := url.Parse(admin)
	u.User = url.UserPassword(username, password)
	return u.String(), nil
}
