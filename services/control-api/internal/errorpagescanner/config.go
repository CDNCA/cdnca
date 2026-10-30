package errorpagescanner

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"time"
	"unicode/utf8"
)

const (
	minimumConnectTimeout = 100 * time.Millisecond
	maximumConnectTimeout = 30 * time.Second
	maximumScanTimeout    = 5 * time.Minute
	maximumSocketPathSize = 100
)

var ErrInvalidConfig = errors.New("invalid error page scanner configuration")

type Config struct {
	SocketPath     string        `json:"-"`
	ConnectTimeout time.Duration `json:"-"`
	ScanTimeout    time.Duration `json:"-"`
}

type safeConfig struct {
	Transport      string `json:"transport"`
	Configured     bool   `json:"configured"`
	ConnectTimeout string `json:"connect_timeout"`
	ScanTimeout    string `json:"scan_timeout"`
}

func (config Config) valid() bool {
	if len(config.SocketPath) < 2 || len(config.SocketPath) > maximumSocketPathSize ||
		!utf8.ValidString(config.SocketPath) || !filepath.IsAbs(config.SocketPath) ||
		filepath.Clean(config.SocketPath) != config.SocketPath {
		return false
	}
	for _, character := range config.SocketPath {
		if character < 0x20 || character == 0x7f {
			return false
		}
	}
	return config.ConnectTimeout >= minimumConnectTimeout && config.ConnectTimeout <= maximumConnectTimeout &&
		config.ScanTimeout >= minimumConnectTimeout && config.ScanTimeout <= maximumScanTimeout &&
		config.ConnectTimeout <= config.ScanTimeout
}

func (config Config) safe() safeConfig {
	return safeConfig{
		Transport: "unix", Configured: config.SocketPath != "",
		ConnectTimeout: config.ConnectTimeout.String(), ScanTimeout: config.ScanTimeout.String(),
	}
}

func (config Config) safeString() string {
	safe := config.safe()
	return fmt.Sprintf("errorpagescanner.Config{transport:%s configured:%t connect_timeout:%s scan_timeout:%s}",
		safe.Transport, safe.Configured, safe.ConnectTimeout, safe.ScanTimeout)
}

func (config Config) String() string   { return config.safeString() }
func (config Config) GoString() string { return config.safeString() }

func (config Config) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, config.safeString())
}

func (config Config) MarshalJSON() ([]byte, error) { return json.Marshal(config.safe()) }
