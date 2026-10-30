package analytics

import (
	"errors"
	"testing"
	"time"
)

func TestNewClientRejectsTimeoutsOutsideDispatchBounds(t *testing.T) {
	base := Config{
		Endpoint:     "https://clickhouse.example.test",
		Database:     "analytics_test",
		QueryTimeout: time.Second,
		WriteTimeout: time.Second,
	}
	for _, test := range []struct {
		name   string
		mutate func(*Config)
	}{
		{name: "sub millisecond query", mutate: func(config *Config) { config.QueryTimeout = time.Millisecond - 1 }},
		{name: "sub millisecond write", mutate: func(config *Config) { config.WriteTimeout = time.Millisecond - 1 }},
		{name: "query above ceiling", mutate: func(config *Config) { config.QueryTimeout = 30*time.Second + time.Millisecond }},
		{name: "write above ceiling", mutate: func(config *Config) { config.WriteTimeout = 30*time.Second + time.Millisecond }},
	} {
		t.Run(test.name, func(t *testing.T) {
			config := base
			test.mutate(&config)
			if _, err := NewClient(config, nil); !errors.Is(err, ErrInvalidConfiguration) {
				t.Fatalf("NewClient() error = %v, want ErrInvalidConfiguration", err)
			}
		})
	}

	for _, timeout := range []time.Duration{time.Millisecond, 30 * time.Second} {
		config := base
		config.QueryTimeout = timeout
		config.WriteTimeout = timeout
		if _, err := NewClient(config, nil); err != nil {
			t.Fatalf("NewClient(timeout=%s) error = %v", timeout, err)
		}
	}
}
