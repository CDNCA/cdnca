package main

import (
	"errors"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/cachetask"
)

// cacheTaskSettings tune the node's purge/prewarm runner (ge-cache): how long
// one prewarm request may take and how large an object and a whole task may
// be. Zero keeps the defaults (cachetask.DefaultConfig: 10 minutes, 4 GiB per
// object, 64 GiB per task).
type cacheTaskSettings struct {
	PrewarmRequestTimeout string `json:"prewarm_request_timeout,omitempty"`
	PrewarmMaxObjectBytes int64  `json:"prewarm_max_object_bytes,omitempty"`
	PrewarmMaxTaskBytes   int64  `json:"prewarm_max_task_bytes,omitempty"`
}

func (s cacheTaskSettings) config() (cachetask.Config, error) {
	config := cachetask.DefaultConfig()
	if s.PrewarmRequestTimeout != "" {
		timeout, err := time.ParseDuration(s.PrewarmRequestTimeout)
		if err != nil || timeout < time.Second || timeout > time.Hour {
			return cachetask.Config{}, errors.New("cache_task.prewarm_request_timeout must be 1s..1h")
		}
		config.RequestTimeout = timeout
	}
	if s.PrewarmMaxObjectBytes != 0 {
		if s.PrewarmMaxObjectBytes < 1<<20 || s.PrewarmMaxObjectBytes > cachetask.MaxPrewarmObjectBytes {
			return cachetask.Config{}, errors.New("cache_task.prewarm_max_object_bytes must be 1 MiB..1 TiB")
		}
		config.MaxResponseBytes = s.PrewarmMaxObjectBytes
	}
	if s.PrewarmMaxTaskBytes != 0 {
		config.MaxTaskBytes = s.PrewarmMaxTaskBytes
	}
	if config.MaxTaskBytes < config.MaxResponseBytes || config.MaxTaskBytes > 1<<44 {
		return cachetask.Config{}, errors.New("cache_task.prewarm_max_task_bytes must be at least the object limit and at most 16 TiB")
	}
	return config, nil
}
