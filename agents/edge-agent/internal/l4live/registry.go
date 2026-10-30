package l4live

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

// ControlRegistry talks to the L4 OpenResty control socket
// (l4runtime.L4ControlSocketPath, engine.lua control()).
type ControlRegistry struct {
	Path string
}

var errControl = errors.New("L4 control socket reply is invalid")

func (registry ControlRegistry) exchange(ctx context.Context, command string, keys []string) (map[string]string, error) {
	dialer := net.Dialer{Timeout: time.Second}
	connection, err := dialer.DialContext(ctx, "unix", registry.Path)
	if err != nil {
		return nil, err
	}
	defer connection.Close()
	deadline := time.Now().Add(5 * time.Second)
	if value, ok := ctx.Deadline(); ok && value.Before(deadline) {
		deadline = value
	}
	_ = connection.SetDeadline(deadline)
	// Write and read at once: the server answers while it reads.
	written := make(chan error, 1)
	go func() {
		writer := bufio.NewWriter(connection)
		_, err := writer.WriteString(command + "\n" + strings.Join(keys, "\n") + "\nend\n")
		if err == nil {
			err = writer.Flush()
		}
		written <- err
	}()
	result := make(map[string]string, len(keys))
	scanner := bufio.NewScanner(connection)
	scanner.Buffer(make([]byte, 4096), 4096)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "end" {
			if err := <-written; err != nil {
				return nil, err
			}
			return result, nil
		}
		key, value, ok := strings.Cut(line, "\t")
		if !ok {
			return nil, errControl
		}
		if value != "-" {
			result[key] = value
		}
	}
	return nil, fmt.Errorf("%w: %v", errControl, scanner.Err())
}

func (registry ControlRegistry) Get(ctx context.Context, keys []string) (map[string]string, error) {
	return registry.exchange(ctx, "get", keys)
}

func (registry ControlRegistry) Kill(ctx context.Context, keys []string) error {
	_, err := registry.exchange(ctx, "kill", keys)
	return err
}
