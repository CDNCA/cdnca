package dynroute

import (
	"errors"
	"log"
	"net"
	"os"
	"strings"
	"syscall"
	"time"
)

// staleDialTimeout bounds the probe of one unix listener path.
const staleDialTimeout = 500 * time.Millisecond

// removeStaleUnixListeners removes the unix socket files the configuration at
// path listens on (the control socket, the security flush socket, the port
// dispatch sockets) that no process accepts on any more. nginx unlinks them
// on a clean exit but not when its master is killed or crashes, and refuses
// to bind over them on its next start ("bind() ... failed (98: Address in
// use)"), which kept a node's OpenResty from starting until they were
// removed by hand. A path is removed only when it is a socket and a connect
// is refused (no listener); a socket that accepts belongs to a live process
// and is left, as is anything that is not a socket or cannot be checked.
func removeStaleUnixListeners(path string) {
	for _, socket := range unixListenPaths(path) {
		info, err := os.Lstat(socket)
		if err != nil || info.Mode()&os.ModeSocket == 0 {
			continue
		}
		connection, err := net.DialTimeout("unix", socket, staleDialTimeout)
		if err == nil {
			_ = connection.Close()
			continue
		}
		if !errors.Is(err, syscall.ECONNREFUSED) {
			continue
		}
		if err := os.Remove(socket); err != nil && !errors.Is(err, os.ErrNotExist) {
			log.Printf("dynamic routing: stale unix socket %s: remove: %v", socket, err)
			continue
		}
		log.Printf("dynamic routing: removed stale unix socket %s (no listener; left by an OpenResty that did not exit cleanly)", socket)
	}
}

// unixListenPaths returns the unix socket paths of the listen directives in
// the configuration at path (listen unix:/p; or listen "unix:/p" ...;).
func unixListenPaths(path string) []string {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var paths []string
	seen := map[string]bool{}
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) < 2 || fields[0] != "listen" {
			continue
		}
		value := strings.Trim(strings.TrimSuffix(fields[1], ";"), `'"`)
		socket, ok := strings.CutPrefix(value, "unix:")
		if !ok || !strings.HasPrefix(socket, "/") || seen[socket] {
			continue
		}
		seen[socket] = true
		paths = append(paths, socket)
	}
	return paths
}
