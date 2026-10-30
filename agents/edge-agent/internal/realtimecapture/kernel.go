package realtimecapture

import (
	"bufio"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

var ErrUnavailable = errors.New("realtime source unavailable")

type Listener struct {
	Connections uint64
	Listening   bool
	Evidence    [32]byte
}

// ReadListeners measures kernel TCP sockets, not completed HTTP requests.
// Callers may attribute a port only when its activated site is unambiguous.
func ReadListeners(ports []uint16) (map[uint16]Listener, error) {
	tcp, err := os.Open("/proc/net/tcp")
	if err != nil {
		return nil, ErrUnavailable
	}
	defer tcp.Close()
	tcp6, err := os.Open("/proc/net/tcp6")
	if err != nil {
		return nil, ErrUnavailable
	}
	defer tcp6.Close()
	return readListeners(ports, tcp, tcp6)
}

func readListeners(ports []uint16, sources ...io.Reader) (map[uint16]Listener, error) {
	if len(ports) == 0 || len(ports) > 10000 || len(sources) != 2 {
		return nil, ErrUnavailable
	}
	result := make(map[uint16]Listener, len(ports))
	for _, port := range ports {
		if port == 0 {
			return nil, ErrUnavailable
		}
		result[port] = Listener{}
	}
	for _, source := range sources {
		limited := &io.LimitedReader{R: source, N: 16<<20 + 1}
		scan := bufio.NewScanner(limited)
		scan.Buffer(make([]byte, 4096), 64<<10)
		if !scan.Scan() || !strings.Contains(scan.Text(), "local_address") || !strings.Contains(scan.Text(), "st") {
			return nil, ErrUnavailable
		}
		for scan.Scan() {
			fields := strings.Fields(scan.Text())
			if len(fields) < 10 {
				return nil, ErrUnavailable
			}
			local := strings.Split(fields[1], ":")
			if len(local) != 2 || len(local[0]) != 8 && len(local[0]) != 32 || len(local[1]) != 4 {
				return nil, ErrUnavailable
			}
			port, err := strconv.ParseUint(local[1], 16, 16)
			if err != nil {
				return nil, ErrUnavailable
			}
			state, err := strconv.ParseUint(fields[3], 16, 8)
			if err != nil {
				return nil, ErrUnavailable
			}
			value, wanted := result[uint16(port)]
			if !wanted {
				continue
			}
			if state == 0x0a {
				value.Listening = true
			}
			if state == 0x01 {
				value.Connections++
			}
			result[uint16(port)] = value
		}
		if scan.Err() != nil || limited.N <= 0 {
			return nil, ErrUnavailable
		}
	}
	for port, value := range result {
		if !value.Listening {
			return nil, ErrUnavailable
		}
		value.Evidence = sha256.Sum256([]byte(fmt.Sprintf("linux-tcp-listener/v1\x00%d\x00%d\x00listening", port, value.Connections)))
		result[port] = value
	}
	return result, nil
}
