package dyntelemetry

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"os"
	"regexp"
	"syscall"
)

// The node runtime's OpenResty error log (<shared>/error.log). The skeleton
// listens with "quic reuseport" (docs/edge/node-skeleton.md §2): on every
// reload each worker logs, once per QUIC socket,
//
//	[emerg] <pid>#<tid>: close() socket 0.0.0.0:443 failed (9: Bad file descriptor)
//
// (ngx_event.c closing the reuseport clones of other workers). It is not a
// failure. ErrorLog reads the log incrementally and reports every
// alert/crit/emerg line except that one; nothing else is filtered.

// reuseportCloseNoise is the known reload noise: emerg level, a close() of a
// listening socket address (IPv4, bracketed IPv6, or the wildcard forms),
// errno 9 exactly.
var reuseportCloseNoise = regexp.MustCompile(`\[emerg\] [0-9]+#[0-9]+: close\(\) socket (?:[0-9.]+|\[[0-9a-fA-F:.]+\]):[0-9]{1,5} failed \(9: Bad file descriptor\)$`)

var severeLevel = regexp.MustCompile(`^[0-9]{4}/[0-9]{2}/[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2} \[(alert|crit|emerg)\] `)

// IsKnownNoise reports whether an error log line is the reuseport reload
// noise.
func IsKnownNoise(line string) bool { return reuseportCloseNoise.MatchString(line) }

// ErrorLogSummary is what one Read found.
type ErrorLogSummary struct {
	Severe []string // alert/crit/emerg lines other than the known noise (at most MaxSevereLines)
	Noise  int      // known noise lines skipped
	Lines  int      // complete lines read
}

// MaxSevereLines bounds the severe lines one Read returns (the count of the
// rest is in Dropped).
const MaxSevereLines = 64

// ErrorLog reads an OpenResty error log from where it stopped. A rotated or
// truncated file (other inode or smaller than the offset) is read from the
// start; a partial last line is read next time.
type ErrorLog struct {
	Path    string
	offset  int64
	inode   uint64
	Dropped int
}

func (log *ErrorLog) Read() (ErrorLogSummary, error) {
	var summary ErrorLogSummary
	file, err := os.Open(log.Path)
	if errors.Is(err, os.ErrNotExist) {
		return summary, nil
	}
	if err != nil {
		return summary, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return summary, err
	}
	inode := uint64(0)
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		inode = uint64(stat.Ino)
	}
	if inode != log.inode || info.Size() < log.offset {
		log.offset, log.inode = 0, inode
	}
	if _, err := file.Seek(log.offset, io.SeekStart); err != nil {
		return summary, err
	}
	reader := bufio.NewReaderSize(file, 64<<10)
	for {
		line, err := reader.ReadBytes('\n')
		if err != nil {
			break // partial or none: next time
		}
		log.offset += int64(len(line))
		summary.Lines++
		text := string(bytes.TrimRight(line, "\r\n"))
		if !severeLevel.MatchString(text) {
			continue
		}
		if IsKnownNoise(text) {
			summary.Noise++
			continue
		}
		if len(summary.Severe) < MaxSevereLines {
			summary.Severe = append(summary.Severe, text)
		} else {
			log.Dropped++
		}
	}
	return summary, nil
}
