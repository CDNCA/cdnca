//go:build linux

package l4live

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"syscall"

	"golang.org/x/sys/unix"
)

// LinuxKernel lists sockets with NETLINK_SOCK_DIAG and closes them by
// duplicating the worker's descriptor (pidfd_getfd, Linux 5.6+) and shutting
// it down: OpenResty then sees the end of the connection and finishes the
// session, logging it.
type LinuxKernel struct{}

func (LinuxKernel) Established(ctx context.Context, ports []uint16) ([]Socket, error) {
	var result []Socket
	for _, family := range []uint8{unix.AF_INET, unix.AF_INET6} {
		sockets, err := dumpFamily(ctx, family, ports)
		if err != nil {
			return nil, err
		}
		result = append(result, sockets...)
	}
	return result, nil
}

func dumpFamily(ctx context.Context, family uint8, ports []uint16) ([]Socket, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, unix.NETLINK_SOCK_DIAG)
	if err != nil {
		return nil, fmt.Errorf("open sock_diag: %w", err)
	}
	defer unix.Close(fd)
	_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 3})
	payload := diagRequest(family, ports)
	header := make([]byte, unix.NLMSG_HDRLEN)
	binary.NativeEndian.PutUint32(header[0:], uint32(unix.NLMSG_HDRLEN+len(payload)))
	binary.NativeEndian.PutUint16(header[4:], sockDiagByFamily)
	binary.NativeEndian.PutUint16(header[6:], unix.NLM_F_REQUEST|unix.NLM_F_DUMP)
	binary.NativeEndian.PutUint32(header[8:], 1)
	if err := unix.Sendto(fd, append(header, payload...), 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return nil, fmt.Errorf("send sock_diag: %w", err)
	}
	var result []Socket
	buffer := make([]byte, 1<<16)
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		n, _, err := unix.Recvfrom(fd, buffer, 0)
		if err != nil {
			return nil, fmt.Errorf("read sock_diag: %w", err)
		}
		messages, err := syscall.ParseNetlinkMessage(buffer[:n])
		if err != nil {
			return nil, err
		}
		for _, message := range messages {
			switch message.Header.Type {
			case unix.NLMSG_DONE:
				return result, nil
			case unix.NLMSG_ERROR:
				code := int32(binary.NativeEndian.Uint32(message.Data))
				return nil, fmt.Errorf("sock_diag: %w", unix.Errno(-code))
			case sockDiagByFamily:
				socket, err := parseDiagMessage(message.Data)
				if err != nil {
					return nil, err
				}
				result = append(result, socket)
			}
		}
	}
}

func (LinuxKernel) Close(ctx context.Context, pids []int, inode uint64) error {
	target := "socket:[" + strconv.FormatUint(inode, 10) + "]"
	for _, pid := range pids {
		if err := ctx.Err(); err != nil {
			return err
		}
		directory := filepath.Join("/proc", strconv.Itoa(pid), "fd")
		entries, err := os.ReadDir(directory)
		if err != nil {
			continue // the worker exited
		}
		for _, entry := range entries {
			link, err := os.Readlink(filepath.Join(directory, entry.Name()))
			if err != nil || link != target {
				continue
			}
			number, err := strconv.Atoi(entry.Name())
			if err != nil {
				continue
			}
			return closeRemote(pid, number)
		}
	}
	return ErrSocketGone
}

func closeRemote(pid, number int) error {
	pidfd, err := unix.PidfdOpen(pid, 0)
	if err != nil {
		return fmt.Errorf("pidfd_open: %w", err)
	}
	defer unix.Close(pidfd)
	fd, err := unix.PidfdGetfd(pidfd, number, 0)
	if err != nil {
		return fmt.Errorf("pidfd_getfd: %w", err)
	}
	defer unix.Close(fd)
	if err := unix.Shutdown(fd, unix.SHUT_RDWR); err != nil && !errors.Is(err, unix.ENOTCONN) {
		return fmt.Errorf("shutdown: %w", err)
	}
	return nil
}

// CanClose reports whether this process may take other processes' sockets:
// it probes pidfd_getfd on itself and requires root (the L4 workers drop to
// an unprivileged user, so only root's CAP_SYS_PTRACE reaches them).
func CanClose() bool {
	if os.Geteuid() != 0 && os.Getenv("CDNCA_L4_LIVE_CLOSE_UNPRIVILEGED") != "1" {
		return false
	}
	pidfd, err := unix.PidfdOpen(os.Getpid(), 0)
	if err != nil {
		return false
	}
	defer unix.Close(pidfd)
	fd, err := unix.PidfdGetfd(pidfd, 0, 0)
	if err != nil {
		return false
	}
	unix.Close(fd)
	return true
}
