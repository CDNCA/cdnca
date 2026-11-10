package packagingtoolset

import (
	"syscall"
	"unsafe"
)

// watch is an inotify instance on the record, scripts and helper directories
// : a report stats the files only after an event, an overflow or a
// read error; with none, the files are as last reported. A directory that
// cannot be watched (missing, or root-only), or a watched directory deleted,
// moved or replaced, makes every report stat, as without the watch.
type watch struct{ fd int }

const watchEvents = syscall.IN_CREATE | syscall.IN_DELETE | syscall.IN_MOVED_FROM | syscall.IN_MOVED_TO |
	syscall.IN_MODIFY | syscall.IN_ATTRIB | syscall.IN_CLOSE_WRITE | syscall.IN_DELETE_SELF | syscall.IN_MOVE_SELF

func newWatch(directories ...string) *watch {
	fd, err := syscall.InotifyInit1(syscall.IN_NONBLOCK | syscall.IN_CLOEXEC)
	if err != nil {
		return &watch{fd: -1}
	}
	for _, directory := range directories {
		if _, err := syscall.InotifyAddWatch(fd, directory, watchEvents); err != nil {
			_ = syscall.Close(fd)
			return &watch{fd: -1}
		}
	}
	return &watch{fd: fd}
}

// changed drains the events and reports whether a file may have changed
// since the last call (always true once the watch is gone).
func (w *watch) changed() bool {
	if w.fd < 0 {
		return true
	}
	var buffer [4096]byte
	changed := false
	for {
		n, err := syscall.Read(w.fd, buffer[:])
		if err == syscall.EAGAIN {
			return changed
		}
		if err == syscall.EINTR {
			continue
		}
		if err != nil || n <= 0 {
			w.close()
			return true
		}
		changed = true
		for offset := 0; offset+syscall.SizeofInotifyEvent <= n; {
			event := (*syscall.InotifyEvent)(unsafe.Pointer(&buffer[offset]))
			if event.Mask&(syscall.IN_IGNORED|syscall.IN_DELETE_SELF|syscall.IN_MOVE_SELF|syscall.IN_Q_OVERFLOW) != 0 {
				w.close()
				return true
			}
			offset += syscall.SizeofInotifyEvent + int(event.Len)
		}
	}
}

func (w *watch) close() {
	_ = syscall.Close(w.fd)
	w.fd = -1
}
