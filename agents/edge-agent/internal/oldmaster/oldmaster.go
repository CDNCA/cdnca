// Package oldmaster ends the OpenResty master an nginx binary upgrade
// replaced (HTTP dynamic routing and L4 alike). CDN nodes hold no sessions
// worth keeping across an upgrade (BATCH 77b): the old master gets QUIT
// (graceful), TERM once QuitGrace passed, and KILL, with its workers, once
// TermGrace more passed. An old master left running would also block the next
// upgrade: nginx ignores USR2 in a master whose replaced parent still runs.
package oldmaster

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	// QuitGrace is how long the old master may finish its sessions after QUIT.
	QuitGrace = 10 * time.Second
	// TermGrace is how long it may take to exit after TERM before KILL.
	TermGrace = 5 * time.Second
)

// process is what /proc/<pid>/stat says about a pid.
type process struct {
	parent int
	start  uint64
	zombie bool
}

type system struct {
	stat     func(pid int) (process, error)
	children func(pid int) []int
	signal   func(pid int, signal syscall.Signal) error
	poll     time.Duration
}

var kernel = system{stat: procStat, children: procChildren, signal: syscall.Kill, poll: 20 * time.Millisecond}

// Retire ends master old, the parent of master fresh (nginx forks the new
// master from the one it replaces): QUIT, TERM after QuitGrace, KILL of old
// and its workers (its children other than fresh) after TermGrace. A
// cancelled ctx skips to KILL. old is identified by its start time, so a pid
// reused after it exited is never signalled. old is not fresh's parent (it
// already exited): nothing to do. The error says old survived KILL.
func Retire(ctx context.Context, old, fresh int) error {
	return kernel.retire(ctx, old, fresh, QuitGrace, TermGrace)
}

// RetirePrevious ends the master named by <pidFile>.oldbin when it still is
// the parent of master (an earlier upgrade's old master left running), the
// same way as Retire. Call it before USR2 to master.
func RetirePrevious(ctx context.Context, pidFile string, master int) error {
	previous, err := readPID(pidFile + ".oldbin")
	if err != nil || previous == master {
		return nil
	}
	return Retire(ctx, previous, master)
}

func (s system) retire(ctx context.Context, old, fresh int, quitGrace, termGrace time.Duration) error {
	if old == fresh || old < 2 {
		return nil
	}
	freshProcess, err := s.stat(fresh)
	if err != nil || freshProcess.parent != old {
		return nil
	}
	oldProcess, err := s.stat(old)
	if err != nil || oldProcess.zombie {
		return nil
	}
	alive := func() bool {
		current, err := s.stat(old)
		return err == nil && !current.zombie && current.start == oldProcess.start
	}
	for _, step := range []struct {
		signal syscall.Signal
		grace  time.Duration
	}{{syscall.SIGQUIT, quitGrace}, {syscall.SIGTERM, termGrace}} {
		if ctx.Err() != nil {
			break
		}
		if err := s.signal(old, step.signal); err != nil {
			if errors.Is(err, syscall.ESRCH) {
				return nil
			}
			break
		}
		if !s.wait(ctx, alive, step.grace) {
			return nil
		}
	}
	if !alive() {
		return nil
	}
	// Workers are listed while old still runs (so they are its children),
	// then old and they get KILL; a master being torn down respawns nothing.
	workers := s.children(old)
	_ = s.signal(old, syscall.SIGKILL)
	for _, worker := range workers {
		if worker != fresh {
			_ = s.signal(worker, syscall.SIGKILL)
		}
	}
	if s.wait(context.WithoutCancel(ctx), alive, termGrace) {
		return fmt.Errorf("old OpenResty master %d did not exit after KILL", old)
	}
	return nil
}

// wait polls until alive reports false (false returned) or grace passed or
// ctx is done (true: still alive).
func (s system) wait(ctx context.Context, alive func() bool, grace time.Duration) bool {
	timer := time.NewTimer(grace)
	defer timer.Stop()
	ticker := time.NewTicker(s.poll)
	defer ticker.Stop()
	for alive() {
		select {
		case <-ctx.Done():
			return alive()
		case <-timer.C:
			return alive()
		case <-ticker.C:
		}
	}
	return false
}

func readPID(path string) (int, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil || pid < 2 {
		return 0, errors.New("invalid pid file")
	}
	return pid, nil
}

// procStat parses /proc/<pid>/stat: state (field 3), ppid (4), starttime (22).
func procStat(pid int) (process, error) {
	raw, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return process{}, err
	}
	separator := strings.LastIndex(string(raw), ") ")
	if separator < 0 {
		return process{}, errors.New("invalid process stat")
	}
	fields := strings.Fields(string(raw[separator+2:]))
	if len(fields) < 20 {
		return process{}, errors.New("invalid process stat")
	}
	parent, err := strconv.Atoi(fields[1])
	if err != nil {
		return process{}, err
	}
	start, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil {
		return process{}, err
	}
	return process{parent: parent, start: start, zombie: fields[0] == "Z" || fields[0] == "X"}, nil
}

func procChildren(pid int) []int {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}
	var children []int
	for _, entry := range entries {
		child, err := strconv.Atoi(entry.Name())
		if err != nil || child == pid {
			continue
		}
		if stat, err := procStat(child); err == nil && stat.parent == pid && !stat.zombie {
			children = append(children, child)
		}
	}
	return children
}
