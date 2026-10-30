package nativebackup

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"regexp"
	"strings"
)

// Command is one external program invocation. Arguments never carry secret
// material: credentials reach the programs through peer authentication,
// owner-only client configuration files or stdin.
type Command struct {
	Path   string
	Args   []string
	Env    []string
	RunAs  string
	Stdin  io.Reader
	Stdout io.Writer
}

// Executor runs commands; tests substitute a recording fake.
type Executor interface {
	Run(context.Context, Command) error
}

// CommandError reports a failed program by name only. The bounded, redacted
// stderr is kept for the private diagnostics file and never placed in Error().
type CommandError struct {
	Program string
	Detail  string
}

func (failure *CommandError) Error() string { return failure.Program + " failed" }

const commandDetailLimit = 2048

var baseEnvironment = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C", "HOME=/root"}

type OSExecutor struct{}

func (OSExecutor) Run(ctx context.Context, command Command) error {
	if command.Path == "" || strings.ContainsAny(command.Path, "\x00\r\n") {
		return errors.New("invalid command")
	}
	name, arguments := command.Path, command.Args
	if command.RunAs != "" {
		// runuser keeps the environment explicit and needs no password.
		arguments = append([]string{"-u", command.RunAs, "--", command.Path}, command.Args...)
		name = "runuser"
	}
	process := exec.CommandContext(ctx, name, arguments...)
	process.Env = append(append([]string(nil), baseEnvironment...), command.Env...)
	process.Stdin = command.Stdin
	process.Stdout = command.Stdout
	if process.Stdout == nil {
		process.Stdout = io.Discard
	}
	var stderr boundedBuffer
	process.Stderr = &stderr
	if err := process.Run(); err != nil {
		program := command.Path
		if index := strings.LastIndexByte(program, '/'); index >= 0 {
			program = program[index+1:]
		}
		return &CommandError{Program: program, Detail: Redact(stderr.String())}
	}
	return nil
}

type boundedBuffer struct{ bytes.Buffer }

func (buffer *boundedBuffer) Write(value []byte) (int, error) {
	if remaining := commandDetailLimit - buffer.Len(); remaining > 0 {
		if len(value) > remaining {
			buffer.Buffer.Write(value[:remaining])
		} else {
			buffer.Buffer.Write(value)
		}
	}
	return len(value), nil
}

var (
	redactAssignment = regexp.MustCompile(`(?i)((?:password|passwd|secret|token|key|credential|authorization)[A-Za-z0-9_-]*\s*[=:]\s*)\S+`)
	redactLong       = regexp.MustCompile(`[A-Za-z0-9+/=_-]{24,}`)
	redactPEM        = regexp.MustCompile(`(?s)-----BEGIN [A-Z ]+-----.*?-----END [A-Z ]+-----`)
)

// Redact removes anything that looks like key material before a program's
// error output is written to the private diagnostics file.
func Redact(value string) string {
	value = redactPEM.ReplaceAllString(value, "[redacted-pem]")
	value = redactAssignment.ReplaceAllString(value, "${1}[redacted]")
	// Backup IDs and SHA256 fingerprints are public identifiers, not secrets.
	value = redactLong.ReplaceAllStringFunc(value, func(token string) string {
		if backupIDPattern.MatchString(token) || runIDPattern.MatchString(token) || regexp.MustCompile(`^[A-Za-z0-9+/]{43}$`).MatchString(token) && strings.Contains(value, "SHA256:"+token) {
			return token
		}
		return "[redacted]"
	})
	return strings.TrimSpace(value)
}

// run executes a command and returns only stdout. Use for short query output.
func run(ctx context.Context, executor Executor, command Command) (string, error) {
	var stdout bytes.Buffer
	command.Stdout = &limitedWriter{writer: &stdout, remaining: 1 << 20}
	if err := executor.Run(ctx, command); err != nil {
		return "", err
	}
	return strings.TrimSpace(stdout.String()), nil
}

type limitedWriter struct {
	writer    io.Writer
	remaining int
}

func (writer *limitedWriter) Write(value []byte) (int, error) {
	if len(value) > writer.remaining {
		return 0, fmt.Errorf("command output exceeded limit")
	}
	count, err := writer.writer.Write(value)
	writer.remaining -= count
	return count, err
}
