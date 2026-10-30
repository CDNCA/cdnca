package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/cdnca/cdnca/libs/passwordpolicy"
	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/google/uuid"
	"golang.org/x/term"
)

type platformRecoveryOptions struct {
	input         identity.PlatformAdministratorRecoveryInput
	passwordStdin bool
	status        bool
}

func platformRecoveryRoot(goos string, uid, euid int) bool {
	return goos == "linux" && uid == 0 && euid == 0
}

func runRecoverPlatformAdministrator(args []string) error {
	// Do this before parsing args, reading a password or connecting to the DB.
	if !platformRecoveryRoot(runtime.GOOS, os.Getuid(), os.Geteuid()) {
		return errors.New("platform_recovery_requires_linux_root")
	}
	options, err := parsePlatformRecoveryOptions(args)
	if err != nil {
		return err
	}
	if !options.status {
		password, err := readPlatformRecoveryPassword(os.Stdin, options.passwordStdin, os.Stderr)
		if err != nil {
			return err
		}
		defer clear(password)
		options.input.NewPassword = string(password)
		defer func() { options.input.NewPassword = "" }()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	pool, err := database.Open(ctx, os.Getenv("DATABASE_URL"))
	if err != nil {
		return identity.ErrPlatformRecoveryUnavailable
	}
	defer pool.Close()
	store := identity.NewStore(pool)
	var receipt identity.PlatformAdministratorRecoveryReceipt
	state := "committed"
	if options.status {
		var found bool
		receipt, found, err = store.PlatformAdministratorRecoveryStatus(ctx, options.input.UserID,
			options.input.ScopeID, options.input.RequestID)
		if err == nil && !found {
			state = "not_found"
			receipt = identity.PlatformAdministratorRecoveryReceipt{UserID: options.input.UserID,
				ScopeID: options.input.ScopeID, RequestID: options.input.RequestID}
		}
	} else {
		receipt, err = store.RecoverPlatformAdministrator(ctx, options.input)
		options.input.NewPassword = ""
	}
	if err != nil {
		return err
	}
	if err := json.NewEncoder(os.Stdout).Encode(struct {
		Status string `json:"status"`
		identity.PlatformAdministratorRecoveryReceipt
	}{state, receipt}); err != nil {
		return errors.New("platform_recovery_output_failed_check_status")
	}
	return nil
}

func parsePlatformRecoveryOptions(args []string) (platformRecoveryOptions, error) {
	var result platformRecoveryOptions
	flags := flag.NewFlagSet("recover-platform-admin", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	userID := flags.String("user-id", "", "")
	scopeID := flags.String("scope-id", "", "")
	flags.StringVar(&result.input.RequestID, "request-id", "", "")
	flags.StringVar(&result.input.ExpectedUsername, "expected-username", "", "")
	flags.Int64Var(&result.input.ExpectedRevision, "expected-revision", 0, "")
	flags.StringVar(&result.input.NewUsername, "new-username", "", "")
	flags.BoolVar(&result.passwordStdin, "password-stdin", false, "")
	flags.BoolVar(&result.status, "status", false, "")
	seen := make(map[string]bool)
	for _, arg := range args {
		if strings.HasPrefix(arg, "-") {
			name := strings.SplitN(strings.TrimLeft(arg, "-"), "=", 2)[0]
			if seen[name] {
				return result, identity.ErrPlatformRecoveryInput
			}
			seen[name] = true
		}
	}
	if flags.Parse(args) != nil || flags.NArg() != 0 {
		return result, identity.ErrPlatformRecoveryInput
	}
	var err error
	result.input.UserID, err = uuid.Parse(*userID)
	if err != nil || result.input.UserID == uuid.Nil || result.input.UserID.String() != *userID {
		return result, identity.ErrPlatformRecoveryInput
	}
	result.input.ScopeID, err = uuid.Parse(*scopeID)
	if err != nil || result.input.ScopeID == uuid.Nil || result.input.ScopeID.String() != *scopeID {
		return result, identity.ErrPlatformRecoveryInput
	}
	requestID, err := uuid.Parse(result.input.RequestID)
	if err != nil || requestID == uuid.Nil || requestID.String() != result.input.RequestID {
		return result, identity.ErrPlatformRecoveryInput
	}
	if result.status {
		if result.passwordStdin || seen["expected-username"] || seen["expected-revision"] || seen["new-username"] {
			return result, identity.ErrPlatformRecoveryInput
		}
	} else if result.input.ExpectedUsername == "" || result.input.NewUsername == "" || result.input.ExpectedRevision < 1 {
		return result, identity.ErrPlatformRecoveryInput
	}
	return result, nil
}

func readPlatformRecoveryPassword(stdin *os.File, fromStdin bool, prompt io.Writer) ([]byte, error) {
	if !fromStdin {
		tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
		if err != nil {
			return nil, errors.New("platform_recovery_tty_required")
		}
		defer tty.Close()
		return readPlatformRecoveryTTYPassword(tty, prompt)
	}
	if stdin == nil {
		return nil, identity.ErrPlatformRecoveryInput
	}
	if term.IsTerminal(int(stdin.Fd())) {
		return readPlatformRecoveryTTYPassword(stdin, prompt)
	}
	info, err := stdin.Stat()
	if err != nil || info.Mode()&os.ModeNamedPipe == 0 {
		return nil, errors.New("platform_recovery_anonymous_pipe_required")
	}
	if runtime.GOOS == "linux" {
		target, err := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", stdin.Fd()))
		if err != nil || !strings.HasPrefix(target, "pipe:[") {
			return nil, errors.New("platform_recovery_anonymous_pipe_required")
		}
	}
	password, err := io.ReadAll(io.LimitReader(stdin, 1026))
	if err == nil && len(password) > 0 && password[len(password)-1] == '\n' {
		password = password[:len(password)-1]
	}
	if err != nil || !validPlatformRecoveryPassword(password) {
		clear(password)
		return nil, identity.ErrPlatformRecoveryInput
	}
	return password, nil
}

func readPlatformRecoveryTTYPassword(tty *os.File, prompt io.Writer) ([]byte, error) {
	if !term.IsTerminal(int(tty.Fd())) {
		return nil, errors.New("platform_recovery_tty_required")
	}
	_, _ = fmt.Fprint(prompt, "New password (hidden): ")
	password, err := term.ReadPassword(int(tty.Fd()))
	_, _ = fmt.Fprintln(prompt)
	if err != nil || !validPlatformRecoveryPassword(password) {
		clear(password)
		return nil, identity.ErrPlatformRecoveryInput
	}
	_, _ = fmt.Fprint(prompt, "Confirm password (hidden): ")
	confirmation, err := term.ReadPassword(int(tty.Fd()))
	_, _ = fmt.Fprintln(prompt)
	defer clear(confirmation)
	if err != nil || !bytes.Equal(password, confirmation) {
		clear(password)
		return nil, errors.New("platform_recovery_password_confirmation_failed")
	}
	return password, nil
}

func validPlatformRecoveryPassword(value []byte) bool {
	return passwordpolicy.Check(string(value)) == nil
}
