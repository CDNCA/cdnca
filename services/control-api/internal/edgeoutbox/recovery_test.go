package edgeoutbox

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"syscall"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/puddle/v2"
)

func TestRunRecoversTransientStoreErrors(t *testing.T) {
	tests := map[string]error{
		"database recovery":  &pgconn.PgError{Code: "57P03"},
		"database shutdown":  &pgconn.PgError{Code: "57P01"},
		"database crash":     &pgconn.PgError{Code: "57P02"},
		"connection missing": &pgconn.PgError{Code: "08003"},
		"connection failure": &pgconn.PgError{Code: "08006"},
		"connection refused": &net.OpError{Op: "dial", Net: "tcp", Err: syscall.ECONNREFUSED},
		"connection reset":   &net.OpError{Op: "read", Net: "tcp", Err: syscall.ECONNRESET},
		"broken pipe":        &net.OpError{Op: "write", Net: "tcp", Err: syscall.EPIPE},
		"socket timeout":     &net.OpError{Op: "read", Net: "tcp", Err: syscall.ETIMEDOUT},
		"EOF":                io.EOF,
		"unexpected EOF":     io.ErrUnexpectedEOF,
		"operation timeout":  context.DeadlineExceeded,
		"fallback addresses": errors.Join(&pgconn.PgError{Code: "57P03"}, syscall.ECONNREFUSED),
	}
	for name, failure := range tests {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			store := &fakeStore{commands: []claimedCommand{validClaim(t)}}
			claims := 0
			store.onClaim = func() {
				claims++
				store.claimErr = nil
				if claims == 1 {
					store.claimErr = fmt.Errorf("claim edge command outbox: %w", failure)
				} else if claims == 3 {
					cancel()
				}
			}
			messages := &fakeMessages{ack: publishAck{stream: DefaultConfig().Stream}}
			publisher := testPublisher(t, store, messages)
			publisher.config.BaseBackoff = time.Millisecond
			publisher.config.MaxBackoff = 4 * time.Millisecond
			if err := publisher.Run(ctx); !errors.Is(err, context.Canceled) {
				t.Fatalf("Run error = %v, want cancellation after recovery", err)
			}
			if claims != 3 || len(store.published) != 1 || len(messages.calls) != 1 || len(store.failed) != 0 {
				t.Fatalf("claims=%d published=%d messages=%d failures=%d", claims, len(store.published), len(messages.calls), len(store.failed))
			}
		})
	}
}

func TestRunReturnsPermanentStoreErrors(t *testing.T) {
	tests := map[string]error{
		"invalid password":       &pgconn.PgError{Code: "28P01"},
		"invalid authorization":  &pgconn.PgError{Code: "28000"},
		"permission denied":      &pgconn.PgError{Code: "42501"},
		"missing relation":       &pgconn.PgError{Code: "42P01"},
		"protocol violation":     &pgconn.PgError{Code: "08P01"},
		"connection rejected":    &pgconn.PgError{Code: "08004"},
		"unknown database error": &pgconn.PgError{Code: "XX000"},
		"unknown error":          errInjected,
		"claim lost":             ErrClaimLost,
		"closed pool":            puddle.ErrClosedPool,
		"certificate invalid":    x509.UnknownAuthorityError{},
		"TLS protocol invalid":   tls.RecordHeaderError{},
		"hostname invalid":       &net.DNSError{IsNotFound: true},
		"connection error mixed": errors.Join(syscall.ECONNREFUSED, &pgconn.PgError{Code: "28P01"}),
		"database error mixed":   errors.Join(&pgconn.PgError{Code: "57P03"}, &pgconn.PgError{Code: "42501"}),
		"configuration invalid":  &pgconn.ParseConfigError{ConnString: "invalid"},
		"cancellation":           context.Canceled,
	}
	for name, failure := range tests {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			wrapped := fmt.Errorf("store operation failed: %w", failure)
			store := &fakeStore{claimErr: wrapped}
			claims := 0
			store.onClaim = func() { claims++ }
			publisher := testPublisher(t, store, &fakeMessages{})
			if err := publisher.Run(ctx); err != wrapped {
				t.Fatalf("Run error = %v, want original permanent error", err)
			}
			if claims != 1 {
				t.Fatalf("claims = %d, want one attempt", claims)
			}
		})
	}
}

func TestRunCancelsDuringStoreBackoff(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	claimed := make(chan struct{}, 1)
	store := &fakeStore{
		claimErr: &pgconn.PgError{Code: "57P03"},
		onClaim:  func() { claimed <- struct{}{} },
	}
	publisher := testPublisher(t, store, &fakeMessages{})
	publisher.config.BaseBackoff = time.Hour
	publisher.config.MaxBackoff = time.Hour
	done := make(chan error, 1)
	go func() { done <- publisher.Run(ctx) }()
	<-claimed
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Run error = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("publisher did not cancel during backoff")
	}
}

func TestRunStoreBackoffCapsAndResetsAfterSuccess(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	store := &fakeStore{}
	attempts := make([]time.Time, 0, 7)
	store.onClaim = func() {
		attempts = append(attempts, time.Now())
		store.claimErr = &pgconn.PgError{Code: "57P03"}
		if len(attempts) == 5 {
			store.claimErr = nil
		} else if len(attempts) == 7 {
			store.claimErr = errInjected
		}
	}
	publisher := testPublisher(t, store, &fakeMessages{})
	publisher.config.BaseBackoff = 10 * time.Millisecond
	publisher.config.MaxBackoff = 30 * time.Millisecond
	publisher.config.PollInterval = 2 * time.Millisecond
	if err := publisher.Run(ctx); !errors.Is(err, errInjected) {
		t.Fatalf("Run error = %v, want final permanent error", err)
	}
	if len(attempts) != 7 {
		t.Fatalf("attempts = %d, want seven", len(attempts))
	}
	wantDelays := []time.Duration{10, 20, 30, 30, 2, 10}
	for index, milliseconds := range wantDelays {
		delay := attempts[index+1].Sub(attempts[index])
		if delay < milliseconds*time.Millisecond || delay > milliseconds*time.Millisecond+100*time.Millisecond {
			t.Errorf("delay %d = %s, want %dms (plus scheduling tolerance)", index, delay, milliseconds)
		}
	}
}
