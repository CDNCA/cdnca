package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

func main() {
	if err := run(); err != nil {
		log.Printf("webhook-audit-sink stopped code=startup_failed error=%v", err)
		os.Exit(1)
	}
}

func run() error {
	secrets, err := receiverSecretsFromEnvironment(time.Now().UTC())
	if err != nil {
		return err
	}
	defer secrets.clear()
	tenantID := os.Getenv("CDNCA_WEBHOOK_TENANT_ID")
	journalPath := environmentOr("CDNCA_WEBHOOK_JOURNAL", "webhook-audit.journal")
	listenAddress := environmentOr("CDNCA_WEBHOOK_LISTEN_ADDR", "127.0.0.1:8080")
	journal, err := openJournal(journalPath)
	if err != nil {
		return err
	}
	defer journal.Close()
	receiver, err := newReceiver(
		secrets.current, secrets.previous, secrets.previousValidUntil,
		tenantID, journal, func() time.Time { return time.Now().UTC() }, 5*time.Minute, log.Default(),
	)
	secrets.clear()
	if err != nil {
		return err
	}
	defer receiver.Close()
	listener, err := net.Listen("tcp", listenAddress)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	defer listener.Close()
	if readyFile := os.Getenv("CDNCA_WEBHOOK_READY_FILE"); readyFile != "" {
		if err := writeReadyFile(readyFile, "http://"+listener.Addr().String()+"\n"); err != nil {
			return err
		}
		defer os.Remove(readyFile)
	}
	server := &http.Server{
		Handler: receiver, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second,
		WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 * 1024,
	}
	serverError := make(chan error, 1)
	go func() { serverError <- server.Serve(listener) }()
	log.Printf("webhook-audit-sink listening addr=%s", listener.Addr())
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(signals)
	select {
	case err := <-serverError:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	case <-signals:
		shutdownContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return server.Shutdown(shutdownContext)
	}
}

type receiverSecrets struct {
	current            []byte
	previous           []byte
	previousValidUntil time.Time
}

func receiverSecretsFromEnvironment(now time.Time) (receiverSecrets, error) {
	current, err := secretFromEnvironment("CDNCA_WEBHOOK_SECRET_CURRENT", true)
	if err != nil {
		return receiverSecrets{}, err
	}
	result := receiverSecrets{current: current}
	previous, err := secretFromEnvironment("CDNCA_WEBHOOK_SECRET_PREVIOUS", false)
	if err != nil {
		result.clear()
		return receiverSecrets{}, err
	}
	validUntilText := os.Getenv("CDNCA_WEBHOOK_SECRET_PREVIOUS_VALID_UNTIL")
	_ = os.Unsetenv("CDNCA_WEBHOOK_SECRET_PREVIOUS_VALID_UNTIL")
	if (len(previous) == 0) != (validUntilText == "") {
		clear(previous)
		result.clear()
		return receiverSecrets{}, errors.New("previous secret and previous valid-until must be configured together")
	}
	if len(previous) == 0 {
		return result, nil
	}
	validUntil, err := parsePreviousValidUntil(validUntilText)
	if err != nil {
		clear(previous)
		result.clear()
		return receiverSecrets{}, errors.New("previous valid-until must be canonical RFC3339 UTC")
	}
	if !now.UTC().Before(validUntil) {
		clear(previous)
		return result, nil
	}
	result.previous = previous
	result.previousValidUntil = validUntil
	return result, nil
}

func parsePreviousValidUntil(value string) (time.Time, error) {
	if !strings.HasSuffix(value, "Z") {
		return time.Time{}, errors.New("previous valid-until must use UTC Z")
	}
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil || parsed.Format(time.RFC3339Nano) != value {
		return time.Time{}, errors.New("previous valid-until must be canonical RFC3339 UTC")
	}
	return parsed.UTC(), nil
}

func (secrets *receiverSecrets) clear() {
	clear(secrets.current)
	clear(secrets.previous)
	secrets.current = nil
	secrets.previous = nil
	secrets.previousValidUntil = time.Time{}
}

func secretFromEnvironment(name string, required bool) ([]byte, error) {
	value := os.Getenv(name)
	_ = os.Unsetenv(name)
	if value == "" && !required {
		return nil, nil
	}
	secret := []byte(value)
	if len(secret) < minimumSecretSize || len(secret) > maximumSecretSize {
		clear(secret)
		return nil, fmt.Errorf("%s must contain 32 to 4096 bytes", name)
	}
	return secret, nil
}

func environmentOr(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func writeReadyFile(path, value string) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create ready file: %w", err)
	}
	if _, err := file.WriteString(value); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}
