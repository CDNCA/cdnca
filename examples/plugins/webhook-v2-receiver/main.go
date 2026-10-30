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
		log.Printf("webhook-v2-receiver stopped code=startup_failed error=%v", err)
		os.Exit(1)
	}
}

func run() error {
	current, err := environmentSecret("CDNCA_WEBHOOK_V2_SECRET_CURRENT", true)
	if err != nil {
		return err
	}
	defer clear(current.Secret)
	previous, err := environmentSecret("CDNCA_WEBHOOK_V2_SECRET_PREVIOUS", false)
	if err != nil {
		return err
	}
	defer clear(previous.Secret)
	if previous.ID != "" && !time.Now().UTC().Before(previous.ValidTil) {
		clear(previous.Secret)
		previous = secretVersion{}
	}
	tenantID := os.Getenv("CDNCA_WEBHOOK_V2_TENANT_ID")
	subscriptionID := os.Getenv("CDNCA_WEBHOOK_V2_SUBSCRIPTION_ID")
	journalPath := environmentOr("CDNCA_WEBHOOK_V2_JOURNAL", "webhook-v2.journal")
	listenAddress := environmentOr("CDNCA_WEBHOOK_V2_LISTEN_ADDR", "127.0.0.1:8080")
	journal, err := openJournal(journalPath)
	if err != nil {
		return err
	}
	defer journal.Close()
	receiver, err := newReceiver(current, previous, tenantID, subscriptionID, journal, func() time.Time { return time.Now().UTC() }, log.Default())
	if err != nil {
		return err
	}
	defer receiver.Close()
	listener, err := net.Listen("tcp", listenAddress)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	defer listener.Close()
	server := &http.Server{Handler: receiver, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 * 1024}
	serverErrors := make(chan error, 1)
	go func() { serverErrors <- server.Serve(listener) }()
	log.Printf("webhook-v2-receiver listening addr=%s", listener.Addr())
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(signals)
	select {
	case err := <-serverErrors:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	case <-signals:
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return server.Shutdown(ctx)
	}
}

func environmentSecret(name string, required bool) (secretVersion, error) {
	value := os.Getenv(name)
	_ = os.Unsetenv(name)
	if value == "" && !required {
		keyID := os.Getenv(name + "_KEY_ID")
		validUntil := os.Getenv(name + "_VALID_UNTIL")
		_ = os.Unsetenv(name + "_KEY_ID")
		_ = os.Unsetenv(name + "_VALID_UNTIL")
		if keyID != "" || validUntil != "" {
			return secretVersion{}, errors.New("previous secret, key id, and valid-until must be configured together")
		}
		return secretVersion{}, nil
	}
	keyIDName := name + "_KEY_ID"
	keyID := os.Getenv(keyIDName)
	_ = os.Unsetenv(keyIDName)
	secret, err := decodeBase64Secret(value)
	if err != nil {
		return secretVersion{}, fmt.Errorf("%s: %w", name, err)
	}
	if !validUUID(keyID) {
		clear(secret)
		return secretVersion{}, fmt.Errorf("%s must have a UUID key id", keyIDName)
	}
	result := secretVersion{ID: keyID, Secret: secret}
	if name == "CDNCA_WEBHOOK_V2_SECRET_PREVIOUS" {
		until := os.Getenv(name + "_VALID_UNTIL")
		_ = os.Unsetenv(name + "_VALID_UNTIL")
		parsed, parseErr := time.Parse(time.RFC3339Nano, until)
		if parseErr != nil || !strings.HasSuffix(until, "Z") || parsed.UTC().Format(time.RFC3339Nano) != until {
			clear(secret)
			return secretVersion{}, errors.New("previous secret valid-until must be canonical UTC RFC3339")
		}
		result.ValidTil = parsed.UTC()
	}
	return result, nil
}

func environmentOr(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}
