package pluginwebhookruntime

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/pluginwebhook"
	"github.com/nats-io/nats.go"
)

type runtimeFailingNATSDialer struct{}

func (runtimeFailingNATSDialer) Dial(string, string) (net.Conn, error) {
	return nil, errors.New("deterministic NATS dial failure")
}

func TestDefaultJetStreamConfigIsFileBackedAndBounded(t *testing.T) {
	config := DefaultJetStreamConfig()
	if !validJetStreamConfig(config) {
		t.Fatal("default JetStream configuration rejected")
	}
	if config.ConsumerMaxDeliver != -1 || config.StreamMaxBytes < MaxMessageBytes ||
		config.DeadLetterMaxBytes < MaxMessageBytes || config.AckWait <= 3*config.OperationTimeout {
		t.Fatalf("default JetStream configuration = %#v", config)
	}
	if !sameConsumer(&nats.ConsumerInfo{Config: *consumerConfig(config)}, consumerConfig(config)) {
		t.Fatal("default stream/consumer contract is not deterministic")
	}
	for _, mutate := range []func(*JetStreamConfig){
		func(candidate *JetStreamConfig) { candidate.DeadLetterStream = "OTHER_DLQ" },
		func(candidate *JetStreamConfig) { candidate.DeadLetterSubject = "cdnca.other.dead-letter.v1" },
	} {
		candidate := config
		mutate(&candidate)
		if validJetStreamConfig(candidate) {
			t.Fatalf("084-incompatible DLQ configuration accepted: %#v", candidate)
		}
	}
}

func TestRuntimeConfigRejectsUnboundedOrMissingDependencies(t *testing.T) {
	valid := Config{
		NATSURL: "nats://127.0.0.1:4222", PollInterval: 100 * time.Millisecond,
		OperationTimeout: time.Second, LeaseDuration: time.Second, ClaimTimeout: time.Second,
		ShutdownTimeout: time.Second, NATSReconnectMin: 250 * time.Millisecond, NATSReconnectMax: 5 * time.Second,
		AttestationKeyID: "plugin-webhook-runtime-key-1",
		AttestationKey:   ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)),
	}
	if !validConfig(valid) {
		t.Fatal("valid runtime configuration rejected")
	}
	for _, mutate := range []func(*Config){
		func(c *Config) { c.AttestationKey = nil },
		func(c *Config) { c.AttestationKeyID = "" },
		func(c *Config) { c.AttestationKeyID = "bad key id" },
		func(c *Config) { c.NextAttestationKeyID = "plugin-webhook-runtime-key-2" },
		func(c *Config) {
			c.NextAttestationKey = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{2}, ed25519.SeedSize))
		},
		func(c *Config) {
			c.NextAttestationKeyID, c.NextAttestationKey = c.AttestationKeyID,
				ed25519.NewKeyFromSeed(bytes.Repeat([]byte{2}, ed25519.SeedSize))
		},
		func(c *Config) {
			c.NextAttestationKeyID, c.NextAttestationKey = "plugin-webhook-runtime-key-2", c.AttestationKey
		},
		func(c *Config) { c.NATSURL = "" },
		func(c *Config) { c.PollInterval = 0 },
		func(c *Config) { c.LeaseDuration = 6 * time.Minute },
		func(c *Config) { c.ClaimTimeout = 500 * time.Millisecond },
		func(c *Config) { c.ShutdownTimeout = 2 * time.Minute },
		func(c *Config) { c.NATSCredsFile = "/run/secrets/nats/runtime.creds" },
		func(c *Config) { c.NATSCAFile = "/run/secrets/nats/ca.crt" },
		func(c *Config) { c.NATSReconnectMin = 0 },
		func(c *Config) { c.NATSReconnectMin = 6 * time.Second },
		func(c *Config) { c.NATSReconnectMax = 5*time.Minute + time.Nanosecond },
	} {
		candidate := valid
		mutate(&candidate)
		if validConfig(candidate) {
			t.Fatalf("invalid runtime configuration accepted: %#v", candidate)
		}
	}
}

func TestRuntimeCycleLeavesOptionalFanoutUnmounted(t *testing.T) {
	runtime := &Runtime{}
	if runtime.fanout != nil {
		t.Fatal("zero runtime unexpectedly mounted fanout")
	}
}

func TestRuntimeNATSOptionsUseCredentialsCAAndBoundedReconnect(t *testing.T) {
	apply := func(config Config) (nats.Options, error) {
		options := nats.GetDefaultOptions()
		for _, option := range runtimeNATSOptions(config, "cdnca-plugin-webhook-test") {
			if err := option(&options); err != nil {
				return options, err
			}
		}
		return options, nil
	}
	base := Config{
		OperationTimeout: time.Second, NATSReconnectMin: 1500 * time.Millisecond, NATSReconnectMax: 2 * time.Second,
	}
	if _, err := apply(Config{
		OperationTimeout: base.OperationTimeout, NATSReconnectMin: base.NATSReconnectMin,
		NATSReconnectMax: base.NATSReconnectMax, NATSCredsFile: "/run/secrets/nats/missing-runtime.creds",
	}); err == nil || !strings.Contains(err.Error(), "missing-runtime.creds") {
		t.Fatalf("runtime NATS credentials option error = %v", err)
	}
	if _, err := apply(Config{
		OperationTimeout: base.OperationTimeout, NATSReconnectMin: base.NATSReconnectMin,
		NATSReconnectMax: base.NATSReconnectMax, NATSCAFile: "/run/secrets/nats/missing-ca.crt",
	}); err == nil || !strings.Contains(err.Error(), "rootCA") {
		t.Fatalf("runtime NATS CA option error = %v", err)
	}
	options, err := apply(base)
	if err != nil {
		t.Fatal(err)
	}
	if options.Name != "cdnca-plugin-webhook-test" || options.Timeout != time.Second ||
		options.MaxReconnect != -1 || options.CustomReconnectDelayCB == nil {
		t.Fatalf("runtime NATS options = %#v", options)
	}
	want := []time.Duration{1500 * time.Millisecond, 1500 * time.Millisecond, 2 * time.Second, 2 * time.Second}
	for attempts, expected := range want {
		if got := options.CustomReconnectDelayCB(attempts); got != expected {
			t.Fatalf("reconnect delay attempt %d = %s want %s", attempts, got, expected)
		}
	}
}

func sendResultSuccess() pluginwebhook.SendResult {
	return pluginwebhook.SendResult{Success: true, Code: "delivered", StatusCode: 204}
}

func TestStableResultRejectsNon2xxSuccessAndAcceptsBoundedRetry(t *testing.T) {
	if validResult(sendResultSuccess()) == false {
		t.Fatal("valid success rejected")
	}
	result := sendResultSuccess()
	result.Success = true
	result.StatusCode = 500
	if validResult(result) {
		t.Fatal("non-2xx success accepted")
	}
	result = sendResultSuccess()
	result.Success = false
	result.Retryable = true
	result.Code = "upstream_timeout"
	result.StatusCode = 503
	if !validResult(result) {
		t.Fatal("bounded retry rejected")
	}
	for _, malformed := range []string{"not-hex", "ab"} {
		result = sendResultSuccess()
		result.ResponseSHA256 = malformed
		if validResult(result) {
			t.Fatalf("malformed response digest %q accepted", malformed)
		}
	}
	result = sendResultSuccess()
	result.ResponseSHA256 = strings.Repeat("ab", 32)
	if !validResult(result) {
		t.Fatal("valid response digest rejected")
	}
}

func TestRetryDelayUsesAuthoritativeDatabaseClock(t *testing.T) {
	databaseNow := time.Date(2026, 8, 7, 8, 0, 0, 0, time.UTC)
	nextAttempt := databaseNow.Add(3 * time.Second)
	delay, err := retryDelayFromDatabaseClock(&nextAttempt, databaseNow)
	if err != nil || delay != 3*time.Second {
		t.Fatalf("future retry delay = %s,%v want 3s", delay, err)
	}

	due := databaseNow.Add(-time.Second)
	delay, err = retryDelayFromDatabaseClock(&due, databaseNow)
	if err != nil || delay != time.Millisecond {
		t.Fatalf("due retry delay = %s,%v want 1ms", delay, err)
	}
	if delay, err = retryDelayFromDatabaseClock(nil, databaseNow); delay != 0 || !errors.Is(err, errNotDue) {
		t.Fatalf("missing retry timestamp = %s,%v want errNotDue", delay, err)
	}
}

func TestRuntimeCloseTerminatesOwnedNATSAfterWaitError(t *testing.T) {
	var nilRuntime *Runtime
	if err := nilRuntime.Close(nil); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("nil Runtime.Close(nil) error = %v", err)
	}
	if err := nilRuntime.Close(t.Context()); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("nil Runtime.Close(context) error = %v", err)
	}
	for _, test := range []struct {
		name            string
		shutdownTimeout time.Duration
		closeContext    func(*testing.T) context.Context
		want            []error
	}{
		{
			name: "already canceled context", shutdownTimeout: time.Second, want: []error{context.Canceled},
			closeContext: func(t *testing.T) context.Context {
				ctx, cancel := context.WithCancel(t.Context())
				cancel()
				return ctx
			},
		},
		{
			name: "worker wait timeout", shutdownTimeout: 20 * time.Millisecond,
			closeContext: func(t *testing.T) context.Context { return t.Context() }, want: []error{context.DeadlineExceeded},
		},
		{
			name: "nil context", shutdownTimeout: 20 * time.Millisecond,
			closeContext: func(*testing.T) context.Context { return nil },
			want:         []error{ErrInvalidConfig, context.DeadlineExceeded},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			connection, err := nats.Connect("nats://deterministic.invalid:4222", nats.SetCustomDialer(runtimeFailingNATSDialer{}),
				nats.RetryOnFailedConnect(true),
				nats.Timeout(10*time.Millisecond), nats.ReconnectWait(10*time.Millisecond), nats.MaxReconnects(-1))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(connection.Close)
			if connection.IsClosed() || !connection.IsReconnecting() {
				t.Fatalf("test NATS connection status = %s", connection.Status())
			}
			workerCtx, cancelWorker := context.WithCancel(context.Background())
			workerCanceled := make(chan struct{})
			releaseWorker := make(chan struct{})
			done := make(chan struct{})
			go func() {
				<-workerCtx.Done()
				close(workerCanceled)
				<-releaseWorker
				close(done)
			}()
			t.Cleanup(func() {
				cancelWorker()
				close(releaseWorker)
				select {
				case <-done:
				case <-time.After(time.Second):
					t.Error("timed out cleaning up blocked runtime worker")
				}
			})
			runtime := &Runtime{
				config: Config{ShutdownTimeout: test.shutdownTimeout}, connection: connection,
				running: true, cancel: cancelWorker, done: done,
			}

			firstErr := runtime.Close(test.closeContext(t))
			for _, want := range test.want {
				if !errors.Is(firstErr, want) {
					t.Fatalf("first Close() error = %v want match %v", firstErr, want)
				}
			}
			select {
			case <-workerCanceled:
			case <-time.After(time.Second):
				t.Fatal("Close did not cancel the runtime worker")
			}
			closedAfterFirst := connection.IsClosed()
			secondErr := runtime.Close(t.Context())
			closedAfterSecond := connection.IsClosed()
			if secondErr != nil || !closedAfterFirst || !closedAfterSecond {
				t.Fatalf("Close cleanup: first_closed=%v second=(%v,%v) reconnecting=%v",
					closedAfterFirst, secondErr, closedAfterSecond, connection.IsReconnecting())
			}
		})
	}
}

func TestAttestationHeadKeySelectsCurrentOrStagedNext(t *testing.T) {
	current := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, ed25519.SeedSize))
	next := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{2}, ed25519.SeedSize))
	other := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{3}, ed25519.SeedSize))
	runtime := &Runtime{config: Config{AttestationKeyID: "key-1", AttestationKey: current,
		NextAttestationKeyID: "key-2", NextAttestationKey: next}}
	if !validNextAttestationKey(runtime.config) {
		t.Fatal("staged next key rejected")
	}
	public := func(key ed25519.PrivateKey) []byte { return key.Public().(ed25519.PublicKey) }
	if key := runtime.headKey("key-1", public(current)); !bytes.Equal(key, current) {
		t.Fatal("head naming the current key did not select it")
	}
	if key := runtime.headKey("key-2", public(next)); !bytes.Equal(key, next) {
		t.Fatal("head naming the staged next key did not select it")
	}
	for name, head := range map[string]struct {
		id  string
		key []byte
	}{
		"unknown key":       {"key-3", public(other)},
		"id/key mismatch":   {"key-1", public(next)},
		"next id, cur key":  {"key-2", public(current)},
		"right id, foreign": {"key-2", public(other)},
	} {
		if runtime.headKey(head.id, head.key) != nil {
			t.Fatalf("%s: head accepted", name)
		}
	}
	runtime.config.NextAttestationKeyID, runtime.config.NextAttestationKey = "", nil
	if runtime.headKey("key-2", public(next)) != nil {
		t.Fatal("unstaged next key selected")
	}
}
