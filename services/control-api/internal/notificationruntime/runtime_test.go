package notificationruntime

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/notification"
	"github.com/google/uuid"
)

type scriptedProcessor struct {
	mu      sync.Mutex
	results []notification.WorkerBatchResult
	errors  []error
	calls   []time.Time
	block   <-chan struct{}
}

type gatedProcessor struct {
	entered chan struct{}
	release chan struct{}
	err     error
	once    sync.Once
}

func newGatedProcessor(err error) *gatedProcessor {
	return &gatedProcessor{entered: make(chan struct{}), release: make(chan struct{}), err: err}
}

func (p *gatedProcessor) ProcessBatch(ctx context.Context) (notification.WorkerBatchResult, error) {
	p.once.Do(func() { close(p.entered) })
	select {
	case <-p.release:
		return notification.WorkerBatchResult{}, p.err
	case <-ctx.Done():
		return notification.WorkerBatchResult{}, ctx.Err()
	}
}

func (p *scriptedProcessor) ProcessBatch(ctx context.Context) (notification.WorkerBatchResult, error) {
	p.mu.Lock()
	index := len(p.calls)
	p.calls = append(p.calls, time.Now())
	var result notification.WorkerBatchResult
	var err error
	if index < len(p.results) {
		result = p.results[index]
	}
	if index < len(p.errors) {
		err = p.errors[index]
	}
	block := p.block
	p.mu.Unlock()
	if block != nil {
		<-block
	}
	if ctx.Err() != nil {
		return result, ctx.Err()
	}
	return result, err
}

func (p *scriptedProcessor) callTimes() []time.Time {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]time.Time(nil), p.calls...)
}

func TestRuntimeStartsBacksOffReportsExitAndCancels(t *testing.T) {
	processor := &scriptedProcessor{errors: []error{
		errors.New("database secret one"), errors.New("database secret two"), errors.New("database secret three"),
	}}
	runtime := testRuntime(t, processor, RuntimeConfig{
		IdleWait: time.Second, ErrorBackoffBase: 20 * time.Millisecond,
		ErrorBackoffMax: 40 * time.Millisecond, MaxConsecutiveFailures: 3,
	})
	err := runtime.Run(context.Background())
	if !errors.Is(err, ErrWorkerExited) || err.Error() != "notification_runtime_worker_exited" {
		t.Fatalf("Run() error = %v", err)
	}
	times := processor.callTimes()
	if len(times) != 3 || times[1].Sub(times[0]) < 20*time.Millisecond || times[2].Sub(times[1]) < 40*time.Millisecond {
		t.Fatalf("backoff call times = %v", times)
	}
	health := runtime.Health()
	if health.State != StateFailed || health.LastErrorClass != "worker_store_unavailable" || health.ConsecutiveFailures != 3 {
		t.Fatalf("failed health = %+v", health)
	}

	cancelProcessor := &scriptedProcessor{errors: []error{errors.New("retry")}}
	cancelRuntime := testRuntime(t, cancelProcessor, RuntimeConfig{
		IdleWait: time.Second, ErrorBackoffBase: time.Second,
		ErrorBackoffMax: time.Second, MaxConsecutiveFailures: 3,
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- cancelRuntime.Run(ctx) }()
	waitFor(t, time.Second, func() bool { return len(cancelProcessor.callTimes()) == 1 })
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("cancelled Run() = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Run did not cancel during backoff")
	}
}

func TestRuntimeReportsWorkerPanicWithoutLeakingPanicValue(t *testing.T) {
	runtime := testRuntime(t, panicProcessor{}, RuntimeConfig{IdleWait: time.Second})
	err := runtime.Run(context.Background())
	if !errors.Is(err, ErrWorkerExited) || err.Error() != "notification_runtime_worker_exited" {
		t.Fatalf("panic Run() error = %v", err)
	}
	health := runtime.Health()
	if health.State != StateFailed || health.LastErrorClass != "worker_panic" {
		t.Fatalf("panic health = %+v", health)
	}
}

func TestRuntimeIsDisabledUntilExplicitlyEnabled(t *testing.T) {
	runtime, err := Build(DefaultRuntimeConfig(), Dependencies{})
	if err != nil {
		t.Fatal(err)
	}
	if health := runtime.Health(); health.Enabled || health.State != StateDisabled {
		t.Fatalf("disabled health = %+v", health)
	}
	if err := runtime.Run(context.Background()); !errors.Is(err, ErrDisabled) {
		t.Fatalf("disabled Run() error = %v", err)
	}
	if runtime.RecoverySender() != nil {
		t.Fatal("disabled runtime exposed a recovery sender")
	}
}

func TestRuntimeReadyGatesWorkerChannelsTemplatesProvidersAndSender(t *testing.T) {
	emailTemplate := notification.TemplateRef{ID: "account_recovery", Version: 1, Channel: notification.ChannelEmail}
	smsTemplate := notification.TemplateRef{ID: "account_recovery", Version: 1, Channel: notification.ChannelSMS}
	tests := []struct {
		name      string
		switches  notification.ChannelSwitches
		resolver  MemberContactResolver
		providers map[notification.Channel]ProviderTransport
		templates map[notification.Channel]notification.TemplateRef
		want      error
	}{
		{name: "no channel", resolver: &testContactResolver{}, want: ErrChannelUnavailable},
		{name: "missing sender", switches: notification.ChannelSwitches{Email: true}, providers: map[notification.Channel]ProviderTransport{notification.ChannelEmail: &testProvider{}}, templates: map[notification.Channel]notification.TemplateRef{notification.ChannelEmail: emailTemplate}, want: ErrSenderUnavailable},
		{name: "missing provider", switches: notification.ChannelSwitches{Email: true}, resolver: &testContactResolver{}, templates: map[notification.Channel]notification.TemplateRef{notification.ChannelEmail: emailTemplate}, want: ErrProviderUnavailable},
		{name: "missing template", switches: notification.ChannelSwitches{Email: true}, resolver: &testContactResolver{}, providers: map[notification.Channel]ProviderTransport{notification.ChannelEmail: &testProvider{}}, want: ErrTemplateUnavailable},
		{name: "provider not ready", switches: notification.ChannelSwitches{Email: true}, resolver: &testContactResolver{}, providers: map[notification.Channel]ProviderTransport{notification.ChannelEmail: &testProvider{ready: errors.New("secret")}}, templates: map[notification.Channel]notification.TemplateRef{notification.ChannelEmail: emailTemplate}, want: ErrProviderNotReady},
		{name: "email ready", switches: notification.ChannelSwitches{Email: true}, resolver: &testContactResolver{}, providers: map[notification.Channel]ProviderTransport{notification.ChannelEmail: &testProvider{}}, templates: map[notification.Channel]notification.TemplateRef{notification.ChannelEmail: emailTemplate}},
		{name: "sms ready", switches: notification.ChannelSwitches{SMS: true}, resolver: &testContactResolver{}, providers: map[notification.Channel]ProviderTransport{notification.ChannelSMS: &testProvider{}}, templates: map[notification.Channel]notification.TemplateRef{notification.ChannelSMS: smsTemplate}},
		{name: "both require both", switches: notification.ChannelSwitches{Email: true, SMS: true}, resolver: &testContactResolver{}, providers: map[notification.Channel]ProviderTransport{notification.ChannelEmail: &testProvider{}}, templates: map[notification.Channel]notification.TemplateRef{notification.ChannelEmail: emailTemplate, notification.ChannelSMS: smsTemplate}, want: ErrProviderUnavailable},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			runtime := testRuntimeWithDelivery(t, &scriptedProcessor{}, RuntimeConfig{IdleWait: time.Second}, test.resolver, test.providers, test.templates)
			ctx, cancel := context.WithCancel(context.Background())
			runDone := make(chan error, 1)
			go func() { runDone <- runtime.Run(ctx) }()
			waitFor(t, time.Second, func() bool { return runtime.Health().WorkerRunning })
			err := runtime.Ready(context.Background(), test.switches)
			if !errors.Is(err, test.want) {
				t.Fatalf("Ready() error = %v, want %v", err, test.want)
			}
			cancel()
			<-runDone
		})
	}
}

func TestRuntimeReadyRequiresFirstSuccessfulBatch(t *testing.T) {
	processor := newGatedProcessor(nil)
	runtime := testRuntime(t, processor, RuntimeConfig{IdleWait: time.Second})
	ctx, cancel := context.WithCancel(context.Background())
	runDone := make(chan error, 1)
	go func() { runDone <- runtime.Run(ctx) }()
	select {
	case <-processor.entered:
	case <-time.After(time.Second):
		t.Fatal("first batch did not start")
	}
	if err := runtime.Ready(context.Background(), notification.ChannelSwitches{Email: true});
		!errors.Is(err, ErrWorkerNotRunning) {
		t.Fatalf("Ready() before first successful batch = %v", err)
	}

	close(processor.release)
	waitFor(t, time.Second, func() bool {
		return runtime.Ready(context.Background(), notification.ChannelSwitches{Email: true}) == nil
	})
	cancel()
	if err := <-runDone; err != nil {
		t.Fatalf("Run() = %v", err)
	}
}

func TestRuntimeReadyNeverPassesAfterFirstBatchStoreError(t *testing.T) {
	processor := newGatedProcessor(errors.New("database unavailable secret"))
	runtime := testRuntime(t, processor, RuntimeConfig{
		IdleWait: time.Second, ErrorBackoffBase: time.Second,
		ErrorBackoffMax: time.Second, MaxConsecutiveFailures: 2,
	})
	ctx, cancel := context.WithCancel(context.Background())
	runDone := make(chan error, 1)
	go func() { runDone <- runtime.Run(ctx) }()
	select {
	case <-processor.entered:
	case <-time.After(time.Second):
		t.Fatal("first batch did not start")
	}
	close(processor.release)
	waitFor(t, time.Second, func() bool { return runtime.Health().State == StateBackoff })
	if err := runtime.Ready(context.Background(), notification.ChannelSwitches{Email: true});
		!errors.Is(err, ErrWorkerNotRunning) {
		t.Fatalf("Ready() after first store error = %v", err)
	}
	cancel()
	if err := <-runDone; err != nil {
		t.Fatalf("Run() = %v", err)
	}
}

func TestRuntimeReadyContainsResolverAndProviderPanics(t *testing.T) {
	emailTemplate := notification.TemplateRef{ID: "account_recovery", Version: 1, Channel: notification.ChannelEmail}
	tests := []struct {
		name      string
		resolver  MemberContactResolver
		provider  ProviderTransport
		wantError error
	}{
		{
			name: "resolver panic", resolver: &panicReadyResolver{},
			provider: &lifecycleProvider{}, wantError: ErrSenderNotReady,
		},
		{
			name: "provider panic", resolver: &testContactResolver{},
			provider: &lifecycleProvider{panicReady: true}, wantError: ErrProviderNotReady,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			runtime := testRuntimeWithDelivery(t, &scriptedProcessor{}, RuntimeConfig{IdleWait: time.Second},
				test.resolver,
				map[notification.Channel]ProviderTransport{notification.ChannelEmail: test.provider},
				map[notification.Channel]notification.TemplateRef{notification.ChannelEmail: emailTemplate},
			)
			ctx, cancel := context.WithCancel(context.Background())
			runDone := make(chan error, 1)
			go func() { runDone <- runtime.Run(ctx) }()
			waitFor(t, time.Second, func() bool {
				runtime.mu.Lock()
				defer runtime.mu.Unlock()
				return runtime.workerHealthy
			})

			readyErr, panicValue := readyCapturingPanic(runtime, context.Background())
			cancel()
			if runErr := <-runDone; runErr != nil {
				t.Fatalf("Run() = %v", runErr)
			}
			if panicValue != nil {
				t.Fatalf("Ready() panic escaped: %v", panicValue)
			}
			if !errors.Is(readyErr, test.wantError) {
				t.Fatalf("Ready() error = %v, want %v", readyErr, test.wantError)
			}
		})
	}
}

func TestRuntimeCloseIsOrderedBoundedAndConverges(t *testing.T) {
	release := make(chan struct{})
	processor := &scriptedProcessor{block: release}
	provider := &testProvider{}
	runtime := testRuntimeWithDelivery(t, processor, RuntimeConfig{
		IdleWait: time.Second, ShutdownTimeout: 25 * time.Millisecond,
	}, &testContactResolver{}, map[notification.Channel]ProviderTransport{
		notification.ChannelEmail: provider,
	}, map[notification.Channel]notification.TemplateRef{
		notification.ChannelEmail: {ID: "account_recovery", Version: 1, Channel: notification.ChannelEmail},
	})
	runDone := make(chan error, 1)
	go func() { runDone <- runtime.Run(context.Background()) }()
	waitFor(t, time.Second, func() bool { return len(processor.callTimes()) == 1 })
	started := time.Now()
	err := runtime.Close(context.Background())
	if !errors.Is(err, ErrCloseTimeout) || time.Since(started) > time.Second {
		t.Fatalf("bounded Close() elapsed=%v error=%v", time.Since(started), err)
	}
	if _, closed := provider.snapshot(); closed != 0 {
		t.Fatal("provider closed before worker joined")
	}
	close(release)
	select {
	case err := <-runDone:
		if err != nil {
			t.Fatalf("Run() after release = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("worker did not converge after release")
	}
	if err := runtime.Close(context.Background()); err != nil {
		t.Fatalf("converged Close() = %v", err)
	}
	if _, closed := provider.snapshot(); closed != 1 {
		t.Fatalf("provider close count = %d", closed)
	}
	if err := runtime.Close(context.Background()); err != nil {
		t.Fatalf("idempotent Close() = %v", err)
	}
}

func TestRuntimeCloseCancelsAndDrainsReadinessBeforeProviderClose(t *testing.T) {
	provider := newBlockingReadyProvider()
	runtime := testRuntimeWithDelivery(t, &scriptedProcessor{}, RuntimeConfig{
		IdleWait: time.Second, ShutdownTimeout: time.Second,
	}, &testContactResolver{}, map[notification.Channel]ProviderTransport{
		notification.ChannelEmail: provider,
	}, map[notification.Channel]notification.TemplateRef{
		notification.ChannelEmail: {ID: "account_recovery", Version: 1, Channel: notification.ChannelEmail},
	})
	runDone := make(chan error, 1)
	go func() { runDone <- runtime.Run(context.Background()) }()
	waitFor(t, time.Second, func() bool { return runtime.Health().WorkerRunning })
	readyDone := make(chan error, 1)
	go func() {
		readyDone <- runtime.Ready(context.Background(), notification.ChannelSwitches{Email: true})
	}()
	select {
	case <-provider.entered:
	case <-time.After(time.Second):
		t.Fatal("provider readiness did not start")
	}
	if err := runtime.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := <-readyDone; !errors.Is(err, ErrWorkerNotRunning) {
		t.Fatalf("cancelled Ready() = %v", err)
	}
	if err := <-runDone; err != nil {
		t.Fatal(err)
	}
	if provider.closed.Load() != 1 || !provider.readyExited.Load() {
		t.Fatalf("provider closed=%d ready_exited=%v", provider.closed.Load(), provider.readyExited.Load())
	}
}

func TestRuntimeCloseContainsProviderPanicContinuesAndConverges(t *testing.T) {
	panicking := &lifecycleProvider{panicClose: true}
	following := &lifecycleProvider{}
	runtime := testRuntimeWithDelivery(t, &scriptedProcessor{}, RuntimeConfig{ShutdownTimeout: time.Second},
		&testContactResolver{},
		map[notification.Channel]ProviderTransport{
			notification.ChannelEmail: panicking,
			notification.ChannelSMS:   following,
		},
		nil,
	)

	firstErr, firstPanic := closeCapturingPanic(runtime)
	secondErr, secondPanic := closeCapturingPanic(runtime)
	if firstPanic != nil || secondPanic != nil {
		t.Fatalf("Close() panics first=%v second=%v", firstPanic, secondPanic)
	}
	if !errors.Is(firstErr, ErrProviderClose) || !errors.Is(secondErr, ErrProviderClose) {
		t.Fatalf("Close() errors first=%v second=%v", firstErr, secondErr)
	}
	if panicking.closeCalls.Load() != 1 || following.closeCalls.Load() != 1 {
		t.Fatalf("provider close calls panicking=%d following=%d",
			panicking.closeCalls.Load(), following.closeCalls.Load())
	}
	if health := runtime.Health(); health.State != StateStopped || health.Ready || health.WorkerRunning {
		t.Fatalf("closed health = %+v", health)
	}
}

func TestRuntimeLogsContainOnlyStableOperationalFields(t *testing.T) {
	var output bytes.Buffer
	processor := &scriptedProcessor{
		results: []notification.WorkerBatchResult{{Claimed: 1, RetryScheduled: 1}},
		errors:  []error{errors.New("recipient@example.test subject body https://secret credential payload")},
	}
	runtime := testRuntime(t, processor, RuntimeConfig{
		IdleWait: time.Second, ErrorBackoffBase: time.Millisecond,
		ErrorBackoffMax: time.Millisecond, MaxConsecutiveFailures: 1,
		Logger: slog.New(slog.NewTextHandler(&output, nil)),
	})
	_ = runtime.Run(context.Background())
	logOutput := output.String()
	for _, sensitive := range []string{"recipient@example.test", "subject", "body", "https://secret", "credential", "payload"} {
		if strings.Contains(logOutput, sensitive) {
			t.Fatalf("log contains %q: %s", sensitive, logOutput)
		}
	}
	for _, required := range []string{"state=backoff", "error_class=worker_store_unavailable", "failure_count=1"} {
		if !strings.Contains(logOutput, required) {
			t.Fatalf("log missing %q: %s", required, logOutput)
		}
	}
}

func testRuntime(t *testing.T, processor batchProcessor, config RuntimeConfig) *Runtime {
	t.Helper()
	return testRuntimeWithDelivery(t, processor, config, &testContactResolver{}, map[notification.Channel]ProviderTransport{
		notification.ChannelEmail: &testProvider{},
	}, map[notification.Channel]notification.TemplateRef{
		notification.ChannelEmail: {ID: "account_recovery", Version: 1, Channel: notification.ChannelEmail},
	})
}

func testRuntimeWithDelivery(
	t *testing.T,
	processor batchProcessor,
	config RuntimeConfig,
	resolver MemberContactResolver,
	providers map[notification.Channel]ProviderTransport,
	templates map[notification.Channel]notification.TemplateRef,
) *Runtime {
	t.Helper()
	config.Enabled = true
	config.RecoveryTemplates = templates
	runtime, err := buildRuntime(config, processor, resolver, providers)
	if err != nil {
		t.Fatal(err)
	}
	return runtime
}

func waitFor(t *testing.T, timeout time.Duration, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("condition did not become true")
}

type panicProcessor struct{}

func (panicProcessor) ProcessBatch(context.Context) (notification.WorkerBatchResult, error) {
	panic("recipient@example.test provider body credential")
}

type panicReadyResolver struct{}

func (*panicReadyResolver) Ready(context.Context, notification.Channel) error {
	panic("resolver secret must not escape")
}

func (*panicReadyResolver) Resolve(
	context.Context,
	uuid.UUID,
	uuid.UUID,
	notification.Channel,
) ContactResolution {
	return ContactResolution{Contact: "member@example.test"}
}

type lifecycleProvider struct {
	panicReady bool
	panicClose bool
	closeCalls atomic.Int32
}

func (p *lifecycleProvider) Ready(context.Context) error {
	if p.panicReady {
		panic("provider readiness secret must not escape")
	}
	return nil
}

func (*lifecycleProvider) Send(context.Context, ProviderMessage) (ProviderResult, error) {
	return ProviderResult{Disposition: ProviderAccepted}, nil
}

func (p *lifecycleProvider) Close(context.Context) error {
	p.closeCalls.Add(1)
	if p.panicClose {
		panic("provider close secret must not escape")
	}
	return nil
}

func readyCapturingPanic(runtime *Runtime, ctx context.Context) (err error, panicValue any) {
	defer func() { panicValue = recover() }()
	err = runtime.Ready(ctx, notification.ChannelSwitches{Email: true})
	return err, nil
}

func closeCapturingPanic(runtime *Runtime) (err error, panicValue any) {
	defer func() { panicValue = recover() }()
	err = runtime.Close(context.Background())
	return err, nil
}

type blockingReadyProvider struct {
	entered     chan struct{}
	readyExited atomic.Bool
	closed      atomic.Int32
	once        sync.Once
}

func newBlockingReadyProvider() *blockingReadyProvider {
	return &blockingReadyProvider{entered: make(chan struct{})}
}

func (p *blockingReadyProvider) Ready(ctx context.Context) error {
	p.once.Do(func() { close(p.entered) })
	<-ctx.Done()
	p.readyExited.Store(true)
	return ctx.Err()
}

func (*blockingReadyProvider) Send(context.Context, ProviderMessage) (ProviderResult, error) {
	return ProviderResult{Disposition: ProviderAccepted}, nil
}

func (p *blockingReadyProvider) Close(context.Context) error {
	if !p.readyExited.Load() {
		return errors.New("readiness still active")
	}
	p.closed.Add(1)
	return nil
}
