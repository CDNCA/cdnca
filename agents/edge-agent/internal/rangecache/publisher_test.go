package rangecache

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

type fakeRuntime struct {
	mu           sync.Mutex
	precheckFail string
	reloadFail   string
	healthFail   string
	reloads      []string
	stops        int
}

func (runtime *fakeRuntime) Precheck(_ context.Context, config string) error {
	if strings.Contains(readConfig(config), runtime.precheckFail) && runtime.precheckFail != "" {
		return errors.New("injected precheck failure")
	}
	return nil
}

func (runtime *fakeRuntime) Reload(_ context.Context, config string) error {
	value := readConfig(config)
	version := configVersion(value)
	runtime.mu.Lock()
	runtime.reloads = append(runtime.reloads, version)
	runtime.mu.Unlock()
	if strings.Contains(value, runtime.reloadFail) && runtime.reloadFail != "" {
		return errors.New("injected reload failure")
	}
	return nil
}

func (runtime *fakeRuntime) Healthy(_ context.Context, config string) error {
	if strings.Contains(readConfig(config), runtime.healthFail) && runtime.healthFail != "" {
		return errors.New("injected health failure")
	}
	return nil
}

func (runtime *fakeRuntime) Stop(_ context.Context, _ string) error {
	runtime.mu.Lock()
	runtime.stops++
	runtime.mu.Unlock()
	return nil
}

func TestPublisherKeepsLKGOnBadPolicyAndRuntimeFailures(t *testing.T) {
	runtime := &fakeRuntime{}
	publisher := newTestPublisher(t, runtime)
	first, err := publisher.ApplyJSON(context.Background(), validPolicyJSON(1, oneSite("v1.test")))
	if err != nil {
		t.Fatal(err)
	}
	if !first.Changed || first.PolicyVersion != 1 {
		t.Fatalf("first publication = %+v", first)
	}
	assertActiveVersion(t, publisher, 1)

	if _, err := publisher.ApplyJSON(context.Background(), []byte(`{"schema_version":"bad"}`)); !errors.Is(err, ErrInvalidPolicy) {
		t.Fatalf("bad policy error = %v", err)
	}
	assertActiveVersion(t, publisher, 1)

	runtime.precheckFail = "version=2"
	if _, err := publisher.ApplyJSON(context.Background(), validPolicyJSON(2, oneSite("v2.test"))); !errors.Is(err, ErrPrecheck) {
		t.Fatalf("precheck error = %v", err)
	}
	assertActiveVersion(t, publisher, 1)
	runtime.precheckFail = ""

	runtime.reloadFail = "version=3"
	if _, err := publisher.ApplyJSON(context.Background(), validPolicyJSON(3, oneSite("v3.test"))); !errors.Is(err, ErrReload) {
		t.Fatalf("reload error = %v", err)
	}
	assertActiveVersion(t, publisher, 1)
	if got := strings.Join(runtime.reloads, ","); got != "1,3,1" {
		t.Fatalf("reload sequence = %s", got)
	}
	runtime.reloadFail = ""

	runtime.healthFail = "version=4"
	if _, err := publisher.ApplyJSON(context.Background(), validPolicyJSON(4, oneSite("v4.test"))); !errors.Is(err, ErrHealth) {
		t.Fatalf("health error = %v", err)
	}
	assertActiveVersion(t, publisher, 1)
	if got := strings.Join(runtime.reloads, ","); got != "1,3,1,4,1" {
		t.Fatalf("reload sequence after health failure = %s", got)
	}
}

func TestPublisherStopsRuntimeWhenInitialHealthCheckFails(t *testing.T) {
	runtime := &fakeRuntime{healthFail: "version=1"}
	publisher := newTestPublisher(t, runtime)
	if _, err := publisher.ApplyJSON(context.Background(), validPolicyJSON(1, oneSite("v1.test"))); !errors.Is(err, ErrHealth) {
		t.Fatalf("health error = %v", err)
	}
	if _, err := publisher.CurrentConfig(); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("current config error = %v, want os.ErrNotExist", err)
	}
	if _, err := publisher.LKGConfig(); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("LKG config error = %v, want os.ErrNotExist", err)
	}
	if runtime.stops != 1 {
		t.Fatalf("stop calls = %d, want 1", runtime.stops)
	}
}

func TestPublisherIsIdempotentAndMonotonic(t *testing.T) {
	publisher := newTestPublisher(t, &fakeRuntime{})
	policy := validPolicyJSON(1, oneSite("one.test"))
	first, err := publisher.ApplyJSON(context.Background(), policy)
	if err != nil {
		t.Fatal(err)
	}
	second, err := publisher.ApplyJSON(context.Background(), policy)
	if err != nil {
		t.Fatal(err)
	}
	if !first.Changed || second.Changed || first.Digest != second.Digest {
		t.Fatalf("idempotency first=%+v second=%+v", first, second)
	}
	if _, err := publisher.ApplyJSON(context.Background(), validPolicyJSON(1, oneSite("changed.test"))); !errors.Is(err, ErrInvalidPolicy) {
		t.Fatalf("same-version conflict error = %v", err)
	}
	if _, err := publisher.ApplyJSON(context.Background(), validPolicyJSON(2, oneSite("two.test"))); err != nil {
		t.Fatal(err)
	}
	if _, err := publisher.ApplyJSON(context.Background(), policy); !errors.Is(err, ErrInvalidPolicy) {
		t.Fatalf("version regression error = %v", err)
	}
	assertActiveVersion(t, publisher, 2)
}

func TestPublisherSerializesConcurrentReadersAndWriters(t *testing.T) {
	publisher := newTestPublisher(t, &fakeRuntime{})
	if _, err := publisher.ApplyJSON(context.Background(), validPolicyJSON(1, oneSite("one.test"))); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	readerErrors := make(chan error, 4)
	var readers sync.WaitGroup
	for index := 0; index < 4; index++ {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for {
				select {
				case <-done:
					return
				default:
				}
				path, err := publisher.CurrentConfig()
				if err != nil {
					readerErrors <- err
					return
				}
				if !strings.Contains(readConfig(path), "generated by cdnca") {
					readerErrors <- errors.New("reader observed invalid config")
					return
				}
			}
		}()
	}
	for version := uint64(2); version <= 12; version++ {
		if _, err := publisher.ApplyJSON(context.Background(), validPolicyJSON(version, oneSite("edge.test"))); err != nil {
			t.Fatal(err)
		}
	}
	close(done)
	readers.Wait()
	close(readerErrors)
	for err := range readerErrors {
		t.Fatal(err)
	}
	assertActiveVersion(t, publisher, 12)
}

func newTestPublisher(t *testing.T, runtime Runtime) *Publisher {
	t.Helper()
	root := filepath.Join(t.TempDir(), "policy")
	t.Cleanup(func() {
		_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err == nil && info.IsDir() {
				_ = os.Chmod(path, 0o700)
			}
			return nil
		})
	})
	state := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(state, 0o700); err != nil {
		t.Fatal(err)
	}
	publisher, err := NewPublisher(root, RuntimePaths{StateRoot: state, LuaRoot: "/opt/cdnca-range"}, runtime)
	if err != nil {
		t.Fatal(err)
	}
	return publisher
}

func assertActiveVersion(t *testing.T, publisher *Publisher, version uint64) {
	t.Helper()
	current, err := publisher.CurrentConfig()
	if err != nil {
		t.Fatal(err)
	}
	lkg, err := publisher.LKGConfig()
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{current, lkg} {
		if got := configVersion(readConfig(path)); got != uintString(version) {
			t.Fatalf("%s version = %s, want %d", path, got, version)
		}
	}
}

func readConfig(path string) string {
	content, err := os.ReadFile(path)
	if err != nil {
		panic(err)
	}
	return string(content)
}

func configVersion(config string) string {
	marker := "version="
	start := strings.Index(config, marker)
	if start < 0 {
		return ""
	}
	start += len(marker)
	end := strings.IndexByte(config[start:], '\n')
	if end < 0 {
		return config[start:]
	}
	return config[start : start+end]
}

func oneSite(host string) string {
	return `[{"site_id":"site","listen_address":"127.0.0.1","listen_port":18086,"hosts":["` + host + `"],"origin_host":"127.0.0.1","origin_port":18090}]`
}
