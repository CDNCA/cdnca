package analyticslog

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func TestRuntimeHTTPClientCapsPerHostTransportCapacity(t *testing.T) {
	entered := make(chan struct{}, 11)
	release := make(chan struct{})
	var releaseOnce sync.Once
	releaseAll := func() { releaseOnce.Do(func() { close(release) }) }
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		entered <- struct{}{}
		<-release
		writer.WriteHeader(http.StatusNoContent)
	}))

	client := newRuntimeHTTPClient(time.Second, 5*time.Second, nil)
	t.Cleanup(func() {
		releaseAll()
		client.CloseIdleConnections()
		server.Close()
	})
	var requests sync.WaitGroup
	requests.Add(11)
	for i := 0; i < 11; i++ {
		go func() {
			defer requests.Done()
			response, err := client.Get(server.URL)
			if err == nil && response != nil {
				_ = response.Body.Close()
			}
		}()
	}

	for i := 0; i < 10; i++ {
		select {
		case <-entered:
		case <-time.After(time.Second):
			t.Fatalf("only %d handlers entered while filling transport capacity", i)
		}
	}
	select {
	case <-entered:
		t.Fatal("11th request entered before one of the first 10 handlers was released")
	case <-time.After(100 * time.Millisecond):
	}

	releaseAll()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("11th request did not enter after transport capacity was released")
	}
	requests.Wait()
}
