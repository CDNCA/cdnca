package controlflowroutes

import (
	"net/http"
	"os"

	"fixture/services/control-api/internal/aliasruntime"
)

var round9EscapedMutator func()

type round9ClosureHolder struct {
	mutate func()
}

func round9KeepMutator(func()) {}

func Round9GoroutineWorkBeforeClose(handler http.Handler) {
	mux := http.NewServeMux()
	done := make(chan struct{})
	go func() {
		mux.Handle("/round9-go-work-before-close", handler)
		_ = aliasruntime.NewRound9BeforeClose()
		close(done)
	}()
	<-done
}

func Round9GoroutineWorkBeforeSend(handler http.Handler) {
	mux := http.NewServeMux()
	done := make(chan struct{})
	go func() {
		mux.Handle("/round9-go-work-before-send", handler)
		_ = aliasruntime.NewRound9BeforeSend()
		done <- struct{}{}
	}()
	<-done
}

func Round9GoroutineSignalBeforeWork(handler http.Handler) {
	mux := http.NewServeMux()
	done := make(chan struct{})
	go func() {
		close(done)
		mux.Handle("/round9-go-signal-before-work", handler)
		_ = aliasruntime.NewRound9AfterSignal()
	}()
	<-done
}

func Round9GoroutineAlternateEarlySignal(handler http.Handler, early bool) {
	mux := http.NewServeMux()
	done := make(chan struct{})
	go func() {
		if early {
			close(done)
			return
		}
		mux.Handle("/round9-go-alternate-signal", handler)
		close(done)
	}()
	<-done
}

func Round9GoroutineConditionalWork(handler http.Handler, register bool) {
	mux := http.NewServeMux()
	done := make(chan struct{})
	go func() {
		if register {
			mux.Handle("/round9-go-conditional-work", handler)
		}
		close(done)
	}()
	<-done
}

func Round9DeferredGlobalEscape(handler http.Handler) {
	var mux Registrar = http.NewServeMux()
	defer func() {
		mux.Handle("/round9-defer-global-escape", handler)
	}()
	round9EscapedMutator = func() {
		mux = &Registry{}
	}
}

func Round9DeferredSelectorEscape(handler http.Handler) {
	var mux Registrar = http.NewServeMux()
	defer func() {
		mux.Handle("/round9-defer-selector-escape", handler)
	}()
	holder := round9ClosureHolder{}
	holder.mutate = func() {
		mux = &Registry{}
	}
}

func Round9DeferredContainerEscape(handler http.Handler) {
	var mux Registrar = http.NewServeMux()
	defer func() {
		mux.Handle("/round9-defer-container-escape", handler)
	}()
	mutators := make([]func(), 1)
	mutators[0] = func() {
		mux = &Registry{}
	}
}

func Round9DeferredUnknownHelperEscape(handler http.Handler) {
	var mux Registrar = http.NewServeMux()
	defer func() {
		mux.Handle("/round9-defer-helper-escape", handler)
	}()
	round9KeepMutator(func() {
		mux = &Registry{}
	})
}

func Round9DeferredOSExit(handler http.Handler) {
	mux := http.NewServeMux()
	defer func() {
		mux.Handle("/round9-defer-os-exit", handler)
	}()
	os.Exit(1)
}
