package controlflowroutes

import (
	"net/http"
	"runtime"

	"fixture/services/control-api/internal/aliasruntime"
)

func Round10ConditionalEarlySignal(handler http.Handler, early bool) {
	mux := http.NewServeMux()
	done := make(chan struct{}, 2)
	go func() {
		if early {
			done <- struct{}{}
		}
		mux.Handle("/round10-conditional-early-signal", handler)
		_ = aliasruntime.NewRound10AfterPossibleSignal()
		done <- struct{}{}
	}()
	<-done
}

func Round10WorkBeforeMultipleSignals(handler http.Handler, extra bool) {
	mux := http.NewServeMux()
	done := make(chan struct{}, 2)
	go func() {
		mux.Handle("/round10-work-before-multiple-signals", handler)
		_ = aliasruntime.NewRound10BeforeSignals()
		if extra {
			done <- struct{}{}
		}
		done <- struct{}{}
	}()
	<-done
}

func Round10ExhaustiveSignalsConservative(handler http.Handler, left bool) {
	mux := http.NewServeMux()
	done := make(chan struct{}, 1)
	go func() {
		mux.Handle("/round10-exhaustive-signals-boundary", handler)
		if left {
			done <- struct{}{}
		} else {
			done <- struct{}{}
		}
	}()
	<-done
}

func Round10ChannelAliasConservative(handler http.Handler) {
	mux := http.NewServeMux()
	done := make(chan struct{}, 1)
	signal := done
	go func() {
		mux.Handle("/round10-channel-alias-boundary", handler)
		signal <- struct{}{}
	}()
	<-done
}

func Round10DeferredMapCompositeEscape(handler http.Handler) {
	var mux Registrar = http.NewServeMux()
	defer func() {
		mux.Handle("/round10-defer-map-composite", handler)
	}()
	mutate := func() {
		mux = &Registry{}
	}
	mutators := map[string]func(){"mutate": mutate}
	_ = mutators
}

func Round10DeferredSliceCompositeEscape(handler http.Handler) {
	var mux Registrar = http.NewServeMux()
	defer func() {
		mux.Handle("/round10-defer-slice-composite", handler)
	}()
	mutate := func() {
		mux = &Registry{}
	}
	mutators := []func(){mutate}
	_ = mutators
}

func Round10DeferredIIFEWrapper(handler http.Handler) {
	var mux Registrar = http.NewServeMux()
	defer func() {
		mux.Handle("/round10-defer-iife-wrapper", handler)
	}()
	mutate := func() {
		mux = &Registry{}
	}
	func() {
		mutate()
	}()
}

func Round10DeferredGoroutineWrapper(handler http.Handler) {
	var mux Registrar = http.NewServeMux()
	defer func() {
		mux.Handle("/round10-defer-goroutine-wrapper", handler)
	}()
	mutate := func() {
		mux = &Registry{}
	}
	done := make(chan struct{})
	go func() {
		mutate()
		close(done)
	}()
	<-done
}

func Round10DeferredUnknownParameter(handler http.Handler, maybeNeverReturns func()) {
	mux := http.NewServeMux()
	defer func() {
		mux.Handle("/round10-defer-unknown-param", handler)
	}()
	maybeNeverReturns()
}

func Round10DeferredGoexit(handler http.Handler) {
	mux := http.NewServeMux()
	defer func() {
		mux.Handle("/round10-defer-goexit", handler)
	}()
	runtime.Goexit()
}
