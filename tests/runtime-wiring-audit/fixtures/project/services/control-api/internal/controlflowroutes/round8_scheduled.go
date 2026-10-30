package controlflowroutes

import "net/http"

func Round8GoroutineDirectReceive(handler http.Handler) {
	mux := http.NewServeMux()
	done := make(chan struct{})
	go func() {
		mux.Handle("/round8-go-direct", handler)
		close(done)
	}()
	<-done
}

func Round8GoroutineSelectDefault(handler http.Handler) {
	mux := http.NewServeMux()
	done := make(chan struct{})
	go func() {
		mux.Handle("/round8-go-select-default", handler)
		close(done)
	}()
	select {
	case <-done:
	default:
	}
}

func Round8GoroutineCompetingCase(handler http.Handler) {
	mux := http.NewServeMux()
	done := make(chan struct{})
	other := make(chan struct{})
	go func() {
		mux.Handle("/round8-go-competing", handler)
		close(done)
	}()
	select {
	case <-done:
	case <-other:
	}
}

func Round8DeferredExplicitReturn(handler http.Handler) {
	mux := http.NewServeMux()
	defer func() {
		mux.Handle("/round8-defer-return", handler)
	}()
	return
}

func Round8DeferredSelectNeverReturns(handler http.Handler) {
	mux := http.NewServeMux()
	defer func() {
		mux.Handle("/round8-defer-select", handler)
	}()
	select {}
}

func Round8DeferredInfiniteLoop(handler http.Handler) {
	mux := http.NewServeMux()
	defer func() {
		mux.Handle("/round8-defer-loop", handler)
	}()
	for {
	}
}

func Round8DeadLocalMutator(handler http.Handler) {
	var mux Registrar = http.NewServeMux()
	mutate := func() {
		mux = &Registry{}
	}
	_ = mutate
	mux.Handle("/round8-dead-mutator", handler)
}

func Round8ParenthesizedRoutes(handler http.Handler) {
	mux := http.NewServeMux()
	register := (func() {
		mux.Handle("/round8-paren-closure", handler)
	})
	alias := (register)
	(alias)()

	var handle = (mux.Handle)
	(handle)("/round8-paren-method", handler)

	(func() {
		mux.Handle("/round8-paren-iife", handler)
	})()
}
