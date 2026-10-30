package controlflowroutes

import (
	"net/http"
	"os"
	"runtime"
)

type Round11Waiter interface {
	Wait()
}

func round11BlocksForever() {
	select {}
}

func round11ExitsThroughHelper() {
	os.Exit(0)
}

func Round11DeferredNamedBlock(handler http.Handler) {
	mux := http.NewServeMux()
	register := func() {
		mux.Handle("/adj-defer-named-block", handler)
	}
	defer register()
	round11BlocksForever()
}

func Round11DeferredNamedExit(handler http.Handler) {
	mux := http.NewServeMux()
	register := func() {
		mux.Handle("/adj-defer-named-exit", handler)
	}
	defer register()
	round11ExitsThroughHelper()
}

func Round11DeferredInterfaceMethod(handler http.Handler, dependency Round11Waiter) {
	mux := http.NewServeMux()
	register := func() {
		mux.Handle("/adj-defer-interface-method", handler)
	}
	defer register()
	dependency.Wait()
}

func Round11AfterGoexit(handler http.Handler) {
	mux := http.NewServeMux()
	runtime.Goexit()
	mux.Handle("/adj-after-goexit", handler)
}
