package controlflowroutes

import "net/http"

type Registrar interface {
	Handle(string, http.Handler)
}

type Registry struct{}

func (*Registry) Handle(string, http.Handler) {}

type Server struct {
	mux *http.ServeMux
}

func TypedParameter(mux *http.ServeMux, handler http.Handler) {
	mux.Handle("/typed-parameter", handler)
}

func (server *Server) TypedField(handler http.Handler) {
	server.mux.Handle("/typed-field", handler)
}

func InterfaceParameter(mux Registrar, handler http.Handler) {
	mux.Handle("/typed-interface", handler)
}

func GotoSkipsInitialization(handler http.Handler) {
	var mux Registrar
	goto register
	mux = http.NewServeMux()
register:
	mux.Handle("/goto-skipped", handler)
}

func DeadBranch(handler http.Handler) {
	mux := http.NewServeMux()
	if false {
		mux.Handle("/dead-branch", handler)
	}
}

func PanicStopsFlow(handler http.Handler) {
	mux := http.NewServeMux()
	panic("stop")
	mux.Handle("/panic-dead", handler)
}

func ConstantSwitch(handler http.Handler) {
	mux := http.NewServeMux()
	switch false {
	case true:
		mux.Handle("/switch-dead", handler)
	}
}

func Direct(handler http.Handler) {
	mux := http.NewServeMux()
	mux.Handle("/cfg-direct", handler)
}

func CaptureLive(handler http.Handler) {
	var mux Registrar = http.NewServeMux()
	register := func() {
		mux.Handle("/capture-live", handler)
	}
	register()
}

func CaptureRebound(handler http.Handler) {
	var mux Registrar = http.NewServeMux()
	register := func() {
		mux.Handle("/capture-rebound", handler)
	}
	mux = &Registry{}
	register()
}

func CaptureDead(handler http.Handler) {
	mux := http.NewServeMux()
	register := func() {
		mux.Handle("/capture-dead", handler)
	}
	_ = register
}

func Immediate(handler http.Handler) {
	mux := http.NewServeMux()
	func() {
		mux.Handle("/capture-iife", handler)
	}()
}

func CaptureWriteInvalidates(handler http.Handler) {
	var mux Registrar = http.NewServeMux()
	rebind := func() {
		mux = &Registry{}
	}
	rebind()
	mux.Handle("/capture-written", handler)
}

func AddressAliasInvalidates(handler http.Handler) {
	var mux Registrar = http.NewServeMux()
	alias := &mux
	*alias = &Registry{}
	mux.Handle("/address-alias", handler)
}

func PriorAddressEscapeInvalidates(handler http.Handler) {
	var mux Registrar
	alias := &mux
	mux = http.NewServeMux()
	*alias = &Registry{}
	mux.Handle("/address-alias-prior", handler)
}

func TypedNilIIFE(handler http.Handler) {
	func(mux *http.ServeMux) {
		mux.Handle("/typed-nil", handler)
	}(nil)
}

func EmptySelectTerminates(handler http.Handler) {
	mux := http.NewServeMux()
	select {}
	mux.Handle("/select-dead", handler)
}

func DeferredCaptureRebound(handler http.Handler) {
	var mux Registrar = http.NewServeMux()
	defer func() {
		mux.Handle("/defer-rebound", handler)
	}()
	mux = &Registry{}
}

func DeferredLocalClosure(handler http.Handler) {
	var mux Registrar = http.NewServeMux()
	register := func() {
		mux.Handle("/defer-local-closure", handler)
	}
	defer register()
	mux = &Registry{}
}

func GoroutineAfterRebind(handler http.Handler) {
	var mux Registrar = http.NewServeMux()
	ready := make(chan struct{})
	done := make(chan struct{})
	go func() {
		<-ready
		mux.Handle("/go-rebound", handler)
		close(done)
	}()
	mux = &Registry{}
	close(ready)
	<-done
}

func DeferredPackageReceiver(handler http.Handler) {
	defer func() {
		http.Handle("/defer-package", handler)
	}()
}

func GoroutinePackageReceiver(handler http.Handler) {
	done := make(chan struct{})
	go func() {
		http.Handle("/go-package", handler)
		close(done)
	}()
	<-done
}

func DirectReceiverAlias(handler http.Handler) {
	mux := http.NewServeMux()
	alias := mux
	alias.Handle("/alias-direct", handler)
}

func ClosureReceiverAlias(handler http.Handler) {
	mux := http.NewServeMux()
	register := func() {
		alias := mux
		alias.Handle("/alias-closure", handler)
	}
	register()
}

func ReceiverMethodValue(handler http.Handler) {
	mux := http.NewServeMux()
	handle := mux.Handle
	handle("/method-value", handler)
}

func DeferredStableLocal(handler http.Handler) {
	mux := http.NewServeMux()
	defer func() {
		mux.Handle("/defer-stable-local", handler)
	}()
}

func DeferredStableReceiver(mux *http.ServeMux, handler http.Handler) {
	defer func() {
		mux.Handle("/defer-stable-receiver", handler)
	}()
}

func DeferredParameterSnapshot(handler http.Handler) {
	var mux Registrar = http.NewServeMux()
	defer func(snapshot Registrar) {
		snapshot.Handle("/defer-parameter-snapshot", handler)
	}(mux)
	mux = &Registry{}
}

func GoroutineWaitedStable(handler http.Handler) {
	mux := http.NewServeMux()
	done := make(chan struct{})
	go func() {
		defer close(done)
		mux.Handle("/go-waited-stable", handler)
	}()
	<-done
}

func VarClosureAliasDeadRebind(handler http.Handler) {
	mux := http.NewServeMux()
	var register = func() {
		mux.Handle("/var-closure-dead-rebind", handler)
	}
	if false {
		register = func() {}
	}
	register()
}

func VarClosureAliasLiveRebind(handler http.Handler) {
	mux := http.NewServeMux()
	var register = func() {
		mux.Handle("/var-closure-live-rebind", handler)
	}
	register = func() {}
	register()
}

func VarClosureAliasFutureRebind(handler http.Handler) {
	mux := http.NewServeMux()
	var register = func() {
		mux.Handle("/var-closure-future-rebind", handler)
	}
	register()
	register = func() {}
}

func VarMethodAliasDeadRebind(handler http.Handler) {
	mux := http.NewServeMux()
	var handle = mux.Handle
	if false {
		handle = (&Registry{}).Handle
	}
	var alias = handle
	alias("/var-method-dead-rebind", handler)
}

func VarMethodAliasLiveRebind(handler http.Handler) {
	mux := http.NewServeMux()
	var handle = mux.Handle
	handle = (&Registry{}).Handle
	var alias = handle
	alias("/var-method-live-rebind", handler)
}

func VarMethodAliasFutureRebind(handler http.Handler) {
	mux := http.NewServeMux()
	var handle = mux.Handle
	var alias = handle
	alias("/var-method-future-rebind", handler)
	alias = (&Registry{}).Handle
}
