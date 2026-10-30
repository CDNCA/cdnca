package main

import "testing"

func TestRound18SelectDefaultReceiveIsNonBlocking(t *testing.T) {
	const source = `package routes

import "net/http"

func register(handler http.Handler, ready <-chan struct{}) {
	mux := http.NewServeMux()
	defer func() {
		mux.Handle("/round18-select-default-receive", handler)
	}()
	select {
	case <-ready:
	default:
	}
}

func registerSend(handler http.Handler, ready chan<- struct{}) {
	mux := http.NewServeMux()
	defer func() {
		mux.Handle("/round18-select-default-send", handler)
	}()
	select {
	case ready <- struct{}{}:
	default:
	}
}
`
	if !round18HasRoute(t, source, "/round18-select-default-receive") {
		t.Fatal("non-blocking select receive prevented a deferred route proof")
	}
	if !round18HasRoute(t, source, "/round18-select-default-send") {
		t.Fatal("non-blocking select send prevented a deferred route proof")
	}
}

func TestRound18SelectCommunicationEvaluationRemainsBlocking(t *testing.T) {
	const source = `package routes

import "net/http"

func registerSendValue(handler http.Handler, out chan<- struct{}, in <-chan struct{}) {
	mux := http.NewServeMux()
	defer func() {
		mux.Handle("/round18-select-send-value-receive", handler)
	}()
	select {
	case out <- <-in:
	default:
	}
}

func registerReceiveChannel(handler http.Handler, channels <-chan (<-chan struct{})) {
	mux := http.NewServeMux()
	defer func() {
		mux.Handle("/round18-select-receive-channel-receive", handler)
	}()
	select {
	case <-(<-channels):
	default:
	}
}
`
	for _, path := range []string{
		"/round18-select-send-value-receive",
		"/round18-select-receive-channel-receive",
	} {
		if round18HasRoute(t, source, path) {
			t.Errorf("select operand evaluation became a proven route: %s", path)
		}
	}
}

func TestRound18DeadBranchReceiveDoesNotBlockDeferredRoute(t *testing.T) {
	const source = `package routes

import "net/http"

func register(handler http.Handler, ready <-chan struct{}) {
	mux := http.NewServeMux()
	defer func() {
		mux.Handle("/round18-dead-branch-receive", handler)
	}()
	if false {
		<-ready
	}
}
`
	if !round18HasRoute(t, source, "/round18-dead-branch-receive") {
		t.Fatal("unreachable receive prevented a deferred route proof")
	}
}

func TestRound18KilledReturnedAliasDoesNotInvalidateDeferredRoute(t *testing.T) {
	const source = `package routes

import "net/http"

type routeHolder struct {
	Mux *http.ServeMux
}

func (self *routeHolder) Reset() {
	self.Mux = nil
}

func (self *routeHolder) Distinct() *routeHolder {
	alias := self
	alias = &routeHolder{Mux: http.NewServeMux()}
	return alias
}

func register(handler http.Handler) {
	holder := &routeHolder{Mux: http.NewServeMux()}
	defer func() {
		holder.Mux.Handle("/round18-killed-returned-alias", handler)
	}()
	alias := holder.Distinct()
	alias.Reset()
}
`
	if !round18HasRoute(t, source, "/round18-killed-returned-alias") {
		t.Fatal("killed returned alias invalidated the original receiver")
	}
}

func TestRound18KilledCalleeAliasDoesNotInvalidateDeferredRoute(t *testing.T) {
	const source = `package routes

import "net/http"

type routeHolder struct {
	Mux *http.ServeMux
}

func (self *routeHolder) Reset() {
	self.Mux = nil
}

func (self *routeHolder) ResetDistinct() {
	alias := self
	alias = &routeHolder{Mux: http.NewServeMux()}
	alias.Reset()
}

func register(handler http.Handler) {
	holder := &routeHolder{Mux: http.NewServeMux()}
	defer func() {
		holder.Mux.Handle("/round18-killed-callee-alias", handler)
	}()
	holder.ResetDistinct()
}
`
	if !round18HasRoute(t, source, "/round18-killed-callee-alias") {
		t.Fatal("killed callee alias invalidated the original receiver")
	}
}

func TestRound18KilledReceiverBindingDoesNotInvalidateDeferredRoute(t *testing.T) {
	const source = `package routes

import "net/http"

type routeHolder struct {
	Mux *http.ServeMux
}

func (self *routeHolder) Reset() {
	self.Mux = nil
}

func (self *routeHolder) ResetDistinct() {
	self = &routeHolder{Mux: http.NewServeMux()}
	self.Reset()
}

func register(handler http.Handler) {
	holder := &routeHolder{Mux: http.NewServeMux()}
	defer func() {
		holder.Mux.Handle("/round18-killed-receiver-binding", handler)
	}()
	holder.ResetDistinct()
}
`
	if !round18HasRoute(t, source, "/round18-killed-receiver-binding") {
		t.Fatal("killed receiver binding invalidated the original receiver")
	}
}

func TestRound18BranchMayAliasStillInvalidatesDeferredRoute(t *testing.T) {
	const source = `package routes

import "net/http"

type routeHolder struct {
	Mux *http.ServeMux
}

func (self *routeHolder) Reset() {
	self.Mux = nil
}

func (self *routeHolder) MaybeDistinct(distinct bool) *routeHolder {
	alias := self
	if distinct {
		alias = &routeHolder{Mux: http.NewServeMux()}
	}
	return alias
}

func register(handler http.Handler, distinct bool) {
	holder := &routeHolder{Mux: http.NewServeMux()}
	defer func() {
		holder.Mux.Handle("/round18-branch-may-alias", handler)
	}()
	alias := holder.MaybeDistinct(distinct)
	alias.Reset()
}
`
	if round18HasRoute(t, source, "/round18-branch-may-alias") {
		t.Fatal("branch that may preserve the receiver alias was proven stable")
	}
}

func TestRound18PackageReceiverSideEffectRemainsRejected(t *testing.T) {
	const source = `package routes

import "net/http"

var sharedMux *http.ServeMux

func resetSharedMux() {
	sharedMux = nil
}

func register(handler http.Handler) {
	sharedMux = http.NewServeMux()
	defer func() {
		sharedMux.Handle("/round18-package-receiver-reset", handler)
	}()
	resetSharedMux()
}
`
	if round18HasRoute(t, source, "/round18-package-receiver-reset") {
		t.Fatal("package receiver side effect was proven stable")
	}
}

func TestRound18OuterClosureKilledAliasDoesNotInvalidateDeferredRoute(t *testing.T) {
	const source = `package routes

import "net/http"

type routeHolder struct {
	Mux *http.ServeMux
}

func (self *routeHolder) Reset() {
	self.Mux = nil
}

func register(handler http.Handler) {
	root := &routeHolder{Mux: http.NewServeMux()}
	returnDistinct := func() *routeHolder {
		alias := root
		alias = &routeHolder{Mux: http.NewServeMux()}
		return alias
	}
	defer func() {
		root.Mux.Handle("/round18-outer-closure-killed-alias", handler)
	}()
	alias := func() *routeHolder {
		return returnDistinct()
	}()
	alias.Reset()
}
`
	if !round18HasRoute(t, source, "/round18-outer-closure-killed-alias") {
		t.Fatal("outer closure killed alias invalidated the original receiver")
	}
}

func TestRound18OuterClosureMayAliasRemainsRejected(t *testing.T) {
	const source = `package routes

import "net/http"

type routeHolder struct {
	Mux *http.ServeMux
}

func (self *routeHolder) Reset() {
	self.Mux = nil
}

func register(handler http.Handler) {
	root := &routeHolder{Mux: http.NewServeMux()}
	returnAlias := func() *routeHolder {
		return root
	}
	defer func() {
		root.Mux.Handle("/round18-outer-closure-may-alias", handler)
	}()
	alias := func() *routeHolder {
		return returnAlias()
	}()
	alias.Reset()
}
`
	if round18HasRoute(t, source, "/round18-outer-closure-may-alias") {
		t.Fatal("outer closure returned alias was proven stable")
	}
}

func TestRound18RecursiveOuterClosureDoesNotProveDeferredExecution(t *testing.T) {
	const source = `package routes

import "net/http"

func register(handler http.Handler) {
	mux := http.NewServeMux()
	var recurse func()
	recurse = func() {
		recurse()
	}
	defer func() {
		mux.Handle("/round18-recursive-outer-closure", handler)
	}()
	func() {
		recurse()
	}()
}
`
	if round18HasRoute(t, source, "/round18-recursive-outer-closure") {
		t.Fatal("recursive outer closure was proven to return")
	}
}

func round18HasRoute(t *testing.T, source, path string) bool {
	t.Helper()
	fact := parseGoFact("services/control-api/internal/round18/routes.go", []byte(source))
	if fact.ParseError != "" {
		t.Fatal(fact.ParseError)
	}
	for _, route := range fact.Routes {
		if route.Path == path {
			return true
		}
	}
	return false
}
