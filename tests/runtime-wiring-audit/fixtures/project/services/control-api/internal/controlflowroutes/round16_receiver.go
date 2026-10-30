package controlflowroutes

import "net/http"

type round16Holder struct {
	Mux Registrar
}

func (holder *round16Holder) Reset() {
	holder.Mux = nil
}

func (holder *round16Holder) Observe() {
	_ = holder.Mux
}

func (holder *round16Holder) Self() *round16Holder {
	return holder
}

func (holder *round16Holder) AliasSelf() *round16Holder {
	alias := holder
	return alias
}

func (holder *round16Holder) RecursiveSelf(recurse bool) *round16Holder {
	if recurse {
		return holder.RecursiveSelf(false)
	}
	return holder
}

func (holder *round16Holder) MutualSelfA(recurse bool) *round16Holder {
	if recurse {
		return holder.MutualSelfB(false)
	}
	return holder
}

func (holder *round16Holder) MutualSelfB(recurse bool) *round16Holder {
	if recurse {
		return holder.MutualSelfA(false)
	}
	return holder
}

func Round16ReturnedReceiverAlias(handler http.Handler) {
	holder := &round16Holder{Mux: http.NewServeMux()}
	defer func() {
		holder.Mux.Handle("/round16-returned-receiver-alias", handler)
	}()
	alias := holder.Self()
	alias.Reset()
}

func Round16ReturnedLocalAlias(handler http.Handler) {
	holder := &round16Holder{Mux: http.NewServeMux()}
	defer func() {
		holder.Mux.Handle("/round16-returned-local-alias", handler)
	}()
	alias := holder.AliasSelf()
	alias.Reset()
}

func Round16IIFEReturnedAlias(handler http.Handler) {
	holder := &round16Holder{Mux: http.NewServeMux()}
	defer func() {
		holder.Mux.Handle("/round16-iife-returned-alias", handler)
	}()
	alias := func() *round16Holder {
		return holder
	}()
	alias.Reset()
}

func Round16RecursiveReturnedAlias(handler http.Handler) {
	holder := &round16Holder{Mux: http.NewServeMux()}
	defer func() {
		holder.Mux.Handle("/round16-recursive-returned-alias", handler)
	}()
	alias := holder.RecursiveSelf(true)
	alias.Reset()
}

func Round16MutualReturnedAlias(handler http.Handler) {
	holder := &round16Holder{Mux: http.NewServeMux()}
	defer func() {
		holder.Mux.Handle("/round16-mutual-returned-alias", handler)
	}()
	alias := holder.MutualSelfA(true)
	alias.Reset()
}

func Round16OverwrittenAlias(handler http.Handler) {
	holder := &round16Holder{Mux: http.NewServeMux()}
	defer func() {
		holder.Mux.Handle("/round16-overwritten-alias", handler)
	}()
	alias := holder
	alias = &round16Holder{Mux: http.NewServeMux()}
	alias.Reset()
}

func Round16ShadowedAlias(handler http.Handler) {
	holder := &round16Holder{Mux: http.NewServeMux()}
	defer func() {
		holder.Mux.Handle("/round16-shadowed-alias", handler)
	}()
	alias := holder
	{
		alias := &round16Holder{Mux: http.NewServeMux()}
		alias.Reset()
	}
	alias.Observe()
}

func Round16ObserveMethodValue(handler http.Handler) {
	holder := &round16Holder{Mux: http.NewServeMux()}
	defer func() {
		holder.Mux.Handle("/round16-observe-method-value", handler)
	}()
	observe := holder.Observe
	observe()
}

func Round16AssignedReceive(handler http.Handler, done <-chan struct{}) {
	mux := http.NewServeMux()
	defer func() {
		mux.Handle("/round16-assigned-receive", handler)
	}()
	value := <-done
	_ = value
}

func Round16CommaOKReceive(handler http.Handler, done <-chan struct{}) {
	mux := http.NewServeMux()
	defer func() {
		mux.Handle("/round16-comma-ok-receive", handler)
	}()
	value, ok := <-done
	_, _ = value, ok
}

func Round16ReturnReceive(handler http.Handler, done <-chan bool) bool {
	mux := http.NewServeMux()
	defer func() {
		mux.Handle("/round16-return-receive", handler)
	}()
	return <-done
}

func Round16IfReceive(handler http.Handler, done <-chan bool) {
	mux := http.NewServeMux()
	defer func() {
		mux.Handle("/round16-if-receive", handler)
	}()
	if <-done {
		return
	}
}

func round16Consume(any) {}

func Round16CallArgumentReceive(handler http.Handler, done <-chan struct{}) {
	mux := http.NewServeMux()
	defer func() {
		mux.Handle("/round16-call-argument-receive", handler)
	}()
	round16Consume(<-done)
}

func Round16GoArgumentReceive(handler http.Handler, done <-chan struct{}) {
	mux := http.NewServeMux()
	defer func() {
		mux.Handle("/round16-go-argument-receive", handler)
	}()
	go round16Consume(<-done)
}

func Round16PanicReceive(handler http.Handler, done <-chan struct{}) {
	mux := http.NewServeMux()
	defer func() {
		mux.Handle("/round16-panic-receive", handler)
	}()
	panic(<-done)
}

func Round16ConsumedCompletionReceive(handler http.Handler) {
	mux := http.NewServeMux()
	defer func() {
		mux.Handle("/round16-consumed-completion-receive", handler)
	}()
	done := make(chan struct{})
	go func() {
		done <- struct{}{}
	}()
	<-done
	value := <-done
	_ = value
}

func Round16ProvenLocalReceive(handler http.Handler) {
	mux := http.NewServeMux()
	defer func() {
		mux.Handle("/round16-proven-local-receive", handler)
	}()
	done := make(chan struct{})
	go func() {
		close(done)
	}()
	value := <-done
	_ = value
}
