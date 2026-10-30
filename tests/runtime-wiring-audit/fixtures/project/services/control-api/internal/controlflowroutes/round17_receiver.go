package controlflowroutes

import "net/http"

type round17Holder struct {
	Mux Registrar
}

func (holder *round17Holder) Reset() {
	holder.Mux = nil
}

func (holder *round17Holder) SelfNamed() (out *round17Holder) {
	out = holder
	return
}

func (holder *round17Holder) Self() *round17Holder {
	return holder
}

func (holder *round17Holder) NewNamed() (out *round17Holder) {
	out = &round17Holder{Mux: http.NewServeMux()}
	return
}

func round17Pair(holder *round17Holder) (*round17Holder, *round17Holder) {
	return holder, holder
}

func Round17NamedReturnedAlias(handler http.Handler) {
	holder := &round17Holder{Mux: http.NewServeMux()}
	defer func() {
		holder.Mux.Handle("/round17-named-returned-alias", handler)
	}()
	alias := holder.SelfNamed()
	alias.Reset()
}

func Round17OrdinaryReturnedAlias(handler http.Handler) {
	holder := &round17Holder{Mux: http.NewServeMux()}
	defer func() {
		holder.Mux.Handle("/round17-ordinary-returned-alias", handler)
	}()
	alias := holder.Self()
	alias.Reset()
}

func Round17IIFEReturnedAlias(handler http.Handler) {
	holder := &round17Holder{Mux: http.NewServeMux()}
	defer func() {
		holder.Mux.Handle("/round17-iife-returned-alias", handler)
	}()
	alias := func() *round17Holder {
		return holder
	}()
	alias.Reset()
}

func Round17PairReturnedAlias(handler http.Handler) {
	holder := &round17Holder{Mux: http.NewServeMux()}
	defer func() {
		holder.Mux.Handle("/round17-pair-returned-alias", handler)
	}()
	alias, _ := round17Pair(holder)
	alias.Reset()
}

func Round17NamedNewReceiver(handler http.Handler) {
	holder := &round17Holder{Mux: http.NewServeMux()}
	defer func() {
		holder.Mux.Handle("/round17-named-new-receiver", handler)
	}()
	alias := holder.NewNamed()
	alias.Reset()
}
