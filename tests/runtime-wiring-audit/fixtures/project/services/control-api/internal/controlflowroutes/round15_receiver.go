package controlflowroutes

import "net/http"

type round15Holder struct {
	Mux Registrar
}

func (holder *round15Holder) Reset() {
	holder.Mux = nil
}

func (holder *round15Holder) ResetViaAlias() {
	alias := holder
	alias.Mux = nil
}

func (holder *round15Holder) ObserveViaAlias() {
	alias := holder
	_ = alias.Mux
}

func round15ResetWrapper(holder *round15Holder) {
	alias := holder
	alias.Reset()
}

var round15PackageHolder *round15Holder
var round15PackageField struct{ Holder *round15Holder }
var round15PackageMap = map[string]*round15Holder{}

func Round15DirectAliasReset(handler http.Handler) {
	holder := &round15Holder{Mux: http.NewServeMux()}
	defer func() {
		holder.Mux.Handle("/round15-direct-alias-reset", handler)
	}()
	alias := holder
	alias.Reset()
}

func Round15MethodAliasReset(handler http.Handler) {
	holder := &round15Holder{Mux: http.NewServeMux()}
	defer func() {
		holder.Mux.Handle("/round15-method-alias-reset", handler)
	}()
	holder.ResetViaAlias()
}

func Round15WrapperAliasReset(handler http.Handler) {
	holder := &round15Holder{Mux: http.NewServeMux()}
	defer func() {
		holder.Mux.Handle("/round15-wrapper-alias-reset", handler)
	}()
	round15ResetWrapper(holder)
}

func Round15SliceAliasReset(handler http.Handler) {
	holder := &round15Holder{Mux: http.NewServeMux()}
	defer func() {
		holder.Mux.Handle("/round15-slice-alias-reset", handler)
	}()
	aliases := []*round15Holder{holder}
	aliases[0].Reset()
}

func Round15FieldAliasReset(handler http.Handler) {
	holder := &round15Holder{Mux: http.NewServeMux()}
	defer func() {
		holder.Mux.Handle("/round15-field-alias-reset", handler)
	}()
	wrapper := struct{ Holder *round15Holder }{Holder: holder}
	wrapper.Holder.Reset()
}

func Round15PackageAliasEscape(handler http.Handler) {
	holder := &round15Holder{Mux: http.NewServeMux()}
	defer func() {
		holder.Mux.Handle("/round15-package-alias-escape", handler)
	}()
	round15PackageHolder = holder
}

func Round15PackageFieldAliasEscape(handler http.Handler) {
	holder := &round15Holder{Mux: http.NewServeMux()}
	defer func() {
		holder.Mux.Handle("/round15-package-field-alias-escape", handler)
	}()
	round15PackageField.Holder = holder
}

func Round15PackageMapAliasEscape(handler http.Handler) {
	holder := &round15Holder{Mux: http.NewServeMux()}
	defer func() {
		holder.Mux.Handle("/round15-package-map-alias-escape", handler)
	}()
	round15PackageMap["holder"] = holder
}

func Round15AmbiguousClosureGo(handler http.Handler, mutate bool) {
	holder := &round15Holder{Mux: http.NewServeMux()}
	defer func() {
		holder.Mux.Handle("/round15-ambiguous-closure-go", handler)
	}()
	run := func() {
		holder.ObserveViaAlias()
	}
	if mutate {
		run = func() {
			alias := holder
			alias.Reset()
		}
	}
	go run()
}

func Round15PureObserveAlias(handler http.Handler) {
	holder := &round15Holder{Mux: http.NewServeMux()}
	defer func() {
		holder.Mux.Handle("/round15-pure-observe-alias", handler)
	}()
	alias := holder
	alias.ObserveViaAlias()
}

func Round15BareReceive(handler http.Handler, done <-chan struct{}) {
	mux := http.NewServeMux()
	defer func() {
		mux.Handle("/round15-bare-receive", handler)
	}()
	<-done
}

func Round15BareSend(handler http.Handler, done chan<- struct{}) {
	mux := http.NewServeMux()
	defer func() {
		mux.Handle("/round15-bare-send", handler)
	}()
	done <- struct{}{}
}

func Round15ProvenLocalSynchronization(handler http.Handler) {
	mux := http.NewServeMux()
	defer func() {
		mux.Handle("/round15-proven-local-sync", handler)
	}()
	done := make(chan struct{})
	go func() {
		close(done)
	}()
	<-done
}

func Round15DeadRecursiveClosure(handler http.Handler) {
	mux := http.NewServeMux()
	var recurse func()
	recurse = func() {
		recurse()
	}
	_ = recurse
	mux.Handle("/round15-dead-recursive-closure", handler)
}
