package controlflowroutes

import "net/http"

var round13SharedMux Registrar

func round13ResetSharedMux() {
	round13SharedMux = nil
}

type round13Holder struct {
	mux Registrar
}

func (holder *round13Holder) Reset() {
	holder.mux = nil
}

func round13SharedMutatorFactory() func() {
	return func() {
		round13SharedMux = nil
	}
}

func round13PureHelper() {}

func round13Helper01() {}
func round13Helper02() { round13Helper01() }
func round13Helper03() { round13Helper02() }
func round13Helper04() { round13Helper03() }
func round13Helper05() { round13Helper04() }
func round13Helper06() { round13Helper05() }
func round13Helper07() { round13Helper06() }
func round13Helper08() { round13Helper07() }
func round13Helper09() { round13Helper08() }
func round13Helper10() { round13Helper09() }
func round13Helper11() { round13Helper10() }
func round13Helper12() { round13Helper11() }
func round13Helper13() { round13Helper12() }
func round13Helper14() { round13Helper13() }
func round13Helper15() { round13Helper14() }
func round13Helper16() { round13Helper15() }
func round13Helper17() { round13Helper16() }

func Round13DeferredSharedReset(handler http.Handler) {
	round13SharedMux = http.NewServeMux()
	defer func() {
		round13SharedMux.Handle("/round13-defer-shared-reset", handler)
	}()
	round13ResetSharedMux()
}

func Round13DeferredConcreteMethodReset(handler http.Handler) {
	holder := &round13Holder{mux: http.NewServeMux()}
	defer func() {
		holder.mux.Handle("/round13-defer-method-reset", handler)
	}()
	holder.Reset()
}

func Round13DeferredGoFactoryMutator(handler http.Handler) {
	round13SharedMux = http.NewServeMux()
	defer func() {
		round13SharedMux.Handle("/round13-defer-go-factory", handler)
	}()
	done := make(chan struct{})
	go func() {
		round13SharedMutatorFactory()()
		close(done)
	}()
	<-done
}

func Round13DeferredPureHelper(handler http.Handler) {
	mux := http.NewServeMux()
	defer func() {
		mux.Handle("/round13-defer-pure-helper", handler)
	}()
	round13PureHelper()
}

func Round13DeferredHelperDepth16(handler http.Handler) {
	mux := http.NewServeMux()
	defer func() {
		mux.Handle("/round13-helper-depth-16", handler)
	}()
	round13Helper16()
}

func Round13DeferredHelperDepth17(handler http.Handler) {
	mux := http.NewServeMux()
	defer func() {
		mux.Handle("/round13-helper-depth-17", handler)
	}()
	round13Helper17()
}
