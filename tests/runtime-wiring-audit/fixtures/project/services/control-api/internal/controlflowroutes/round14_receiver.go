package controlflowroutes

import (
	"net/http"

	"fixture/services/control-api/internal/round14holder"
)

var round14SharedMux Registrar
var round14EscapedGlobal func()
var round14EscapeField struct{ Mutator func() }
var round14EscapeMap = map[string]func(){}
var round14EscapeSlice []func()

type round14PureHolder struct {
	Mux Registrar
}

func (holder *round14PureHolder) Observe() {
	_ = holder.Mux
}

func round14MutatorFactory() func() {
	return func() {
		round14SharedMux = nil
	}
}

func round14PureFactory() func() {
	return func() {}
}

func round14StoreMutator(mutator func()) {
	round14EscapedGlobal = mutator
}

func Round14ImportedMethodReset(handler http.Handler) {
	holder := &round14holder.Holder{Mux: http.NewServeMux()}
	defer func() {
		holder.Mux.Handle("/round14-imported-method-reset", handler)
	}()
	done := make(chan struct{})
	go func() {
		holder.Reset()
		close(done)
	}()
	<-done
}

func Round14PureLocalMethod(handler http.Handler) {
	holder := &round14PureHolder{Mux: http.NewServeMux()}
	defer func() {
		holder.Mux.Handle("/round14-pure-local-method", handler)
	}()
	holder.Observe()
}

func Round14FactoryGlobalEscape(handler http.Handler) {
	round14SharedMux = http.NewServeMux()
	defer func() {
		round14SharedMux.Handle("/round14-factory-global", handler)
	}()
	round14EscapedGlobal = round14MutatorFactory()
}

func Round14FactoryFieldEscape(handler http.Handler) {
	round14SharedMux = http.NewServeMux()
	defer func() {
		round14SharedMux.Handle("/round14-factory-field", handler)
	}()
	round14EscapeField.Mutator = round14MutatorFactory()
}

func Round14FactoryIndexEscape(handler http.Handler) {
	round14SharedMux = http.NewServeMux()
	defer func() {
		round14SharedMux.Handle("/round14-factory-index", handler)
	}()
	round14EscapeMap["mutator"] = round14MutatorFactory()
}

func Round14FactoryContainerEscape(handler http.Handler) {
	round14SharedMux = http.NewServeMux()
	defer func() {
		round14SharedMux.Handle("/round14-factory-container", handler)
	}()
	round14EscapeSlice = append(round14EscapeSlice, round14MutatorFactory())
}

func Round14FactoryHelperEscape(handler http.Handler) {
	round14SharedMux = http.NewServeMux()
	defer func() {
		round14SharedMux.Handle("/round14-factory-helper", handler)
	}()
	round14StoreMutator(round14MutatorFactory())
}

func Round14PureFactoryEscape(handler http.Handler) {
	round14SharedMux = http.NewServeMux()
	defer func() {
		round14SharedMux.Handle("/round14-pure-factory", handler)
	}()
	round14EscapedGlobal = round14PureFactory()
}
