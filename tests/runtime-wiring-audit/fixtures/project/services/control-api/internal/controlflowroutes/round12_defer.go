package controlflowroutes

import (
	"net/http"
	"os"
)

func round12BlocksForever() {
	select {}
}

func round12BlockedValue() any {
	select {}
}

func round12ExitValue() any {
	os.Exit(0)
	return nil
}

func round12PureValue() any {
	return "pure"
}

func round12NestedPureValue() any {
	return round12PureValue()
}

func round12EmptyHelper() {}

func round12RecursiveHelper() {
	round12RecursiveHelper()
}

func round12AcceptValue(any) {}

func Round12PanicBlockedArgument(handler http.Handler) {
	mux := http.NewServeMux()
	register := func() {
		mux.Handle("/round12-panic-blocked-argument", handler)
	}
	defer register()
	panic(round12BlockedValue())
}

func Round12PanicExitArgument(handler http.Handler) {
	mux := http.NewServeMux()
	register := func() {
		mux.Handle("/round12-panic-exit-argument", handler)
	}
	defer register()
	panic(round12ExitValue())
}

func Round12PanicLiteral(handler http.Handler) {
	mux := http.NewServeMux()
	register := func() {
		mux.Handle("/round12-panic-literal", handler)
	}
	defer register()
	panic("literal")
}

func Round12PanicPureHelper(handler http.Handler) {
	mux := http.NewServeMux()
	register := func() {
		mux.Handle("/round12-panic-pure-helper", handler)
	}
	defer register()
	panic(round12PureValue())
}

func Round12PanicNestedPureHelper(handler http.Handler) {
	mux := http.NewServeMux()
	register := func() {
		mux.Handle("/round12-panic-nested-helper", handler)
	}
	defer register()
	panic(round12NestedPureValue())
}

func Round12PanicConversionBuiltin(handler http.Handler) {
	mux := http.NewServeMux()
	register := func() {
		mux.Handle("/round12-panic-conversion-builtin", handler)
	}
	defer register()
	panic(string(rune(len("x"))))
}

func Round12GoNamedBlockingCallee(handler http.Handler) {
	mux := http.NewServeMux()
	register := func() {
		mux.Handle("/round12-go-named-block", handler)
	}
	defer register()
	go round12BlocksForever()
}

func Round12GoBlockingIIFE(handler http.Handler) {
	mux := http.NewServeMux()
	register := func() {
		mux.Handle("/round12-go-iife-block", handler)
	}
	defer register()
	go func() {
		select {}
	}()
}

func Round12GoBlockedArgument(handler http.Handler) {
	mux := http.NewServeMux()
	register := func() {
		mux.Handle("/round12-go-blocked-argument", handler)
	}
	defer register()
	go round12AcceptValue(round12BlockedValue())
}

func Round12SimpleHelperReturns(handler http.Handler) {
	mux := http.NewServeMux()
	register := func() {
		mux.Handle("/round12-simple-helper", handler)
	}
	defer register()
	round12EmptyHelper()
}

func Round12RecursiveHelperUnknown(handler http.Handler) {
	mux := http.NewServeMux()
	register := func() {
		mux.Handle("/round12-recursive-helper", handler)
	}
	defer register()
	round12RecursiveHelper()
}
