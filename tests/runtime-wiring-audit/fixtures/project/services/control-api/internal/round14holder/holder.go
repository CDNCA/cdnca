package round14holder

import "net/http"

type Registrar interface {
	Handle(string, http.Handler)
}

type Holder struct {
	Mux Registrar
}

func (holder *Holder) Reset() {
	holder.Mux = nil
}
