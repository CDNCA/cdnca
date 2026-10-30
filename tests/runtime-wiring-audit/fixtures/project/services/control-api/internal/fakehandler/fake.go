package fakehandler

type Handler struct{}

func Build() *Handler { return &Handler{} }
