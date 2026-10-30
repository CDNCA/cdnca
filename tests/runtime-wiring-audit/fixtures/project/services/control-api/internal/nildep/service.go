package nildep

type Dependency interface{ Ready() bool }

func NewService(Dependency) struct{} { return struct{}{} }
