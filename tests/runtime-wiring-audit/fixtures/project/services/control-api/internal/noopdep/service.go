package noopdep

type Dependency interface{ Ready() bool }

type NoopDependency struct{}

func (NoopDependency) Ready() bool { return true }

func NewNoop() Dependency { return NoopDependency{} }

func NewService(Dependency) struct{} { return struct{}{} }
