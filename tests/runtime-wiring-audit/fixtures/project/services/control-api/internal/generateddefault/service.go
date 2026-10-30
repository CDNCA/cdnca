package generateddefault

type Dependency interface{ Ready() bool }

type GeneratedMock struct{}

func (GeneratedMock) Ready() bool { return true }

func NewGeneratedMock() Dependency { return GeneratedMock{} }

func NewService(Dependency) struct{} { return struct{}{} }
