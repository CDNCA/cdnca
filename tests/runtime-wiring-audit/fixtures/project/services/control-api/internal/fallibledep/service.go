package fallibledep

type Dependency interface{ Ready() bool }

type Real struct{}

func (Real) Ready() bool { return true }

func NewService(Dependency) struct{} { return struct{}{} }
