package nilescape

type Dependency interface {
	Ready() bool
}

type Real struct{}

func (*Real) Ready() bool { return true }

type Client struct {
	dependency Dependency
}

func NewImmediateClient(dependency Dependency) *Client {
	if dependency == nil {
		dependency = &Real{}
	}
	func() {
		dependency = nil
	}()
	return &Client{dependency: dependency}
}

func NewClosureClient(dependency Dependency) *Client {
	if dependency == nil {
		dependency = &Real{}
	}
	reset := func() {
		dependency = nil
	}
	reset()
	return &Client{dependency: dependency}
}

func NewAliasClient(dependency Dependency) *Client {
	if dependency == nil {
		dependency = &Real{}
	}
	alias := &dependency
	*alias = nil
	return &Client{dependency: dependency}
}

func clearDependency(dependency *Dependency) {
	*dependency = nil
}

func NewHelperClient(dependency Dependency) *Client {
	if dependency == nil {
		dependency = &Real{}
	}
	clearDependency(&dependency)
	return &Client{dependency: dependency}
}
