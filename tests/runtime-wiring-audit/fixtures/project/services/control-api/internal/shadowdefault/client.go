package shadowdefault

type Dependency interface {
	Ready() bool
}

type Real struct{}

func (*Real) Ready() bool { return true }

type Client struct {
	dependency Dependency
}

func NewShortClient(dependency Dependency) *Client {
	if dependency == nil {
		dependency, ok := &Real{}, true
		_ = dependency
		_ = ok
	}
	return &Client{dependency: dependency}
}

func NewIfInitClient(dependency Dependency) *Client {
	if dependency := dependency; dependency == nil {
		dependency = &Real{}
	}
	return &Client{dependency: dependency}
}
