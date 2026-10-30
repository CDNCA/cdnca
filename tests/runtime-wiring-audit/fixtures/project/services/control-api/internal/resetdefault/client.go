package resetdefault

type Dependency interface {
	Ready() bool
}

type Real struct{}

func (Real) Ready() bool { return true }

type Client struct {
	dependency Dependency
}

func NewClient(dependency Dependency) *Client {
	if dependency == nil {
		dependency = &Real{}
	}
	dependency = nil
	return &Client{dependency: dependency}
}
