package marketadminproxy

const (
	PermOverviewView = "marketplace.overview.view"
)

var routes = []Route{
	rt("GET", "sellers", "M1", forwarded, q(), PermOverviewView),
	rt("GET", "future", "M9", pending, q(), PermOverviewView),
}
