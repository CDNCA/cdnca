//go:build !linux

package firewall

func newSystemRunner(string) (Runner, error) {
	return nil, ErrUnsupported
}
