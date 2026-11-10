//go:build !linux

package packagingtoolset

// watch without inotify: every report stats the files.
type watch struct{}

func newWatch(...string) *watch { return &watch{} }

func (*watch) changed() bool { return true }
