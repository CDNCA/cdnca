//go:build !darwin && !linux

package updater

import "errors"

func availableDiskBytes(string) (uint64, error) {
	return 0, errors.New("disk capacity checks are unsupported on this platform")
}

func regularLinkCount(any) (uint64, bool) { return 0, false }
