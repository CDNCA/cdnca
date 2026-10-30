//go:build !linux && !darwin

package enrollment

import "errors"

func renameNoReplace(string, string) error {
	return errors.New("atomic no-replace directory rename is unsupported on this platform")
}
