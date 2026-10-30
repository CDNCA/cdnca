//go:build !unix

package rulepackvault

import "os"

// Nodes run Linux; elsewhere the owner is unknown.
func ownerUID(os.FileInfo) (int, bool) { return 0, false }
