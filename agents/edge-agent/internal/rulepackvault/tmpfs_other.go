//go:build !linux

package rulepackvault

// Nodes run Linux; elsewhere no directory counts as tmpfs.
func isTmpfs(string) (bool, error) { return false, nil }
