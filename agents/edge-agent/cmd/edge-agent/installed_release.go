package main

import (
	"bufio"
	"io"
	"os"
	"strconv"
	"strings"
)

// installedReleaseManifestPath is the signed release manifest of the running
// install (packaging lib.sh: current -> versions/<version>).
const installedReleaseManifestPath = "/usr/lib/cdnca-edge-agent/current/manifest"

// installedReleaseSequence reads release_sequence (line 2) of the installed
// release manifest for the SAME_VERSION_UPGRADE report. 0 when
// it cannot be read: the node then does not declare the capability.
// Informational only; the root helper re-verifies the signed manifest.
func installedReleaseSequence(path string) uint64 {
	file, err := os.Open(path)
	if err != nil {
		return 0
	}
	defer file.Close()
	return parseInstalledReleaseSequence(io.LimitReader(file, 64*1024))
}

func parseInstalledReleaseSequence(reader io.Reader) uint64 {
	scanner := bufio.NewScanner(reader)
	for line := 1; scanner.Scan() && line <= 2; line++ {
		value, found := strings.CutPrefix(scanner.Text(), "release_sequence=")
		if line == 2 && found {
			sequence, err := strconv.ParseUint(value, 10, 64)
			if err != nil || strconv.FormatUint(sequence, 10) != value {
				return 0
			}
			return sequence
		}
	}
	return 0
}
