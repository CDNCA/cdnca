package nodesshinstall

import (
	"os"
	"regexp"
)

// the console's management root pin, the same value the
// copied install command uses (install-control.sh writes it to
// runtime-config.js as window.__CDNCA_CONTROL_CA_SHA256__; empty for a
// publicly trusted certificate).

var runtimeControlCA = regexp.MustCompile(`(?m)^window\.__CDNCA_CONTROL_CA_SHA256__ = "([0-9a-f]{64})?";$`)

// UseControlCA sets where SSH installs read the pin; it is read for every
// job so a console that changes its certificate needs no restart. Call it
// before Run.
func (service *Service) UseControlCA(digest func() string) { service.controlCA = digest }

func (service *Service) controlCASHA256() string {
	if service.controlCA == nil {
		return ""
	}
	return service.controlCA()
}

// RuntimeControlCA reads the pin from runtime-config.js at path. A missing
// file or line means no pin (system trust): the install then fails closed on
// an untrusted certificate instead of skipping verification.
func RuntimeControlCA(path string) func() string {
	return func() string {
		content, err := os.ReadFile(path)
		if err != nil {
			return ""
		}
		matches := runtimeControlCA.FindAllSubmatch(content, -1)
		if len(matches) != 1 {
			return ""
		}
		return string(matches[0][1])
	}
}
