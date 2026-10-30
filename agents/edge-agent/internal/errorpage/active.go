package errorpage

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

// ActiveRuntime is the error page policy a site runtime renders: the Lua
// policy and, per site key ("" is global), the statuses that have a site
// page (node pages, no_host and unknown_site, are not counted).
type ActiveRuntime struct {
	Digest     string
	RuntimeLua []byte
	Statuses   map[string][]int
	// UnknownSiteStatus is the status of the global unknown_site page (a
	// request for a host no site serves: the default servers), 0 for none.
	UnknownSiteStatus int
}

// SiteStatuses is the sorted union of a site's own and the global statuses.
func (active ActiveRuntime) SiteStatuses(siteKey string) []int {
	seen := make(map[int]struct{})
	for _, key := range []string{"", siteKey} {
		for _, status := range active.Statuses[key] {
			seen[status] = struct{}{}
		}
	}
	result := make([]int, 0, len(seen))
	for status := range seen {
		result = append(result, status)
	}
	sort.Ints(result)
	return result
}

// ReadActiveRuntime reads the publisher's current release without its lock:
// the site runtime calls it while the publisher activates, and the current
// pointer only ever names a complete, immutable release.
func ReadActiveRuntime(stateRoot string) (ActiveRuntime, bool, error) {
	if !cleanAbsolutePath(stateRoot) {
		return ActiveRuntime{}, false, invalidPolicy("error page state root is invalid")
	}
	parent, err := openDirectoryPathNoSymlink(filepath.Dir(stateRoot))
	if errors.Is(err, os.ErrNotExist) {
		return ActiveRuntime{}, false, nil
	} else if err != nil {
		return ActiveRuntime{}, false, err
	}
	root, err := openOwnedDirectoryAt(parent, filepath.Base(stateRoot), 0o700, false)
	_ = parent.Close()
	if errors.Is(err, os.ErrNotExist) {
		return ActiveRuntime{}, false, nil
	} else if err != nil {
		return ActiveRuntime{}, false, err
	}
	defer root.Close()
	versions, err := openOwnedDirectoryAt(root, "versions", 0o700, false)
	if errors.Is(err, os.ErrNotExist) {
		return ActiveRuntime{}, false, nil
	} else if err != nil {
		return ActiveRuntime{}, false, err
	}
	defer versions.Close()
	state := &publisherState{root: root, versions: versions}
	publisher := &Publisher{stateRoot: stateRoot}
	target, manifest, found, err := publisher.readPointer(state, "current")
	if err != nil || !found {
		return ActiveRuntime{}, false, err
	}
	release, err := openOwnedDirectoryAt(versions, manifest.Digest, 0o500, false)
	if err != nil {
		return ActiveRuntime{}, false, fmt.Errorf("open current error page release %s: %w", target, err)
	}
	defer release.Close()
	policyJSON, err := readImmutableAt(release, "policy.json")
	if err != nil {
		return ActiveRuntime{}, false, err
	}
	runtimeLua, err := readImmutableAt(release, "policy.lua")
	if err != nil {
		return ActiveRuntime{}, false, err
	}
	var policy canonicalPolicy
	if err := json.Unmarshal(policyJSON, &policy); err != nil {
		return ActiveRuntime{}, false, fmt.Errorf("decode current error page policy: %w", err)
	}
	active := ActiveRuntime{Digest: manifest.Digest, RuntimeLua: runtimeLua, Statuses: make(map[string][]int)}
	seen := make(map[string]map[int]struct{})
	for _, binding := range policy.Bindings {
		// no_host and unknown_site answer requests no site serves: they are
		// never a site's statuses (they would intercept a site's own origin
		// responses with that code).
		if binding.Category == CategoryUnknownSite {
			active.UnknownSiteStatus = binding.Status
			continue
		}
		if binding.Category == CategoryNoHost {
			continue
		}
		if seen[binding.SiteKey] == nil {
			seen[binding.SiteKey] = make(map[int]struct{})
		}
		if _, exists := seen[binding.SiteKey][binding.Status]; !exists {
			seen[binding.SiteKey][binding.Status] = struct{}{}
			active.Statuses[binding.SiteKey] = append(active.Statuses[binding.SiteKey], binding.Status)
		}
	}
	for key := range active.Statuses {
		sort.Ints(active.Statuses[key])
	}
	return active, true, nil
}
