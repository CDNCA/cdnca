package dynroute

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/cdnca/cdnca/libs/edgeconfig/edgeskeleton"
	"github.com/cdnca/cdnca/libs/edgeconfig/siteobject"
)

// NodePage is one node page (D13-b2): the global no_host or unknown_site
// error page of a scope, served to requests no site serves, or an error page
// slot page (errpage-3, siteobject.SlotNodePageStatus). Region / NodeID
// restrict it to the nodes of that region or that node (scope overrides).
type NodePage struct {
	Category  string // siteobject.NodePageNoHost / NodePageUnknownSite / a slot
	Status    int
	MIMEType  string
	StyleHash string
	Body      []byte
	Region    string
	NodeID    string
}

// selectNodePages keeps, per category, the page for this node: its own
// (NodeID), else its region's, else the one without a selector; among
// equals the first (scope order) wins. Pages for other nodes or regions drop.
func selectNodePages(pages []NodePage, nodeID, region string) []NodePage {
	rank := func(page NodePage) int {
		switch {
		case page.NodeID != "":
			if page.NodeID == nodeID {
				return 3
			}
			return 0
		case page.Region != "":
			if page.Region == region {
				return 2
			}
			return 0
		default:
			return 1
		}
	}
	best := map[string]int{}
	var order []string
	for index, page := range pages {
		if rank(page) == 0 {
			continue
		}
		current, seen := best[page.Category]
		if !seen {
			order = append(order, page.Category)
			best[page.Category] = index
		} else if rank(page) > rank(pages[current]) {
			best[page.Category] = index
		}
	}
	result := make([]NodePage, 0, len(order))
	for _, category := range order {
		result = append(result, pages[best[category]])
	}
	return result
}

// nodePageRecord is a node page in state.json: its body is the file
// <state>/node-pages/<sha256>.
type nodePageRecord struct {
	Category  string `json:"category"`
	Status    int    `json:"status"`
	MIMEType  string `json:"mime_type"`
	StyleHash string `json:"style_hash,omitempty"`
	SHA256    string `json:"sha256"`
}

const nodePageDirectory = "node-pages"

func (runtime *Runtime) nodePageRoot() string {
	return filepath.Join(runtime.config.StateRoot, nodePageDirectory)
}

// writeNodePages stores the bodies (content addressed) and returns the
// records, one per category. Node pages are platform pages, the same in every
// scope; when scopes differ the first one (by scope order of the input) wins.
func (runtime *Runtime) writeNodePages(pages []NodePage) ([]nodePageRecord, error) {
	seen := map[string]bool{}
	var records []nodePageRecord
	for _, page := range selectNodePages(pages, strings.ToLower(runtime.config.NodeID), runtime.region) {
		if seen[page.Category] {
			continue
		}
		seen[page.Category] = true
		sum := sha256.Sum256(page.Body)
		record := nodePageRecord{Category: page.Category, Status: page.Status, MIMEType: page.MIMEType,
			StyleHash: page.StyleHash, SHA256: hex.EncodeToString(sum[:])}
		if _, err := toSkeletonPage(runtime.nodePageRoot(), record); err != nil {
			return nil, err
		}
		if err := os.MkdirAll(runtime.nodePageRoot(), 0o755); err != nil {
			return nil, err
		}
		path := filepath.Join(runtime.nodePageRoot(), record.SHA256)
		if _, err := os.Stat(path); err != nil {
			temporary := path + ".tmp"
			if err := os.WriteFile(temporary, page.Body, 0o644); err != nil {
				return nil, err
			}
			if err := os.Rename(temporary, path); err != nil {
				return nil, err
			}
		}
		records = append(records, record)
	}
	sort.Slice(records, func(i, j int) bool { return records[i].Category < records[j].Category })
	return records, nil
}

func toSkeletonPage(root string, record nodePageRecord) (*edgeskeleton.NodePage, error) {
	page := &edgeskeleton.NodePage{Status: record.Status, MIMEType: record.MIMEType, StyleHash: record.StyleHash,
		BodyFile: filepath.Join(root, record.SHA256)}
	statuses := edgeskeleton.UnknownSiteStatuses
	switch record.Category {
	case siteobject.NodePageNoHost:
		statuses = []int{400}
	case siteobject.NodePageUnknownSite:
	default:
		status, slot := siteobject.SlotNodePageStatus[record.Category]
		if !slot {
			return nil, fmt.Errorf("node page category %q", record.Category)
		}
		statuses = []int{status}
	}
	for _, status := range statuses {
		if status == record.Status {
			return page, nil
		}
	}
	return nil, fmt.Errorf("node page %s status %d", record.Category, record.Status)
}

// skeletonPages are the skeleton inputs of records (nil when absent).
func (runtime *Runtime) skeletonPages(records []nodePageRecord) (unknown, noHost *edgeskeleton.NodePage,
	slots map[string]*edgeskeleton.NodePage, err error) {
	for _, record := range records {
		page, err := toSkeletonPage(runtime.nodePageRoot(), record)
		if err != nil {
			return nil, nil, nil, err
		}
		switch record.Category {
		case siteobject.NodePageNoHost:
			noHost = page
		case siteobject.NodePageUnknownSite:
			unknown = page
		default:
			if slots == nil {
				slots = map[string]*edgeskeleton.NodePage{}
			}
			slots[record.Category] = page
		}
	}
	return unknown, noHost, slots, nil
}

// retainNodePages removes bodies the active state does not name.
func (runtime *Runtime) retainNodePages() error {
	keep := map[string]bool{}
	for _, record := range runtime.state.NodePages {
		keep[record.SHA256] = true
	}
	entries, err := os.ReadDir(runtime.nodePageRoot())
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if !keep[entry.Name()] {
			if err := os.Remove(filepath.Join(runtime.nodePageRoot(), entry.Name())); err != nil && !os.IsNotExist(err) {
				return err
			}
		}
	}
	return nil
}
