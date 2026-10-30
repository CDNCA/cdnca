package firewall

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/netip"
	"strings"
)

const (
	allowIPv4Set = "allow_v4"
	allowIPv6Set = "allow_v6"
	denyIPv4Set  = "deny_v4"
	denyIPv6Set  = "deny_v6"
	// dropLogLimit is the table's one named limit every logged drop shares:
	// under an attack from many banned addresses the kernel log (and the
	// KernelHitSource reading it) sees at most this many lines a second, not
	// one per dropped packet. nft `limit` is a match, so each drop is two
	// rules: the first counts, logs within the limit and drops; packets over
	// the limit fall through to the second, which drops without logging.
	dropLogLimit     = "cdnca_drop_log"
	DropLogRate      = 20
	DropLogRateBurst = 40
)

// writeLoggedDrop writes the two rules of one logged drop (see dropLogLimit).
// A non-empty comment is written as the rules' nft comment.
func writeLoggedDrop(output *strings.Builder, expression, prefix string, comment ...string) {
	suffix := ""
	if len(comment) > 0 && comment[0] != "" {
		suffix = fmt.Sprintf(" comment %q", comment[0])
	}
	fmt.Fprintf(output, "add rule %s %s input %s counter limit name %q log prefix %q drop%s\n", TableFamily, TableName, expression, dropLogLimit, prefix, suffix)
	fmt.Fprintf(output, "add rule %s %s input %s drop%s\n", TableFamily, TableName, expression, suffix)
}

func Compile(version FirewallVersion) (CompiledVersion, error) {
	normalized, digest, err := normalize(version)
	if err != nil {
		return CompiledVersion{}, err
	}
	return compileNormalized(normalized, digest), nil
}

func compileNormalized(version FirewallVersion, digest string) CompiledVersion {
	sets := map[string][]string{
		allowIPv4Set: nil,
		allowIPv6Set: nil,
		denyIPv4Set:  nil,
		denyIPv6Set:  nil,
	}
	seen := map[string]map[string]struct{}{
		allowIPv4Set: {}, allowIPv6Set: {}, denyIPv4Set: {}, denyIPv6Set: {},
	}
	for _, entry := range version.Entries {
		if entry.Protocol != ProtocolAny {
			continue
		}
		prefix := netip.MustParsePrefix(entry.Network)
		name := denyIPv4Set
		if entry.Action == ActionAllow {
			name = allowIPv4Set
		}
		if prefix.Addr().Is6() {
			if entry.Action == ActionAllow {
				name = allowIPv6Set
			} else {
				name = denyIPv6Set
			}
		}
		if _, exists := seen[name][entry.Network]; !exists {
			seen[name][entry.Network] = struct{}{}
			sets[name] = append(sets[name], entry.Network)
		}
	}
	var output strings.Builder
	fmt.Fprintf(&output, "destroy table %s %s\n", TableFamily, TableName)
	fmt.Fprintf(&output, "add table %s %s { comment \"%s\"; }\n", TableFamily, TableName, tableVersionComment(version.VersionID, digest))
	for _, set := range []struct {
		name, valueType string
	}{
		{allowIPv4Set, "ipv4_addr"},
		{allowIPv6Set, "ipv6_addr"},
		{denyIPv4Set, "ipv4_addr"},
		{denyIPv6Set, "ipv6_addr"},
	} {
		fmt.Fprintf(&output, "add set %s %s %s { type %s; flags interval; auto-merge; }\n", TableFamily, TableName, set.name, set.valueType)
		if len(sets[set.name]) > 0 {
			fmt.Fprintf(&output, "add element %s %s %s { %s }\n", TableFamily, TableName, set.name, strings.Join(sets[set.name], ", "))
		}
	}
	groups := scopedGroups(version.Entries)
	for _, group := range groups {
		fmt.Fprintf(&output, "add set %s %s %s { type %s; flags interval; auto-merge; }\n", TableFamily, TableName, group.set(), group.valueType())
		fmt.Fprintf(&output, "add element %s %s %s { %s }\n", TableFamily, TableName, group.set(), strings.Join(group.networks, ", "))
	}
	fmt.Fprintf(&output, "add limit %s %s %s { rate %d/second burst %d packets; }\n", TableFamily, TableName, dropLogLimit, DropLogRate, DropLogRateBurst)
	fmt.Fprintf(&output, "add chain %s %s input { type filter hook input priority -10; policy accept; }\n", TableFamily, TableName)
	fmt.Fprintf(&output, "add rule %s %s input ip saddr @%s accept\n", TableFamily, TableName, allowIPv4Set)
	fmt.Fprintf(&output, "add rule %s %s input ip6 saddr @%s accept\n", TableFamily, TableName, allowIPv6Set)
	for _, group := range groups {
		if group.key.action == ActionAllow {
			fmt.Fprintf(&output, "add rule %s %s input %s accept\n", TableFamily, TableName, group.expression())
		}
	}
	for _, group := range groups {
		if group.key.action != ActionDeny {
			continue
		}
		if group.key.source == "" {
			writeLoggedDrop(&output, group.expression(), fmt.Sprintf("cdnca-fw g%d", group.index))
			continue
		}
		// Kernel bans name their source (cc_ban / waf_ban / security_ban) in
		// the rule comment and the drop log.
		writeLoggedDrop(&output, group.expression(), fmt.Sprintf("cdnca-fw g%d %s ", group.index, group.key.source), group.key.source)
	}
	writeLoggedDrop(&output, "ip saddr @"+denyIPv4Set, "cdnca-fw ipset")
	writeLoggedDrop(&output, "ip6 saddr @"+denyIPv6Set, "cdnca-fw ipset")
	return CompiledVersion{Version: version, Digest: digest, Batch: []byte(output.String())}
}

// maxTableComment is nftables' limit on a table comment
// (NFTNL_UDATA_COMMENT_MAXLEN); nft --check refuses a longer one.
const maxTableComment = 128

// tableVersionComment names the applied version in the table comment, which
// the manager compares to know what the kernel runs. A scoped version ID
// ("runtime-" + a UUID) with the digest exceeds the limit, so every scoped
// batch was refused by nft; such versions are named by a hash of both
// instead. Comments that fit keep their text, so tables already applied
// still match.
func tableVersionComment(versionID, digest string) string {
	comment := "cdnca version=" + versionID + " digest=" + digest
	if len(comment) <= maxTableComment {
		return comment
	}
	sum := sha256.Sum256([]byte(versionID + "\x00" + digest))
	return "cdnca version-digest=" + hex.EncodeToString(sum[:])
}

// scopedGroupKey is what a protocol-scoped entry matches besides its source
// network. Entries sharing it become one address set and one rule (one per
// action), so thousands of kernel bans on a stream's or site's ports cost one
// set lookup, not a linear walk over thousands of rules.
type scopedGroupKey struct {
	action     Action
	ipv6       bool
	protocol   Protocol
	start, end uint16
	// source: a kernel ban source (banSourceKinds), else empty.
	source string
}

type scopedGroup struct {
	key      scopedGroupKey
	index    int
	networks []string
}

// scopedGroups groups the protocol-scoped entries in entry order (the hit
// log marker "g<index>" names a group).
func scopedGroups(entries []Entry) []scopedGroup {
	var groups []scopedGroup
	positions := map[scopedGroupKey]int{}
	seen := map[scopedGroupKey]map[string]struct{}{}
	for _, entry := range entries {
		if entry.Protocol == ProtocolAny {
			continue
		}
		key := entryGroupKey(entry)
		position, exists := positions[key]
		if !exists {
			position = len(groups)
			positions[key] = position
			seen[key] = map[string]struct{}{}
			groups = append(groups, scopedGroup{key: key, index: position + 1})
		}
		if _, duplicate := seen[key][entry.Network]; !duplicate {
			seen[key][entry.Network] = struct{}{}
			groups[position].networks = append(groups[position].networks, entry.Network)
		}
	}
	return groups
}

func entryGroupKey(entry Entry) scopedGroupKey {
	key := scopedGroupKey{action: entry.Action, ipv6: netip.MustParsePrefix(entry.Network).Addr().Is6(),
		protocol: entry.Protocol, start: entry.PortStart, end: entry.PortEnd}
	if entry.Action == ActionDeny && banSourceKinds[entry.Source] {
		key.source = entry.Source
	}
	return key
}

func (group scopedGroup) set() string { return fmt.Sprintf("scoped_%d", group.index) }

func (group scopedGroup) valueType() string {
	if group.key.ipv6 {
		return "ipv6_addr"
	}
	return "ipv4_addr"
}

func (group scopedGroup) expression() string {
	family := "ip"
	if group.key.ipv6 {
		family = "ip6"
	}
	address := family + " saddr @" + group.set()
	switch group.key.protocol {
	case ProtocolTCP, ProtocolUDP:
		if group.key.start == 0 {
			return address + " meta l4proto " + string(group.key.protocol)
		}
		if group.key.end != group.key.start {
			return fmt.Sprintf("%s %s dport %d-%d", address, group.key.protocol, group.key.start, group.key.end)
		}
		return fmt.Sprintf("%s %s dport %d", address, group.key.protocol, group.key.start)
	case ProtocolICMP:
		if group.key.ipv6 {
			return address + " meta l4proto ipv6-icmp"
		}
		return address + " meta l4proto icmp"
	default:
		return address
	}
}

func deleteBatch() []byte {
	return []byte(fmt.Sprintf("destroy table %s %s\n", TableFamily, TableName))
}
