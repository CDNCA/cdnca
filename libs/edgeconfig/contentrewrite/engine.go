package contentrewrite

import (
	"bytes"
	"regexp"
	"slices"
	"strings"
)

// MaxTag is the longest HTML tag the link stage rewrites.
const MaxTag = 4096

// rawHold: a CSS/JS chunk keeps its last bytes when they may start
// "https:/" (7 bytes) split by the chunk boundary.
const rawHold = 7

// AttributePattern tokenizes a tag's attributes: name, separator, value
// (cdnca_rewrite.lua uses the same text; \s is spelled out, PCRE's \s also
// has \v).
const AttributePattern = `([^\t\n\f\r "'>/=]+)(?:([\t\n\f\r ]*=[\t\n\f\r ]*)("[^"]*"|'[^']*'|[^\t\n\f\r "'>]+))?`

var attributeRE = regexp.MustCompile(AttributePattern)

var urlAttributes = map[string]bool{"href": true, "src": true, "srcset": true, "action": true}

type stage interface {
	write(data []byte, eof bool) []byte
	take() []byte
}

// Stream is one response's rewrite: Write each chunk in order (eof on the
// last); input beyond MaxBytes passes through unchanged.
type Stream struct {
	stages       []stage
	limit        int64
	consumed     int64
	passthrough  bool
	Truncated    bool
	Replacements int
}

// NewStream builds the pipeline of the active node rules (Node.Active):
// one link stage (link and https rules merged, the first rule naming a host
// wins) then one stage per replace rule in order.
func NewStream(node *Node, active []int, typeKey string) *Stream {
	stream := &Stream{limit: node.MaxBytes}
	link := &linkStage{html: typeKey == "html", hosts: map[string]LinkTarget{}, exact: map[string]bool{}, count: &stream.Replacements}
	replaces := []stage{}
	for _, index := range active {
		rule := node.Rules[index]
		switch rule.Kind {
		case KindLink:
			for host, target := range rule.Map {
				if _, ok := link.hosts[host]; !ok {
					link.hosts[host] = target
				}
			}
		case KindHTTPS:
			for _, host := range rule.Hosts {
				if suffix, ok := strings.CutPrefix(host, "*."); ok {
					link.suffixes = append(link.suffixes, "."+suffix)
				} else {
					link.exact[host] = true
				}
			}
		case KindReplace:
			stage := &replaceStage{literal: []byte(rule.Literal), template: parseTemplate(rule.Replace), count: &stream.Replacements}
			if rule.Pattern != "" {
				stage.literal, stage.re, stage.maxLen = nil, regexp.MustCompile(rule.Pattern), rule.MaxLen
			}
			replaces = append(replaces, stage)
		}
	}
	if len(link.hosts) > 0 || len(link.exact) > 0 || len(link.suffixes) > 0 {
		stream.stages = append(stream.stages, link)
	}
	stream.stages = append(stream.stages, replaces...)
	return stream
}

func (s *Stream) Write(chunk []byte, eof bool) []byte {
	if s.passthrough {
		return chunk
	}
	var rest []byte
	if s.consumed+int64(len(chunk)) > s.limit {
		cut := s.limit - s.consumed
		chunk, rest = chunk[:cut], chunk[cut:]
		s.Truncated = true
	}
	s.consumed += int64(len(chunk))
	data := chunk
	for _, stage := range s.stages {
		data = stage.write(data, eof && rest == nil)
	}
	if rest == nil {
		return data
	}
	// over the limit: what each stage still holds came after what it passed
	// on, so the last stage's comes first
	s.passthrough = true
	out := slices.Clone(data)
	for index := len(s.stages) - 1; index >= 0; index-- {
		out = append(out, s.stages[index].take()...)
	}
	return append(out, rest...)
}

// ---------------------------------------------------------------- replace

type replaceStage struct {
	literal  []byte
	re       *regexp.Regexp
	maxLen   int
	template []segment
	hold     []byte
	count    *int
}

func (r *replaceStage) take() []byte {
	held := r.hold
	r.hold = nil
	return held
}

// write: a match is final when its start plus the longest match is inside
// the data (no anchors, so nothing beyond decides it); the bytes from the
// first undecided start on wait for the next chunk.
func (r *replaceStage) write(chunk []byte, eof bool) []byte {
	data := append(r.take(), chunk...)
	n, pos := len(data), 0
	var out []byte
	keep := len(r.literal) - 1
	if r.re != nil {
		keep = r.maxLen - 1
	}
	for pos < n {
		var start, end int
		var groups []int
		if r.re == nil {
			at := bytes.Index(data[pos:], r.literal)
			if at < 0 {
				break
			}
			start, end = pos+at, pos+at+len(r.literal)
		} else {
			groups = r.re.FindSubmatchIndex(data[pos:])
			if groups == nil {
				break
			}
			start, end = pos+groups[0], pos+groups[1]
			if !eof && start+r.maxLen > n {
				break
			}
		}
		out = append(out, data[pos:start]...)
		if r.re == nil {
			out = append(out, expand(r.template, nil, nil, 0)...)
		} else {
			out = append(out, expand(r.template, data, groups, pos)...)
		}
		*r.count++
		pos = end
	}
	cut := n
	if !eof {
		cut = max(pos, n-keep)
	}
	out = append(out, data[pos:cut]...)
	r.hold = slices.Clone(data[cut:])
	return out
}

func expand(template []segment, data []byte, groups []int, base int) []byte {
	var out []byte
	for _, part := range template {
		if part.group < 0 {
			out = append(out, part.text...)
			continue
		}
		if 2*part.group+1 < len(groups) && groups[2*part.group] >= 0 {
			out = append(out, data[base+groups[2*part.group]:base+groups[2*part.group+1]]...)
		}
	}
	return out
}

// ---------------------------------------------------------------- links

type linkStage struct {
	html     bool
	hosts    map[string]LinkTarget
	exact    map[string]bool
	suffixes []string
	hold     []byte
	count    *int
}

func (l *linkStage) take() []byte {
	held := l.hold
	l.hold = nil
	return held
}

func (l *linkStage) write(chunk []byte, eof bool) []byte {
	data := append(l.take(), chunk...)
	var out []byte
	var cut int
	if l.html {
		out, cut = l.writeHTML(data, eof)
	} else {
		out, cut = l.writeRaw(data, eof)
	}
	l.hold = slices.Clone(data[cut:])
	return out
}

func isHostByte(value byte) bool {
	return 'a' <= value && value <= 'z' || 'A' <= value && value <= 'Z' || '0' <= value && value <= '9' || value == '-' || value == '.'
}

func isLetter(value byte) bool { return 'a' <= value && value <= 'z' || 'A' <= value && value <= 'Z' }

// hostEnd: the end of the host run from start (at most 253 bytes, one
// trailing dot left out); ok false when the run is longer, or reaches the
// end of data before eof (more may follow).
func hostEnd(data []byte, start int, eof bool) (end int, ok bool, more bool) {
	end = start
	for end < len(data) && end-start <= 253 && isHostByte(data[end]) {
		end++
	}
	if end-start > 253 {
		return end, false, false
	}
	if end == len(data) && !eof {
		return end, false, true
	}
	if end > start && data[end-1] == '.' {
		end--
	}
	if end == start || end < len(data) && (data[end] == ':' || data[end] == '@') {
		return end, false, false
	}
	return end, true, false
}

// rewrite: the new scheme://host (scheme "" is protocol-relative and stays
// so) and whether anything changed.
func (l *linkStage) rewrite(scheme, host string) (string, bool) {
	newScheme, newHost := scheme, host
	if target, ok := l.hosts[strings.ToLower(host)]; ok {
		newHost = target.Host
		if scheme != "" && target.Scheme != SchemeKeep {
			newScheme = target.Scheme
		}
	}
	if strings.EqualFold(newScheme, "http") && !strings.Contains(newHost, ":") && l.forceHTTPS(strings.ToLower(newHost)) {
		newScheme = "https"
	}
	if newScheme == scheme && newHost == host {
		return "", false
	}
	if newScheme == "" {
		return "//" + newHost, true
	}
	return newScheme + "://" + newHost, true
}

func (l *linkStage) forceHTTPS(host string) bool {
	if l.exact[host] {
		return true
	}
	for _, suffix := range l.suffixes {
		if len(host) > len(suffix) && strings.HasSuffix(host, suffix) {
			return true
		}
	}
	return false
}

// writeRaw (CSS, JS): explicit http:// and https:// URLs in the text.
func (l *linkStage) writeRaw(data []byte, eof bool) ([]byte, int) {
	n, pos, search := len(data), 0, 0
	var out []byte
	for {
		at := bytes.Index(data[search:], []byte("://"))
		if at < 0 {
			break
		}
		at += search
		start := -1
		if at-5 >= pos && strings.EqualFold(string(data[at-5:at]), "https") {
			start = at - 5
		} else if at-4 >= pos && strings.EqualFold(string(data[at-4:at]), "http") {
			start = at - 4
		}
		if start < 0 {
			search = at + 1
			continue
		}
		end, ok, more := hostEnd(data, at+3, eof)
		if more {
			out = append(out, data[pos:start]...)
			return out, start
		}
		if ok {
			if value, changed := l.rewrite(string(data[start:at]), string(data[at+3:end])); changed {
				out = append(out, data[pos:start]...)
				out = append(out, value...)
				pos = end
				*l.count++
			}
		}
		search = max(end, at+3)
	}
	cut := n
	if !eof {
		cut = max(pos, n-(rawHold-1))
	}
	out = append(out, data[pos:cut]...)
	return out, cut
}

// writeHTML: tags "<letter ... >" up to MaxTag bytes; an unfinished tag
// waits for the next chunk.
func (l *linkStage) writeHTML(data []byte, eof bool) ([]byte, int) {
	n, pos, index, gt := len(data), 0, 0, -2
	var out []byte
	for {
		at := bytes.IndexByte(data[index:], '<')
		if at < 0 {
			break
		}
		lt := index + at
		if lt+1 >= n {
			if !eof {
				out = append(out, data[pos:lt]...)
				return out, lt
			}
			break
		}
		if !isLetter(data[lt+1]) {
			index = lt + 1
			continue
		}
		if gt != -1 && gt <= lt {
			if found := bytes.IndexByte(data[lt+1:], '>'); found < 0 {
				gt = -1
			} else {
				gt = lt + 1 + found
			}
		}
		if gt == -1 {
			if !eof && n-lt < MaxTag {
				out = append(out, data[pos:lt]...)
				return out, lt
			}
			index = lt + 1
			continue
		}
		if gt-lt+1 > MaxTag {
			index = lt + 1
			continue
		}
		if tag := data[lt : gt+1]; bytes.Contains(tag, []byte("//")) {
			if value, changed := l.rewriteTag(tag); changed {
				out = append(out, data[pos:lt]...)
				out = append(out, value...)
				pos = gt + 1
			}
		}
		index = gt + 1
	}
	out = append(out, data[pos:]...)
	return out, n
}

func (l *linkStage) rewriteTag(tag []byte) ([]byte, bool) {
	var out []byte
	pos, changed := 0, false
	for _, match := range attributeRE.FindAllSubmatchIndex(tag[1:], -1) {
		if match[6] < 0 {
			continue
		}
		name := strings.ToLower(string(tag[1+match[2] : 1+match[3]]))
		if !urlAttributes[name] {
			continue
		}
		start, end := 1+match[6], 1+match[7]
		if quote := tag[start]; quote == '"' || quote == '\'' {
			start, end = start+1, end-1
		}
		value, ok := l.rewriteValue(string(tag[start:end]), name == "srcset")
		if !ok {
			continue
		}
		out = append(out, tag[pos:start]...)
		out = append(out, value...)
		pos, changed = end, true
	}
	if !changed {
		return nil, false
	}
	return append(out, tag[pos:]...), true
}

func isSpace(value byte) bool {
	return value == ' ' || value == '\t' || value == '\n' || value == '\f' || value == '\r'
}

// rewriteValue: the URL at the start of the value (and, in srcset, after
// each comma), leading white space skipped.
func (l *linkStage) rewriteValue(value string, srcset bool) (string, bool) {
	var out strings.Builder
	pos, changed := 0, false
	candidate := 0
	for candidate <= len(value) {
		for candidate < len(value) && isSpace(value[candidate]) {
			candidate++
		}
		scheme, hostStart := "", -1
		rest := value[candidate:]
		switch {
		case len(rest) >= 8 && strings.EqualFold(rest[:8], "https://"):
			scheme, hostStart = rest[:5], candidate+8
		case len(rest) >= 7 && strings.EqualFold(rest[:7], "http://"):
			scheme, hostStart = rest[:4], candidate+7
		case strings.HasPrefix(rest, "//"):
			hostStart = candidate + 2
		}
		if hostStart >= 0 {
			if end, ok, _ := hostEnd([]byte(value), hostStart, true); ok {
				if replaced, did := l.rewrite(scheme, value[hostStart:end]); did {
					out.WriteString(value[pos:candidate])
					out.WriteString(replaced)
					pos, changed = end, true
					*l.count++
				}
			}
		}
		if !srcset {
			break
		}
		from := max(candidate, pos)
		comma := strings.IndexByte(value[from:], ',')
		if comma < 0 {
			break
		}
		candidate = from + comma + 1
	}
	if !changed {
		return "", false
	}
	out.WriteString(value[pos:])
	return out.String(), true
}
