package dnsproviderlive

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"runtime"
	"strings"
	"unicode"
	"unicode/utf8"
	"unsafe"
)

const (
	maxDNSMessageSize = 65535
	maxTXTValueSize   = 4096
	maxNegativeTTL    = 7 * 24 * 60 * 60
)

var (
	ErrDNSUnavailable        = errors.New("dns_live_dns_unavailable")
	ErrDNSInvalidResponse    = errors.New("dns_live_dns_invalid_response")
	ErrCredentialUnavailable = errors.New("dns_live_credential_unavailable")
)

type dnsExchange func(context.Context, string, Endpoint, []byte) ([]byte, error)

type WireDNS struct {
	exchange dnsExchange
	random   io.Reader
}

func NewWireDNS() *WireDNS {
	return newWireDNS(exchangeDNS, rand.Reader)
}

func newWireDNS(exchange dnsExchange, random io.Reader) *WireDNS {
	return &WireDNS{exchange: exchange, random: random}
}

func (d *WireDNS) LookupTXT(ctx context.Context, endpoint Endpoint, owner string) (TXTObservation, error) {
	if ctx == nil {
		return TXTObservation{}, ErrDNSUnavailable
	}
	if err := ctx.Err(); err != nil {
		return TXTObservation{}, err
	}
	if d == nil || d.exchange == nil || d.random == nil || !validEndpoint(endpoint) {
		return TXTObservation{}, ErrDNSUnavailable
	}
	question, err := encodeDNSName(owner)
	if err != nil {
		return TXTObservation{}, ErrDNSUnavailable
	}
	idBytes := make([]byte, 2)
	if _, err := io.ReadFull(d.random, idBytes); err != nil {
		zero(idBytes)
		return TXTObservation{}, ErrDNSUnavailable
	}
	id := binary.BigEndian.Uint16(idBytes)
	zero(idBytes)
	request := make([]byte, 12, 12+len(question)+4)
	binary.BigEndian.PutUint16(request[0:2], id)
	binary.BigEndian.PutUint16(request[2:4], 0x0100)
	binary.BigEndian.PutUint16(request[4:6], 1)
	request = append(request, question...)
	request = binary.BigEndian.AppendUint16(request, 16)
	request = binary.BigEndian.AppendUint16(request, 1)

	response, err := d.exchange(ctx, "udp", endpoint, request)
	if err != nil {
		return TXTObservation{}, classifyDNSError(ctx)
	}
	if isTruncatedResponse(request, response, owner) {
		response, err = d.exchange(ctx, "tcp", endpoint, request)
		if err != nil {
			return TXTObservation{}, classifyDNSError(ctx)
		}
	}
	return parseTXTResponse(request, response, owner)
}

func classifyDNSError(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return ErrDNSUnavailable
}

func validEndpoint(endpoint Endpoint) bool {
	return endpoint.Address.IsValid() && endpoint.Address.Port() != 0 &&
		!endpoint.Address.Addr().IsUnspecified() && !endpoint.Address.Addr().IsMulticast()
}

func encodeDNSName(owner string) ([]byte, error) {
	if owner == "" || owner != strings.ToLower(owner) || !strings.HasSuffix(owner, ".") ||
		strings.TrimSpace(owner) != owner || len(owner) > 254 || !utf8.ValidString(owner) {
		return nil, ErrDNSUnavailable
	}
	labels := strings.Split(strings.TrimSuffix(owner, "."), ".")
	encoded := make([]byte, 0, len(owner)+1)
	for _, label := range labels {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return nil, ErrDNSUnavailable
		}
		for _, character := range label {
			if (character < 'a' || character > 'z') && (character < '0' || character > '9') &&
				character != '-' && character != '_' {
				return nil, ErrDNSUnavailable
			}
		}
		encoded = append(encoded, byte(len(label)))
		encoded = append(encoded, label...)
	}
	encoded = append(encoded, 0)
	return encoded, nil
}

func isTruncatedResponse(request, response []byte, owner string) bool {
	if len(request) < 12 || len(response) < 12 || len(response) > maxDNSMessageSize ||
		binary.BigEndian.Uint16(response[0:2]) != binary.BigEndian.Uint16(request[0:2]) {
		return false
	}
	flags := binary.BigEndian.Uint16(response[2:4])
	if flags&0x8000 == 0 || flags&0x7800 != 0 || flags&0x0200 == 0 ||
		binary.BigEndian.Uint16(response[4:6]) != 1 {
		return false
	}
	name, offset, err := readDNSName(response, 12)
	if err != nil || name != owner || offset+4 > len(response) {
		return false
	}
	return binary.BigEndian.Uint16(response[offset:offset+2]) == 16 &&
		binary.BigEndian.Uint16(response[offset+2:offset+4]) == 1
}

func parseTXTResponse(request, response []byte, owner string) (TXTObservation, error) {
	if len(request) < 12 || len(response) < 12 || len(response) > maxDNSMessageSize ||
		binary.BigEndian.Uint16(response[0:2]) != binary.BigEndian.Uint16(request[0:2]) {
		return TXTObservation{}, ErrDNSInvalidResponse
	}
	flags := binary.BigEndian.Uint16(response[2:4])
	if flags&0x8000 == 0 || flags&0x7800 != 0 || flags&0x0200 != 0 || flags&0x0040 != 0 ||
		binary.BigEndian.Uint16(response[4:6]) != 1 {
		return TXTObservation{}, ErrDNSInvalidResponse
	}
	rcode := int(flags & 0x000f)
	answerCount := int(binary.BigEndian.Uint16(response[6:8]))
	authorityCount := int(binary.BigEndian.Uint16(response[8:10]))
	additionalCount := int(binary.BigEndian.Uint16(response[10:12]))
	if rcode != 0 && answerCount != 0 {
		return TXTObservation{}, ErrDNSInvalidResponse
	}

	questionName, offset, err := readDNSName(response, 12)
	if err != nil || questionName != owner || offset+4 > len(response) ||
		binary.BigEndian.Uint16(response[offset:offset+2]) != 16 ||
		binary.BigEndian.Uint16(response[offset+2:offset+4]) != 1 {
		return TXTObservation{}, ErrDNSInvalidResponse
	}
	offset += 4
	values := make([]string, 0, answerCount)
	seen := make(map[string]struct{}, answerCount)
	for range answerCount {
		name, next, recordType, class, rdata, parseErr := readResourceRecord(response, offset)
		if parseErr != nil || name != owner || recordType != 16 || class != 1 {
			return TXTObservation{}, ErrDNSInvalidResponse
		}
		value, parseErr := parseTXTData(rdata)
		if parseErr != nil {
			return TXTObservation{}, ErrDNSInvalidResponse
		}
		if _, duplicate := seen[value]; duplicate {
			return TXTObservation{}, ErrDNSInvalidResponse
		}
		seen[value] = struct{}{}
		values = append(values, value)
		offset = next
	}
	negative := answerCount == 0 && (rcode == 0 || rcode == 3)
	validSOA := false
	for range authorityCount {
		recordOffset := offset
		name, next, recordType, class, rdata, parseErr := readResourceRecord(response, offset)
		if parseErr != nil {
			return TXTObservation{}, ErrDNSInvalidResponse
		}
		if negative {
			valid, validationErr := validNegativeSOA(
				response, recordOffset, next, owner, name, recordType, class, rdata,
			)
			if validationErr != nil {
				return TXTObservation{}, ErrDNSInvalidResponse
			}
			validSOA = validSOA || valid
		}
		offset = next
	}
	for range additionalCount {
		_, next, _, _, _, parseErr := readResourceRecord(response, offset)
		if parseErr != nil {
			return TXTObservation{}, ErrDNSInvalidResponse
		}
		offset = next
	}
	if offset != len(response) || negative && !validSOA {
		return TXTObservation{}, ErrDNSInvalidResponse
	}
	return TXTObservation{
		Authoritative: flags&0x0400 != 0,
		Recursive:     flags&0x0080 != 0,
		RCode:         uint8(rcode),
		Values:        values,
	}, nil
}

func validNegativeSOA(message []byte, recordOffset, recordEnd int, queryOwner, recordOwner string,
	recordType, class uint16, rdata []byte) (bool, error) {
	if recordType != 6 || class != 1 ||
		recordOwner != queryOwner && !strings.HasSuffix(queryOwner, "."+recordOwner) {
		return false, nil
	}
	_, headerOffset, err := readDNSName(message, recordOffset)
	dataStart := recordEnd - len(rdata)
	if err != nil || headerOffset+10 > dataStart || dataStart < 0 || dataStart > recordEnd {
		return false, ErrDNSInvalidResponse
	}
	_, offset, err := readDNSName(message, dataStart)
	if err != nil || offset >= recordEnd {
		return false, ErrDNSInvalidResponse
	}
	_, offset, err = readDNSName(message, offset)
	if err != nil || recordEnd-offset != 20 {
		return false, ErrDNSInvalidResponse
	}
	ttl := binary.BigEndian.Uint32(message[headerOffset+4 : headerOffset+8])
	minimum := binary.BigEndian.Uint32(message[recordEnd-4 : recordEnd])
	if minimum < ttl {
		ttl = minimum
	}
	return ttl > 0 && ttl <= maxNegativeTTL, nil
}

func readResourceRecord(message []byte, offset int) (string, int, uint16, uint16, []byte, error) {
	name, offset, err := readDNSName(message, offset)
	if err != nil || offset+10 > len(message) {
		return "", 0, 0, 0, nil, ErrDNSInvalidResponse
	}
	recordType := binary.BigEndian.Uint16(message[offset : offset+2])
	class := binary.BigEndian.Uint16(message[offset+2 : offset+4])
	length := int(binary.BigEndian.Uint16(message[offset+8 : offset+10]))
	offset += 10
	if length > len(message)-offset {
		return "", 0, 0, 0, nil, ErrDNSInvalidResponse
	}
	return name, offset + length, recordType, class, message[offset : offset+length], nil
}

func readDNSName(message []byte, start int) (string, int, error) {
	if start < 0 || start >= len(message) {
		return "", 0, ErrDNSInvalidResponse
	}
	offset := start
	next := -1
	visited := make(map[int]struct{})
	labels := make([]string, 0, 4)
	totalLength := 1
	for {
		if offset >= len(message) {
			return "", 0, ErrDNSInvalidResponse
		}
		if _, duplicate := visited[offset]; duplicate {
			return "", 0, ErrDNSInvalidResponse
		}
		visited[offset] = struct{}{}
		length := int(message[offset])
		switch {
		case length&0xc0 == 0xc0:
			if offset+2 > len(message) {
				return "", 0, ErrDNSInvalidResponse
			}
			pointer := int(binary.BigEndian.Uint16(message[offset:offset+2]) & 0x3fff)
			if pointer < 12 || pointer >= offset || pointer >= len(message) {
				return "", 0, ErrDNSInvalidResponse
			}
			if next < 0 {
				next = offset + 2
			}
			offset = pointer
		case length&0xc0 != 0:
			return "", 0, ErrDNSInvalidResponse
		case length == 0:
			if next < 0 {
				next = offset + 1
			}
			if len(labels) == 0 || totalLength > 254 {
				return "", 0, ErrDNSInvalidResponse
			}
			return strings.Join(labels, ".") + ".", next, nil
		default:
			if length > 63 || offset+1+length > len(message) {
				return "", 0, ErrDNSInvalidResponse
			}
			labelBytes := message[offset+1 : offset+1+length]
			for _, character := range labelBytes {
				if (character < 'a' || character > 'z') && (character < '0' || character > '9') &&
					character != '-' && character != '_' {
					return "", 0, ErrDNSInvalidResponse
				}
			}
			labels = append(labels, string(labelBytes))
			totalLength += length + 1
			offset += length + 1
		}
	}
}

func parseTXTData(rdata []byte) (string, error) {
	if len(rdata) == 0 {
		return "", ErrDNSInvalidResponse
	}
	value := make([]byte, 0, len(rdata))
	for offset := 0; offset < len(rdata); {
		length := int(rdata[offset])
		offset++
		if length > len(rdata)-offset || len(value)+length > maxTXTValueSize {
			return "", ErrDNSInvalidResponse
		}
		value = append(value, rdata[offset:offset+length]...)
		offset += length
	}
	if !utf8.Valid(value) {
		return "", ErrDNSInvalidResponse
	}
	return string(value), nil
}

func exchangeDNS(ctx context.Context, network string, endpoint Endpoint, request []byte) ([]byte, error) {
	if network != "udp" && network != "tcp" || !validEndpoint(endpoint) || len(request) < 12 {
		return nil, ErrDNSUnavailable
	}
	connection, err := (&net.Dialer{}).DialContext(ctx, network, endpoint.Address.String())
	if err != nil {
		return nil, ErrDNSUnavailable
	}
	defer connection.Close()
	stop := context.AfterFunc(ctx, func() { _ = connection.Close() })
	defer stop()
	if deadline, ok := ctx.Deadline(); ok {
		_ = connection.SetDeadline(deadline)
	}
	if network == "udp" {
		if err := writeAll(connection, request); err != nil {
			return nil, ErrDNSUnavailable
		}
		response := make([]byte, maxDNSMessageSize+1)
		count, err := connection.Read(response)
		if err != nil || count > maxDNSMessageSize {
			return nil, ErrDNSUnavailable
		}
		return response[:count], nil
	}
	framed := make([]byte, 2, len(request)+2)
	binary.BigEndian.PutUint16(framed, uint16(len(request)))
	framed = append(framed, request...)
	if err := writeAll(connection, framed); err != nil {
		return nil, ErrDNSUnavailable
	}
	header := make([]byte, 2)
	if _, err := io.ReadFull(connection, header); err != nil {
		return nil, ErrDNSUnavailable
	}
	length := int(binary.BigEndian.Uint16(header))
	if length < 12 || length > maxDNSMessageSize {
		return nil, ErrDNSUnavailable
	}
	response := make([]byte, length)
	if _, err := io.ReadFull(connection, response); err != nil {
		return nil, ErrDNSUnavailable
	}
	return response, nil
}

func writeAll(writer io.Writer, value []byte) error {
	for len(value) > 0 {
		count, err := writer.Write(value)
		if err != nil || count <= 0 {
			return ErrDNSUnavailable
		}
		value = value[count:]
	}
	return nil
}

type KeychainReader func(service, account string) ([]byte, error)

// CredentialLease owns the mutable Keychain response backing all Values.
// Values is read-only; it and copied string headers are invalid after Close.
type CredentialLease struct {
	Values  map[string]string
	backing []byte
	closed  bool
}

func (l *CredentialLease) Close() {
	if l == nil || l.closed {
		return
	}
	zero(l.backing)
	for field := range l.Values {
		l.Values[field] = ""
		delete(l.Values, field)
	}
	l.Values = nil
	runtime.KeepAlive(l.backing)
	l.backing = nil
	l.closed = true
}

func LoadCredential(reader KeychainReader, provider, service, account string) (*CredentialLease, error) {
	if reader == nil || !validAlias(service) || !validAlias(account) {
		return nil, ErrCredentialUnavailable
	}
	fields, ok := credentialFields(provider)
	if !ok {
		return nil, ErrCredentialUnavailable
	}
	raw, err := reader(service, account)
	if err != nil || len(raw) == 0 || len(raw) > maxDNSMessageSize {
		zero(raw)
		return nil, ErrCredentialUnavailable
	}
	values, err := parseCredentialObject(raw, fields)
	if err != nil {
		zero(raw)
		return nil, ErrCredentialUnavailable
	}
	lease := &CredentialLease{Values: values, backing: raw}
	runtime.KeepAlive(raw)
	return lease, nil
}

type mutableJSONParser struct {
	data   []byte
	offset int
}

func parseCredentialObject(raw []byte, fields map[string]struct{}) (map[string]string, error) {
	parser := mutableJSONParser{data: raw}
	parser.skipWhitespace()
	if !parser.take('{') {
		return nil, ErrCredentialUnavailable
	}
	values := make(map[string]string, len(fields))
	parser.skipWhitespace()
	if parser.take('}') {
		return nil, ErrCredentialUnavailable
	}
	for {
		fieldStart, fieldEnd, err := parser.parseString()
		if err != nil {
			return nil, ErrCredentialUnavailable
		}
		field := string(raw[fieldStart:fieldEnd])
		if _, expected := fields[field]; !expected {
			return nil, ErrCredentialUnavailable
		}
		if _, duplicate := values[field]; duplicate {
			return nil, ErrCredentialUnavailable
		}
		parser.skipWhitespace()
		if !parser.take(':') {
			return nil, ErrCredentialUnavailable
		}
		parser.skipWhitespace()
		valueStart, valueEnd, err := parser.parseString()
		if err != nil {
			return nil, ErrCredentialUnavailable
		}
		value := mutableStringView(raw[valueStart:valueEnd])
		if !validCredentialValue(field, value) {
			return nil, ErrCredentialUnavailable
		}
		values[field] = value
		parser.skipWhitespace()
		if parser.take('}') {
			break
		}
		if !parser.take(',') {
			return nil, ErrCredentialUnavailable
		}
		parser.skipWhitespace()
	}
	parser.skipWhitespace()
	if parser.offset != len(raw) || len(values) != len(fields) {
		return nil, ErrCredentialUnavailable
	}
	runtime.KeepAlive(raw)
	return values, nil
}

func (p *mutableJSONParser) skipWhitespace() {
	for p.offset < len(p.data) {
		switch p.data[p.offset] {
		case ' ', '\t', '\n', '\r':
			p.offset++
		default:
			return
		}
	}
}

func (p *mutableJSONParser) take(want byte) bool {
	if p.offset >= len(p.data) || p.data[p.offset] != want {
		return false
	}
	p.offset++
	return true
}

func (p *mutableJSONParser) parseString() (int, int, error) {
	if !p.take('"') {
		return 0, 0, ErrCredentialUnavailable
	}
	start := p.offset
	read, write := p.offset, p.offset
	for read < len(p.data) {
		character := p.data[read]
		if character == '"' {
			p.offset = read + 1
			if !utf8.Valid(p.data[start:write]) {
				return 0, 0, ErrCredentialUnavailable
			}
			return start, write, nil
		}
		if character < 0x20 {
			return 0, 0, ErrCredentialUnavailable
		}
		if character != '\\' {
			p.data[write] = character
			write++
			read++
			continue
		}
		read++
		if read >= len(p.data) {
			return 0, 0, ErrCredentialUnavailable
		}
		escape := p.data[read]
		read++
		switch escape {
		case '"', '\\', '/':
			p.data[write] = escape
			write++
		case 'b':
			p.data[write] = '\b'
			write++
		case 'f':
			p.data[write] = '\f'
			write++
		case 'n':
			p.data[write] = '\n'
			write++
		case 'r':
			p.data[write] = '\r'
			write++
		case 't':
			p.data[write] = '\t'
			write++
		case 'u':
			decoded, next, err := decodeEscapedRune(p.data, read)
			if err != nil {
				return 0, 0, ErrCredentialUnavailable
			}
			read = next
			write += utf8.EncodeRune(p.data[write:], decoded)
		default:
			return 0, 0, ErrCredentialUnavailable
		}
	}
	return 0, 0, ErrCredentialUnavailable
}

func decodeEscapedRune(data []byte, offset int) (rune, int, error) {
	unit, ok := decodeHexUnit(data, offset)
	if !ok {
		return 0, 0, ErrCredentialUnavailable
	}
	offset += 4
	if unit >= 0xdc00 && unit <= 0xdfff {
		return 0, 0, ErrCredentialUnavailable
	}
	if unit < 0xd800 || unit > 0xdbff {
		return rune(unit), offset, nil
	}
	if offset+6 > len(data) || data[offset] != '\\' || data[offset+1] != 'u' {
		return 0, 0, ErrCredentialUnavailable
	}
	low, ok := decodeHexUnit(data, offset+2)
	if !ok || low < 0xdc00 || low > 0xdfff {
		return 0, 0, ErrCredentialUnavailable
	}
	decoded := rune(0x10000 + (uint32(unit)-0xd800)<<10 + (uint32(low) - 0xdc00))
	return decoded, offset + 6, nil
}

func decodeHexUnit(data []byte, offset int) (uint16, bool) {
	if offset < 0 || offset+4 > len(data) {
		return 0, false
	}
	var result uint16
	for _, character := range data[offset : offset+4] {
		result <<= 4
		switch {
		case character >= '0' && character <= '9':
			result |= uint16(character - '0')
		case character >= 'a' && character <= 'f':
			result |= uint16(character-'a') + 10
		case character >= 'A' && character <= 'F':
			result |= uint16(character-'A') + 10
		default:
			return 0, false
		}
	}
	return result, true
}

// mutableStringView is the only unsafe boundary. The returned string is valid
// only while the owning CredentialLease remains open.
func mutableStringView(value []byte) string {
	if len(value) == 0 {
		return ""
	}
	return unsafe.String(unsafe.SliceData(value), len(value))
}

func credentialFields(provider string) (map[string]struct{}, bool) {
	var names []string
	switch provider {
	case "cloudflare":
		names = []string{"api_token"}
	case "aliyun":
		names = []string{"access_key_id", "access_key_secret"}
	case "huawei":
		names = []string{"access_key", "secret_key", "region", "project_id"}
	case "dnspod_cn":
		names = []string{"dp_id", "dp_key"}
	case "dns_com":
		names = []string{"api_key", "api_secret"}
	case "dns_la":
		names = []string{"api_id", "api_secret"}
	default:
		return nil, false
	}
	fields := make(map[string]struct{}, len(names))
	for _, name := range names {
		fields[name] = struct{}{}
	}
	return fields, true
}

func validCredentialValue(field, value string) bool {
	if value == "" || len(value) > maxTXTValueSize || !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return field != "api_id" || !strings.Contains(value, ":")
}

func validAlias(value string) bool {
	if value == "" || len(value) > 256 || value != strings.TrimSpace(value) || !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func zero(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
