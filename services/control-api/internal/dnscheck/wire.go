package dnscheck

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"strings"
)

const (
	defaultMaximumResponseBytes = 16 * 1024
	maximumDNSResponseBytes     = 65535
	maximumDNSRecords           = 256
	maximumCompressionPointers  = 32
)

type dnsMessage struct {
	id            uint16
	response      bool
	authoritative bool
	truncated     bool
	rcode         uint8
	questions     []DNSQuery
	answers       []DNSRecord
	authority     []DNSRecord
}

func buildDNSQuery(id uint16, query DNSQuery) ([]byte, error) {
	name, err := encodeDNSName(query.Name)
	if err != nil || !supportedRecordType(query.Type) {
		return nil, ErrInvalidInput
	}
	message := make([]byte, 12, 12+len(name)+4)
	binary.BigEndian.PutUint16(message[0:2], id)
	binary.BigEndian.PutUint16(message[2:4], 0x0100)
	binary.BigEndian.PutUint16(message[4:6], 1)
	message = append(message, name...)
	message = binary.BigEndian.AppendUint16(message, uint16(query.Type))
	message = binary.BigEndian.AppendUint16(message, 1)
	return message, nil
}

func encodeDNSName(name string) ([]byte, error) {
	name, err := normalizeDNSName(name, true)
	if err != nil {
		return nil, err
	}
	if name == "." {
		return []byte{0}, nil
	}
	result := make([]byte, 0, len(name)+1)
	for _, label := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		if len(label) == 0 || len(label) > 63 {
			return nil, ErrInvalidInput
		}
		result = append(result, byte(len(label)))
		result = append(result, label...)
	}
	result = append(result, 0)
	if len(result) > 255 {
		return nil, ErrInvalidInput
	}
	return result, nil
}

func parseDNSMessage(message []byte, maximumBytes int) (dnsMessage, error) {
	if maximumBytes < 512 || maximumBytes > maximumDNSResponseBytes || len(message) < 12 {
		return dnsMessage{}, ErrMalformedResponse
	}
	if len(message) > maximumBytes {
		return dnsMessage{}, ErrResponseTooLarge
	}
	flags := binary.BigEndian.Uint16(message[2:4])
	if flags&0x7840 != 0 {
		return dnsMessage{}, ErrMalformedResponse
	}
	questionCount := int(binary.BigEndian.Uint16(message[4:6]))
	answerCount := int(binary.BigEndian.Uint16(message[6:8]))
	authorityCount := int(binary.BigEndian.Uint16(message[8:10]))
	additionalCount := int(binary.BigEndian.Uint16(message[10:12]))
	if questionCount != 1 || answerCount+authorityCount+additionalCount > maximumDNSRecords {
		return dnsMessage{}, ErrMalformedResponse
	}
	parsed := dnsMessage{
		id:            binary.BigEndian.Uint16(message[0:2]),
		response:      flags&0x8000 != 0,
		authoritative: flags&0x0400 != 0,
		truncated:     flags&0x0200 != 0,
		rcode:         uint8(flags & 0x000f),
		questions:     make([]DNSQuery, 0, questionCount),
		answers:       make([]DNSRecord, 0, answerCount),
		authority:     make([]DNSRecord, 0, authorityCount),
	}
	offset := 12
	for index := 0; index < questionCount; index++ {
		name, next, err := parseDNSName(message, offset)
		if err != nil || next+4 > len(message) {
			return dnsMessage{}, ErrMalformedResponse
		}
		if binary.BigEndian.Uint16(message[next+2:next+4]) != 1 {
			return dnsMessage{}, ErrMalformedResponse
		}
		parsed.questions = append(parsed.questions, DNSQuery{
			Name: name,
			Type: RecordType(binary.BigEndian.Uint16(message[next : next+2])),
		})
		offset = next + 4
	}
	totalRecords := answerCount + authorityCount + additionalCount
	for index := 0; index < totalRecords; index++ {
		name, next, err := parseDNSName(message, offset)
		if err != nil || next+10 > len(message) {
			return dnsMessage{}, ErrMalformedResponse
		}
		recordType := RecordType(binary.BigEndian.Uint16(message[next : next+2]))
		class := binary.BigEndian.Uint16(message[next+2 : next+4])
		if index < answerCount+authorityCount && class != 1 {
			return dnsMessage{}, ErrMalformedResponse
		}
		ttl := binary.BigEndian.Uint32(message[next+4 : next+8])
		dataLength := int(binary.BigEndian.Uint16(message[next+8 : next+10]))
		dataStart := next + 10
		dataEnd := dataStart + dataLength
		if dataEnd < dataStart || dataEnd > len(message) {
			return dnsMessage{}, ErrMalformedResponse
		}
		if index < answerCount {
			record, keep, err := parseAnswerRecord(message, name, recordType, ttl, dataStart, dataEnd)
			if err != nil {
				return dnsMessage{}, err
			}
			if keep {
				parsed.answers = append(parsed.answers, record)
			}
		} else if index < answerCount+authorityCount {
			record, keep, err := parseAuthorityRecord(message, name, recordType, ttl, dataStart, dataEnd)
			if err != nil {
				return dnsMessage{}, err
			}
			if keep {
				parsed.authority = append(parsed.authority, record)
			}
		}
		offset = dataEnd
	}
	if offset != len(message) || !parsed.response {
		return dnsMessage{}, ErrMalformedResponse
	}
	if err := validateAnswerRRsets(parsed.answers); err != nil {
		return dnsMessage{}, err
	}
	return parsed, nil
}

func validateAnswerRRsets(records []DNSRecord) error {
	type ownerState struct {
		cnameTarget string
		hasCNAME    bool
		hasData     bool
	}
	owners := make(map[string]ownerState)
	for _, record := range records {
		state := owners[record.Name]
		switch record.Type {
		case RecordCNAME:
			if state.hasData || state.hasCNAME && state.cnameTarget != record.Value {
				return ErrMalformedResponse
			}
			state.cnameTarget = record.Value
			state.hasCNAME = true
		case RecordA, RecordAAAA, RecordTXT:
			if state.hasCNAME {
				return ErrMalformedResponse
			}
			state.hasData = true
		}
		owners[record.Name] = state
	}
	return nil
}

func parseAnswerRecord(message []byte, name string, recordType RecordType, ttl uint32, dataStart, dataEnd int) (DNSRecord, bool, error) {
	record := DNSRecord{Name: name, Type: recordType, TTL: ttl}
	switch recordType {
	case RecordA:
		if dataEnd-dataStart != 4 {
			return DNSRecord{}, false, ErrMalformedResponse
		}
		record.Value = netip.AddrFrom4([4]byte(message[dataStart:dataEnd])).String()
	case RecordAAAA:
		if dataEnd-dataStart != 16 {
			return DNSRecord{}, false, ErrMalformedResponse
		}
		var address [16]byte
		copy(address[:], message[dataStart:dataEnd])
		record.Value = netip.AddrFrom16(address).String()
	case RecordCNAME:
		value, next, err := parseDNSName(message, dataStart)
		if err != nil || next != dataEnd {
			return DNSRecord{}, false, ErrMalformedResponse
		}
		record.Value = value
	case RecordTXT:
		if dataEnd-dataStart < 1 {
			return DNSRecord{}, false, ErrMalformedResponse
		}
		chunks := make([]string, 0, 1)
		for position := dataStart; position < dataEnd; {
			length := int(message[position])
			position++
			if position+length > dataEnd {
				return DNSRecord{}, false, ErrMalformedResponse
			}
			chunks = append(chunks, string(message[position:position+length]))
			position += length
		}
		record.Value = strings.Join(chunks, "")
	default:
		return DNSRecord{}, false, nil
	}
	return record, true, nil
}

func parseAuthorityRecord(message []byte, name string, recordType RecordType, ttl uint32, dataStart, dataEnd int) (DNSRecord, bool, error) {
	if recordType != RecordSOA {
		return DNSRecord{}, false, nil
	}
	_, next, err := parseDNSName(message, dataStart)
	if err != nil || next >= dataEnd {
		return DNSRecord{}, false, ErrMalformedResponse
	}
	_, next, err = parseDNSName(message, next)
	if err != nil || dataEnd-next != 20 {
		return DNSRecord{}, false, ErrMalformedResponse
	}
	minimumTTL := binary.BigEndian.Uint32(message[dataEnd-4 : dataEnd])
	negativeTTL := ttl
	if minimumTTL < negativeTTL {
		negativeTTL = minimumTTL
	}
	return DNSRecord{Name: name, Type: RecordSOA, TTL: ttl, NegativeTTL: negativeTTL, negativeTTLSet: true}, true, nil
}

func parseDNSName(message []byte, start int) (string, int, error) {
	if start < 0 || start >= len(message) {
		return "", 0, ErrMalformedResponse
	}
	labels := make([]string, 0, 4)
	position := start
	next := -1
	pointers := 0
	visited := make(map[int]struct{}, 4)
	wireLength := 1
	for {
		if position >= len(message) {
			return "", 0, ErrMalformedResponse
		}
		length := int(message[position])
		switch length & 0xc0 {
		case 0xc0:
			if position+1 >= len(message) || pointers >= maximumCompressionPointers {
				return "", 0, ErrMalformedResponse
			}
			pointer := int(binary.BigEndian.Uint16(message[position:position+2]) & 0x3fff)
			if pointer >= position {
				return "", 0, ErrMalformedResponse
			}
			if _, duplicate := visited[pointer]; duplicate {
				return "", 0, ErrMalformedResponse
			}
			visited[pointer] = struct{}{}
			if next < 0 {
				next = position + 2
			}
			position = pointer
			pointers++
			continue
		case 0x00:
		default:
			return "", 0, ErrMalformedResponse
		}
		position++
		if length == 0 {
			if next < 0 {
				next = position
			}
			if len(labels) == 0 {
				return ".", next, nil
			}
			name := strings.Join(labels, ".") + "."
			if len(name) > 254 {
				return "", 0, ErrMalformedResponse
			}
			return strings.ToLower(name), next, nil
		}
		if length > 63 || position+length > len(message) {
			return "", 0, ErrMalformedResponse
		}
		label := message[position : position+length]
		for _, character := range label {
			if !((character >= 'a' && character <= 'z') ||
				(character >= 'A' && character <= 'Z') ||
				(character >= '0' && character <= '9') ||
				character == '_' || character == '-' ||
				(character == '*' && len(label) == 1)) {
				return "", 0, ErrMalformedResponse
			}
		}
		wireLength += length + 1
		if wireLength > 255 {
			return "", 0, ErrMalformedResponse
		}
		labels = append(labels, string(label))
		position += length
	}
}

func validateDNSResponse(message dnsMessage, id uint16, query DNSQuery) error {
	if message.id != id || len(message.questions) != 1 || message.questions[0].Name != query.Name || message.questions[0].Type != query.Type {
		return fmt.Errorf("%w: response question mismatch", ErrMalformedResponse)
	}
	return nil
}

func validateTruncatedDNSResponse(message []byte, maximumBytes int, id uint16, query DNSQuery) error {
	if maximumBytes < 512 || maximumBytes > maximumDNSResponseBytes || len(message) < 12 {
		return ErrMalformedResponse
	}
	if len(message) > maximumBytes {
		return ErrResponseTooLarge
	}
	flags := binary.BigEndian.Uint16(message[2:4])
	if flags&0x8000 == 0 || flags&0x0200 == 0 || flags&0x7840 != 0 || binary.BigEndian.Uint16(message[4:6]) != 1 {
		return ErrMalformedResponse
	}
	name, next, err := parseDNSName(message, 12)
	if err != nil || next+4 > len(message) || binary.BigEndian.Uint16(message[next+2:next+4]) != 1 {
		return ErrMalformedResponse
	}
	return validateDNSResponse(dnsMessage{
		id: binary.BigEndian.Uint16(message[0:2]),
		questions: []DNSQuery{{
			Name: name,
			Type: RecordType(binary.BigEndian.Uint16(message[next : next+2])),
		}},
	}, id, query)
}
