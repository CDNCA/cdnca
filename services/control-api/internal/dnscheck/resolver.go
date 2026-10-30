package dnscheck

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"time"
)

type NetworkResolverOptions struct {
	MaximumResponseBytes int
}

type NetworkResolver struct {
	policy               EndpointPolicy
	maximumResponseBytes int
}

func NewNetworkResolver(policy EndpointPolicy, options NetworkResolverOptions) (*NetworkResolver, error) {
	maximumBytes := options.MaximumResponseBytes
	if maximumBytes == 0 {
		maximumBytes = defaultMaximumResponseBytes
	}
	if len(policy.allowed) == 0 || maximumBytes < 512 || maximumBytes > maximumDNSResponseBytes {
		return nil, ErrInvalidInput
	}
	return &NetworkResolver{policy: policy, maximumResponseBytes: maximumBytes}, nil
}

func (r *NetworkResolver) Resolve(ctx context.Context, endpoint ResolverEndpoint, query DNSQuery) (DNSResponse, error) {
	if err := r.policy.Check(endpoint); err != nil {
		return DNSResponse{}, err
	}
	name, err := normalizeDNSName(query.Name, true)
	if err != nil || !supportedRecordType(query.Type) {
		return DNSResponse{}, ErrInvalidInput
	}
	query.Name = name
	id, err := randomQueryID()
	if err != nil {
		return DNSResponse{}, err
	}
	payload, err := buildDNSQuery(id, query)
	if err != nil {
		return DNSResponse{}, err
	}
	message, err := r.exchange(ctx, endpoint.Network, endpoint, payload)
	if err != nil {
		return DNSResponse{}, err
	}
	if endpoint.Network == "udp" && len(message) >= 4 && binary.BigEndian.Uint16(message[2:4])&0x0200 != 0 {
		if err := validateTruncatedDNSResponse(message, r.maximumResponseBytes, id, query); err != nil {
			return DNSResponse{}, err
		}
		message, err = r.exchange(ctx, "tcp", endpoint, payload)
		if err != nil {
			return DNSResponse{}, err
		}
	}
	parsed, err := parseDNSMessage(message, r.maximumResponseBytes)
	if err != nil {
		return DNSResponse{}, err
	}
	if err := validateDNSResponse(parsed, id, query); err != nil {
		return DNSResponse{}, err
	}
	if parsed.truncated {
		return DNSResponse{}, ErrMalformedResponse
	}
	return DNSResponse{
		Authoritative: parsed.authoritative,
		Truncated:     parsed.truncated,
		RCode:         parsed.rcode,
		Answers:       parsed.answers,
		Authority:     parsed.authority,
	}, nil
}

func (r *NetworkResolver) exchange(ctx context.Context, network string, endpoint ResolverEndpoint, payload []byte) ([]byte, error) {
	connection, err := (&net.Dialer{}).DialContext(ctx, network, net.JoinHostPort(endpoint.Address.String(), portString(endpoint.Port)))
	if err != nil {
		return nil, mapContextError(ctx, err)
	}
	defer connection.Close()
	if deadline, ok := ctx.Deadline(); ok {
		if err := connection.SetDeadline(deadline); err != nil {
			return nil, err
		}
	}
	stopCancellation := context.AfterFunc(ctx, func() {
		_ = connection.SetDeadline(time.Now())
	})
	defer stopCancellation()
	if network == "tcp" {
		if len(payload) > maximumDNSResponseBytes {
			return nil, ErrResponseTooLarge
		}
		framed := make([]byte, 2, len(payload)+2)
		binary.BigEndian.PutUint16(framed, uint16(len(payload)))
		framed = append(framed, payload...)
		if err := writeAll(connection, framed); err != nil {
			return nil, mapContextError(ctx, err)
		}
		lengthPrefix := make([]byte, 2)
		if _, err := io.ReadFull(connection, lengthPrefix); err != nil {
			return nil, mapContextError(ctx, err)
		}
		length := int(binary.BigEndian.Uint16(lengthPrefix))
		if length > r.maximumResponseBytes {
			return nil, ErrResponseTooLarge
		}
		response := make([]byte, length)
		if _, err := io.ReadFull(connection, response); err != nil {
			return nil, mapContextError(ctx, err)
		}
		return response, nil
	}
	if _, err := connection.Write(payload); err != nil {
		return nil, mapContextError(ctx, err)
	}
	response := make([]byte, r.maximumResponseBytes+1)
	read, err := connection.Read(response)
	if err != nil {
		return nil, mapContextError(ctx, err)
	}
	if read > r.maximumResponseBytes {
		return nil, ErrResponseTooLarge
	}
	return response[:read], nil
}

func writeAll(connection net.Conn, payload []byte) error {
	for len(payload) > 0 {
		written, err := connection.Write(payload)
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrUnexpectedEOF
		}
		payload = payload[written:]
	}
	return nil
}

func randomQueryID() (uint16, error) {
	var value [2]byte
	if _, err := rand.Read(value[:]); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint16(value[:]), nil
}

func mapContextError(ctx context.Context, err error) error {
	if contextError := ctx.Err(); contextError != nil {
		return contextError
	}
	var networkError net.Error
	if errors.As(err, &networkError) && networkError.Timeout() {
		return context.DeadlineExceeded
	}
	return err
}

func portString(port uint16) string {
	var buffer [5]byte
	index := len(buffer)
	value := port
	for {
		index--
		buffer[index] = byte(value%10) + '0'
		value /= 10
		if value == 0 {
			return string(buffer[index:])
		}
	}
}
