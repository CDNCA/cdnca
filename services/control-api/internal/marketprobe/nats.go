package marketprobe

import (
	"context"
	"errors"

	contract "github.com/cdnca/cdnca/libs/edgeconfig/marketprobe"
	"github.com/nats-io/nats.go"
)

// NATSRequester reaches node sessions through agent-gateway's core NATS
// request subject (libs/edgeconfig/marketprobe).
type NATSRequester struct{ connection *nats.Conn }

func NewNATSRequester(connection *nats.Conn) (*NATSRequester, error) {
	if connection == nil || connection.IsClosed() {
		return nil, errors.New("market probe requester requires an active edge NATS connection")
	}
	return &NATSRequester{connection: connection}, nil
}

func (r *NATSRequester) Request(ctx context.Context, nodeID string, command []byte) ([]byte, error) {
	reply, err := r.connection.RequestWithContext(ctx, contract.Subject(nodeID), command)
	if errors.Is(err, nats.ErrNoResponders) {
		return nil, ErrOffline
	}
	if err != nil {
		return nil, err
	}
	if len(reply.Data) > contract.MaxCarrierBytes {
		return nil, errors.New("market probe reply is too large")
	}
	return reply.Data, nil
}
