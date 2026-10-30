//go:build !linux

package helper

import (
	"context"
	"os"

	"github.com/cdnca/cdnca/agents/edge-agent/packaging/helper/protocol"
)

type Listener struct{}

type Exchange struct {
	Packet   []byte
	Request  protocol.Request
	Artifact *os.File
	Peer     PeerIdentity
	Context  context.Context
}

func ListenerFromSystemd() (*Listener, error) {
	return nil, ErrTransportUnavailable
}

func (l *Listener) Accept(context.Context) (*Exchange, error) {
	return nil, ErrTransportUnavailable
}

func (l *Listener) Close() error { return nil }

func (e *Exchange) Respond(context.Context, protocol.Response) error {
	return ErrTransportUnavailable
}

func (e *Exchange) Close() error {
	if e != nil && e.Artifact != nil {
		return e.Artifact.Close()
	}
	return nil
}

func roundTrip(context.Context, socketPolicy, protocol.Request, *os.File) (protocol.Response, error) {
	return protocol.Response{}, ErrTransportUnavailable
}
