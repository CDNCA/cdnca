package gateway

// net.Conn over a WebSocket (binary frames) and a channel-fed net.Listener,
// so the unchanged gRPC servers accept connections that arrive inside a
// tunnel or after the shared-port split (ADR 0013 §4.2).

import (
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

type wsConn struct {
	ws     *websocket.Conn
	remote net.Addr
	reader io.Reader
	rmu    sync.Mutex
	wmu    sync.Mutex
}

func (c *wsConn) Read(p []byte) (int, error) {
	c.rmu.Lock()
	defer c.rmu.Unlock()
	for {
		if c.reader == nil {
			kind, reader, err := c.ws.NextReader()
			if err != nil {
				return 0, err
			}
			if kind != websocket.BinaryMessage {
				continue
			}
			c.reader = reader
		}
		n, err := c.reader.Read(p)
		if errors.Is(err, io.EOF) {
			c.reader = nil
			if n > 0 {
				return n, nil
			}
			continue
		}
		return n, err
	}
}

func (c *wsConn) Write(p []byte) (int, error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if err := c.ws.WriteMessage(websocket.BinaryMessage, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *wsConn) Close() error         { return c.ws.Close() }
func (c *wsConn) LocalAddr() net.Addr  { return c.ws.LocalAddr() }
func (c *wsConn) RemoteAddr() net.Addr { return c.remote }

// gorilla/websocket stores the write deadline without locking; set it under
// the write lock so it never races a concurrent Write.
func (c *wsConn) SetDeadline(t time.Time) error {
	if err := c.SetReadDeadline(t); err != nil {
		return err
	}
	return c.SetWriteDeadline(t)
}
func (c *wsConn) SetReadDeadline(t time.Time) error { return c.ws.SetReadDeadline(t) }
func (c *wsConn) SetWriteDeadline(t time.Time) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	return c.ws.SetWriteDeadline(t)
}

// chanListener hands connections to grpc.Server.Serve or http.Server.Serve.
// Close (called by grpc.Server.Stop) runs onClose once; fail makes Accept
// return err so Serve reports why the underlying listener stopped.
type chanListener struct {
	conns   chan net.Conn
	done    chan struct{}
	once    sync.Once
	addr    net.Addr
	err     error
	onClose func()
}

func newChanListener(addr net.Addr, onClose func()) *chanListener {
	return &chanListener{conns: make(chan net.Conn), done: make(chan struct{}), addr: addr, err: net.ErrClosed, onClose: onClose}
}

func (l *chanListener) Accept() (net.Conn, error) {
	select {
	case conn := <-l.conns:
		return conn, nil
	case <-l.done:
		return nil, l.err
	}
}

func (l *chanListener) fail(err error) {
	l.once.Do(func() {
		if err != nil {
			l.err = err
		}
		close(l.done)
		if l.onClose != nil {
			l.onClose()
		}
	})
}

func (l *chanListener) Close() error   { l.fail(nil); return nil }
func (l *chanListener) Addr() net.Addr { return l.addr }

// deliver passes conn to the listener or closes it when the listener is gone.
func (l *chanListener) deliver(conn net.Conn) {
	select {
	case l.conns <- conn:
	case <-l.done:
		_ = conn.Close()
	}
}

// prefixConn replays bytes read while peeking at the TLS ClientHello.
type prefixConn struct {
	net.Conn
	prefix []byte
}

func (c *prefixConn) Read(p []byte) (int, error) {
	if len(c.prefix) > 0 {
		n := copy(p, c.prefix)
		c.prefix = c.prefix[n:]
		return n, nil
	}
	return c.Conn.Read(p)
}
