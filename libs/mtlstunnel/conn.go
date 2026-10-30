package mtlstunnel

import (
	"net"
	"os"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// wsConn exposes a WebSocket as a byte stream of binary frames (no frame
// above MaxFrameBytes is written; the read limit enforces it inbound).
//
// Read deadlines are kept here, not on the WebSocket: gorilla/websocket makes
// any read error permanent, while net/http's server aborts its background read
// between requests with a past deadline and expects the connection to stay
// usable (the same holds for crypto/tls, which treats timeouts as temporary).
// A pump goroutine reads frames; Read waits for one or for the deadline.
type wsConn struct {
	ws *websocket.Conn

	frames   chan []byte
	closed   chan struct{}
	closeOne sync.Once
	readErr  error // set before frames is closed

	rmu     sync.Mutex
	pending []byte

	dmu       sync.Mutex
	deadline  time.Time
	deadlineC chan struct{} // closed and replaced when the deadline changes

	wmu sync.Mutex
}

func newWSConn(ws *websocket.Conn) *wsConn {
	ws.SetReadLimit(MaxFrameBytes)
	c := &wsConn{ws: ws, frames: make(chan []byte), closed: make(chan struct{}), deadlineC: make(chan struct{})}
	go c.pump()
	return c
}

func (c *wsConn) pump() {
	defer close(c.frames)
	for {
		kind, data, err := c.ws.ReadMessage()
		if err != nil {
			c.readErr = err
			return
		}
		if kind != websocket.BinaryMessage || len(data) == 0 {
			continue
		}
		select {
		case c.frames <- data:
		case <-c.closed:
			c.readErr = net.ErrClosed
			return
		}
	}
}

func (c *wsConn) Read(p []byte) (int, error) {
	c.rmu.Lock()
	defer c.rmu.Unlock()
	for len(c.pending) == 0 {
		c.dmu.Lock()
		deadline, changed := c.deadline, c.deadlineC
		c.dmu.Unlock()
		var expired <-chan time.Time
		if !deadline.IsZero() {
			wait := time.Until(deadline)
			if wait <= 0 {
				return 0, os.ErrDeadlineExceeded
			}
			timer := time.NewTimer(wait)
			defer timer.Stop()
			expired = timer.C
		}
		select {
		case frame, ok := <-c.frames:
			if !ok {
				return 0, c.readErr
			}
			c.pending = frame
		case <-expired:
			return 0, os.ErrDeadlineExceeded
		case <-changed:
		case <-c.closed:
			return 0, net.ErrClosed
		}
	}
	n := copy(p, c.pending)
	c.pending = c.pending[n:]
	return n, nil
}

func (c *wsConn) Write(p []byte) (int, error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	written := 0
	for written < len(p) {
		end := min(len(p), written+MaxFrameBytes)
		if err := c.ws.WriteMessage(websocket.BinaryMessage, p[written:end]); err != nil {
			return written, err
		}
		written = end
	}
	return written, nil
}

func (c *wsConn) Close() error {
	err := net.ErrClosed
	c.closeOne.Do(func() {
		close(c.closed)
		err = c.ws.Close()
	})
	return err
}

func (c *wsConn) LocalAddr() net.Addr  { return c.ws.LocalAddr() }
func (c *wsConn) RemoteAddr() net.Addr { return c.ws.RemoteAddr() }

func (c *wsConn) SetDeadline(t time.Time) error {
	if err := c.SetReadDeadline(t); err != nil {
		return err
	}
	return c.SetWriteDeadline(t)
}

func (c *wsConn) SetReadDeadline(t time.Time) error {
	c.dmu.Lock()
	c.deadline = t
	close(c.deadlineC)
	c.deadlineC = make(chan struct{})
	c.dmu.Unlock()
	return nil
}

// gorilla/websocket stores the write deadline without locking; set it under
// the write lock so it never races a concurrent Write.
func (c *wsConn) SetWriteDeadline(t time.Time) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	return c.ws.SetWriteDeadline(t)
}
