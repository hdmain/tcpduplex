package tcpduplex

import (
	"context"
	"io"
	"net"
	"sync"
	"sync/atomic"

	"github.com/hdmain/tcpduplex/crypto"
	"github.com/hdmain/tcpduplex/protocol"
)

type outbound struct {
	typ uint8
	pt  []byte
}

// Conn is an encrypted full-duplex tcpduplex session after handshake.
// Writes are serialized through a dedicated writer goroutine; reads dispatch either to Receive
// or—when configured—to OnMessage without blocking the record reader beyond bounded channel ops.
type Conn struct {
	nc   net.Conn
	sess *crypto.Session
	cfg  frozenConfig

	sendCh chan outbound

	recvMu     sync.Mutex
	recvErr    error
	recvClosed bool
	recvCh     chan []byte

	msgJobs       chan []byte
	deliverCancel context.CancelFunc
	deliverWG     sync.WaitGroup

	callbackDropped atomic.Uint64

	stopSend chan struct{}

	shutdownStarted atomic.Bool

	writeDone chan struct{}
	readDone  chan struct{}

	closed atomic.Bool
}

func newConn(nc net.Conn, sess *crypto.Session, cfg frozenConfig) *Conn {
	c := &Conn{
		nc:        nc,
		sess:      sess,
		cfg:       cfg,
		sendCh:    make(chan outbound, cfg.SendQueueDepth),
		recvCh:    make(chan []byte, cfg.ReceiveQueueDepth),
		stopSend:  make(chan struct{}),
		writeDone: make(chan struct{}),
		readDone:  make(chan struct{}),
	}
	if cfg.OnMessage != nil {
		c.msgJobs = make(chan []byte, cfg.OnMessageBufferDepth)
		dctx, cancel := context.WithCancel(context.Background())
		c.deliverCancel = cancel
		c.deliverWG.Add(1)
		go c.deliverLoop(dctx)
	}
	go c.readLoop()
	go c.writeLoop()
	return c
}

func (c *Conn) deliverLoop(ctx context.Context) {
	defer c.deliverWG.Done()
	fn := c.cfg.OnMessage
	for {
		select {
		case payload := <-c.msgJobs:
			if fn != nil {
				fn(payload)
			}
		case <-ctx.Done():
			for {
				select {
				case payload := <-c.msgJobs:
					if fn != nil {
						fn(payload)
					}
				default:
					return
				}
			}
		}
	}
}

// Send queues an application message (encrypted as MsgText).
func (c *Conn) Send(payload []byte) error {
	return c.SendContext(context.Background(), payload)
}

// SendContext waits until payload is accepted into the outbound queue or ctx is done.
func (c *Conn) SendContext(ctx context.Context, payload []byte) error {
	if c.closed.Load() {
		return ErrClosed
	}
	if len(payload) > c.cfg.MaxMessageBytes {
		return ErrMessageTooLarge
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	body := append([]byte(nil), payload...)
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-c.stopSend:
		return ErrClosed
	case c.sendCh <- outbound{typ: protocol.MsgText, pt: body}:
		return nil
	}
}

// Receive blocks until the next application message or an error (requires OnMessage == nil).
func (c *Conn) Receive() ([]byte, error) {
	return c.ReceiveContext(context.Background())
}

// ReceiveContext waits for the next MsgText or termination subject to ctx.
func (c *Conn) ReceiveContext(ctx context.Context) ([]byte, error) {
	if c.cfg.OnMessage != nil {
		return nil, ErrReceiveDisabled
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case msg, ok := <-c.recvCh:
		if !ok {
			c.recvMu.Lock()
			err := c.recvErr
			c.recvMu.Unlock()
			if err == nil {
				err = ErrClosed
			}
			return nil, err
		}
		return msg, nil
	}
}

// CallbackDropped counts inbound messages dropped because OnMessageBufferDepth was exhausted.
func (c *Conn) CallbackDropped() uint64 {
	return c.callbackDropped.Load()
}

// Close performs graceful shutdown with unlimited waits (writes flush, close record, reads drain).
func (c *Conn) Close() error {
	return c.Shutdown(context.Background())
}

// Shutdown tears down the session honoring ctx for waits on writer/delivery completion.
func (c *Conn) Shutdown(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if !c.shutdownStarted.CompareAndSwap(false, true) {
		return ErrClosed
	}

	c.closed.Store(true)
	close(c.stopSend)

	err := waitChan(ctx, c.writeDone)
	if c.deliverCancel != nil {
		c.deliverCancel()
		err = firstNonNil(err, waitWaitGroup(ctx, &c.deliverWG))
	}

	closeErr := c.nc.Close()
	err = firstNonNil(err, waitChan(ctx, c.readDone))
	if err != nil {
		return err
	}
	return closeErr
}

func waitChan(ctx context.Context, ch <-chan struct{}) error {
	select {
	case <-ch:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func waitWaitGroup(ctx context.Context, wg *sync.WaitGroup) error {
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func firstNonNil(a, b error) error {
	if a != nil {
		return a
	}
	return b
}

func (c *Conn) abortRecv(err error) {
	c.recvMu.Lock()
	defer c.recvMu.Unlock()
	if c.recvClosed {
		return
	}
	c.recvClosed = true
	if err == nil {
		err = io.EOF
	}
	c.recvErr = err
	close(c.recvCh)
}

func (c *Conn) readLoop() {
	defer close(c.readDone)

	for {
		msgType, sealed, err := protocol.ReadRecord(c.nc)
		if err != nil {
			c.abortRecv(err)
			return
		}
		pt, err := c.sess.Open(sealed)
		if err != nil {
			c.abortRecv(err)
			return
		}
		switch msgType {
		case protocol.MsgText:
			if len(pt) > c.cfg.MaxMessageBytes {
				c.abortRecv(ErrMessageTooLarge)
				return
			}
			if c.cfg.OnMessage != nil {
				payload := append([]byte(nil), pt...)
				select {
				case c.msgJobs <- payload:
				default:
					if c.cfg.DisconnectOnSlowCallbackConsumer {
						c.abortRecv(ErrSlowConsumer)
						return
					}
					c.callbackDropped.Add(1)
				}
			} else {
				select {
				case c.recvCh <- append([]byte(nil), pt...):
				case <-c.stopSend:
					c.abortRecv(ErrClosed)
					return
				}
			}
		case protocol.MsgPing:
			reply := append([]byte(nil), pt...)
			select {
			case <-c.stopSend:
				c.abortRecv(ErrClosed)
				return
			case c.sendCh <- outbound{typ: protocol.MsgPong, pt: reply}:
			}
		case protocol.MsgPong:
		case protocol.MsgClose:
			c.abortRecv(io.EOF)
			return
		default:
			c.abortRecv(protocol.ErrBadFrame)
			return
		}
	}
}

func (c *Conn) writeLoop() {
	defer close(c.writeDone)

	writeOut := func(out outbound) bool {
		sealed, err := c.sess.Seal(out.pt)
		if err != nil {
			return false
		}
		if err := protocol.WriteRecord(c.nc, out.typ, sealed); err != nil {
			return false
		}
		return true
	}

	for {
		select {
		case <-c.stopSend:
			goto flush
		case out := <-c.sendCh:
			if !writeOut(out) {
				return
			}
		}
	}
flush:
	for {
		select {
		case out := <-c.sendCh:
			if !writeOut(out) {
				return
			}
		default:
			_ = writeOut(outbound{typ: protocol.MsgClose, pt: nil})
			return
		}
	}
}

// Underlying returns the TCP connection wrapped by this session.
func (c *Conn) Underlying() net.Conn {
	return c.nc
}
