package engine

import (
	"context"
	"fmt"
	"net"
	"sync"

	"github.com/bclswl0827/govpn/protocols/l2tp/internal/logutil"
	"github.com/bclswl0827/govpn/protocols/l2tp/internal/mschap"
	"github.com/bclswl0827/govpn/protocols/l2tp/internal/ppp"
)

// PlainClientConfig configures unencrypted L2TPv2 over UDP/1701.
type PlainClientConfig struct {
	Server   *net.UDPAddr
	Username string
	Password string
	DNS      []net.IP
	Logger   *logutil.Logger
}

// PlainClient is an L2TP LAC carrying PPP directly over UDP, without IPsec.
type PlainClient struct {
	cfg    PlainClientConfig
	conn   *net.UDPConn
	tun    tunIO
	logger *logutil.Logger

	mu       sync.Mutex
	tunnel   *Tunnel
	ppp      *ppp.Session
	closed   bool
	upCh     chan NetConfig
	done     chan struct{}
	closeErr error
}

func NewPlainClient(conn *net.UDPConn, tun tunIO, cfg PlainClientConfig) *PlainClient {
	c := &PlainClient{cfg: cfg, conn: conn, tun: tun, logger: cfg.Logger, upCh: make(chan NetConfig, 1), done: make(chan struct{})}
	c.tunnel = NewTunnel(RoleLAC, c.send, c)
	return c
}

func (c *PlainClient) Handshake(ctx context.Context) (NetConfig, error) {
	go c.recvLoop()
	c.tunnel.Start()
	select {
	case nc := <-c.upCh:
		return nc, nil
	case <-c.done:
		return NetConfig{}, c.closeErr
	case <-ctx.Done():
		_ = c.Close()
		return NetConfig{}, ctx.Err()
	}
}

func (c *PlainClient) send(payload []byte) error {
	_, err := c.conn.WriteToUDP(payload, c.cfg.Server)
	return err
}

func (c *PlainClient) recvLoop() {
	buffer := make([]byte, 65535)
	for {
		n, from, err := c.conn.ReadFromUDP(buffer)
		if err != nil {
			c.fail(fmt.Errorf("l2tp: socket read: %w", err))
			return
		}
		if !from.IP.Equal(c.cfg.Server.IP) || from.Port != c.cfg.Server.Port {
			continue
		}
		c.tunnel.HandleInbound(append([]byte(nil), buffer[:n]...))
	}
}

func (c *PlainClient) Wait() error  { <-c.done; return c.closeErr }
func (c *PlainClient) Close() error { c.fail(nil); return c.closeErr }

func (c *PlainClient) fail(err error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	c.closed = true
	c.closeErr = err
	t := c.tunnel
	c.mu.Unlock()
	close(c.done)
	_ = c.conn.Close()
	if t != nil {
		t.Close()
	}
}

func (c *PlainClient) SessionUp() {
	c.mu.Lock()
	c.ppp = ppp.New(c.cfg.Username, c.cfg.Password, c.tunnel, plainClientPPP{c})
	p := c.ppp
	c.mu.Unlock()
	c.logger.Printf("l2tp: plain L2TP session up, starting PPP")
	p.Start()
}

func (c *PlainClient) DataFrame(frame []byte) {
	if ip, ok := ppp.IsIP(frame); ok {
		_, _ = c.tun.Write(ip)
		return
	}
	c.mu.Lock()
	p := c.ppp
	c.mu.Unlock()
	if p != nil {
		p.Receive(frame)
	}
}

func (c *PlainClient) Closed(err error) { c.fail(err) }

type plainClientPPP struct{ c *PlainClient }

func (h plainClientPPP) Authenticated([mschap.NTResponseLen]byte) {}
func (h plainClientPPP) Closed(err error)                         { h.c.fail(err) }
func (h plainClientPPP) NetworkUp(cfg ppp.IPConfig) {
	c := h.c
	c.logger.Printf("l2tp: PPP up, address %s gateway %s", cfg.LocalIP, cfg.PeerIP)
	go c.tunToTunnel()
	dns := cfg.DNS
	if len(dns) == 0 {
		dns = c.cfg.DNS
	}
	select {
	case c.upCh <- NetConfig{AssignedIP: cfg.LocalIP, Netmask: net.IPv4(255, 255, 255, 255), Gateway: cfg.PeerIP, DNS: dns}:
	default:
	}
}

func (c *PlainClient) tunToTunnel() {
	buf := make([]byte, 65535)
	for {
		n, err := c.tun.Read(buf)
		if err != nil {
			c.fail(fmt.Errorf("l2tp: TUN read: %w", err))
			return
		}
		if err := c.tunnel.SendPPP(ppp.EncapsulateIP(append([]byte(nil), buf[:n]...))); err != nil {
			c.fail(fmt.Errorf("l2tp: send: %w", err))
			return
		}
	}
}
