package l2tp

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"

	"github.com/bclswl0827/govpn"
	"github.com/bclswl0827/govpn/internal/packet"
	"github.com/bclswl0827/govpn/protocols/l2tp/internal/engine"
	"github.com/bclswl0827/govpn/protocols/l2tp/internal/logutil"
)

func (c *Client) startPlain(ctx context.Context, settings resolvedSettings) (*govpn.Session, error) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero})
	if err != nil {
		return nil, fmt.Errorf("l2tp: bind UDP: %w", err)
	}
	device, err := packet.New("l2tp-client", settings.mtu)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	runContext, cancelRun := context.WithCancel(context.Background())
	logger := c.Config.Logger
	if logger == nil {
		logger = log.New(io.Discard, "", 0)
	}
	client := engine.NewPlainClient(conn, packetIO{ctx: runContext, device: device}, engine.PlainClientConfig{
		Server: settings.remote, Username: c.Config.Username, Password: c.Config.Password,
		Auth: c.Config.Auth, Logger: logutil.New(logger),
	})
	closeOnError := true
	defer func() {
		if closeOnError {
			cancelRun()
			_ = client.Close()
			_ = device.Close()
		}
	}()
	handshakeContext, cancelHandshake := context.WithTimeout(ctx, settings.timeout)
	defer cancelHandshake()
	c.logf("starting plain L2TP client: remote=%s", settings.remote)
	network, err := client.Handshake(handshakeContext)
	if err != nil {
		return nil, fmt.Errorf("l2tp: handshake: %w", err)
	}
	assigned, ok := netip.AddrFromSlice(network.AssignedIP)
	if !ok || !assigned.Is4() {
		return nil, errors.New("l2tp: PPP did not assign an IPv4 address")
	}
	done := make(chan error, 1)
	go func() { done <- client.Wait() }()
	closeTransport := func() error {
		cancelRun()
		return client.Close()
	}
	session, err := govpn.NewSession([]netip.Prefix{netip.PrefixFrom(assigned.Unmap(), 32)}, uint32(settings.mtu), device, closeTransport, done)
	if err != nil {
		return nil, err
	}
	closeOnError = false
	c.logf("plain L2TP data channel ready: address=%s/32", assigned)
	return session, nil
}
