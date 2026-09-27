package vpn

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

type Session interface {
	DialContext(context.Context, string, string) (net.Conn, error)
	ListenPacket(string, string) (net.PacketConn, error)
}

type DNSConfig struct {
	Server         string
	DoHURL         string
	DoHBootstrapIP string
}

// Dialer resolves names over the VPN. For DoH, the HTTPS connection is also
// carried inside the VPN and uses a fixed bootstrap IP, never the host DNS.
type Dialer struct {
	session Session
	resolve func(context.Context, string) ([]net.IP, error)
}

func NewDialer(session Session, config DNSConfig) (*Dialer, error) {
	d := &Dialer{session: session}
	if config.DoHURL != "" {
		resolver, err := newDoHResolver(session, config.DoHURL, config.DoHBootstrapIP)
		if err != nil {
			return nil, err
		}
		d.resolve = resolver.lookupIPv4
		return d, nil
	}
	resolver := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return session.DialContext(ctx, "udp4", config.Server)
	}}
	d.resolve = func(ctx context.Context, host string) ([]net.IP, error) {
		return resolver.LookupIP(ctx, "ip4", host)
	}
	return d, nil
}

func (d *Dialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	if net.ParseIP(host) == nil {
		addresses, err := d.ResolveIPv4(ctx, host)
		if err != nil {
			return nil, err
		}
		if len(addresses) == 0 {
			return nil, fmt.Errorf("resolve %s: no IPv4 address", host)
		}
		host, network = addresses[0].String(), "tcp4"
	}
	return d.session.DialContext(ctx, network, net.JoinHostPort(host, port))
}

func (d *Dialer) ListenPacket(network, address string) (net.PacketConn, error) {
	return d.session.ListenPacket(network, address)
}

func (d *Dialer) ResolveIPv4(ctx context.Context, host string) ([]net.IP, error) {
	addresses, err := d.resolve(ctx, host)
	if err != nil {
		return nil, err
	}
	result := make([]net.IP, 0, len(addresses))
	for _, address := range addresses {
		if ip := address.To4(); ip != nil {
			result = append(result, ip)
		}
	}
	return result, nil
}

type dohResolver struct {
	endpoint *url.URL
	client   *http.Client
}

func newDoHResolver(session Session, endpoint, bootstrapIP string) (*dohResolver, error) {
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" {
		return nil, errors.New("invalid DoH HTTPS endpoint")
	}
	if ip := net.ParseIP(bootstrapIP); ip == nil || ip.To4() == nil {
		return nil, errors.New("invalid DoH bootstrap IPv4 address")
	}
	transport := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, _, address string) (net.Conn, error) {
			_, port, err := net.SplitHostPort(address)
			if err != nil {
				return nil, err
			}
			return session.DialContext(ctx, "tcp4", net.JoinHostPort(bootstrapIP, port))
		},
		ForceAttemptHTTP2: true,
		IdleConnTimeout:   30 * time.Second,
	}
	return &dohResolver{endpoint: parsed, client: &http.Client{Transport: transport, Timeout: 15 * time.Second}}, nil
}

func (r *dohResolver) lookupIPv4(ctx context.Context, host string) ([]net.IP, error) {
	name, err := dnsmessage.NewName(strings.TrimSuffix(host, ".") + ".")
	if err != nil {
		return nil, fmt.Errorf("invalid DNS name %q: %w", host, err)
	}
	var idBytes [2]byte
	if _, err := rand.Read(idBytes[:]); err != nil {
		return nil, err
	}
	query := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: binary.BigEndian.Uint16(idBytes[:]), RecursionDesired: true},
		Questions: []dnsmessage.Question{{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}},
	}
	wire, err := query.Pack()
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.endpoint.String(), bytes.NewReader(wire))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/dns-message")
	req.Header.Set("Content-Type", "application/dns-message")
	response, err := r.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("DoH request: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DoH server returned %s", response.Status)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 65536))
	if err != nil {
		return nil, err
	}
	var message dnsmessage.Message
	if err := message.Unpack(body); err != nil {
		return nil, fmt.Errorf("decode DoH response: %w", err)
	}
	if message.Header.ID != query.Header.ID || !message.Header.Response {
		return nil, errors.New("invalid DoH response")
	}
	if message.Header.RCode != dnsmessage.RCodeSuccess {
		return nil, fmt.Errorf("DoH response code: %s", message.Header.RCode)
	}
	addresses := make([]net.IP, 0, len(message.Answers))
	for _, answer := range message.Answers {
		if resource, ok := answer.Body.(*dnsmessage.AResource); ok {
			addresses = append(addresses, net.IPv4(resource.A[0], resource.A[1], resource.A[2], resource.A[3]))
		}
	}
	return addresses, nil
}
