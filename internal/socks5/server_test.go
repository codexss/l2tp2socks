package socks5

import (
	"net"
	"testing"
)

func TestUDPClientMatcherPinsFirstPort(t *testing.T) {
	matcher := &udpClientMatcher{ip: net.ParseIP("192.0.2.10")}
	if !matcher.accept(&net.UDPAddr{IP: net.ParseIP("192.0.2.10"), Port: 40000}) {
		t.Fatal("first matching endpoint rejected")
	}
	if matcher.accept(&net.UDPAddr{IP: net.ParseIP("192.0.2.10"), Port: 40001}) {
		t.Fatal("different source port accepted")
	}
	if matcher.accept(&net.UDPAddr{IP: net.ParseIP("192.0.2.11"), Port: 40000}) {
		t.Fatal("different source IP accepted")
	}
}

func TestParseUDPDomainRequest(t *testing.T) {
	packet := []byte{0, 0, 0, addressDomain, 11}
	packet = append(packet, []byte("example.com")...)
	packet = append(packet, 0, 53, 1, 2, 3)
	host, port, payload, err := parseUDPRequest(packet)
	if err != nil {
		t.Fatal(err)
	}
	if host != "example.com" || port != 53 || len(payload) != 3 {
		t.Fatalf("got host=%q port=%d payload=%v", host, port, payload)
	}
}

func BenchmarkParseUDPRequest(b *testing.B) {
	packet := []byte{0, 0, 0, addressIPv4, 1, 1, 1, 1, 0, 53, 1, 2, 3, 4}
	for b.Loop() {
		_, _, _, _ = parseUDPRequest(packet)
	}
}
