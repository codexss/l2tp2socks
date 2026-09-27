package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"time"
)

type Config struct {
	L2TP   L2TP   `json:"l2tp"`
	SOCKS5 SOCKS5 `json:"socks5"`
}

type L2TP struct {
	Server         string   `json:"server"`
	Port           int      `json:"port"`
	Username       string   `json:"username"`
	Password       string   `json:"password"`
	Auth           string   `json:"auth"`
	MTU            int      `json:"mtu"`
	ConnectTimeout Duration `json:"connectTimeout"`
	DNSServer      string   `json:"dnsServer"`
	DoHURL         string   `json:"dohUrl"`
	DoHBootstrapIP string   `json:"dohBootstrapIp"`
}

type SOCKS5 struct {
	Listen   string `json:"listen"`
	Username string `json:"username"`
	Password string `json:"password"`
}

type Duration struct{ time.Duration }

func (d *Duration) UnmarshalJSON(data []byte) error {
	var value string
	if err := json.Unmarshal(data, &value); err != nil {
		return errors.New("duration must be a string such as 30s")
	}
	parsed, err := time.ParseDuration(value)
	if err != nil {
		return err
	}
	d.Duration = parsed
	return nil
}

func Defaults() Config {
	return Config{L2TP: L2TP{Port: 1701, Auth: "auto", MTU: 1400, ConnectTimeout: Duration{30 * time.Second}, DNSServer: "1.1.1.1:53", DoHURL: "https://cloudflare-dns.com/dns-query", DoHBootstrapIP: "1.1.1.1"}, SOCKS5: SOCKS5{Listen: "127.0.0.1:1080"}}
}

func Load(path string) (Config, error) {
	value := Defaults()
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read config: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&value); err != nil {
		return Config{}, fmt.Errorf("parse config: %w", err)
	}
	if err := value.Validate(); err != nil {
		return Config{}, err
	}
	return value, nil
}

func (c Config) Validate() error {
	if c.L2TP.Server == "" {
		return errors.New("l2tp.server is required")
	}
	if c.L2TP.Username == "" || c.L2TP.Password == "" {
		return errors.New("l2tp.username and l2tp.password are required")
	}
	switch c.L2TP.Auth {
	case "auto", "pap", "chap", "chap-md5", "mschapv2":
	default:
		return errors.New("l2tp.auth must be auto, pap, chap-md5, or mschapv2")
	}
	if c.L2TP.Port < 1 || c.L2TP.Port > 65535 {
		return errors.New("l2tp.port must be between 1 and 65535")
	}
	if c.L2TP.MTU < 576 || c.L2TP.MTU > 1400 {
		return errors.New("l2tp.mtu must be between 576 and 1400")
	}
	if c.L2TP.ConnectTimeout.Duration <= 0 {
		return errors.New("l2tp.connectTimeout must be positive")
	}
	if _, _, err := net.SplitHostPort(c.L2TP.DNSServer); err != nil {
		return fmt.Errorf("invalid l2tp.dnsServer: %w", err)
	}
	if c.L2TP.DoHURL != "" {
		parsed, err := url.Parse(c.L2TP.DoHURL)
		if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" {
			return errors.New("l2tp.dohUrl must be a valid HTTPS URL")
		}
		bootstrap := net.ParseIP(c.L2TP.DoHBootstrapIP)
		if bootstrap == nil || bootstrap.To4() == nil {
			return errors.New("l2tp.dohBootstrapIp must be an IPv4 address when dohUrl is set")
		}
	}
	host, _, err := net.SplitHostPort(c.SOCKS5.Listen)
	if err != nil {
		return fmt.Errorf("invalid socks5.listen: %w", err)
	}
	if (c.SOCKS5.Username == "") != (c.SOCKS5.Password == "") {
		return errors.New("socks5.username and socks5.password must both be set or both be empty")
	}
	if len(c.SOCKS5.Username) > 255 || len(c.SOCKS5.Password) > 255 {
		return errors.New("SOCKS5 credentials must not exceed 255 bytes")
	}
	listenIP := net.ParseIP(host)
	if c.SOCKS5.Username == "" && (listenIP == nil || !listenIP.IsLoopback()) {
		return errors.New("SOCKS5 authentication is required when socks5.listen is not a loopback address")
	}
	return nil
}
