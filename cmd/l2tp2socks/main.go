package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/bclswl0827/govpn/protocols/l2tp"
	"github.com/example/l2tp2socks/internal/config"
	"github.com/example/l2tp2socks/internal/socks5"
	"github.com/example/l2tp2socks/internal/vpn"
)

var version = "dev"

func main() {
	configPath := flag.String("config", "config.json", "path to JSON configuration")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Println(version)
		return
	}

	logger := log.New(os.Stderr, "", log.LstdFlags|log.Lmicroseconds)
	settings, err := config.Load(*configPath)
	if err != nil {
		logger.Fatalf("configuration error: %v", err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	logger.Printf("WARNING: plain L2TP is unencrypted; credentials and traffic can be observed or modified in transit")
	client := l2tp.NewClient(l2tp.Config{
		Server: settings.L2TP.Server, L2TPPort: settings.L2TP.Port, DisableIPsec: true,
		Username: settings.L2TP.Username, Password: settings.L2TP.Password,
		Auth: settings.L2TP.Auth,
		MTU:  settings.L2TP.MTU, Timeout: settings.L2TP.ConnectTimeout.Duration, Logger: logger,
	})
	session, err := client.Start(ctx)
	if err != nil {
		logger.Fatalf("connect L2TP: %v", err)
	}
	defer session.Close()
	logger.Printf("L2TP connected; assigned addresses: %v", session.Addresses())

	dialer, err := vpn.NewDialer(session, vpn.DNSConfig{
		Server: settings.L2TP.DNSServer, DoHURL: settings.L2TP.DoHURL,
		DoHBootstrapIP: settings.L2TP.DoHBootstrapIP,
	})
	if err != nil {
		logger.Fatalf("configure DNS: %v", err)
	}
	server := socks5.New(settings.SOCKS5.Listen, settings.SOCKS5.Username, settings.SOCKS5.Password, dialer, logger)
	err = server.Run(ctx)
	if err != nil && !errors.Is(err, context.Canceled) {
		logger.Fatalf("SOCKS5 server: %v", err)
	}
}
