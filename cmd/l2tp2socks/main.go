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
	"time"

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
	if err := run(ctx, settings, logger); err != nil {
		logger.Fatalf("stopped: %v", err)
	}
}

func run(ctx context.Context, settings config.Config, logger *log.Logger) error {
	delay := settings.L2TP.ReconnectInitialDelay.Duration
	for attempt := 1; ; attempt++ {
		if ctx.Err() != nil {
			return nil
		}
		logger.Printf("[l2tp] connection attempt %d", attempt)
		connectedAt, err := runSession(ctx, settings, logger)
		if ctx.Err() != nil {
			return nil
		}
		if connectedAt.IsZero() {
			logger.Printf("[l2tp] connection failed: %v", err)
		} else {
			logger.Printf("[l2tp] session lost: %v", err)
			if time.Since(connectedAt) >= settings.L2TP.ReconnectMaxDelay.Duration {
				delay = settings.L2TP.ReconnectInitialDelay.Duration
			}
		}
		logger.Printf("[l2tp] reconnecting in %s", delay)
		if !waitForRetry(ctx, delay) {
			return nil
		}
		delay = nextBackoff(delay, settings.L2TP.ReconnectMaxDelay.Duration)
	}
}

func runSession(ctx context.Context, settings config.Config, logger *log.Logger) (time.Time, error) {
	client := l2tp.NewClient(l2tp.Config{
		Server: settings.L2TP.Server, L2TPPort: settings.L2TP.Port, DisableIPsec: true,
		Username: settings.L2TP.Username, Password: settings.L2TP.Password,
		Auth: settings.L2TP.Auth,
		MTU:  settings.L2TP.MTU, Timeout: settings.L2TP.ConnectTimeout.Duration, Logger: logger,
	})
	session, err := client.Start(ctx)
	if err != nil {
		return time.Time{}, err
	}
	connectedAt := time.Now()
	logger.Printf("[l2tp] connected; assigned addresses: %v", session.Addresses())

	dialer, err := vpn.NewDialer(session, vpn.DNSConfig{
		Server: settings.L2TP.DNSServer, DoHURL: settings.L2TP.DoHURL,
		DoHBootstrapIP: settings.L2TP.DoHBootstrapIP,
	})
	if err != nil {
		_ = session.Close()
		return connectedAt, fmt.Errorf("configure DNS: %w", err)
	}

	serveCtx, cancel := context.WithCancel(ctx)
	server := socks5.New(settings.SOCKS5.Listen, settings.SOCKS5.Username, settings.SOCKS5.Password, dialer, logger)
	serverDone := make(chan error, 1)
	sessionDone := make(chan error, 1)
	go func() { serverDone <- server.Run(serveCtx) }()
	go func() { sessionDone <- session.Wait(serveCtx) }()

	var result error
	select {
	case <-ctx.Done():
		result = ctx.Err()
	case err = <-sessionDone:
		result = err
	case err = <-serverDone:
		if err == nil {
			result = errors.New("SOCKS5 server stopped unexpectedly")
		} else {
			result = fmt.Errorf("SOCKS5 server: %w", err)
		}
	}

	// Canceling the server closes its listener and every active TCP/UDP client.
	// Closing the session also releases the L2TP transport and unblocks Wait.
	cancel()
	_ = session.Close()
	return connectedAt, result
}

func waitForRetry(ctx context.Context, delay time.Duration) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-ctx.Done():
		return false
	}
}

func nextBackoff(current, maximum time.Duration) time.Duration {
	if current >= maximum-current {
		return maximum
	}
	return current * 2
}
