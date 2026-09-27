package config

import (
	"testing"
	"time"
)

func TestDefaultsValidateAfterCredentials(t *testing.T) {
	c := Defaults()
	c.L2TP.Server = "192.0.2.1"
	c.L2TP.Username = "user"
	c.L2TP.Password = "password"
	if err := c.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestRejectsInvalidReconnectDelays(t *testing.T) {
	c := Defaults()
	c.L2TP.Server = "192.0.2.1"
	c.L2TP.Username = "user"
	c.L2TP.Password = "password"
	c.L2TP.ReconnectInitialDelay = Duration{2 * time.Second}
	c.L2TP.ReconnectMaxDelay = Duration{time.Second}
	if err := c.Validate(); err == nil {
		t.Fatal("expected validation error")
	}
}

func TestRejectsUnauthenticatedPublicSOCKS(t *testing.T) {
	c := Defaults()
	c.L2TP.Server = "192.0.2.1"
	c.L2TP.Username = "user"
	c.L2TP.Password = "password"
	c.SOCKS5.Listen = "0.0.0.0:1080"
	if err := c.Validate(); err == nil {
		t.Fatal("expected validation error")
	}
}
