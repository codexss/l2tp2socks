package main

import (
	"context"
	"testing"
	"time"
)

func TestNextBackoffCapsAtMaximum(t *testing.T) {
	if got := nextBackoff(time.Second, 30*time.Second); got != 2*time.Second {
		t.Fatalf("nextBackoff(1s) = %s", got)
	}
	if got := nextBackoff(20*time.Second, 30*time.Second); got != 30*time.Second {
		t.Fatalf("nextBackoff(20s) = %s", got)
	}
}

func TestWaitForRetryCanBeCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if waitForRetry(ctx, time.Hour) {
		t.Fatal("waitForRetry returned true after cancellation")
	}
}
