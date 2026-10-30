//go:build boxlite_dev && race

// Copyright 2026 BoxLite AI
// SPDX-License-Identifier: AGPL-3.0

package boxlite

import (
	"context"
	"os"
	"sync"
	"testing"
	"time"
)

// TestCloseRacesACallInFlight reproduces the Box handle race directly against a
// live local runtime: a shared *Box is closed while other goroutines are mid
// Metrics call, exactly as the runner shares one handle per box.
//
// It is gated on the `race` build tag so it only compiles under `go test -race`,
// where the detector reports the conflicting access cleanly. Without the fix the
// run fails with a data race between Close freeing the handle (box_handle.go) and
// Metrics reading it (metrics.go); with the fix Close waits for in-flight calls
// and the run passes.
//
//	go test -tags boxlite_dev -race -run TestCloseRacesACallInFlight ./sdks/go
func TestCloseRacesACallInFlight(t *testing.T) {
	home, err := os.MkdirTemp("", "bl-close-race-")
	if err != nil {
		t.Fatalf("temp home: %v", err)
	}
	defer os.RemoveAll(home)

	rt, err := NewRuntime(WithHomeDir(home))
	if err != nil {
		t.Skipf("runtime not available: %v", err)
	}
	defer rt.Close()

	ctx := context.Background()
	bx, _, err := rt.GetOrCreate(ctx, "alpine:latest",
		WithName("close-race-probe"), WithAutoRemove(false))
	if err != nil {
		t.Skipf("create could not complete (infrastructure prerequisite): %v", err)
	}

	var wg sync.WaitGroup
	start := make(chan struct{})
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for range 200 {
				_, _ = bx.Metrics(ctx)
			}
		}()
	}
	close(start)
	time.Sleep(2 * time.Millisecond)
	_ = bx.Close()
	wg.Wait()
}
