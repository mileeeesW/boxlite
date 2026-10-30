// Copyright 2026 BoxLite AI
// SPDX-License-Identifier: AGPL-3.0

package boxlite

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	boxlite "github.com/boxlite-ai/boxlite/sdks/go"
)

// evictBox drops a spent handle so the next lookup fetches a bootable one. It
// must drop only the handle it was handed: a concurrent Create or fetch can
// re-cache the same box id in between, and unmapping that winner would throw
// away a live entry the other caller is about to use.
//
// The handles here are zero-value wrappers used purely as identities. evictBox
// also closes the one it unmaps, but a zero-value wrapper holds no native
// handle, so these never touch the FFI.
func TestEvictBoxRemovesOnlyTheHandleItWasGiven(t *testing.T) {
	stale := &boxlite.Box{}
	winner := &boxlite.Box{}

	t.Run("removes the stale handle", func(t *testing.T) {
		c := &Client{boxes: map[string]*boxlite.Box{"box-1": stale}}

		c.evictBox("box-1", stale)

		if _, ok := c.boxes["box-1"]; ok {
			t.Fatal("stale handle must be unmapped")
		}
	})

	t.Run("keeps a handle that replaced the stale one", func(t *testing.T) {
		c := &Client{boxes: map[string]*boxlite.Box{"box-1": winner}}

		c.evictBox("box-1", stale)

		if got := c.boxes["box-1"]; got != winner {
			t.Fatalf("the replacing handle must survive, got %v", got)
		}
	})

	t.Run("is a no-op for an id that is not cached", func(t *testing.T) {
		c := &Client{boxes: map[string]*boxlite.Box{}}

		c.evictBox("box-absent", stale)

		if len(c.boxes) != 0 {
			t.Fatalf("cache must stay empty, got %d entries", len(c.boxes))
		}
	})
}

// Concurrent eviction of the same entry must not race or double-delete; the
// mutex inside evictBox is what makes the read-modify-write safe.
func TestEvictBoxIsSafeUnderConcurrentCallers(t *testing.T) {
	stale := &boxlite.Box{}
	c := &Client{boxes: map[string]*boxlite.Box{"box-1": stale}}

	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c.evictBox("box-1", stale)
		}()
	}
	wg.Wait()

	if _, ok := c.boxes["box-1"]; ok {
		t.Fatal("handle must be unmapped after concurrent eviction")
	}
}

// An evicted handle used to be unmapped and then left alive for the life of the
// process: closing it could free the FFI handle under a goroutine that was
// mid-call on the same *boxlite.Box. The SDK now makes Close wait for such a
// call and refuse the ones after it, so the handle a lookup swaps out is
// released.
//
// The handles are real but need no VM: the runtime is a REST client for a
// server that knows one stopped box.
func TestGetOrFetchBoxReleasesTheHandleItEvicts(t *testing.T) {
	rt := newStoppedBoxRestRuntime(t, "box-1")
	ctx := context.Background()

	spent, err := rt.Get(ctx, "box-1")
	if err != nil {
		t.Fatalf("Get box-1: %v", err)
	}
	t.Cleanup(func() { _ = spent.Close() })
	c := &Client{runtime: rt, boxes: map[string]*boxlite.Box{"box-1": spent}}

	fresh, err := c.getOrFetchBox(ctx, "box-1")
	if err != nil {
		t.Fatalf("getOrFetchBox: %v", err)
	}
	t.Cleanup(func() { _ = fresh.Close() })
	if fresh == spent {
		t.Fatal("a stopped box's cached handle must be swapped for a fresh one")
	}

	if _, err := spent.Metrics(ctx); !errors.Is(err, boxlite.ErrBoxClosed) {
		t.Fatalf("the evicted handle is still open (Metrics: %v): it was unmapped without being released", err)
	}
}

// Releasing evicted handles means a lookup can read a handle from the map just
// before another lookup, finding the box down, evicts and closes it. The first
// lookup's state read then fails with ErrBoxClosed on a handle it never closed.
// That only says the handle was swapped out from under it, so it must fetch a
// fresh one as the other lookup did instead of failing the request.
//
// Leaving the closed handle mapped stands in for that earlier read:
// getOrFetchBox takes the same path whether or not the map still holds it.
func TestGetOrFetchBoxReplacesAHandleClosedUnderIt(t *testing.T) {
	rt := newStoppedBoxRestRuntime(t, "box-1")
	ctx := context.Background()

	closedUnderIt, err := rt.Get(ctx, "box-1")
	if err != nil {
		t.Fatalf("Get box-1: %v", err)
	}
	if err := closedUnderIt.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	c := &Client{runtime: rt, boxes: map[string]*boxlite.Box{"box-1": closedUnderIt}}

	fresh, err := c.getOrFetchBox(ctx, "box-1")
	if err != nil {
		t.Fatalf("a handle closed by a concurrent eviction must be replaced, not reported: %v", err)
	}
	t.Cleanup(func() { _ = fresh.Close() })
	if fresh == closedUnderIt {
		t.Fatal("the closed handle must not be handed out again")
	}
}

// newStoppedBoxRestRuntime returns a runtime whose box handles are real but need
// no VM: a REST client for a server that knows one stopped box.
func newStoppedBoxRestRuntime(t *testing.T, id string) *boxlite.Runtime {
	t.Helper()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/v1/boxes/"+id {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{
			"box_id":"`+id+`","name":"`+id+`","status":"stopped",
			"created_at":"2026-10-14T00:00:00Z","updated_at":"2026-10-14T00:00:00Z",
			"pid":null,"image":"alpine:3.21","cpus":1,"memory_mib":256
		}`)
	}))
	t.Cleanup(server.Close)

	rt, err := boxlite.NewRest(boxlite.BoxliteRestOptions{URL: server.URL})
	if err != nil {
		t.Fatalf("NewRest: %v", err)
	}
	t.Cleanup(func() { _ = rt.Close() })
	return rt
}
