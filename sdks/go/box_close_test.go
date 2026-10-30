package boxlite

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// A *Box is shared: the runner's handle cache hands the same one to every
// request for its box, so one goroutine can close it while another is in the
// middle of a call on it. Close used to free the native handle regardless, and
// a call that had already read it went on into the runtime with a freed
// pointer. That is why the runner never closes a handle it evicts and leaks it
// instead (apps/runner/pkg/boxlite/client.go, evictBox).
//
// The window that matters is the call into the runtime itself, which no public
// method can be held open in from a test, so the test takes the pin such a call
// holds for that window.
func TestBoxCloseWaitsForACallStillUsingTheHandle(t *testing.T) {
	box := getRestBox(t, "box1")

	unpin, err := box.pin()
	if err != nil {
		t.Fatalf("pin an open handle: %v", err)
	}

	closed := make(chan struct{})
	go func() {
		_ = box.Close()
		close(closed)
	}()

	select {
	case <-closed:
		unpin()
		t.Fatal("Close freed the handle while a call was still using it")
	case <-time.After(200 * time.Millisecond):
	}

	unpin()
	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not finish after the last call let the handle go")
	}

	if _, err := box.Metrics(context.Background()); !errors.Is(err, ErrBoxClosed) {
		t.Fatalf("Metrics after Close = %v, want ErrBoxClosed: a closed handle must be refused before it reaches the runtime", err)
	}
}

// getRestBox returns a real box handle without a VM: a REST runtime backed by a
// server that knows one stopped box.
func getRestBox(t *testing.T, id string) *Box {
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

	rt, err := NewRest(BoxliteRestOptions{URL: server.URL})
	if err != nil {
		t.Fatalf("NewRest: %v", err)
	}
	t.Cleanup(func() { _ = rt.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	box, err := rt.Get(ctx, id)
	if err != nil {
		t.Fatalf("Get %s: %v", id, err)
	}
	t.Cleanup(func() { _ = box.Close() })
	return box
}
