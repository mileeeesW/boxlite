package boxlite

/*
#include "bridge.h"
*/
import "C"
import (
	"context"
	"runtime/cgo"
	"sync"
)

// Box is a handle to a BoxLite box (virtual machine).
// Call Close to release the handle when done. Closing does not destroy the box.
//
// A Box may be shared between goroutines, one of which closes it while others
// are mid-call: Close waits for the calls already using the native handle, and
// every call that starts after it fails with ErrBoxClosed.
type Box struct {
	runtime *Runtime
	id      string
	name    string

	// mu keeps handle alive across each call into the runtime. A call holds the
	// read side only while it is inside the runtime, which clones what it keeps
	// before returning; Close holds the write side to free the handle.
	mu     sync.RWMutex
	handle *C.CBoxHandle
}

// newBoxFromHandle wraps a freshly-returned C.CBoxHandle into the Go Box
// type. The box keeps a reference to its parent Runtime so the same drain
// loop services its async lifecycle ops.
func newBoxFromHandle(r *Runtime, handle *C.CBoxHandle, name string) *Box {
	id := ""
	if handle != nil {
		cID := C.boxlite_box_id(handle)
		if cID != nil {
			id = C.GoString(cID)
			freeBoxliteString(cID)
		}
	}
	return &Box{runtime: r, handle: handle, id: id, name: name}
}

// ID returns the unique identifier of the box.
func (b *Box) ID() string { return b.id }

// Name returns the user-defined name of the box, if set.
func (b *Box) Name() string { return b.name }

// pin holds the native handle open for one call into the runtime and returns
// the function that lets it go. Call unpin as soon as that call returns: waiting
// on its result afterwards needs nothing from the handle. Once Close has run,
// pin refuses with ErrBoxClosed instead of handing the runtime a freed handle.
func (b *Box) pin() (unpin func(), err error) {
	b.mu.RLock()
	if b.handle == nil {
		b.mu.RUnlock()
		return nil, ErrBoxClosed
	}
	return b.mu.RUnlock, nil
}

// Start starts (or restarts) the box.
func (b *Box) Start(ctx context.Context) error {
	b.runtime.ensureDrainRunning()

	unpin, err := b.pin()
	if err != nil {
		return err
	}
	ch := make(chan error, 1)
	h := registerHandleForDispatch(cgo.NewHandle(ch))

	var cerr C.CBoxliteError
	code := C.boxlite_start_box(b.handle, C.cbStartBox(), handleToPtr(h), &cerr)
	unpin()
	if code != C.Ok {
		deleteHandleForDispatch(h)
		return freeError(&cerr)
	}

	select {
	case err := <-ch:
		return err
	case <-ctx.Done():
		abandonAsyncErr(ch, h, b.runtime.closing)
		return ctx.Err()
	case <-b.runtime.closing:
		abandonAsyncErr(ch, h, b.runtime.closing)
		return ErrRuntimeClosed
	}
}

// Stop stops the box.
func (b *Box) Stop(ctx context.Context) error {
	b.runtime.ensureDrainRunning()

	unpin, err := b.pin()
	if err != nil {
		return err
	}
	ch := make(chan error, 1)
	h := registerHandleForDispatch(cgo.NewHandle(ch))

	var cerr C.CBoxliteError
	code := C.boxlite_stop_box(b.handle, C.cbStopBox(), handleToPtr(h), &cerr)
	unpin()
	if code != C.Ok {
		deleteHandleForDispatch(h)
		return freeError(&cerr)
	}

	select {
	case err := <-ch:
		return err
	case <-ctx.Done():
		abandonAsyncErr(ch, h, b.runtime.closing)
		return ctx.Err()
	case <-b.runtime.closing:
		abandonAsyncErr(ch, h, b.runtime.closing)
		return ErrRuntimeClosed
	}
}

// Close releases the box handle. The box itself continues to exist in the runtime.
//
// Close waits for calls already using the handle, so it is safe while other
// goroutines share this Box, and closing twice is harmless.
func (b *Box) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.handle != nil {
		C.boxlite_box_free(b.handle)
		b.handle = nil
	}
	return nil
}
