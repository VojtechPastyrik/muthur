package store

import (
	"context"
	"testing"
	"time"
)

func TestMemory_SetGet(t *testing.T) {
	m := NewMemory()
	defer m.Close()
	ctx := context.Background()

	if _, ok, _ := m.Get(ctx, "k"); ok {
		t.Fatal("expected miss on empty store")
	}
	if err := m.Set(ctx, "k", []byte("v"), 0); err != nil {
		t.Fatal(err)
	}
	v, ok, _ := m.Get(ctx, "k")
	if !ok || string(v) != "v" {
		t.Fatalf("got %q ok=%v, want v true", v, ok)
	}
}

func TestMemory_SetNX(t *testing.T) {
	m := NewMemory()
	defer m.Close()
	ctx := context.Background()

	set, _ := m.SetNX(ctx, "k", []byte("1"), time.Minute)
	if !set {
		t.Fatal("first SetNX should set")
	}
	set, _ = m.SetNX(ctx, "k", []byte("2"), time.Minute)
	if set {
		t.Fatal("second SetNX should not set")
	}
}

func TestMemory_Expiry(t *testing.T) {
	m := NewMemory()
	defer m.Close()
	ctx := context.Background()

	m.Set(ctx, "k", []byte("v"), time.Millisecond)
	time.Sleep(5 * time.Millisecond)
	if _, ok, _ := m.Get(ctx, "k"); ok {
		t.Fatal("expected expiry")
	}
}

func TestMemory_ListByPrefix(t *testing.T) {
	m := NewMemory()
	defer m.Close()
	ctx := context.Background()

	m.Set(ctx, "vec:a", []byte("1"), 0)
	m.Set(ctx, "vec:b", []byte("2"), 0)
	m.Set(ctx, "cache:c", []byte("3"), 0)

	vals, _ := m.ListByPrefix(ctx, "vec:")
	if len(vals) != 2 {
		t.Fatalf("got %d values, want 2", len(vals))
	}
}
