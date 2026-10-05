package ratelimit

import (
	"testing"
	"time"
)

func TestStore_AllowsBurstThenBlocks(t *testing.T) {
	s := newStore(1.0/60.0, 3) // slow refill so the test only observes the burst window

	for i := 0; i < 3; i++ {
		if !s.Allow("actor-1") {
			t.Fatalf("call %d: expected Allow to succeed within burst", i+1)
		}
	}
	for i := 0; i < 3; i++ {
		if s.Allow("actor-1") {
			t.Fatalf("call %d beyond burst: expected Allow to fail", i+1)
		}
	}
}

func TestStore_KeysAreIndependent(t *testing.T) {
	s := newStore(1.0/60.0, 2)

	for i := 0; i < 2; i++ {
		if !s.Allow("actor-1") {
			t.Fatalf("actor-1 call %d: expected Allow to succeed within burst", i+1)
		}
	}
	if s.Allow("actor-1") {
		t.Fatal("actor-1: expected burst to be exhausted")
	}
	for i := 0; i < 2; i++ {
		if !s.Allow("actor-2") {
			t.Fatalf("actor-2 call %d: expected a fresh key to have its own burst", i+1)
		}
	}
}

func TestStore_RefillsWithClock(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	s := newStore(1, 1, WithClock(func() time.Time { return now }))

	if !s.Allow("k") {
		t.Fatal("first call should pass")
	}
	if s.Allow("k") {
		t.Fatal("second immediate call should be limited")
	}
	now = now.Add(time.Second)
	if !s.Allow("k") {
		t.Fatal("call after 1s refill should pass")
	}
}

func TestStore_MaxEntriesEvictsLeastRecentlySeen(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	s := newStore(1, 1, WithMaxEntries(2), WithClock(func() time.Time { return now }))

	s.Allow("a")
	now = now.Add(time.Second)
	s.Allow("b")
	now = now.Add(time.Second)
	s.Allow("c") // map full → "a" (oldest) evicted

	if s.Len() != 2 {
		t.Fatalf("Len = %d, want 2", s.Len())
	}
	if _, ok := s.entries["a"]; ok {
		t.Fatal("expected oldest key \"a\" to be evicted")
	}
}

func TestStore_PruneDropsIdleKeys(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	s := newStore(1, 1, WithClock(func() time.Time { return now }))
	s.Allow("idle")
	now = now.Add(idleAfter + time.Second)
	s.Allow("fresh")
	s.prune()
	if _, ok := s.entries["idle"]; ok {
		t.Fatal("idle key should have been pruned")
	}
	if _, ok := s.entries["fresh"]; !ok {
		t.Fatal("fresh key should survive prune")
	}
}
