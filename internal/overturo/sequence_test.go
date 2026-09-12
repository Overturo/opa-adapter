package overturo

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSequenceManagerStartsAtOne(t *testing.T) {
	m, err := NewSequenceManager("")
	if err != nil {
		t.Fatalf("NewSequenceManager: %v", err)
	}
	if got := m.Next(); got != 1 {
		t.Errorf("first Next() = %d; want 1", got)
	}
	if got := m.Next(); got != 2 {
		t.Errorf("second Next() = %d; want 2", got)
	}
}

func TestSequenceManagerRestoresFromFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sequence.json")
	if err := os.WriteFile(path, []byte("42"), 0o600); err != nil {
		t.Fatalf("seed file: %v", err)
	}

	m, err := NewSequenceManager(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if got := m.Next(); got != 43 {
		t.Errorf("Next() after restore = %d; want 43", got)
	}
}

func TestSequenceManagerMissingFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "absent.json")
	m, err := NewSequenceManager(path)
	if err != nil {
		t.Fatalf("missing file should be OK: %v", err)
	}
	if got := m.Next(); got != 1 {
		t.Errorf("Next() with missing state file = %d; want 1", got)
	}
}

func TestSequenceManagerPersistAtomic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sequence.json")

	m, err := NewSequenceManager(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	seq := m.Next()
	if err := m.Persist(seq); err != nil {
		t.Fatalf("persist: %v", err)
	}

	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if string(body) != "1" {
		t.Errorf("persisted = %q; want %q", body, "1")
	}
}

func TestSequenceManagerPersistEmpty(t *testing.T) {
	m, err := NewSequenceManager("")
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Persist(5); err != nil {
		t.Errorf("Persist() with empty filePath should be no-op; got %v", err)
	}
}

func TestSequenceManagerPeek(t *testing.T) {
	m, _ := NewSequenceManager("")
	if got := m.Peek(); got != 1 {
		t.Errorf("Peek() initial = %d; want 1", got)
	}
	m.Next()
	if got := m.Peek(); got != 2 {
		t.Errorf("Peek() after first Next = %d; want 2", got)
	}
}

// B5 regression — Rewind rolls back a failed submission so the next
// Next() returns the same value, preventing attestation.gap_detected.
func TestSequenceManagerRewindSuccess(t *testing.T) {
	m, _ := NewSequenceManager("")
	seq := m.Next() // returns 1
	if !m.Rewind(seq) {
		t.Errorf("Rewind(%d) returned false; expected true", seq)
	}
	if next := m.Next(); next != 1 {
		t.Errorf("after Rewind, Next() = %d; want 1 (rewound)", next)
	}
}

func TestSequenceManagerRewindSkippedWhenAdvanced(t *testing.T) {
	m, _ := NewSequenceManager("")
	first := m.Next() // 1
	_ = m.Next()      // 2 — counter advanced past first
	if m.Rewind(first) {
		t.Errorf("Rewind(%d) = true; expected false (counter advanced)", first)
	}
	if next := m.Next(); next != 3 {
		t.Errorf("Next() after rejected rewind = %d; want 3", next)
	}
}
