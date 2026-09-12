// sequence-number manager.
//
// Tracks a monotonic counter; persists to a local file so the
// adapter survives process restarts without tripping the server's
// `AttestationOutOfOrder` / `attestation.gap_detected` flow.
//
// `Persist()` writes after every successful attest; failures log
// but don't crash the adapter (operator can recover from the next
// successful persist).
package overturo

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
)

type SequenceManager struct {
	mu       sync.Mutex
	current  int64
	filePath string
}

// NewSequenceManager loads any persisted state from `filePath`.
// Missing file ⇒ starts at 0 (next() returns 1 first).
func NewSequenceManager(filePath string) (*SequenceManager, error) {
	m := &SequenceManager{filePath: filePath, current: 0}
	if filePath == "" {
		return m, nil
	}
	data, err := os.ReadFile(filePath)
	if errors.Is(err, fs.ErrNotExist) {
		return m, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read sequence state %s: %w", filePath, err)
	}
	var stored int64
	if err := json.Unmarshal(data, &stored); err != nil {
		return nil, fmt.Errorf("parse sequence state %s: %w", filePath, err)
	}
	m.current = stored
	return m, nil
}

// Next returns the next sequence number (monotonic; thread-safe).
func (m *SequenceManager) Next() int64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.current++
	return m.current
}

// Persist writes the given sequence to the configured state file
// (no-op when `filePath` is empty).
func (m *SequenceManager) Persist(seq int64) error {
	if m.filePath == "" {
		return nil
	}
	data, err := json.Marshal(seq)
	if err != nil {
		return err
	}
	// Atomic via tmpfile + rename.
	dir := filepath.Dir(m.filePath)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, ".sequence-*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	return os.Rename(tmpPath, m.filePath)
}

// Peek returns the value the NEXT call to Next() will return (test helper).
func (m *SequenceManager) Peek() int64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.current + 1
}

// Rewind decrements the in-memory counter if + only if it currently
// equals `seq`. The submission goroutine uses this to roll back when
// an attestation fails AFTER `Next()` returned a value — without
// rewind, the failed sequence is silently consumed and the server
// later sees `attestation.gap_detected` on the next success.
//
// Returns true when the rewind succeeded. Returns false when the
// counter has moved past `seq` (a later submission already raced
// past); in that case the gap is unavoidable and the caller should
// log + continue.
func (m *SequenceManager) Rewind(seq int64) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.current != seq {
		return false
	}
	m.current--
	return true
}
