// Package state persists scan progress so interrupted runs can resume without
// rescanning completed domains.
package state

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// saveInterval bounds how often Mark rewrites the file. Rewriting on every
// mark is quadratic on large runs; a crash loses at most this much progress.
const saveInterval = 2 * time.Second

// State tracks which domains have been completed.
type State struct {
	mu        sync.Mutex
	path      string
	dirty     bool
	lastSave  time.Time
	Completed map[string]bool `json:"completed"`
}

// Load reads state from path, or returns a fresh state if the file is absent.
// A file that exists but can't be parsed is an error: silently starting over
// would rescan everything the operator meant to skip.
func Load(path string) (*State, error) {
	s := &State{path: path, Completed: make(map[string]bool)}
	data, err := os.ReadFile(path) //nolint:gosec // operator-supplied path
	if err != nil {
		if os.IsNotExist(err) {
			return s, nil
		}
		return nil, err
	}
	if len(data) > 0 {
		if err := json.Unmarshal(data, s); err != nil {
			return nil, fmt.Errorf("resume file %q is not valid state JSON: %w", path, err)
		}
		if s.Completed == nil {
			s.Completed = make(map[string]bool)
		}
	}
	return s, nil
}

// Done reports whether a domain was already completed.
func (s *State) Done(domain string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.Completed[domain]
}

// Len returns the number of completed domains.
func (s *State) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.Completed)
}

// Mark records a domain as completed. The file is rewritten at most every
// saveInterval; call Flush when the run ends.
func (s *State) Mark(domain string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Completed[domain] = true
	s.dirty = true
	if time.Since(s.lastSave) < saveInterval {
		return nil
	}
	return s.saveLocked()
}

// Flush writes any unsaved progress.
func (s *State) Flush() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.dirty {
		return nil
	}
	return s.saveLocked()
}

func (s *State) saveLocked() error {
	if s.path == "" {
		return nil
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	if err := writeAtomic(s.path, data); err != nil {
		return err
	}
	s.dirty = false
	s.lastSave = time.Now()
	return nil
}

// writeAtomic replaces path via a temp file and rename, so a crash mid-write
// leaves either the old or the new state, never a truncated file.
func writeAtomic(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		os.Remove(tmpName)
		return err
	}
	return nil
}
