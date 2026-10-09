// Package state persists scan progress so interrupted runs can resume without
// rescanning completed domains.
package state

import (
	"encoding/json"
	"os"
	"sync"
)

// State tracks which domains have been completed.
type State struct {
	mu        sync.Mutex
	path      string
	Completed map[string]bool `json:"completed"`
}

// Load reads state from path, or returns a fresh state if the file is absent.
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
		_ = json.Unmarshal(data, s)
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

// Mark records a domain as completed and persists the state (best effort).
func (s *State) Mark(domain string) {
	s.mu.Lock()
	s.Completed[domain] = true
	data, _ := json.MarshalIndent(s, "", "  ")
	path := s.path
	s.mu.Unlock()
	if path != "" {
		_ = os.WriteFile(path, data, 0644)
	}
}
