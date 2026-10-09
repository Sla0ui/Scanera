package state

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMarkPersistsAndReloads(t *testing.T) {
	path := filepath.Join(t.TempDir(), "resume.json")

	s, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if s.Done("a.com") {
		t.Fatal("fresh state should be empty")
	}
	for _, d := range []string{"a.com", "b.com"} {
		if err := s.Mark(d); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Flush(); err != nil {
		t.Fatal(err)
	}

	again, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if !again.Done("a.com") || !again.Done("b.com") || again.Done("c.com") {
		t.Errorf("reloaded state wrong: %v", again.Completed)
	}
	if again.Len() != 2 {
		t.Errorf("Len()=%d want 2", again.Len())
	}

	// No temp files left behind.
	entries, _ := os.ReadDir(filepath.Dir(path))
	if len(entries) != 1 {
		t.Errorf("expected only the state file, found %d entries", len(entries))
	}
}

func TestLoadRejectsCorruptFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "resume.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("expected an error for a corrupt resume file")
	}
}
