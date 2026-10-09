package portscan

import "testing"

func TestParsePortsTop(t *testing.T) {
	if len(ParsePorts("top")) == 0 {
		t.Fatal("expected top ports")
	}
}

func TestParsePortsListAndRange(t *testing.T) {
	got := ParsePorts("80,443,8000-8002,443")
	want := []int{80, 443, 8000, 8001, 8002}
	if len(got) != len(want) {
		t.Fatalf("got %v want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v want %v", got, want)
		}
	}
}

func TestParsePortsFallback(t *testing.T) {
	if len(ParsePorts("garbage")) == 0 {
		t.Fatal("expected fallback to top ports")
	}
}

func TestParsePortsFull(t *testing.T) {
	if len(ParsePorts("full")) != 65535 {
		t.Fatalf("full should be 65535 ports, got %d", len(ParsePorts("full")))
	}
}
