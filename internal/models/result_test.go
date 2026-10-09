package models

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestResultMarshalJSON_ErrorAsString(t *testing.T) {
	r := Result{
		Domain: "example.com",
		Error:  errors.New("domain not resolvable: no such host"),
	}

	data, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	// Decode generically and assert "error" is a non-empty string, not {}.
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	got, ok := m["error"]
	if !ok {
		t.Fatalf("expected an \"error\" field, got: %s", data)
	}
	s, ok := got.(string)
	if !ok {
		t.Fatalf("expected \"error\" to be a string, got %T (%s)", got, data)
	}
	if !strings.Contains(s, "no such host") {
		t.Fatalf("expected error message to be preserved, got %q", s)
	}
}

func TestResultMarshalJSON_NilErrorOmitted(t *testing.T) {
	r := Result{Domain: "example.com"}

	data, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	if strings.Contains(string(data), "\"error\"") {
		t.Fatalf("expected no \"error\" field for a nil error, got: %s", data)
	}
}

func TestResultJSONRoundTripKeepsError(t *testing.T) {
	in := Result{Domain: "example.com", Error: errors.New("connection refused"), Findings: []Finding{{ID: "x"}}}
	data, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	var out Result
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatal(err)
	}
	if out.Error == nil || out.Error.Error() != "connection refused" || out.Domain != "example.com" || len(out.Findings) != 1 {
		t.Fatalf("round trip lost data: %+v", out)
	}
}
