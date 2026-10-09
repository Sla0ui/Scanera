package subdomain

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"
)

func TestFilterNames(t *testing.T) {
	got := filterNames("example.com", []string{
		"*.Example.com",
		"www.example.com.",
		"api.example.com",
		"api.example.com",
		"evil-example.com",
		"example.com.evil.net",
		"bad name.example.com",
		"a..example.com",
		"",
	})
	want := []string{"api.example.com", "example.com", "www.example.com"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("filterNames = %v, want %v", got, want)
	}
}

func TestEnumeratePassiveSources(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/crt":
			if r.URL.Query().Get("q") != "%.example.com" {
				t.Errorf("unexpected crt.sh query %q", r.URL.RawQuery)
			}
			_, _ = w.Write([]byte(`[{"name_value":"www.example.com\nmail.example.com"},{"name_value":"*.dev.example.com"}]`))
		case "/cs":
			w.WriteHeader(http.StatusTooManyRequests)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	oldCrt, oldCS := crtshURL, certspotterURL
	crtshURL, certspotterURL = srv.URL+"/crt", srv.URL+"/cs"
	defer func() { crtshURL, certspotterURL = oldCrt, oldCS }()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	subs, err := Enumerate(ctx, "Example.com", Options{PassiveOnly: true, Client: srv.Client()})

	want := []string{"dev.example.com", "mail.example.com", "www.example.com"}
	if !reflect.DeepEqual(subs, want) {
		t.Errorf("subs = %v, want %v", subs, want)
	}
	if err == nil {
		t.Error("expected the failing certspotter source to be reported")
	}
}
