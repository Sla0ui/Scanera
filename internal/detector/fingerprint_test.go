package detector

import "testing"

func TestDetectWithVersionsBody(t *testing.T) {
	techs := DetectWithVersions(`<script src="/js/jquery-3.3.1.min.js"></script>`, nil)
	var found bool
	for _, tch := range techs {
		if tch.Name == "jQuery" && tch.Version == "3.3.1" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected jQuery 3.3.1, got %+v", techs)
	}
}

func TestDetectWithVersionsHeader(t *testing.T) {
	techs := DetectWithVersions("", map[string][]string{"Server": {"nginx/1.18.0"}})
	var found bool
	for _, tch := range techs {
		if tch.Name == "nginx" && tch.Version == "1.18.0" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected nginx 1.18.0, got %+v", techs)
	}
}
