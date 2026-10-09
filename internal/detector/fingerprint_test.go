package detector

import (
	"testing"

	"github.com/Sla0ui/scanera/internal/models"
)

func findTech(techs []models.Tech, name string) (models.Tech, bool) {
	for _, t := range techs {
		if t.Name == name {
			return t, true
		}
	}
	return models.Tech{}, false
}

func TestDetectWithVersionsBody(t *testing.T) {
	techs := DetectWithVersions(`<script src="/js/jquery-3.3.1.min.js"></script>`, nil)
	if tch, ok := findTech(techs, "jQuery"); !ok || tch.Version != "3.3.1" {
		t.Fatalf("expected jQuery 3.3.1, got %+v", techs)
	}
}

func TestDetectWithVersionsHeader(t *testing.T) {
	techs := DetectWithVersions("", map[string][]string{"Server": {"nginx/1.18.0"}})
	if tch, ok := findTech(techs, "nginx"); !ok || tch.Version != "1.18.0" {
		t.Fatalf("expected nginx 1.18.0, got %+v", techs)
	}
}

func TestDetectWithVersionsWordPressJQuery(t *testing.T) {
	body := `<script src="https://example.com/wp-includes/js/jquery/jquery.min.js?ver=3.7.1"></script>
<script src="https://example.com/wp-includes/js/jquery/jquery-migrate.min.js?ver=3.4.1"></script>`
	techs := DetectWithVersions(body, nil)
	if tch, ok := findTech(techs, "jQuery"); !ok || tch.Version != "3.7.1" {
		t.Fatalf("expected jQuery 3.7.1 from ?ver=, got %+v", techs)
	}
}

func TestDetectWithVersionsMigrateIsNotJQuery(t *testing.T) {
	body := `<script src="/wp-includes/js/jquery/jquery-migrate.min.js?ver=3.4.1"></script>`
	if tch, ok := findTech(DetectWithVersions(body, nil), "jQuery"); ok && tch.Version == "3.4.1" {
		t.Fatalf("jquery-migrate version must not be reported as jQuery: %+v", tch)
	}
}

func TestDetectWithVersionsDrupal(t *testing.T) {
	techs := DetectWithVersions("", map[string][]string{"X-Generator": {"Drupal 10 (https://www.drupal.org)"}})
	if tch, ok := findTech(techs, "Drupal"); !ok || tch.Version != "10" {
		t.Fatalf("expected Drupal 10 from X-Generator, got %+v", techs)
	}

	techs = DetectWithVersions(`<meta name="Generator" content="Drupal 7 (http://drupal.org)" />`, nil)
	if tch, ok := findTech(techs, "Drupal"); !ok || tch.Version != "7" {
		t.Fatalf("expected Drupal 7 from generator meta, got %+v", techs)
	}

	if _, ok := findTech(DetectWithVersions(`<p>We migrated off Drupal 7 last year.</p>`, nil), "Drupal"); ok {
		t.Fatal("prose mentioning Drupal must not be fingerprinted")
	}
}
