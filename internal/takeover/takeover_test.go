package takeover

import "testing"

func TestMatch(t *testing.T) {
	cases := map[string]string{
		"acme.github.io":                          "GitHub Pages",
		"assets.acme.com.s3.amazonaws.com":        "AWS S3",
		"acme.s3-website-us-east-1.amazonaws.com": "AWS S3",
		"acme.herokudns.com.":                     "Heroku",
		"acme.azurewebsites.net":                  "Microsoft Azure",
		"acme.eu-west-1.elasticbeanstalk.com":     "AWS Elastic Beanstalk",
		"shops.myshopify.com":                     "Shopify",
	}
	for cname, want := range cases {
		svc, ok := Match(cname)
		if !ok || svc.Name != want {
			t.Errorf("Match(%q) = %q,%v want %q", cname, svc.Name, ok, want)
		}
	}
	for _, cname := range []string{"github.io.evil.com", "example.com", "notgithub.io", "ec2-1-2-3-4.compute.amazonaws.com"} {
		if svc, ok := Match(cname); ok {
			t.Errorf("Match(%q) unexpectedly matched %s", cname, svc.Name)
		}
	}
}

func TestCheckResponse(t *testing.T) {
	body := "<html><body>404 There isn't a GitHub Pages site here.</body></html>"
	f, ok := CheckResponse("docs.acme.com", "acme.github.io", body)
	if !ok || f.ID != "subdomain-takeover" || f.Severity != "high" {
		t.Fatalf("expected a high takeover finding, got %+v %v", f, ok)
	}
	if _, ok := CheckResponse("docs.acme.com", "acme.github.io", "<html>Welcome to the docs</html>"); ok {
		t.Error("a claimed site must not be flagged")
	}
	if _, ok := CheckResponse("docs.acme.com", "cdn.acme.net", body); ok {
		t.Error("a fingerprint without a matching CNAME must not be flagged")
	}
}

func TestCheckDangling(t *testing.T) {
	f, ok := CheckDangling("app.acme.com", "acme-prod.azurewebsites.net")
	if !ok || f.ID != "subdomain-takeover" || f.Severity != "high" {
		t.Fatalf("Azure NXDOMAIN should be a high takeover, got %+v", f)
	}
	f, ok = CheckDangling("old.acme.com", "legacy.some-vendor.com")
	if !ok || f.ID != "dangling-cname" || f.Severity != "medium" {
		t.Fatalf("unknown dangling target should be medium dangling-cname, got %+v", f)
	}
	// GitHub Pages is fingerprint-based, not NXDOMAIN-based.
	if f, _ := CheckDangling("x.acme.com", "acme.github.io"); f.ID != "dangling-cname" {
		t.Errorf("non-NXDOMAIN provider should fall back to dangling-cname, got %s", f.ID)
	}
	if _, ok := CheckDangling("x.acme.com", ""); ok {
		t.Error("no CNAME means nothing to report")
	}
}
