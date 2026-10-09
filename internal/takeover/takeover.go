// Package takeover flags subdomains whose CNAME points at a third-party
// service where the resource behind it no longer exists, so anyone could claim
// it and serve content on the victim's hostname. Checks are passive: they use
// the CNAME and the response the scanner already fetched.
package takeover

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/Sla0ui/scanera/internal/models"
)

// Service describes a provider that can be claimed through a stale CNAME.
type Service struct {
	Name string
	// CNAME matches the alias target (lowercase, no trailing dot).
	CNAME *regexp.Regexp
	// Fingerprints are body substrings the provider serves for unclaimed names.
	Fingerprints []string
	// NXDomain means the provider is claimable when the target doesn't resolve.
	NXDomain bool
}

// Services is the built-in list, kept to providers with well-documented,
// still-working takeover conditions.
var Services = []Service{
	{Name: "GitHub Pages", CNAME: regexp.MustCompile(`\.github\.io$`),
		Fingerprints: []string{"There isn't a GitHub Pages site here."}},
	{Name: "AWS S3", CNAME: regexp.MustCompile(`(^|\.)s3[.-]([a-z0-9-]+\.)*amazonaws\.com$|\.s3-website[.-][a-z0-9.-]+\.amazonaws\.com$`),
		Fingerprints: []string{"NoSuchBucket", "The specified bucket does not exist"}},
	{Name: "Heroku", CNAME: regexp.MustCompile(`\.herokuapp\.com$|\.herokudns\.com$`),
		Fingerprints: []string{"herokucdn.com/error-pages/no-such-app.html", "<title>No such app</title>"}},
	{Name: "Microsoft Azure", NXDomain: true,
		CNAME: regexp.MustCompile(`\.(azurewebsites\.net|cloudapp\.net|cloudapp\.azure\.com|trafficmanager\.net|blob\.core\.windows\.net|azureedge\.net|azure-api\.net|azurecontainer\.io|azurefd\.net|azurehdinsight\.net|redis\.cache\.windows\.net|search\.windows\.net|servicebus\.windows\.net|visualstudio\.com)$`)},
	{Name: "AWS Elastic Beanstalk", NXDomain: true, CNAME: regexp.MustCompile(`\.elasticbeanstalk\.com$`)},
	{Name: "Shopify", CNAME: regexp.MustCompile(`\.myshopify\.com$`),
		Fingerprints: []string{"Sorry, this shop is currently unavailable."}},
	{Name: "Fastly", CNAME: regexp.MustCompile(`\.fastly\.net$`),
		Fingerprints: []string{"Fastly error: unknown domain"}},
	{Name: "Ghost", CNAME: regexp.MustCompile(`\.ghost\.io$`),
		Fingerprints: []string{"The thing you were looking for is no longer here, or never was"}},
	{Name: "Pantheon", CNAME: regexp.MustCompile(`\.pantheonsite\.io$`),
		Fingerprints: []string{"The gods are wise, but do not know of the site which you seek."}},
	{Name: "Tumblr", CNAME: regexp.MustCompile(`^domains\.tumblr\.com$`),
		Fingerprints: []string{"Whatever you were looking for doesn't currently exist at this address."}},
	{Name: "Surge.sh", CNAME: regexp.MustCompile(`(^|\.)surge\.sh$`),
		Fingerprints: []string{"project not found"}},
	{Name: "Bitbucket", CNAME: regexp.MustCompile(`\.bitbucket\.io$`),
		Fingerprints: []string{"Repository not found"}},
	{Name: "Zendesk", CNAME: regexp.MustCompile(`\.zendesk\.com$`),
		Fingerprints: []string{"Help Center Closed"}},
	{Name: "ReadMe", CNAME: regexp.MustCompile(`\.readme\.io$`),
		Fingerprints: []string{"Project doesnt exist... yet!"}},
	{Name: "Help Scout", CNAME: regexp.MustCompile(`\.helpscoutdocs\.com$`),
		Fingerprints: []string{"No settings were found for this company:"}},
	{Name: "WordPress.com", CNAME: regexp.MustCompile(`\.wordpress\.com$`),
		Fingerprints: []string{"Do you want to register"}},
	{Name: "Netlify", CNAME: regexp.MustCompile(`\.netlify\.(app|com)$`),
		Fingerprints: []string{"Not Found - Request ID:"}},
}

// Match returns the service a CNAME target belongs to, if any.
func Match(cname string) (Service, bool) {
	cname = strings.ToLower(strings.TrimSuffix(cname, "."))
	for _, s := range Services {
		if s.CNAME.MatchString(cname) {
			return s, true
		}
	}
	return Service{}, false
}

// CheckDangling handles a host that doesn't resolve but still has a CNAME.
// A known NXDOMAIN-claimable provider is a likely takeover; any other dangling
// alias is reported for manual review, since the target domain itself may be
// unregistered.
func CheckDangling(host, cname string) (models.Finding, bool) {
	if cname == "" {
		return models.Finding{}, false
	}
	if svc, ok := Match(cname); ok && svc.NXDomain {
		return finding(host, cname, svc.Name, models.SeverityHigh,
			fmt.Sprintf("%s points at a %s resource that no longer exists; registering that name would serve content on %s.", host, svc.Name, host)), true
	}
	return models.Finding{
		ID:          "dangling-cname",
		Title:       "Dangling CNAME",
		Severity:    models.SeverityMedium,
		Source:      "takeover",
		Description: fmt.Sprintf("%s is an alias for %s, which does not resolve. If the target can be registered or claimed, the subdomain can be taken over.", host, cname),
		Evidence:    "CNAME " + cname,
		Location:    host,
		Tags:        []string{"takeover", "dns"},
	}, true
}

// CheckResponse handles a host that resolved and answered: the body served by
// a matching provider shows its "unclaimed" page.
func CheckResponse(host, cname, body string) (models.Finding, bool) {
	svc, ok := Match(cname)
	if !ok {
		return models.Finding{}, false
	}
	for _, fp := range svc.Fingerprints {
		if strings.Contains(body, fp) {
			return finding(host, cname, svc.Name, models.SeverityHigh,
				fmt.Sprintf("%s points at %s, which serves its page for an unclaimed resource. Claiming it would serve content on %s.", host, svc.Name, host)), true
		}
	}
	return models.Finding{}, false
}

func finding(host, cname, service string, sev models.Severity, desc string) models.Finding {
	return models.Finding{
		ID:          "subdomain-takeover",
		Title:       "Possible subdomain takeover (" + service + ")",
		Severity:    sev,
		Source:      "takeover",
		Description: desc,
		Evidence:    "CNAME " + cname,
		Location:    host,
		References:  []string{"https://github.com/EdOverflow/can-i-take-over-xyz"},
		Tags:        []string{"takeover", strings.ToLower(service)},
	}
}
