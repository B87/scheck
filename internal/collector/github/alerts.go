package github

import (
	"context"
	"encoding/json"
	"maps"
	"net/url"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/b87/scheck/internal/engagement/gate"
)

const (
	OpOrganizationSecrets        = "github.organization_secrets"         //nolint:gosec // compiled identifier, not a credential
	OpSelectedSecretRepositories = "github.secret_selected_repositories" //nolint:gosec // compiled operation identifier, not a credential
	OpRepositorySecrets          = "github.repository_secrets"           //nolint:gosec // compiled operation identifier, not a credential
	OpDependabotAlerts           = "github.dependabot_alerts"
	OpSecretAlerts               = "github.secret_scanning_alerts"    //nolint:gosec // compiled operation identifier, not a credential
	OpSecretLocations            = "github.secret_scanning_locations" //nolint:gosec // compiled operation identifier, not a credential
	AlertRulesVersion            = "github-alerts:2026-10-10"
)

func alertOps() []gate.Op {
	base := gate.Op{Provider: "github", Method: gate.GET, Level: gate.Observe, Auth: gate.GitHubToken, APIVersion: "2026-03-10", Accept: []string{"application/json", "application/vnd.github+json"}, MaxBytes: 1 << 20, GitHubMetadata: true}
	list := func(id, endpoint, subject, items string, params []gate.Param, fields []string) gate.Op {
		o := base
		o.ID = id
		o.URL = "https://api.github.com" + endpoint + "?per_page=100&page={page}"
		o.Subject = subject
		o.Keep = fields
		o.Params = append(slices.Clone(params), gate.Param{Name: "page", Type: gate.Count, Optional: true})
		o.List = &gate.List{Items: items, Kind: gate.KindOther, Next: &gate.Pages{Param: "page"}, MaxPages: 100}
		return o
	}
	orgParams := []gate.Param{{Name: "org", Type: gate.Login}}
	repoParams := []gate.Param{{Name: "owner", Type: gate.Login}, {Name: "repo", Type: gate.RepoName}}
	fields := []string{"name", "created_at", "updated_at", "visibility"}
	org := list(OpOrganizationSecrets, "/orgs/{org}/actions/secrets", "saas:github:{org}", "secrets", orgParams, fields)
	selected := list(OpSelectedSecretRepositories, "/orgs/{org}/actions/secrets/{secret_name}/repositories", "saas:github:{org}", "repositories", append(slices.Clone(orgParams), gate.Param{Name: "secret_name", Type: gate.SecretName}), []string{"id", "name", "full_name", "owner.id", "owner.login", "owner.type", "visibility"})
	selected.List.Kind = gate.KindRepo
	selected.List.ExcludeKey = "full_name"
	selected.List.Subject = "repo:github:{key}"
	repo := list(OpRepositorySecrets, "/repos/{owner}/{repo}/actions/secrets", "repo:github:{owner}/{repo}", "secrets", repoParams, fields[:3])
	dep := list(OpDependabotAlerts, "/repos/{owner}/{repo}/dependabot/alerts", "repo:github:{owner}/{repo}", "$", repoParams, []string{"number", "state", "dependency.manifest_path", "dependency.scope", "dependency.package.name", "dependency.package.ecosystem", "security_advisory.ghsa_id", "security_advisory.severity", "security_vulnerability.severity", "dismissed_reason"})
	dep.URL = "https://api.github.com/repos/{owner}/{repo}/dependabot/alerts?per_page=100&after={after}"
	dep.Params = append(slices.Clone(repoParams), gate.Param{Name: "after", Type: gate.Cursor, Optional: true})
	dep.List.Next = &gate.Pages{Param: "after"}
	secret := list(OpSecretAlerts, "/repos/{owner}/{repo}/secret-scanning/alerts", "repo:github:{owner}/{repo}", "$", repoParams, []string{"number", "state", "secret_type", "validity", "resolution", "redaction_marker"})
	secret.URL += "&hide_secret=true"
	locations := list(OpSecretLocations, "/repos/{owner}/{repo}/secret-scanning/alerts/{alert_number}/locations", "repo:github:{owner}/{repo}", "$", append(slices.Clone(repoParams), gate.Param{Name: "alert_number", Type: gate.AlertNumber}), []string{"type", "details.commit_sha", "details.path", "details.start_line", "details.end_line", "details.start_column", "details.end_column"})
	return []gate.Op{org, selected, repo, dep, secret, locations}
}

type ActionsSecret struct {
	Name       string  `json:"name"`
	CreatedAt  *string `json:"created_at,omitempty"`
	UpdatedAt  *string `json:"updated_at,omitempty"`
	Visibility *string `json:"visibility,omitempty"`
}
type SelectedSecret struct {
	Name         string                 `json:"name"`
	Repositories Population[Repository] `json:"repositories"`
}
type DependencyAlert struct {
	Number     int64  `json:"number"`
	State      string `json:"state"`
	Dependency struct {
		ManifestPath string `json:"manifest_path"`
		Scope        string `json:"scope"`
		Package      struct {
			Name      string `json:"name"`
			Ecosystem string `json:"ecosystem"`
		} `json:"package"`
	} `json:"dependency"`
	Advisory struct {
		GHSA     string `json:"ghsa_id"`
		Severity string `json:"severity"`
	} `json:"security_advisory"`
	Vulnerability struct {
		Severity string `json:"severity"`
	} `json:"security_vulnerability"`
	DismissedReason *string `json:"dismissed_reason,omitempty"`
}
type SecretAlert struct {
	Number          int64   `json:"number"`
	State           string  `json:"state"`
	Type            string  `json:"secret_type"`
	Validity        *string `json:"validity,omitempty"`
	Resolution      *string `json:"resolution,omitempty"`
	RedactionMarker string  `json:"redaction_marker,omitempty"`
}
type SecretLocation struct {
	Type    string `json:"type"`
	Details struct {
		SHA         string `json:"commit_sha"`
		Path        string `json:"path"`
		StartLine   int64  `json:"start_line"`
		EndLine     int64  `json:"end_line"`
		StartColumn int64  `json:"start_column"`
		EndColumn   int64  `json:"end_column"`
	} `json:"details"`
}
type LocatedSecret struct {
	Alert     SecretAlert                `json:"alert"`
	Locations Population[SecretLocation] `json:"locations"`
}
type RepositoryAlerts struct {
	RepositoryRead Read                        `json:"repository_read"`
	Asset          string                      `json:"asset"`
	Visibility     *string                     `json:"visibility,omitempty"`
	Secrets        Population[ActionsSecret]   `json:"secrets"`
	Dependencies   Population[DependencyAlert] `json:"dependencies"`
	SecretAlerts   Population[SecretAlert]     `json:"secret_alerts"`
	Located        []LocatedSecret             `json:"located,omitempty"`
}

func (r RepositoryAlerts) Reads() []Read {
	out := slices.Concat(r.Secrets.Reads, r.Dependencies.Reads, r.SecretAlerts.Reads)
	for _, s := range r.Located {
		out = append(out, s.Locations.Reads...)
	}
	return out
}

// Recognition is per metadata field: a discarded provider secret's redaction does
// not invalidate an independently recognized alert number, state or location.
func metadataReadOK(r Read) bool {
	return (r.Decision == gate.DecisionSent || r.Decision == gate.DecisionReused) && r.Status == 200 && (r.Reason == "" || r.Reason == "limit_reached") && r.Gap == "" && !r.Truncated
}
func metadataObserved[T any](p Population[T]) bool {
	return slices.ContainsFunc(p.Reads, metadataReadOK)
}
func metadataComplete[T any](p Population[T]) bool {
	return p.Complete && p.VisibilityComplete && len(p.Reads) > 0 && !slices.ContainsFunc(p.Reads, func(r Read) bool { return !metadataReadOK(r) })
}
func metadataPopulation[T any](ctx context.Context, g Sender, req gate.Request, key func(T) string) Population[T] {
	p := Population[T]{Complete: true, VisibilityComplete: true}
	seen := map[string]bool{}
	requests := map[string]bool{}
	for range 100 {
		r := g.Send(ctx, req)
		p.Reads = append(p.Reads, readOf(req.Op, r))
		var items []T
		if !usable(r) || string(r.Response.Body) == "null" || json.Unmarshal(r.Response.Body, &items) != nil {
			uncertain(&p, "metadata_unavailable")
			return p
		}
		for _, item := range items {
			k := key(item)
			if k == "" {
				uncertain(&p, "metadata_unrecognized")
				continue
			}
			if seen[k] {
				uncertain(&p, "duplicate_item")
				continue
			}
			seen[k] = true
			p.Items = append(p.Items, item)
		}
		if r.Response.Population == nil {
			uncertain(&p, "population_unknown")
			return p
		}
		for _, gap := range r.Response.Population.Incomplete {
			uncertain(&p, gap)
		}
		if !r.Response.Population.More {
			return p
		}
		if r.RequestID == "" || requests[r.RequestID] {
			uncertain(&p, "pagination_unrecognized")
			return p
		}
		requests[r.RequestID] = true
		req.NextOf = r.RequestID
	}
	uncertain(&p, "page_limit")
	return p
}
func secretNameKey(s ActionsSecret) string {
	if !gate.ValidSecretName(s.Name) {
		return ""
	}
	return strings.ToLower(s.Name)
}
func numberKey(n int64) string {
	if n < 1 {
		return ""
	}
	return strconv.FormatInt(n, 10)
}

var plainTypeRE = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$`)

func manifestOK(p string) bool {
	for _, r := range p {
		if r < 32 || r == 127 {
			return false
		}
	}
	return p != "" && len(p) <= 1024 && !strings.ContainsAny(p, "\\\x00\r\n\t") && !strings.Contains(p, "[REDACTED:") && !strings.HasPrefix(p, "/") && path.Clean(p) == p && p != "." && p != ".." && !strings.HasPrefix(p, "../")
}
func locationKey(l SecretLocation) string {
	d := l.Details
	if l.Type != "commit" || !fullSHA.MatchString(d.SHA) || !manifestOK(d.Path) || d.StartLine < 1 || d.EndLine < d.StartLine || d.StartColumn < 1 || d.EndColumn < 1 || d.EndLine == d.StartLine && d.EndColumn < d.StartColumn {
		return ""
	}
	return "commit:" + strings.ToLower(d.SHA) + ":" + url.PathEscape(d.Path) + ":" + strconv.FormatInt(d.StartLine, 10) + ":" + strconv.FormatInt(d.StartColumn, 10)
}

// CollectAlerts reads admitted repository objects only, never target-provided URLs.
// docs/spec/github-collector.md, "Secret metadata and provider alerts: step 5 definition".
func CollectAlerts(ctx context.Context, g Sender, e Evidence, org Organization) Evidence {
	if e.Organization != nil {
		req := gate.Request{Op: OpOrganizationSecrets, Asset: org.Asset, Stage: org.Stage, Exists: true, Params: map[string]string{"org": org.Name}}
		e.OrganizationSecrets = metadataPopulation(ctx, g, req, secretNameKey)
		n := 0
		for _, s := range e.OrganizationSecrets.Items {
			if s.Visibility == nil || *s.Visibility != "selected" {
				continue
			}
			if n >= 100 {
				metadataLimit(&e.OrganizationSecrets, "selected_secret_limit")
				break
			}
			n++
			req.Op = OpSelectedSecretRepositories
			req.NextOf = ""
			req.Params = map[string]string{"org": org.Name, "secret_name": s.Name}
			p := metadataPopulation(ctx, g, req, func(r Repository) string {
				if !repositoryOK(r, org.Name) {
					return ""
				}
				return strings.ToLower(r.FullName)
			})
			e.SelectedSecrets = append(e.SelectedSecrets, SelectedSecret{Name: s.Name, Repositories: p})
		}
	}
	for _, a := range e.RepositoriesAccess {
		if a.Repository == nil {
			continue
		}
		repo := a.Repository
		req := func(op string, extra map[string]string) gate.Request {
			p := map[string]string{"owner": repo.Owner.Login, "repo": repo.Name}
			maps.Copy(p, extra)
			return gate.Request{Op: op, Asset: a.Asset, Stage: org.Stage, Exists: true, Params: p}
		}
		c := RepositoryAlerts{Asset: a.Asset, RepositoryRead: a.RepositoryRead, Visibility: repo.Visibility}
		c.Secrets = metadataPopulation(ctx, g, req(OpRepositorySecrets, nil), secretNameKey)
		c.Dependencies = metadataPopulation(ctx, g, req(OpDependabotAlerts, nil), func(d DependencyAlert) string { return numberKey(d.Number) })
		c.SecretAlerts = metadataPopulation(ctx, g, req(OpSecretAlerts, nil), func(s SecretAlert) string { return numberKey(s.Number) })
		for i, s := range c.SecretAlerts.Items {
			if i >= 100 {
				metadataLimit(&c.SecretAlerts, "secret_location_limit")
				break
			}
			p := metadataPopulation(ctx, g, req(OpSecretLocations, map[string]string{"alert_number": numberKey(s.Number)}), func(l SecretLocation) string { return locationKey(l) })
			c.Located = append(c.Located, LocatedSecret{Alert: s, Locations: p})
		}
		e.RepositoriesAlerts = append(e.RepositoriesAlerts, c)
	}
	return e
}
func metadataLimit[T any](p *Population[T], gap string) {
	uncertain(p, gap)
	if len(p.Reads) > 0 {
		p.Reads[len(p.Reads)-1].Reason = "limit_reached"
		p.Reads[len(p.Reads)-1].Detail = "GitHub metadata follow-up reached its compiled limit"
	}
}
