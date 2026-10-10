package gate

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"strings"

	"github.com/b87/scheck/internal/policy"
)

const codeMetadataLimit = "metadata_structure_limit"

var errMetadataLimit = errors.New("metadata structure limit")

var actionsSecretRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,254}$`)

func ValidSecretName(v string) bool {
	return actionsSecretRE.MatchString(v) && !strings.HasPrefix(strings.ToUpper(v), "GITHUB_")
}

// Metadata resources vary only within their compiled owning tenant/repository.
// docs/spec/github-collector.md, "Secret metadata and provider alerts: step 5 definition".
func (c *compiled) checkMetadataResource(p Param) error {
	if c.Provider != "github" || c.Method != GET || p.Optional || !c.GitHubMetadata {
		return errors.New("metadata resources require compiled GitHub GETs")
	}
	switch p.Type {
	case SecretName:
		if p.Name != "secret_name" || c.path != "/orgs/{org}/actions/secrets/{secret_name}/repositories" || c.Subject != "saas:github:{org}" || c.types["org"].Type != Login {
			return errors.New("secret name outside compiled selected-repository read")
		}
	case AlertNumber:
		if p.Name != "alert_number" || c.path != "/repos/{owner}/{repo}/secret-scanning/alerts/{alert_number}/locations" || c.Subject != "repo:github:{owner}/{repo}" || c.types["owner"].Type != Login || c.types["repo"].Type != RepoName {
			return errors.New("alert number outside compiled location read")
		}
	}
	return nil
}
func (c *compiled) checkMetadataOp() error {
	if !c.GitHubMetadata {
		return nil
	}
	if c.Provider != "github" || c.Method != GET || c.WorkflowYAML || c.List == nil {
		return errors.New("metadata projection requires a compiled GitHub list GET")
	}
	switch c.path {
	case "/orgs/{org}/actions/secrets", "/orgs/{org}/actions/secrets/{secret_name}/repositories":
		if c.Subject != "saas:github:{org}" {
			return errors.New("secret metadata tenant mismatch")
		}
	case "/repos/{owner}/{repo}/actions/secrets", "/repos/{owner}/{repo}/dependabot/alerts", "/repos/{owner}/{repo}/secret-scanning/alerts", "/repos/{owner}/{repo}/secret-scanning/alerts/{alert_number}/locations":
		if c.Subject != "repo:github:{owner}/{repo}" {
			return errors.New("alert metadata repository mismatch")
		}
	default:
		return errors.New("metadata projection outside compiled surface")
	}
	for _, f := range c.Keep {
		if f == "secret" || f == "metadata" || f == "details" || strings.HasSuffix(f, "url") {
			return errors.New("metadata must not retain secret values, raw details or URLs")
		}
	}
	return nil
}

// Check structure on redacted bytes before projection. Duplicate members, excessive
// depth and ambiguous list containers never become absence evidence.
func metadataJSON(clean []byte, op *compiled) ([]byte, string) {
	d := json.NewDecoder(bytes.NewReader(clean))
	d.UseNumber()
	nodes := 0
	var value func(int) error
	value = func(depth int) error {
		nodes++
		if depth > 40 || nodes > 50000 {
			return errMetadataLimit
		}
		t, err := d.Token()
		if err != nil {
			return err
		}
		delim, ok := t.(json.Delim)
		if !ok {
			return nil
		}
		switch delim {
		case '{':
			keys := map[string]bool{}
			for d.More() {
				k, err := d.Token()
				if err != nil {
					return err
				}
				key, ok := k.(string)
				if !ok || keys[key] {
					return errors.New("duplicate")
				}
				keys[key] = true
				if err := value(depth + 1); err != nil {
					return err
				}
			}
		case '[':
			for d.More() {
				if err := value(depth + 1); err != nil {
					return err
				}
			}
		default:
			return errors.New("delimiter")
		}
		_, err = d.Token()
		return err
	}
	if err := value(0); err != nil {
		if errors.Is(err, errMetadataLimit) {
			return nil, codeMetadataLimit
		}
		return nil, codeMalformed
	}
	if _, err := d.Token(); !errors.Is(err, io.EOF) {
		return nil, codeMalformed
	}
	doc, code := parseRedacted(clean)
	if code != "" {
		return nil, code
	}
	items, code := listItems(op.List, doc)
	if code != "" {
		return nil, code
	}
	// GitHub always supplies a real array, unlike Google's omitted empty lists.
	if op.List.Items != "$" {
		f, ok := fieldAt(doc, op.List.Items)
		if !ok || f == nil {
			return nil, codeMalformed
		}
	}
	for _, item := range items {
		m, ok := item.(map[string]any)
		if !ok {
			return nil, codeMalformed
		}
		if op.path == "/repos/{owner}/{repo}/secret-scanning/alerts/{alert_number}/locations" && m["type"] != "commit" {
			delete(m, "details")
		}
		// The value itself is discarded by Keep. Only the redactor's marker is retained.
		delete(m, "redaction_marker") // a target cannot supply trusted provenance
		if v, present := m["secret"]; present && op.path == "/repos/{owner}/{repo}/secret-scanning/alerts" {
			if s, ok := v.(string); ok && strings.HasPrefix(s, "[REDACTED:") {
				m["redaction_marker"] = s
			} else {
				m["redaction_marker"] = policy.Marker("provider-secret", len(marshal(v)))
			}
		}
	}
	return marshal(doc), ""
}

func metadataBody(raw []byte, red *policy.Redactor, op *compiled) ([]byte, []policy.Hit, string) {
	clean, hits, err := red.RedactJSON(raw)
	if err != nil {
		return nil, nil, codeMalformed
	}
	clean, code := metadataJSON(clean, op)
	return clean, hits, code
}
