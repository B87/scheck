package finding_test

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/b87/scheck/internal/collector/github"
	"github.com/b87/scheck/internal/collector/web"
	"github.com/b87/scheck/internal/engagement/report"
	"github.com/b87/scheck/internal/finding"
)

// These compile-time checks prevent another collector/report mapping shape.
var (
	_ func(web.Input) []finding.Judgment                       = web.Judge
	_ func(github.Evidence, github.Context) []finding.Judgment = github.Judge
	_ report.Judgment                                          = finding.Judgment{}
)

// findings.json keeps a judgment's attribution, declaration sources, gaps
// and optional asset-wide subject as Analyze gave them. It is output only:
// nothing reads it back (docs/spec/runs.md, "Verdicts are not evidence").
func TestPersistedJudgmentRoundTrip(t *testing.T) {
	for name, raw := range map[string]string{
		"github asset":   `{"id":"github.org_mfa_not_required","asset":"saas:github:acme","verdict":"abstained","reason":"insufficient_evidence","reads":[],"source":["access.mfa[0]"]}`,
		"github account": `{"id":"identity.former_person_has_access","asset":"repo:github:acme/shop","subject":{"kind":"account","key":"alice","label":"Alice","provider_id":"42","person":"alice"},"verdict":"fired","reads":["members"],"excerpt":"redacted evidence","not_checked":["session usability"],"attributes":[{"name":"admin","ref":{"observation":"members","excerpt":"redacted evidence"}}],"listed":["alice"],"details":{"role":"admin"},"why":"Alice left and still holds admin.","source":["people.alice"]}`,
		"web wildcard":   `{"id":"dns.takeover_candidate","asset":"domain:example.com","subject":{"kind":"dns_name","key":"*.example.com","label":"*.example.com"},"verdict":"fired","reads":["wildcard"],"excerpt":"names with matching DNS answers (their pages were not read): blog.example.com, docs.example.com"}`,
	} {
		t.Run(name, func(t *testing.T) {
			var j finding.Judgment
			if err := json.Unmarshal([]byte(raw), &j); err != nil {
				t.Fatal(err)
			}
			encoded, err := json.Marshal(j)
			if err != nil {
				t.Fatal(err)
			}
			var before, after any
			if err := json.Unmarshal([]byte(raw), &before); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(encoded, &after); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(before, after) {
				t.Fatalf("persisted judgment changed:\n%s\n%s", raw, encoded)
			}
		})
	}
}
