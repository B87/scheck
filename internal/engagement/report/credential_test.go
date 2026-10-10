package report

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	githubc "github.com/b87/scheck/internal/collector/github"
)

func TestAssessmentCredentialNotesAreUnranked(t *testing.T) {
	for _, scopes := range [][]string{{"repo", "read:org"}, {"read:org"}, nil} {
		t.Run(strings.Join(scopes, ","), func(t *testing.T) {
			in := githubAccessFiredReport(t)
			for i := range in.Assets {
				in.Assets[i].InventoryNotes = nil
			}
			before := Build(in)
			note := githubc.AssessmentCredential(githubc.PrincipalRead{Read: githubc.Read{Decision: "sent", Status: 200}, Account: &githubc.Account{ID: 41, Login: "alice", Type: "User"}, Identity: "github:user:41", Scopes: scopes})
			kind := "github_credential"
			if note.Capability == githubc.CapabilityBeyondReads {
				kind = "github_credential_warning"
			}
			in.Assets[0].InventoryNotes = []Note{{Kind: kind, Source: in.Assets[0].ID, Detail: note.Detail}}
			after := Build(in)
			for name, pair := range map[string][2]any{
				"findings": {before.Findings, after.Findings}, "assessments": {before.Assessments, after.Assessments},
				"ranking": {before.Summary, after.Summary}, "coverage": {before.Coverage, after.Coverage},
				"acceptances": {before.Acceptances, after.Acceptances}, "exit": {before.Exit, after.Exit},
			} {
				if !reflect.DeepEqual(pair[0], pair[1]) {
					t.Fatalf("credential note changed %s", name)
				}
			}
			encoded, err := json.Marshal(after)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Contains(encoded, []byte(kind)) {
				t.Fatal("missing credential note in JSON")
			}
			for _, verbose := range []int{0, 1} {
				var text bytes.Buffer
				if err := WriteText(&text, after, Options{Verbose: verbose}); err != nil {
					t.Fatal(err)
				}
				at := strings.Index(text.String(), "GitHub assessment credential:")
				ranking := strings.Index(text.String(), "Fix these first:")
				if at < 0 || ranking < 0 || at >= ranking {
					t.Fatal("credential note absent or below ranking")
				}
				if note.Capability == githubc.CapabilityBeyondReads && !strings.Contains(text.String(), "Warning") {
					t.Fatal("broad grant not labeled warning")
				}
			}
		})
	}
}
