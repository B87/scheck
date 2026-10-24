package engagement

import (
	"strings"
	"testing"
)

func TestCheckoutValidationAndResolution(t *testing.T) {
	prefix := "schema: 1\nengagement: {name: mirrors, operator: alice, timezone: UTC, trigger: routine}\nroots: [{repo: 'github:acme/shop'}, {host: local}]\nassets:\n"
	for _, tc := range []struct{ entry, word string }{{" shop: {repo: 'github:acme/shop', checkout: /absolute/mirror}\n", ""}, {" shop: {repo: 'github:acme/shop', checkout: ./relative}\n", "absolute"}, {" local: {host: local, checkout: /absolute/mirror}\n", "repo asset"}} {
		r, e := Parse("mirrors.yaml", []byte(prefix+tc.entry), testOpts)
		if tc.word != "" {
			if e == nil || !strings.Contains(e.Error(), tc.word) {
				t.Fatal(e)
			}
			continue
		}
		if e != nil {
			t.Fatal(e)
		}
		found := false
		for _, a := range r.Assets {
			if a.ID == "repo:github:acme/shop" {
				found = a.Checkout == "/absolute/mirror"
			}
		}
		if !found {
			t.Fatal(r)
		}
	}
}
