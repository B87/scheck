package policy

import (
	"bytes"
	"encoding/json"
	"errors"
	"math/rand/v2"
	"strconv"
	"strings"
	"testing"
)

const seededKey = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\nQyNTUxOQAAACBSEEDEDSEEDED\n-----END OPENSSH PRIVATE KEY-----"

func TestRedactSeededSecrets(t *testing.T) {
	r, err := NewRedactor([]string{`internal\.example\.com`})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name   string
		input  string
		secret string // must not survive
		rule   string
	}{
		{"private key", "key:\n" + seededKey + "\nend", "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQ", "private-key"},
		{"truncated private key", "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAseededseeded", "MIIEowIBAAKCAQEAseededseeded", "private-key"},
		{"aws access key", "aws_access_key_id = AKIAIOSFODNN7EXAMPLE", "AKIAIOSFODNN7EXAMPLE", "aws-access-key"},
		{"aws secret via kv", "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "wJalrXUtnFEMI", "kv-secret"},
		{"bearer", "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.SEEDEDPAYLOAD.SEEDEDSIG", "SEEDEDPAYLOAD", "bearer"},
		{"password=", "DB_PASSWORD=hunter2seeded\nother=1", "hunter2seeded", "kv-secret"},
		{"password: quoted", `password: "s3cr3t seeded"`, "s3cr3t", "kv-secret"},
		{"token=", "token=abcdef123456seeded", "abcdef123456seeded", "kv-secret"},
		{"github token", "url = https://ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@github.com", "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", "github-token"},
		{"extra rule", "host = db.internal.example.com", "internal.example.com", "extra:0"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, hits := r.RedactString(tc.input)
			if strings.Contains(out, tc.secret) {
				t.Fatalf("secret survived: %q", out)
			}
			if !strings.Contains(out, "[REDACTED:"+tc.rule+":") {
				t.Fatalf("no marker for %s in %q (hits %v)", tc.rule, out, hits)
			}
			if len(hits) == 0 || out == "" {
				t.Fatalf("redaction must leave a marker, got %q", out)
			}
		})
	}
}

func TestRedactLeavesLegitimateContentAlone(t *testing.T) {
	r, _ := NewRedactor(nil)
	keep := []string{
		// Certificates and plist payloads are needed by the model; the v0.1
		// "long base64" rule was dropped for exactly this reason.
		"-----BEGIN CERTIFICATE-----\nMIIDdzCCAl+gAwIBAgIEbGludXgwDQYJKoZIhvcNAQELBQAw\n-----END CERTIFICATE-----",
		"<data>\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n</data>",
		// sshd -T output: settings, not secrets.
		"passwordauthentication yes\npermitrootlogin no\nkbdinteractiveauthentication no",
		"PasswordAuthentication=no",
		"token_required: false",
		"# password: none",
		// sudoers tags: the value after NOPASSWD: is the granted command, and
		// hiding it is what made a model call a per-command grant "broad".
		"ops ALL=(root) NOPASSWD: /usr/bin/cat /etc/sudoers  # privesc.sudoers",
		"# %wheel\tALL=(ALL)\tNOPASSWD: ALL",
		"%admin ALL=(ALL) PASSWD: /usr/bin/systemctl",
		"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGxpbnV4bGludXhsaW51eGxpbnV4bGludXhsaW4 ops@bastion",
	}
	for _, in := range keep {
		out, hits := r.RedactString(in)
		if out != in {
			t.Errorf("legitimate content altered:\n in: %q\nout: %q\nhits: %v", in, out, hits)
		}
	}
}

func TestRedactMarkerCountsBytes(t *testing.T) {
	r, _ := NewRedactor(nil)
	out, hits := r.RedactString("x=AKIAIOSFODNN7EXAMPLE")
	if out != "x="+Marker("aws-access-key", 20) || hits[0].Bytes != 20 {
		t.Errorf("out=%q hits=%v", out, hits)
	}
}

func TestRedactBadExtraPattern(t *testing.T) {
	if _, err := NewRedactor([]string{"("}); err == nil {
		t.Fatal("want compile error")
	}
}

// A literal is redacted wherever it appears, ahead of the token shapes, so a
// credential a provider echoes back is hidden by its own rule.
func TestWithLiteralRedactsTheExactValue(t *testing.T) {
	base, err := NewRedactor(nil)
	if err != nil {
		t.Fatal(err)
	}
	r := base.WithLiteral("credential", "opaque-value-1234")
	out, hits := r.RedactString(`{"echo":"opaque-value-1234","again":"xopaque-value-1234y"}`)
	if strings.Contains(out, "opaque-value-1234") || len(hits) != 2 || hits[0].Rule != "credential" {
		t.Fatalf("%s %+v", out, hits)
	}
	if got, _ := base.RedactString("opaque-value-1234"); got != "opaque-value-1234" {
		t.Error("WithLiteral changed the base redactor")
	}
	if base.WithLiteral("credential", "") != base {
		t.Error("an empty literal must add nothing")
	}
}

// When the source was cut, a secret prefix in the last RedactSlack bytes is
// never kept, even when a rule that shrinks its input (a private key)
// brings the output under the cap.
func TestFinishDropsTheUnreadTail(t *testing.T) {
	r, err := NewRedactor(nil)
	if err != nil {
		t.Fatal(err)
	}
	key := "-----BEGIN OPENSSH PRIVATE KEY-----\n" + strings.Repeat("A", 4200) + "\n-----END OPENSSH PRIVATE KEY-----\n"
	raw := []byte(key + strings.Repeat("x", 100))
	raw = append(raw, "ghp_SECRETPREFIX"...) // a token whose end the source never sent
	out, truncated, _ := r.Finish(raw, true, 256)
	if strings.Contains(string(out), "SECRETPREFI") || strings.Contains(string(out), "ghp_") || !truncated {
		t.Fatalf("%q", out)
	}
	if !strings.Contains(string(out), "[REDACTED:private-key:") {
		t.Errorf("the key's marker is missing: %q", out)
	}
	// A complete read keeps everything up to the cap.
	whole, _, _ := r.Finish([]byte("short and complete"), false, 256)
	if string(whole) != "short and complete" {
		t.Errorf("%q", whole)
	}
}

// fakeSecret builds a token of a provider's shape at run time, so no file
// in the repository holds a string a secret scanner would block a push on.
func fakeSecret(prefix string, n int) string {
	const alphabet = "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"
	b := make([]byte, n)
	for i := range b {
		b[i] = alphabet[(i*7+3)%len(alphabet)]
	}
	return prefix + string(b)
}

// The shapes added with the scope gate redact in host output as in a
// response body (docs/spec/scope.md, "Responses").
func TestRedactProviderTokenShapes(t *testing.T) {
	r, err := NewRedactor(nil)
	if err != nil {
		t.Fatal(err)
	}
	webhook := fakeSecret("T", 10) + "/" + fakeSecret("B", 10) + "/" + fakeSecret("", 24)
	cases := []struct{ name, input, secret, rule string }{
		{"google access token", "Authorization: OAuth " + fakeSecret("ya"+"29.", 40), fakeSecret("ya"+"29.", 40), "google-access-token"},
		{"google refresh token", "refresh " + fakeSecret("1/"+"/0g", 40), fakeSecret("1/"+"/0g", 40), "google-refresh-token"},
		{"google api key", "key " + fakeSecret("AI"+"za", 35), fakeSecret("AI"+"za", 35), "google-api-key"},
		{"google client secret", "client " + fakeSecret("GOC"+"SPX-", 28), fakeSecret("GOC"+"SPX-", 28), "google-client-secret"},
		{"stripe secret key", "STRIPE " + fakeSecret("sk_"+"live_", 24), fakeSecret("sk_"+"live_", 24), "stripe-key"},
		{"stripe restricted key", "STRIPE " + fakeSecret("rk_"+"live_", 24), fakeSecret("rk_"+"live_", 24), "stripe-key"},
		{"npm token", "//registry.npmjs.org/:_authToken " + fakeSecret("np"+"m_", 36), fakeSecret("np"+"m_", 36), "npm-token"},
		{"slack webhook", "post to https://hooks.slack.com/services/" + webhook, webhook, "slack-webhook"},
		{"json member", `{"access_token": "opaque` + fakeSecret("", 20) + `"}`, "opaque" + fakeSecret("", 20), "json-secret"},
		{"json member escaped", `{"client_secret":"ab\"cd` + fakeSecret("", 12) + `"}`, `ab\"cd` + fakeSecret("", 12), "json-secret"},
		{"url query in json", `{"download_url":"https://x.example.com/f?token=` + fakeSecret("", 20) + `","size":3}`, fakeSecret("", 20), "kv-secret"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, _ := r.RedactString(tc.input)
			if strings.Contains(out, tc.secret) {
				t.Fatalf("secret survived: %q", out)
			}
			if !strings.Contains(out, "[REDACTED:"+tc.rule+":") {
				t.Fatalf("no %s marker in %q", tc.rule, out)
			}
		})
	}
	// A webhook keeps its host, which says a webhook exists.
	if out, _ := r.RedactString("https://hooks.slack.com/services/" + webhook); !strings.HasPrefix(out, "https://hooks.slack.com/services/[REDACTED:") {
		t.Errorf("%q", out)
	}
	// Keys that only look secret keep their values.
	for _, in := range []string{`{"token_type":"bearer"}`, `{"access_tokens_url":"https://api.github.com/x"}`, `{"secret_scanning":{"status":"enabled"}}`, `{"password_required":false}`, `{"nextPageToken":"Cg0xNzA5NjA0MDAwMDAw"}`} {
		if out, _ := r.RedactString(in); out != in {
			t.Errorf("altered %q to %q", in, out)
		}
	}
}

// Redacted JSON still parses, and keeps its structure (docs/spec/scope.md,
// "Responses"): the gate parses what RedactJSON returns, so a span that
// crossed strings would delete every item between them and still parse.
// The documents are generated from a fixed seed, compact and indented, with
// secrets in member values, keys, URLs and prose, split across strings,
// and behind escapes.
func TestRedactedJSONStillParses(t *testing.T) {
	r, err := NewRedactor([]string{`internal\.example\.net`})
	if err != nil {
		t.Fatal(err)
	}
	secrets := []string{
		fakeSecret("ya"+"29.", 40), fakeSecret("1/"+"/0g", 40), fakeSecret("AI"+"za", 35), fakeSecret("GOC"+"SPX-", 28),
		fakeSecret("sk_"+"live_", 24), fakeSecret("np"+"m_", 36), fakeSecret("gh"+"p_", 36), "AKIAIOSFODNN7EXAMPLE",
		"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.c2lnbmF0dXJlc2lnbg",
	}
	prose := []string{
		"Set your token:", "password=", "token: %s", "export API_KEY=%s", `password: "%s"`, "Bearer %s",
		"https://dl.example.com/f?token=%s&x=1", "see db.internal.example.net", "secret=%s;other", `token=a\b%s`,
		"https://hooks.slack.com/services/T0000/B0000/%s", "-----BEGIN PRIVATE KEY-----\nMII%s\n-----END PRIVATE KEY-----",
		"plain words", "", "token:", `"quoted" token="%s"`, "use token='abc here", "it's x", "line one\n%s",
		"-----BEGIN PRIVATE KEY-----", "-----END PRIVATE KEY-----", `password="`, `", "after`,
	}
	keys := []string{"access_token", "client_secret", "password", "name", "token_type", "description", "url", "api_key", "refresh_token", "x"}
	rng := rand.New(rand.NewPCG(7, 11))
	var planted []string
	var gen func(depth int) any
	gen = func(depth int) any {
		switch n := rng.IntN(10); {
		case depth > 3 || n < 4:
			s := secrets[rng.IntN(len(secrets))]
			switch rng.IntN(3) {
			case 0:
				planted = append(planted, s)
				return s
			case 1:
				p := prose[rng.IntN(len(prose))]
				if strings.Contains(p, "%s") {
					planted = append(planted, s)
					return strings.ReplaceAll(p, "%s", s)
				}
				return p
			default:
				return rng.IntN(1000)
			}
		case n < 7:
			m := map[string]any{}
			for range rng.IntN(5) {
				m[keys[rng.IntN(len(keys))]] = gen(depth + 1)
			}
			return m
		default:
			var a []any
			for range rng.IntN(4) {
				a = append(a, gen(depth+1))
			}
			return a
		}
	}
	for i := range 3000 {
		planted = planted[:0]
		doc := map[string]any{keys[rng.IntN(len(keys))]: gen(0), keys[rng.IntN(len(keys))]: gen(0)}
		var raw []byte
		if i%2 == 0 {
			raw, _ = json.Marshal(doc)
		} else {
			raw, _ = json.MarshalIndent(doc, "", "  ")
		}
		out, _, err := r.RedactJSON(raw)
		if err != nil {
			t.Fatal(err)
		}
		var before, after any
		if err := json.Unmarshal(out, &after); err != nil {
			t.Fatalf("redacted JSON no longer parses:\n in: %s\nout: %s", raw, out)
		}
		_ = json.Unmarshal(raw, &before)
		if !sameShape(before, after) {
			t.Fatalf("redaction changed the structure:\n in: %s\nout: %s", raw, out)
		}
		for _, s := range planted {
			if bytes.Contains(out, []byte(s)) {
				t.Fatalf("secret %q survived in %s", s[:6], out)
			}
		}
		if bytes.Contains(out, []byte("internal.example.net")) {
			t.Fatalf("redact_extra survived in %s", out)
		}
	}
}

// sameShape compares two documents' objects, keys and array lengths; a
// leaf may change, from a number to a marker string too.
func sameShape(a, b any) bool {
	switch x := a.(type) {
	case map[string]any:
		y, ok := b.(map[string]any)
		if !ok || len(x) != len(y) {
			return false
		}
		for k, v := range x {
			w, ok := y[k]
			if !ok || !sameShape(v, w) {
				return false
			}
		}
		return true
	case []any:
		y, ok := b.([]any)
		if !ok || len(x) != len(y) {
			return false
		}
		for i := range x {
			if !sameShape(x[i], y[i]) {
				return false
			}
		}
		return true
	}
	_, isMap := b.(map[string]any)
	_, isArr := b.([]any)
	return !isMap && !isArr
}

// The cases the value-by-value redaction exists for: a span across
// strings, an escape in front of a token, a token split by \/, a number
// redact_extra names, and a secret member whose value only part of a rule
// matched.
func TestRedactJSONValueByValue(t *testing.T) {
	r, err := NewRedactor([]string{`8675309`})
	if err != nil {
		t.Fatal(err)
	}
	r = r.WithLiteral("credential", "tok/en-0123456789abcdef")
	for _, tc := range []struct{ in, want string }{
		{`{"a":"use token='abc here","b":"it's x"}`, `{"a":"use token=[REDACTED:kv-secret:4 bytes] here","b":"it's x"}`},
		{`[{"n":"-----BEGIN PRIVATE KEY-----"},{"id":"101"},{"n":"-----END PRIVATE KEY-----"}]`,
			`[{"n":"[REDACTED:private-key:27 bytes]"},{"id":"101"},{"n":"-----END PRIVATE KEY-----"}]`},
		{`{"log":"line\nAKIAIOSFODNN7EXAMPLE"}`, `{"log":"line\n[REDACTED:aws-access-key:20 bytes]"}`},
		{`{"echo":"tok\/en-0123456789abcdef"}`, `{"echo":"[REDACTED:credential:23 bytes]"}`},
		{`{"account":8675309,"n":1}`, `{"account":"[REDACTED:extra:0:7 bytes]","n":1}`},
		{`{"api_key":"prefix AKIAIOSFODNN7EXAMPLE"}`, `{"api_key":"[REDACTED:json-secret:27 bytes]"}`},
		{`{"access_token":"` + fakeSecret("ya"+"29.", 40) + `"}`, `{"access_token":"[REDACTED:google-access-token:45 bytes]"}`},
		{`{"secret":{"x":"plain"},"token_type":"bearer","password":"no"}`, `{"secret":{"x":"plain"},"token_type":"bearer","password":"[REDACTED:json-secret:2 bytes]"}`},
		// A narrower rule that hit part of a secret value does not stand
		// for the whole of it.
		{`{"password":"[hunter2 ` + fakeSecret("gh"+"p_", 36) + `]"}`, `{"password":"[REDACTED:json-secret:50 bytes]"}`},
		{`{"client_secrets":"[\"` + fakeSecret("gh"+"p_", 36) + `\", \"hunter2\"]"}`, `{"client_secrets":"[REDACTED:json-secret:55 bytes]"}`},
		// Every scalar under a secret key, in arrays too; not an object's
		// members, and not a literal.
		{`{"token_required":1,"api_token":0}`, `{"token_required":1,"api_token":0}`},
		{`{"api_key":123456789012,"api_keys":["plainsecretvalue",["nested"]],"secret":{"n":5},"token":true}`,
			`{"api_key":"[REDACTED:json-secret:12 bytes]","api_keys":["[REDACTED:json-secret:16 bytes]",["[REDACTED:json-secret:6 bytes]"]],"secret":{"n":5},"token":true}`},
	} {
		out, _, err := r.RedactJSON([]byte(tc.in))
		if err != nil || string(out) != tc.want {
			t.Errorf("RedactJSON(%s)\n got %s %v\nwant %s", tc.in, out, err, tc.want)
		}
	}
	if _, _, err := r.RedactJSON([]byte(`{"a":`)); !errors.Is(err, ErrNotJSON) {
		t.Errorf("not JSON: %v", err)
	}
}

// kv-secret in text is what it was before E4: the JSON-aware terminators
// belong to RedactJSON, never to host output.
func TestKVSecretInTextIsUnchanged(t *testing.T) {
	r, _ := NewRedactor(nil)
	for _, in := range []string{`DB_PASSWORD=",8675309"`, `password: ":20240101"`, `password=Hunt3r":x9Q`, `token=abc"]def-rest-of-secret`} {
		out, _ := r.RedactString(in)
		for _, frag := range []string{"8675309", "20240101", "x9Q", "Hunt3r", "rest-of-secret"} {
			if strings.Contains(in, frag) && strings.Contains(out, frag) {
				t.Errorf("%q leaked %q: %q", in, frag, out)
			}
		}
	}
}

// Under a secret-shaped JSON key only true, false, null, 0, 1, "0", "1" and
// "" stay as they are; every other value is redacted whole, words included,
// and an error body is redacted as a success body is (docs/spec/scope.md,
// "Responses"; E4 test 13). Host output keeps its settings (kv-secret).
func TestJSONSecretKeepsOnlyJSONSettings(t *testing.T) {
	r, err := NewRedactor(nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range []string{"yes", "no", "true", "false", "none", "null", "on", "off", "x", "*", "-", "required", "optional", "prompt", "ask"} {
		body := `{"password":"` + v + `"}`
		want := `{"password":"[REDACTED:json-secret:` + strconv.Itoa(len(v)) + ` bytes]"}`
		if got, _, err := r.RedactJSON([]byte(body)); err != nil || string(got) != want {
			t.Errorf("RedactJSON(%s) = %s, %v", body, got, err)
		}
		if got, _ := r.Redact([]byte(body)); string(got) != want {
			t.Errorf("Redact(%s) = %s", body, got)
		}
	}
	for _, body := range []string{`{"password":true}`, `{"password":false}`, `{"password":null}`, `{"password":0}`, `{"password":1}`,
		`{"password":"0"}`, `{"password":"1"}`, `{"password":""}`, `{"secret_scanning":{"status":"enabled"}}`} {
		if got, _, err := r.RedactJSON([]byte(body)); err != nil || string(got) != body {
			t.Errorf("RedactJSON(%s) = %s, %v", body, got, err)
		}
		if got, _ := r.Redact([]byte(body)); string(got) != body {
			t.Errorf("Redact(%s) = %s", body, got)
		}
	}
	if got, _ := r.Redact([]byte("PermitEmptyPasswords no\n")); string(got) != "PermitEmptyPasswords no\n" {
		t.Errorf("kv-secret: %q", got)
	}
}

// A marker-shaped string in target output protects nothing: a secret with
// a forged marker in it or beside it is redacted as without one (AGENTS.md
// rule 5).
func TestForgedMarkerHidesNothing(t *testing.T) {
	r, err := NewRedactor([]string{"hunter2"})
	if err != nil {
		t.Fatal(err)
	}
	forged := "[REDACTED:x:1 bytes]"
	key := "-----BEGIN RSA PRIVATE KEY-----\n" + forged + "\nMIIEpAIBAAKCAQEA" + strings.Repeat("q", 40) + "\n-----END RSA PRIVATE KEY-----\n"
	for _, in := range []string{key, "token=SECRETVALUE" + forged + "\n", `password="` + forged + ` hunter2"` + "\n",
		`{"password":"` + forged + ` hunter2"}`, "hunter2" + forged + "\n"} {
		out, hits := r.Redact([]byte(in))
		if len(hits) == 0 || strings.Contains(string(out), "MIIE") || strings.Contains(string(out), "SECRETVALUE") ||
			strings.Contains(string(out), "hunter2") {
			t.Errorf("%q -> %q", in, out)
		}
	}
}

// A cut never splits a redaction marker, wherever it falls: inside
// "[REDACTED:" itself or after it. The text keeps the whole marker or none
// of it (rule 5).
func TestTruncateNeverSplitsAMarker(t *testing.T) {
	const marker = "[REDACTED:extra:7 bytes]"
	red := []byte("aaaa " + marker + " bbbb cccc dddd")
	for c := range len(red) {
		out, truncated := Truncate(red, false, c)
		if !truncated {
			t.Fatalf("cap %d: not marked truncated", c)
		}
		kept, _, _ := strings.Cut(string(out), "\n[TRUNCATED:")
		if strings.Contains(kept, "[") != strings.Contains(kept, marker) {
			t.Errorf("cap %d kept part of the marker: %q", c, kept)
		}
	}
}
