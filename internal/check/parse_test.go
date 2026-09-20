package check

import (
	"reflect"
	"strings"
	"testing"
)

// ck is a throwaway check with a parser and an argv, which is what Parse
// needs: a typed shape is read differently depending on which tool produced
// it (docs/SPEC.md §3).
func ck(kind ParserKind, argv ...string) Check {
	if len(argv) == 0 {
		argv = []string{"true"}
	}
	return Check{ID: "test.check", Platform: Any, Parser: kind, Argv: argv}
}

func TestParseKV(t *testing.T) {
	in := "port 22\nlistenaddress [::]:22\nProductName:\tmacOS\nNAME=\"Ubuntu\"\naws_access_key_id = X\n# comment\nnosep\nport 23\n"
	got, err := Parse(ck(ParseKV), []byte(in))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"port": "22", "listenaddress": "[::]:22", "productname": "macOS", "name": "Ubuntu", "aws_access_key_id": "X"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v\nwant %v", got, want)
	}
}

// A colon-terminated label is the only key form that may contain spaces, and
// it must not steal a value that merely contains a colon. Both shapes appear
// in the catalog: `sestatus` prints the first, `sshd -T` the second, and the
// SELinux posture rule (docs/SPEC.md §7.5) reads a key with a space in it.
func TestParseKVKeysWithSpacesAndValuesWithColons(t *testing.T) {
	in := "SELinux status:                 enabled\n" +
		"Current mode:                   enforcing\n" +
		"listenaddress [::]:22\n" +
		"NTPSynchronized=yes\n"
	got, _ := Parse(ck(ParseKV), []byte(in))
	want := map[string]string{
		"selinux status": "enabled", "current mode": "enforcing",
		"listenaddress": "[::]:22", "ntpsynchronized": "yes",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v\nwant %v", got, want)
	}
}

func TestParseLinesAndJSON(t *testing.T) {
	got, _ := Parse(ck(ParseLines), []byte("\xef\xbb\xbfa\r\n\n b \n"))
	if !reflect.DeepEqual(got, []string{"a", " b "}) {
		t.Errorf("lines: %#v", got)
	}
	if _, err := Parse(ck(ParseJSON), []byte("")); err == nil {
		t.Error("empty json accepted")
	}
	if _, err := Parse(ck(ParseJSON), []byte("{\"a\":1")); err == nil {
		t.Error("malformed json accepted")
	}
	if v, err := Parse(ck(ParseJSON), []byte(`{"a":[1]}`)); err != nil || v.(map[string]any)["a"] == nil {
		t.Errorf("json: %v %v", v, err)
	}
	if _, err := Parse(ck("xml"), nil); err == nil {
		t.Error("unknown parser accepted")
	}
}

// Malformed and edge-case input for every parser kind must degrade, never
// panic (roadmap M1.3).
func TestParseEdgeCases(t *testing.T) {
	cases := []struct {
		kind ParserKind
		in   string
		want any
		err  bool
	}{
		{ParseRaw, "", "", false},
		{ParseLines, "", []string{}, false},
		{ParseLines, "   \n\t\n", []string{}, false},
		{ParseLines, "a\r\nb\r\n", []string{"a", "b"}, false},
		{ParseLines, "a\nb", []string{"a", "b"}, false}, // truncated: no trailing newline
		{ParseKV, "", map[string]string{}, false},
		{ParseKV, "\xef\xbb\xbfA=1\r\nB: two\r\n", map[string]string{"a": "1", "b": "two"}, false},
		{ParseKV, "key=", map[string]string{"key": ""}, false},
		{ParseKV, "=value\n:x\n", map[string]string{}, false},
		{ParseKV, "dup=1\ndup=2\n", map[string]string{"dup": "1"}, false},
		{ParseKV, "cut=va", map[string]string{"cut": "va"}, false}, // truncated mid-value
		{ParseKV, "[TRUNCATED:12 bytes]", map[string]string{}, false},
		{ParseJSON, "   ", nil, true},
		{ParseJSON, `{"a":1}trailing`, nil, true},
		{ParseJSON, `[1,2`, nil, true},
		{ParseJSON, `null`, nil, false},
		{ParseJSON, `[]`, []any{}, false},
	}
	for i, tc := range cases {
		got, err := Parse(ck(tc.kind), []byte(tc.in))
		if (err != nil) != tc.err {
			t.Errorf("case %d (%s %q): err=%v want error=%v", i, tc.kind, tc.in, err, tc.err)
			continue
		}
		if !tc.err && !reflect.DeepEqual(got, tc.want) {
			t.Errorf("case %d (%s %q): got %#v want %#v", i, tc.kind, tc.in, got, tc.want)
		}
	}
	// 1 MiB of garbage must parse (or fail) quickly and quietly.
	big := []byte(strings.Repeat("\x00\xff=\n", 256<<10))
	for _, k := range []ParserKind{ParseRaw, ParseLines, ParseKV, ParseJSON, ParseListeners, ParseUpdates, ParseUnits, ParseAccounts, ParsePasswdStatus, ParseLaunchd, ParseFileMode} {
		_, _ = Parse(ck(k, "ss"), big)
	}
}

func records(t *testing.T, c Check, in string) Records {
	t.Helper()
	v, err := Parse(c, []byte(in))
	if err != nil {
		t.Fatalf("%s: %v", c.Parser, err)
	}
	r, ok := v.(Records)
	if !ok {
		t.Fatalf("%s did not produce records: %#v", c.Parser, v)
	}
	return r
}

// The typed shapes of docs/SPEC.md §3: one record per thing, with the fields
// a summary, a posture rule or a future diff needs by name.
func TestTypedShapes(t *testing.T) {
	t.Run("listeners/ss", func(t *testing.T) {
		in := "tcp LISTEN 0      128    0.0.0.0:22 0.0.0.0:*\n" +
			"tcp LISTEN 0      128       [::]:22    [::]:* users:((\"sshd\",pid=712,fd=4))\n"
		r := records(t, ck(ParseListeners, "ss", "-tulpnH"), in)
		if r.Len() != 2 || r.Partial {
			t.Fatalf("got %#v", r)
		}
		if r.Items[0][FieldAddress] != "0.0.0.0" || r.Items[0][FieldPort] != "22" {
			t.Errorf("address/port: %v", r.Items[0])
		}
		if r.Items[1][FieldAddress] != "::" || r.Items[1][FieldProcess] != "sshd" || r.Items[1][FieldPID] != "712" {
			t.Errorf("v6 record: %v", r.Items[1])
		}
	})
	t.Run("listeners/lsof", func(t *testing.T) {
		in := "COMMAND     PID   USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME\n" +
			"rapportd   1020 alice   10u  IPv4 0xf442d598091222ee      0t0  TCP *:53019 (LISTEN)\n" +
			"Chrome     2001 alice   30u  IPv4 0x1111111111111111      0t0  TCP 10.0.0.2:52000->1.1.1.1:443 (ESTABLISHED)\n"
		r := records(t, ck(ParseListeners, "lsof", "-nP"), in)
		if r.Len() != 1 || r.Partial {
			t.Fatalf("established sockets or the header leaked in: %#v", r)
		}
		got := r.Items[0]
		if got[FieldProcess] != "rapportd" || got[FieldPID] != "1020" || got[FieldPort] != "53019" || got[FieldProtocol] != "tcp" {
			t.Errorf("record: %v", got)
		}
	})
	t.Run("accounts/passwd", func(t *testing.T) {
		r := records(t, ck(ParseAccounts, "cat", "/etc/passwd"),
			"root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n")
		if r.Len() != 2 || r.Items[0][FieldShell] != "/bin/bash" || r.Items[1][FieldUID] != "1" {
			t.Fatalf("got %#v", r)
		}
	})
	t.Run("accounts/dscl", func(t *testing.T) {
		r := records(t, ck(ParseAccounts, "dscl", "."), "_amavisd                 83\nalice 501\n")
		if r.Len() != 2 || r.Items[1][FieldName] != "alice" || r.Items[1][FieldUID] != "501" {
			t.Fatalf("got %#v", r)
		}
		if _, ok := r.Items[0][FieldShell]; ok {
			t.Error("dscl output has no shell field to report")
		}
	})
	t.Run("passwd_status", func(t *testing.T) {
		r := records(t, ck(ParsePasswdStatus, "passwd", "-S", "-a"), "root L 2026-09-11 0 99999 7 -1\nalice NP 2026-09-11\n")
		if r.Len() != 2 || r.Items[1][FieldStatus] != "NP" {
			t.Fatalf("got %#v", r)
		}
	})
	t.Run("units", func(t *testing.T) {
		in := "UNIT FILE               STATE   PRESET\ncron.service            enabled enabled\n\n13 unit files listed.\n"
		r := records(t, ck(ParseUnits, "systemctl", "list-unit-files"), in)
		if r.Len() != 1 || r.Partial || r.Items[0][FieldName] != "cron.service" || r.Items[0][FieldState] != "enabled" {
			t.Fatalf("header or footer became a unit: %#v", r)
		}
	})
	t.Run("updates/apt", func(t *testing.T) {
		in := "Listing...\nbash/noble-updates 5.2.21-2ubuntu4 arm64 [upgradable from: 5.2.21-2ubuntu3]\n"
		r := records(t, ck(ParseUpdates, "apt", "list", "--upgradable"), in)
		if r.Len() != 1 || r.Items[0][FieldName] != "bash" || r.Items[0][FieldVersion] != "5.2.21-2ubuntu4" {
			t.Fatalf("got %#v", r)
		}
		empty := records(t, ck(ParseUpdates, "apt", "list", "--upgradable"), "Listing...\n")
		if empty.Len() != 0 || empty.Partial {
			t.Fatalf("an up-to-date host is complete evidence of zero updates: %#v", empty)
		}
	})
	t.Run("updates/dnf", func(t *testing.T) {
		r := records(t, ck(ParseUpdates, "dnf", "-q", "check-update"), "\nzstd.aarch64    1.5.7-1.fc40    updates\n")
		if r.Len() != 1 || r.Items[0][FieldName] != "zstd.aarch64" || r.Items[0][FieldVersion] != "1.5.7-1.fc40" {
			t.Fatalf("got %#v", r)
		}
	})
	t.Run("updates/softwareupdate", func(t *testing.T) {
		in := "Software Update Tool\n\nSoftware Update found the following new or updated software:\n" +
			"* Label: Safari27.0TahoeAuto-27.0\n\tTitle: Safari, Version: 27.0, Size: 249465KiB, Recommended: YES, \n"
		r := records(t, ck(ParseUpdates, "softwareupdate", "-l"), in)
		if r.Len() != 1 || r.Partial || r.Items[0][FieldVersion] != "27.0" {
			t.Fatalf("banner lines are not updates: %#v", r)
		}
	})
	t.Run("launchd", func(t *testing.T) {
		r := records(t, ck(ParseLaunchd, "launchctl", "list"), "PID\tStatus\tLabel\n-\t0\tcom.apple.a\n972\t0\tcom.apple.b\n")
		if r.Len() != 2 || r.Items[1][FieldLabel] != "com.apple.b" || r.Items[1][FieldPID] != "972" {
			t.Fatalf("got %#v", r)
		}
	})
	t.Run("file_mode", func(t *testing.T) {
		r := records(t, ck(ParseFileMode, "stat"), "-rw-r-----:640:root:shadow:577\n")
		if r.Len() != 1 || r.Items[0][FieldMode] != "640" || r.Items[0][FieldGroup] != "shadow" {
			t.Fatalf("got %#v", r)
		}
		if _, err := Parse(ck(ParseFileMode, "stat"), []byte("cannot stat\n")); err == nil {
			t.Error("a mode scheck cannot read must be a parse error, not a guess")
		}
		if _, err := Parse(ck(ParseFileMode, "stat"), nil); err == nil {
			t.Error("empty output accepted as a mode")
		}
	})
}

// Incomplete evidence stays labelled, because a posture rule may prove an
// existential condition from a partial record set but never a negative one
// (docs/SPEC.md §7.5).
func TestTypedShapesRecordIncompleteness(t *testing.T) {
	c := ck(ParsePasswdStatus, "passwd", "-S", "-a")
	truncated := records(t, c, "root L 2026-09-11\n[TRUNCATED:812 bytes]")
	if !truncated.Partial || truncated.Len() != 1 {
		t.Errorf("truncation not carried into the records: %#v", truncated)
	}
	redacted := records(t, c, "root L 2026-09-11\n[REDACTED:kv-secret:9 bytes]\n")
	if !redacted.Partial {
		t.Errorf("redaction not carried into the records: %#v", redacted)
	}
	garbled := records(t, c, "root L 2026-09-11\n?\n")
	if !garbled.Partial || garbled.Len() != 1 || !strings.Contains(garbled.Note, "not recognised") {
		t.Errorf("unreadable line not reported: %#v", garbled)
	}
	crlf := records(t, c, "root L 2026-09-11\r\nalice P 2026-09-11\r\n")
	if crlf.Partial || crlf.Len() != 2 {
		t.Errorf("CRLF input: %#v", crlf)
	}
	header := records(t, ck(ParseUnits, "systemctl"), "UNIT FILE STATE PRESET\n")
	if header.Len() != 0 || header.Partial {
		t.Errorf("header-only output: %#v", header)
	}
}
