package check

import (
	"strings"
	"testing"
)

func TestBindHappyPath(t *testing.T) {
	c := Check{ID: "text.head", Argv: []string{"head", "-n", "{lines}", "{path}"},
		Params: []Param{{Name: "lines", Kind: KindInt, Min: 1, Max: 500}, {Name: "path", Kind: KindPath}}}
	argv, err := c.Bind(map[string]string{"lines": "20", "path": "/etc/ssh/sshd_config"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(argv, " ") != "head -n 20 /etc/ssh/sshd_config" {
		t.Errorf("argv = %q", argv)
	}
}

// Hostile inputs: each must be refused at bind time with a message naming the
// param, before any policy or exec is involved.
func TestBindRejectsHostileParams(t *testing.T) {
	c := Check{ID: "text.head", Argv: []string{"head", "-n", "{lines}", "{path}"},
		Params: []Param{{Name: "lines", Kind: KindInt, Min: 1, Max: 500}, {Name: "path", Kind: KindPath}}}
	cases := map[string]map[string]string{
		"traversal":         {"lines": "1", "path": "/etc/../etc/shadow"},
		"relative":          {"lines": "1", "path": "etc/passwd"},
		"space":             {"lines": "1", "path": "/etc/passwd /etc/shadow"},
		"semicolon":         {"lines": "1", "path": "/etc/passwd;id"},
		"dollar":            {"lines": "1", "path": "/etc/$HOME"},
		"glob":              {"lines": "1", "path": "/etc/*"},
		"newline":           {"lines": "1", "path": "/etc/passwd\n"},
		"int out of range":  {"lines": "9999", "path": "/etc/passwd"},
		"int not a number":  {"lines": "1;id", "path": "/etc/passwd"},
		"missing param":     {"path": "/etc/passwd"},
		"unknown param":     {"lines": "1", "path": "/etc/passwd", "extra": "x"},
		"empty path":        {"lines": "1", "path": ""},
		"unicode homoglyph": {"lines": "1", "path": "/etc/pаsswd"},
	}
	for name, params := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := c.Bind(params); err == nil {
				t.Fatalf("accepted %v", params)
			}
		})
	}
}

func TestBindEnumAndIdent(t *testing.T) {
	c := Check{ID: "svc.show", Argv: []string{"systemctl", "show", "{unit}", "--property", "{prop}"},
		Params: []Param{{Name: "unit", Kind: KindIdent}, {Name: "prop", Kind: KindEnum, Enum: []string{"ActiveState", "UnitFileState"}}}}
	if _, err := c.Bind(map[string]string{"unit": "sshd.service", "prop": "ActiveState"}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Bind(map[string]string{"unit": "sshd.service", "prop": "ExecStart"}); err == nil {
		t.Error("enum value outside list accepted")
	}
	if _, err := c.Bind(map[string]string{"unit": "sshd service", "prop": "ActiveState"}); err == nil {
		t.Error("ident with space accepted")
	}
	if _, err := c.Bind(map[string]string{"unit": "../x", "prop": "ActiveState"}); err == nil {
		t.Error("ident with slash accepted")
	}
}

func TestRegisterAndLookup(t *testing.T) {
	Reset()
	t.Cleanup(Reset)
	Register(
		Check{ID: "fs.stat", Platform: Linux, Argv: []string{"stat"}},
		Check{ID: "fs.stat", Platform: MacOS, Argv: []string{"stat", "-f"}},
		Check{ID: "sys.uname", Platform: Any, Argv: []string{"uname", "-a"}, Baseline: true},
		Check{ID: "svc.show", Platform: Linux, Argv: []string{"systemctl", "show"}, MinProfile: ProfileHardened},
	)
	if c, ok := Lookup("fs.stat", MacOS); !ok || c.Argv[1] != "-f" {
		t.Errorf("platform-specific lookup failed: %+v %v", c, ok)
	}
	if c, ok := Lookup("sys.uname", MacOS); !ok || c.Platform != Any {
		t.Errorf("any lookup failed: %+v %v", c, ok)
	}
	if _, ok := Lookup("svc.show", MacOS); ok {
		t.Error("linux-only check visible on macos")
	}
	if got := len(ForPlatform(Linux, ProfileBaseline)); got != 2 {
		t.Errorf("baseline-profile linux menu = %d, want 2", got)
	}
	if got := len(ForPlatform(Linux, ProfileHardened)); got != 3 {
		t.Errorf("hardened-profile linux menu = %d, want 3", got)
	}
	if got := Baseline(Linux); len(got) != 1 || got[0].ID != "sys.uname" {
		t.Errorf("baseline = %+v", got)
	}
	defer func() {
		if recover() == nil {
			t.Error("duplicate registration did not panic")
		}
	}()
	Register(Check{ID: "fs.stat", Platform: Any, Argv: []string{"stat"}})
}

func TestExitAllowed(t *testing.T) {
	if !(Check{}).ExitAllowed(0) || (Check{}).ExitAllowed(1) {
		t.Error("default must be {0}")
	}
	c := Check{ExitOK: []int{0, 100}}
	if !c.ExitAllowed(100) || c.ExitAllowed(1) {
		t.Error("explicit list")
	}
	if !(Check{ExitOK: AnyExit}).ExitAllowed(255) {
		t.Error("AnyExit")
	}
}
