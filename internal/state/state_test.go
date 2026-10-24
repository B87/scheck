package state

import (
	"strings"
	"testing"
)

func TestDirPrecedence(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", "/tmp/xdg")
	if d, _ := Dir(""); d != "/tmp/xdg/scheck" {
		t.Errorf("xdg: %s", d)
	}
	if d, _ := Dir("/explicit"); d != "/explicit" {
		t.Errorf("explicit: %s", d)
	}
	t.Setenv("XDG_STATE_HOME", "")
	if d, _ := Dir(""); !strings.HasSuffix(d, "/.local/state/scheck") {
		t.Errorf("default: %s", d)
	}
}
