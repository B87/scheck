package report

import "testing"

// A creds.app_env_N slot is undeclared when it lies past the application
// folders the asset declares: the report never blames the run's clock for it
// (docs/spec/engagement.md, "Host settings").
func TestUndeclaredAppEnvSlot(t *testing.T) {
	v := &hostView{h: &HostInput{AppPaths: 2}}
	for id, want := range map[string]bool{
		"creds.app_env_1": false, "creds.app_env_2": false, "creds.app_env_3": true, "creds.app_env_5": true,
		"creds.home_files": false, "creds.app_env_x": false,
	} {
		if got := v.undeclaredSlot(id); got != want {
			t.Errorf("%s: %v, want %v", id, got, want)
		}
	}
	if !(&hostView{h: &HostInput{}}).undeclaredSlot("creds.app_env_1") {
		t.Error("with no folder declared every slot is undeclared")
	}
}
