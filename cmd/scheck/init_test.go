package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/b87/scheck/internal/engagement"
	"github.com/b87/scheck/internal/engagement/hostasset"
)

func TestInitWritesBrightcartAndContactsNothing(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	prev := collectHost
	collectHost = func(context.Context, hostasset.Options) (*hostasset.Collection, error) {
		t.Fatal("init contacted a host")
		return nil, nil
	}
	t.Cleanup(func() { collectHost = prev })
	path := filepath.Join(dir, "engagement.yaml")
	script := strings.Join([]string{
		"an incident", ".",
		"brightcart-2026-q4", ".",
		"Dani, IT and operations", ".",
		"Europe/London", ".",
		"domain: brightcart.co.uk", "saas: google-workspace:brightcart.co.uk", "saas: github:brightcart-dev", ".",
		".",
		"domain: brightcart.co.uk", "service: Google Workspace", ".",
		"handle: dani", "kind: employee", "workspace: dani@brightcart.co.uk", ".",
		".",
		"where: google-workspace:brightcart.co.uk", "handles: dani", ".",
		".",
		"where: google-workspace:brightcart.co.uk", "enforced: some accounts", ".",
		".",
		".",
		".",
		"cloud", ".",
	}, "\n") + "\n"
	// The script is one answer per asked question, in order. Blank answers
	// are a single dot. Questions a root makes inapplicable are not read.
	root := newRootCmd()
	var stderr bytes.Buffer
	root.SetIn(strings.NewReader(script))
	root.SetOut(&bytes.Buffer{})
	root.SetErr(&stderr)
	root.SetArgs([]string{"init", path})
	err := root.Execute()
	if err != nil {
		t.Fatalf("exit: %v\nstderr:\n%s", err, stderr.String())
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v %v", fi, err)
	}
	text := string(raw)
	if !strings.Contains(text, "Keep it out of public repositories") || strings.Contains(text, "mailboxes:") {
		t.Fatalf("file:\n%s", text)
	}
	if _, err := engagement.Parse(path, raw, engagementOptions); err != nil {
		t.Fatalf("written file: %v\n%s", err, text)
	}
	msg := stderr.String()
	if !strings.Contains(msg, "admin.directory.user.security") || !strings.Contains(msg, "gmail.readonly") || !strings.Contains(msg, "nothing contacted") {
		t.Fatalf("stderr:\n%s", msg)
	}
}

func TestInitRefusesACredential(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "engagement.yaml")
	token := "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	root := newRootCmd()
	root.SetIn(strings.NewReader("pat " + token + "\n.\n"))
	root.SetOut(&bytes.Buffer{})
	root.SetErr(&bytes.Buffer{})
	root.SetArgs([]string{"init", path})
	err := root.Execute()
	if err == nil || !strings.Contains(err.Error(), "detector github-token") || strings.Contains(err.Error(), token) {
		t.Fatalf("got %v", err)
	}
	if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
		t.Fatal("init wrote a file after refusing a credential")
	}
}

func TestInitAsksOnlyWhatTheHostFileDoesNotAnswer(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "host.yaml")
	if _, _, code := runEngagement(t, "--host", "deploy@203.0.113.5", "--write-engagement", path); code != exitOK {
		t.Fatal(code)
	}
	// operator, exclude, people, exposed, restricted, context, not_used.
	script := "platform-team\n.\n.\n.\n.\n.\nname: host-203-0-113-5\nexposure: lan\nenvironment: prod\n.\ncloud\n.\n"
	root := newRootCmd()
	var stderr bytes.Buffer
	root.SetIn(strings.NewReader(script))
	root.SetOut(&bytes.Buffer{})
	root.SetErr(&stderr)
	root.SetArgs([]string{"init", path})
	if err := root.Execute(); err != nil {
		t.Fatalf("%v\n%s", err, stderr.String())
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	res, err := engagement.Parse(path, raw, engagementOptions)
	if err != nil {
		t.Fatalf("%v\n%s", err, raw)
	}
	if res.Engagement.Name != "host-203-0-113-5" || res.Engagement.Operator != "platform-team" {
		t.Fatalf("name/operator %+v", res.Engagement)
	}
	if strings.Contains(stderr.String(), "What brought you to run this") {
		t.Fatal("init asked the trigger the host file already answered")
	}
}
